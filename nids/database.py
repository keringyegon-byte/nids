"""Logging Module: thread-safe SQLite persistence. All queries are parameterised."""
import csv
import functools
import sqlite3
import threading
from datetime import datetime
from typing import Dict, List, Optional

from .detector import Rule
from .models import Detection, format_time, TYPE_INFO

SCHEMA = """
CREATE TABLE IF NOT EXISTS attack_type (
    type_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type_name        TEXT NOT NULL UNIQUE,
    description      TEXT,
    category         TEXT NOT NULL DEFAULT 'NETWORK',
    default_severity TEXT NOT NULL CHECK (default_severity IN ('LOW','MEDIUM','HIGH'))
);
CREATE TABLE IF NOT EXISTS detection_rule (
    rule_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    type_id        INTEGER NOT NULL UNIQUE REFERENCES attack_type(type_id),
    threshold      INTEGER NOT NULL CHECK (threshold > 0),
    window_seconds INTEGER NOT NULL DEFAULT 1,
    extra          INTEGER NOT NULL DEFAULT 0,
    is_enabled     INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS monitoring_session (
    session_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_name TEXT NOT NULL,
    started_at     TEXT NOT NULL,
    ended_at       TEXT
);
CREATE TABLE IF NOT EXISTS alert (
    alert_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER NOT NULL REFERENCES monitoring_session(session_id),
    type_id       INTEGER NOT NULL REFERENCES attack_type(type_id),
    detected_at   TEXT NOT NULL,
    source_ip     TEXT,
    target_ip     TEXT,
    device        TEXT,
    packet_count  INTEGER NOT NULL,
    severity      TEXT NOT NULL,
    details       TEXT,
    simulated     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS trusted_host (
    host_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT NOT NULL UNIQUE,
    description TEXT,
    added_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS restricted_port (
    port_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    port_number INTEGER NOT NULL CHECK (port_number BETWEEN 1 AND 65535),
    category    TEXT NOT NULL DEFAULT 'RESTRICTED' CHECK (category IN ('RESTRICTED','AUTH')),
    description TEXT,
    UNIQUE (port_number, category)
);
CREATE TABLE IF NOT EXISTS trusted_usb (
    usb_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    dev_id      TEXT NOT NULL UNIQUE,
    description TEXT,
    added_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS usb_event (
    event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time TEXT NOT NULL,
    action     TEXT NOT NULL,
    kind       TEXT,
    dev_id     TEXT,
    name       TEXT,
    mount      TEXT,
    size_bytes INTEGER,
    verdict    TEXT,
    details    TEXT,
    simulated  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alert_time   ON alert(detected_at);
CREATE INDEX IF NOT EXISTS idx_alert_source ON alert(source_ip);
CREATE INDEX IF NOT EXISTS idx_alert_type   ON alert(type_id);
"""

DEFAULT_RESTRICTED = [(23, "Telnet"), (4444, "Common backdoor / Metasploit"), (5900, "VNC remote access")]
DEFAULT_AUTH = [(21, "FTP login"), (22, "SSH login"), (3389, "Remote Desktop login")]


def default_rules() -> List[Rule]:
    return [Rule(n, v[2], float(v[3]), v[1], True, v[4]) for n, v in TYPE_INFO.items()]


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def locked(fn):
    @functools.wraps(fn)
    def wrapper(self, *a, **kw):
        with self.lock:
            return fn(self, *a, **kw)
    return wrapper


class Database:
    def __init__(self, path: str = "nids_v2.db"):
        self.path = path
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self._type_ids: Dict[str, int] = {}
        self._seed()

    @locked
    def _seed(self) -> None:
        c = self.conn
        for name, v in TYPE_INFO.items():
            if c.execute("SELECT 1 FROM attack_type WHERE type_name=?", (name,)).fetchone():
                continue
            cur = c.execute("INSERT INTO attack_type(type_name, description, category, default_severity)"
                            " VALUES (?,?,?,?)", (name, v[0], v[7], v[1]))
            c.execute("INSERT INTO detection_rule(type_id, threshold, window_seconds, extra) VALUES (?,?,?,?)",
                      (cur.lastrowid, v[2], v[3], v[4]))
        if c.execute("SELECT COUNT(*) FROM restricted_port").fetchone()[0] == 0:
            c.executemany("INSERT INTO restricted_port(port_number, category, description) VALUES (?,'RESTRICTED',?)",
                          DEFAULT_RESTRICTED)
            c.executemany("INSERT INTO restricted_port(port_number, category, description) VALUES (?,'AUTH',?)",
                          DEFAULT_AUTH)
        c.commit()

    @locked
    def close(self) -> None:
        self.conn.close()

    # ---------------------------------------------------------------- sessions
    @locked
    def start_session(self, interface: str) -> int:
        cur = self.conn.execute("INSERT INTO monitoring_session(interface_name, started_at) VALUES (?,?)",
                                (interface, _now()))
        self.conn.commit()
        return cur.lastrowid

    @locked
    def end_session(self, session_id: int) -> None:
        self.conn.execute("UPDATE monitoring_session SET ended_at=? WHERE session_id=?", (_now(), session_id))
        self.conn.commit()

    # ------------------------------------------------------------------ alerts
    def _type_id(self, name: str) -> int:
        if name not in self._type_ids:
            row = self.conn.execute("SELECT type_id FROM attack_type WHERE type_name=?", (name,)).fetchone()
            if row is None:
                raise KeyError(f"Unknown attack type: {name}")
            self._type_ids[name] = row[0]
        return self._type_ids[name]

    @locked
    def add_alert(self, d: Detection, session_id: int) -> int:
        cur = self.conn.execute(
            "INSERT INTO alert(session_id, type_id, detected_at, source_ip, target_ip, device, packet_count,"
            " severity, details, simulated) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (session_id, self._type_id(d.attack_type), format_time(d.timestamp), d.source_ip, d.target_ip,
             d.device, d.count, d.severity, d.details, int(d.simulated)))
        self.conn.commit()
        return cur.lastrowid

    _ALERT_SQL = ("SELECT a.alert_id, a.detected_at, a.source_ip, a.target_ip, a.device, t.type_name, "
                  "a.packet_count, a.severity, a.details, a.simulated FROM alert a "
                  "JOIN attack_type t ON t.type_id = a.type_id WHERE 1=1")

    @locked
    def search_alerts(self, date_from=None, date_to=None, source_ip=None, attack_type=None,
                      severity=None, simulated=None, limit=None, offset=0):
        sql, args = self._ALERT_SQL, []
        if date_from:
            sql += " AND a.detected_at >= ?"; args.append(date_from + " 00:00:00")
        if date_to:
            sql += " AND a.detected_at <= ?"; args.append(date_to + " 23:59:59")
        if source_ip:
            sql += " AND (a.source_ip = ? OR a.device LIKE ?)"; args += [source_ip, f"%{source_ip}%"]
        if attack_type:
            sql += " AND t.type_name = ?"; args.append(attack_type)
        if severity:
            sql += " AND a.severity = ?"; args.append(severity)
        if simulated is not None:
            sql += " AND a.simulated = ?"; args.append(int(simulated))
        sql += " ORDER BY a.alert_id DESC"
        if limit:
            sql += " LIMIT ? OFFSET ?"; args += [int(limit), int(offset)]
        return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    @locked
    def stats(self) -> dict:
        q = self.conn.execute
        return {
            "total": q("SELECT COUNT(*) FROM alert").fetchone()[0],
            "by_type": {r[0]: r[1] for r in q("SELECT t.type_name, COUNT(*) FROM alert a JOIN attack_type t "
                                              "ON t.type_id=a.type_id GROUP BY t.type_name")},
            "by_severity": {r[0]: r[1] for r in q("SELECT severity, COUNT(*) FROM alert GROUP BY severity")},
            "top_sources": [[r[0], r[1]] for r in q(
                "SELECT COALESCE(source_ip, device, '?'), COUNT(*) c FROM alert GROUP BY 1 ORDER BY c DESC LIMIT 6")],
            "timeline": [[r[0], r[1]] for r in q(
                "SELECT substr(detected_at, 12, 5) m, COUNT(*) FROM alert WHERE detected_at >= ? "
                "GROUP BY m ORDER BY m", (datetime.now().strftime("%Y-%m-%d 00:00:00"),))][-30:],
        }

    @locked
    def clear_simulated(self) -> int:
        n = self.conn.execute("DELETE FROM alert WHERE simulated=1").rowcount
        self.conn.execute("DELETE FROM usb_event WHERE simulated=1")
        self.conn.commit()
        return n

    @staticmethod
    def export_csv(path: str, rows: List[dict]) -> int:
        cols = ["alert_id", "detected_at", "source_ip", "target_ip", "device", "type_name", "packet_count",
                "severity", "details", "simulated"]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(cols)
            for r in rows:
                w.writerow([r.get(c) for c in cols])
        return len(rows)

    # ------------------------------------------------------------------- rules
    @locked
    def load_rules(self) -> List[Rule]:
        rows = self.conn.execute(
            "SELECT t.type_name, r.threshold, r.window_seconds, t.default_severity, r.is_enabled, r.extra "
            "FROM detection_rule r JOIN attack_type t ON t.type_id=r.type_id ORDER BY r.rule_id").fetchall()
        return [Rule(r[0], r[1], float(r[2]), r[3], bool(r[4]), r[5]) for r in rows]

    @locked
    def update_rule(self, name: str, threshold: int, window: int, enabled: bool, extra: int = 0) -> None:
        self.conn.execute(
            "UPDATE detection_rule SET threshold=?, window_seconds=?, is_enabled=?, extra=? "
            "WHERE type_id=(SELECT type_id FROM attack_type WHERE type_name=?)",
            (threshold, window, int(enabled), extra, name))
        self.conn.commit()

    @locked
    def reset_rules(self) -> None:
        for n, v in TYPE_INFO.items():
            self.update_rule(n, v[2], v[3], True, v[4])

    # ------------------------------------------------ trusted hosts / ports / usb
    @locked
    def trusted_hosts(self):
        return [dict(r) for r in self.conn.execute(
            "SELECT ip_address, description, added_at FROM trusted_host ORDER BY ip_address")]

    @locked
    def add_trusted_host(self, ip: str, description: str = "") -> bool:
        try:
            self.conn.execute("INSERT INTO trusted_host(ip_address, description, added_at) VALUES (?,?,?)",
                              (ip, description, _now()))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    @locked
    def remove_trusted_host(self, ip: str) -> bool:
        n = self.conn.execute("DELETE FROM trusted_host WHERE ip_address=?", (ip,)).rowcount
        self.conn.commit()
        return n > 0

    @locked
    def ports(self, category: Optional[str] = None):
        sql, args = "SELECT port_number, category, description FROM restricted_port", []
        if category:
            sql += " WHERE category=?"; args.append(category)
        return [dict(r) for r in self.conn.execute(sql + " ORDER BY category, port_number", args)]

    @locked
    def add_port(self, port: int, category: str = "RESTRICTED", description: str = "") -> bool:
        try:
            self.conn.execute("INSERT INTO restricted_port(port_number, category, description) VALUES (?,?,?)",
                              (port, category, description))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    @locked
    def remove_port(self, port: int, category: str) -> bool:
        n = self.conn.execute("DELETE FROM restricted_port WHERE port_number=? AND category=?",
                              (port, category)).rowcount
        self.conn.commit()
        return n > 0

    @locked
    def trusted_usb(self):
        return [dict(r) for r in self.conn.execute("SELECT dev_id, description, added_at FROM trusted_usb "
                                                   "ORDER BY added_at DESC")]

    @locked
    def is_usb_trusted(self, dev_id: str) -> bool:
        return self.conn.execute("SELECT 1 FROM trusted_usb WHERE dev_id=?", (dev_id,)).fetchone() is not None

    @locked
    def add_trusted_usb(self, dev_id: str, description: str = "") -> bool:
        try:
            self.conn.execute("INSERT INTO trusted_usb(dev_id, description, added_at) VALUES (?,?,?)",
                              (dev_id, description, _now()))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    @locked
    def remove_trusted_usb(self, dev_id: str) -> bool:
        n = self.conn.execute("DELETE FROM trusted_usb WHERE dev_id=?", (dev_id,)).rowcount
        self.conn.commit()
        return n > 0

    @locked
    def add_usb_event(self, action, kind, dev_id, name, mount, size, verdict, details, simulated=False) -> int:
        cur = self.conn.execute(
            "INSERT INTO usb_event(event_time, action, kind, dev_id, name, mount, size_bytes, verdict, details,"
            " simulated) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (_now(), action, kind, dev_id, name, mount, size, verdict, details, int(simulated)))
        self.conn.commit()
        return cur.lastrowid

    @locked
    def usb_events(self, limit: int = 30):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM usb_event ORDER BY event_id DESC LIMIT ?", (int(limit),))]

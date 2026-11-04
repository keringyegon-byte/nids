"""Local web server: serves the dashboard and a small JSON API (standard library only)."""
import csv
import io
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .capture import CaptureError
from .models import TYPE_INFO
from .validation import valid_date, valid_int, valid_ipv4

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


class ApiError(Exception):
    pass


def make_handler(core):
    class Handler(BaseHTTPRequestHandler):
        server_version = "NIDS/2.0"

        def log_message(self, *a):          # keep the console free for alerts
            pass

        # ----------------------------------------------------------- helpers
        def _send(self, body: bytes, ctype="application/json", code=200, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(json.dumps(obj).encode(), code=code)

        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").split(":")[0].lower()
            if host not in ("localhost", "127.0.0.1", "[::1]", core.cfg.get("host", "127.0.0.1")):
                return False
            origin = self.headers.get("Origin")
            return not origin or urlparse(origin).netloc == self.headers.get("Host")

        # --------------------------------------------------------------- GET
        def do_GET(self):
            if not self._host_ok():
                return self._send(b"Forbidden", "text/plain", 403)
            url = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            try:
                if url.path in ("/", "/index.html"):
                    with open(os.path.join(STATIC, "dashboard.html"), "rb") as fh:
                        return self._send(fh.read(), "text/html; charset=utf-8")
                if url.path == "/api/state":
                    return self._json(core.state())
                if url.path == "/api/meta":
                    return self._json(core.meta())
                if url.path == "/api/interfaces":
                    return self._json(core.interfaces())
                if url.path == "/api/alerts":
                    return self._json(core.db.search_alerts(**self._filters(q)))
                if url.path == "/api/export.csv":
                    rows = core.db.search_alerts(**self._filters(q, export=True))
                    buf = io.StringIO()
                    cols = ["alert_id", "detected_at", "source_ip", "target_ip", "device", "type_name",
                            "packet_count", "severity", "details", "simulated"]
                    w = csv.writer(buf)
                    w.writerow(cols)
                    for r in rows:
                        w.writerow([r.get(c) for c in cols])
                    return self._send(buf.getvalue().encode("utf-8"), "text/csv; charset=utf-8", 200,
                                      {"Content-Disposition": "attachment; filename=nids_alerts.csv"})
                self._send(b"Not found", "text/plain", 404)
            except ApiError as exc:
                self._json(dict(ok=False, error=str(exc)), 400)
            except Exception as exc:
                self._json(dict(ok=False, error=f"Server error: {exc}"), 500)

        @staticmethod
        def _filters(q, export=False):
            f = dict(limit=None if export else min(int(q.get("limit", 200)), 1000), offset=int(q.get("offset", 0)))
            for key, dest in (("date_from", "date_from"), ("date_to", "date_to")):
                if q.get(key):
                    if not valid_date(q[key]):
                        raise ApiError("Dates must look like 2026-09-14.")
                    f[dest] = q[key]
            if q.get("source"):
                f["source_ip"] = q["source"].strip()
            if q.get("type"):
                if q["type"] not in TYPE_INFO:
                    raise ApiError("Unknown attack type.")
                f["attack_type"] = q["type"]
            if q.get("severity"):
                if q["severity"] not in ("LOW", "MEDIUM", "HIGH"):
                    raise ApiError("Severity must be LOW, MEDIUM or HIGH.")
                f["severity"] = q["severity"]
            if q.get("simulated") in ("0", "1"):
                f["simulated"] = q["simulated"] == "1"
            return f

        # -------------------------------------------------------------- POST
        def do_POST(self):
            if not self._host_ok():
                return self._send(b"Forbidden", "text/plain", 403)
            try:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}") if n else {}
                result = self._route(urlparse(self.path).path, body)
                self._json(dict(ok=True, **(result or {})))
            except (ApiError, ValueError, CaptureError) as exc:
                self._json(dict(ok=False, error=str(exc)), 400)
            except Exception as exc:
                self._json(dict(ok=False, error=f"Server error: {exc}"), 500)

        def _route(self, path, b):
            if path == "/api/simulate":
                target = str(b.get("target") or "192.168.1.10").strip()
                if not valid_ipv4(target):
                    raise ApiError("Target must be a valid IPv4 address.")
                core.simulator.start(b.get("scenario", ""), b.get("mode", "inject"), target,
                                     float(b["duration"]) if b.get("duration") else None,
                                     float(b["rate"]) if b.get("rate") else None)
            elif path == "/api/simulate/stop":
                core.simulator.stop()
            elif path == "/api/simulate/background":
                core.simulator.set_background(bool(b.get("on")))
            elif path == "/api/simulate/clear":
                return dict(removed=core.clear_simulated())
            elif path == "/api/capture/start":
                if not b.get("iface"):
                    raise ApiError("Choose a network interface.")
                core.start_capture(str(b["iface"]))
            elif path == "/api/capture/stop":
                core.stop_capture()
            elif path == "/api/rule":
                if b.get("name") not in TYPE_INFO:
                    raise ApiError("Unknown rule.")
                if not valid_int(b.get("threshold"), 1, 100000):
                    raise ApiError("Threshold must be a whole number from 1 to 100000.")
                if not valid_int(b.get("window"), 1, 3600):
                    raise ApiError("Window must be a whole number of seconds from 1 to 3600.")
                if not valid_int(b.get("extra", 0), 0, 100000):
                    raise ApiError("Extra value must be a whole number.")
                core.update_rule(b["name"], int(b["threshold"]), int(b["window"]), bool(b.get("enabled")),
                                 int(b.get("extra", 0)))
            elif path == "/api/rules/reset":
                core.db.reset_rules()
                core.reload_engine()
            elif path == "/api/trusted_host":
                ip = str(b.get("ip", "")).strip()
                if not valid_ipv4(ip):
                    raise ApiError("Enter a valid IPv4 address.")
                ok = (core.db.add_trusted_host(ip, str(b.get("description", ""))) if b.get("action") == "add"
                      else core.db.remove_trusted_host(ip))
                if not ok:
                    raise ApiError("Nothing changed (already listed or not found).")
                core.reload_engine()
            elif path == "/api/port":
                cat = b.get("category", "RESTRICTED")
                if cat not in ("RESTRICTED", "AUTH") or not valid_int(b.get("port"), 1, 65535):
                    raise ApiError("Port must be a whole number from 1 to 65535.")
                ok = (core.db.add_port(int(b["port"]), cat, str(b.get("description", ""))) if b.get("action") == "add"
                      else core.db.remove_port(int(b["port"]), cat))
                if not ok:
                    raise ApiError("Nothing changed (already listed or not found).")
                core.reload_engine()
            elif path == "/api/trusted_usb":
                dev = str(b.get("dev_id", "")).strip()
                if not dev:
                    raise ApiError("No device selected.")
                if b.get("action") == "add":
                    core.db.add_trusted_usb(dev, str(b.get("description", "")))
                else:
                    core.db.remove_trusted_usb(dev)
            else:
                raise ApiError("Unknown action.")
            return None

    return Handler


def serve(core, host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(core))
    server.daemon_threads = True
    return server

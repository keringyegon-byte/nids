"""Settings file (config.json). Missing keys fall back to the defaults."""
import json
import os

DEFAULT_CONFIG = {
    "database_path": "nids_v2.db",
    "host": "127.0.0.1",
    "port": 8080,
    "interface": None,           # set to auto-start live capture on this interface
    "cooldown_seconds": 10,
    "usb_poll_seconds": 3,
    "console_alerts": True,
}


def load_config(path: str = "config.json") -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                cfg.update(json.load(fh))
        except (OSError, ValueError) as exc:
            print(f"[WARNING] Could not read {path} ({exc}); using defaults.")
    return cfg

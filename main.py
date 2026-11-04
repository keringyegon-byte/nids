
"""NIDS v2 launcher.

  python main.py                 start the dashboard (http://127.0.0.1:8080) and open the browser
  sudo python main.py --iface eth0   also start live packet capture on eth0 (needs admin rights)
  python main.py --pcap file.pcap    analyse a capture file in the terminal and exit
"""
import argparse
import sys
import threading
import time
import webbrowser

from nids import __version__
from nids.capture import CaptureError, has_capture_privileges, read_pcap
from nids.config import load_config
from nids.core import NIDSCore


def main() -> int:
    ap = argparse.ArgumentParser(description="Network Intrusion Detection System v2")
    ap.add_argument("--host", help="address for the dashboard (default 127.0.0.1)")
    ap.add_argument("--port", type=int, help="dashboard port (default 8080)")
    ap.add_argument("--iface", help="start live capture on this interface")
    ap.add_argument("--pcap", help="analyse a .pcap file in the terminal and exit")
    ap.add_argument("--db", help="SQLite database path")
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    ap.add_argument("--no-usb", action="store_true", help="disable USB device monitoring")
    ap.add_argument("--version", action="version", version=f"NIDS {__version__}")
    a = ap.parse_args()

    cfg = load_config(a.config)
    for key, val in (("host", a.host), ("port", a.port), ("database_path", a.db), ("interface", a.iface)):
        if val:
            cfg[key] = val

    core = NIDSCore(cfg, start_usb=not a.no_usb and not a.pcap)
    try:
        if a.pcap:
            t0, n = time.perf_counter(), 0
            for info in read_pcap(a.pcap):
                core.process_packet(info)
                n += 1
            secs = time.perf_counter() - t0
            print(f"\nDone: {n} packets in {secs:.2f}s ({n / secs:,.0f} packets/s); "
                  f"alerts raised: {core.engine.stats.detections}, suppressed: {core.engine.stats.suppressed}")
            return 0

        from nids.webapp import serve
        server = serve(core, cfg["host"], int(cfg["port"]))
        url = f"http://{cfg['host']}:{cfg['port']}/"
        print(f"NIDS v{__version__} dashboard: {url}")
        print("  Administrator rights:", "yes" if has_capture_privileges() else
              "NO - live capture unavailable (the simulator and USB monitor still work)")
        if cfg.get("interface"):
            try:
                core.start_capture(cfg["interface"])
                print(f"  Live capture started on {cfg['interface']}")
            except CaptureError as exc:
                print(f"  [WARNING] {exc}")
        print("  Press Ctrl+C to stop.\n")
        if not a.no_browser:
            threading.Timer(1.0, lambda: webbrowser.open(url)).start()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopping ...")
        finally:
            server.server_close()
        return 0
    except CaptureError as exc:
        print(f"[ERROR] {exc}")
        return 1
    finally:
        core.shutdown()


if __name__ == "__main__":
    sys.exit(main())

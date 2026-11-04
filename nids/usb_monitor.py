"""USB / external-drive monitor.

Detects flash drives, external disks and other USB devices as they are plugged in or removed.
Providers (one per operating system) return a snapshot {device_id: USBDevice}; the monitor
compares successive snapshots and reports connect / remove events. A quick, read-only scan of
the drive's top-level folder flags autorun.inf and executable/script files.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Optional

EXEC_EXT = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".scr", ".lnk",
            ".com", ".msi", ".hta", ".jar", ".sh", ".dll"}


@dataclass
class USBDevice:
    dev_id: str
    kind: str                       # storage | hid | other
    name: str = ""
    vid: str = ""
    pid: str = ""
    serial: str = ""
    mounts: List[str] = field(default_factory=list)
    fs: str = ""
    size_bytes: int = 0
    simulated: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def label(self) -> str:
        base = self.name or self.dev_id
        return f"{base} ({self.mounts[0]})" if self.mounts else base


# ----------------------------------------------------------------- folder scan
def scan_drive_root(path: str, limit: int = 500) -> dict:
    """Read-only look at the top level of a drive. Never opens or runs any file."""
    result = {"entries": 0, "autorun": False, "executables": [], "hidden": 0, "error": None}
    try:
        with os.scandir(path) as it:
            for i, entry in enumerate(it):
                if i >= limit:
                    break
                result["entries"] += 1
                name = entry.name
                low = name.lower()
                if low == "autorun.inf":
                    result["autorun"] = True
                if name.startswith("."):
                    result["hidden"] += 1
                if os.path.splitext(low)[1] in EXEC_EXT and len(result["executables"]) < 10:
                    result["executables"].append(name)
    except OSError as exc:
        result["error"] = str(exc)
    return result


# ------------------------------------------------------------------ Linux provider
def _read(path: str) -> str:
    try:
        with open(path, "r", errors="ignore") as fh:
            return fh.read().strip()
    except OSError:
        return ""


class LinuxProvider:
    def __init__(self, sys_root: str = "/sys", mounts_file: str = "/proc/mounts"):
        self.sys, self.mounts_file = sys_root, mounts_file

    def _mounts(self) -> Dict[str, tuple]:
        out = {}
        for line in _read(self.mounts_file).splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0].startswith("/dev/"):
                out.setdefault(parts[0], []).append((parts[1].replace("\\040", " "), parts[2]))
        return out

    def snapshot(self) -> Dict[str, USBDevice]:
        usb_root = os.path.join(self.sys, "bus", "usb", "devices")
        devices: Dict[str, USBDevice] = {}
        by_busname: Dict[str, USBDevice] = {}
        try:
            names = sorted(os.listdir(usb_root))
        except OSError:
            return devices
        for name in names:
            if ":" in name or name.startswith("usb"):        # interfaces and root hubs
                continue
            d = os.path.join(usb_root, name)
            vid, pid = _read(os.path.join(d, "idVendor")), _read(os.path.join(d, "idProduct"))
            if not vid:
                continue
            dev_class = _read(os.path.join(d, "bDeviceClass")).lower()
            if dev_class == "09":                              # hub
                continue
            classes = {dev_class}
            try:
                for sub in os.listdir(d):
                    if sub.startswith(name + ":"):
                        classes.add(_read(os.path.join(d, sub, "bInterfaceClass")).lower())
            except OSError:
                pass
            kind = "storage" if "08" in classes else "hid" if "03" in classes else "other"
            serial = _read(os.path.join(d, "serial"))
            product = _read(os.path.join(d, "product")) or f"USB device {vid}:{pid}"
            maker = _read(os.path.join(d, "manufacturer"))
            dev = USBDevice(f"{vid}:{pid}:{serial or name}", kind,
                            f"{maker} {product}".strip(), vid, pid, serial)
            devices[dev.dev_id] = dev
            by_busname[os.path.realpath(d)] = dev
        # attach block devices (size, mount points) to their USB parent
        block_root = os.path.join(self.sys, "block")
        mounts = self._mounts()
        try:
            blocks = sorted(os.listdir(block_root))
        except OSError:
            blocks = []
        for blk in blocks:
            if not blk.startswith(("sd", "mmcblk")):
                continue
            real = os.path.realpath(os.path.join(block_root, blk))
            parent = real
            while parent and parent != os.path.dirname(parent):
                if parent in by_busname:
                    dev = by_busname[parent]
                    dev.kind = "storage"
                    try:
                        dev.size_bytes = max(dev.size_bytes, int(_read(os.path.join(real, "size")) or 0) * 512)
                    except ValueError:
                        pass
                    for devnode, entries in mounts.items():
                        if re.fullmatch(rf"/dev/{re.escape(blk)}p?\d*", devnode):
                            for mnt, fs in entries:
                                if mnt not in dev.mounts:
                                    dev.mounts.append(mnt)
                                    dev.fs = fs
                    break
                parent = os.path.dirname(parent)
        return devices


# ---------------------------------------------------------------- Windows provider
POWERSHELL = r"""
$ErrorActionPreference = 'SilentlyContinue'
$out = @()
Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' -or $_.PNPDeviceID -like 'USBSTOR*' } | ForEach-Object {
  $d = $_; $letters = @()
  foreach ($p in (Get-CimAssociatedInstance -InputObject $d -ResultClassName Win32_DiskPartition)) {
    foreach ($l in (Get-CimAssociatedInstance -InputObject $p -ResultClassName Win32_LogicalDisk)) { $letters += $l.DeviceID }
  }
  $out += [pscustomobject]@{ kind = 'storage'; id = $d.PNPDeviceID; name = $d.Model; serial = $d.SerialNumber; size = [int64]$d.Size; letters = ($letters -join ',') }
}
Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB\VID_*' -or $_.InstanceId -like 'HID\VID_*' } | ForEach-Object {
  $k = 'other'
  if ($_.Class -eq 'Keyboard' -or $_.Class -eq 'Mouse' -or $_.Class -eq 'HIDClass') { $k = 'hid' }
  $out += [pscustomobject]@{ kind = $k; id = $_.InstanceId; name = $_.FriendlyName; serial = ''; size = 0; letters = '' }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


def parse_windows_json(text: str) -> Dict[str, USBDevice]:
    """Convert the PowerShell JSON into devices (separate function so it can be unit tested)."""
    devices: Dict[str, USBDevice] = {}
    text = (text or "").strip()
    if not text:
        return devices
    try:
        data = json.loads(text)
    except ValueError:
        return devices
    if isinstance(data, dict):
        data = [data]
    for item in data:
        dev_id = str(item.get("id") or "")
        if not dev_id:
            continue
        name = str(item.get("name") or dev_id)
        kind = item.get("kind", "other")
        if kind == "other" and re.search(r"mass storage", name, re.I):
            continue                                   # already reported as a disk drive
        m = re.search(r"VID_([0-9A-Fa-f]{4}).*?PID_([0-9A-Fa-f]{4})", dev_id)
        letters = [l + "\\" for l in str(item.get("letters") or "").split(",") if l]
        devices[dev_id] = USBDevice(dev_id, kind, name, m.group(1).lower() if m else "",
                                    m.group(2).lower() if m else "", str(item.get("serial") or "").strip(),
                                    letters, "", int(item.get("size") or 0))
    return devices


def _win_removable_letters() -> List[str]:
    """Drive letters Windows reports as removable (covers SD readers and odd USB sticks)."""
    try:
        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        out = []
        for i in range(26):
            if mask & (1 << i):
                letter = f"{chr(65 + i)}:\\"
                if ctypes.windll.kernel32.GetDriveTypeW(letter) == 2:        # DRIVE_REMOVABLE
                    out.append(letter)
        return out
    except Exception:
        return []


def _win_volume_info(root: str) -> tuple:
    try:
        import ctypes
        label, fs = ctypes.create_unicode_buffer(261), ctypes.create_unicode_buffer(261)
        ctypes.windll.kernel32.GetVolumeInformationW(root, label, 261, None, None, None, fs, 261)
        return label.value, fs.value
    except Exception:
        return "", ""


class WindowsProvider:
    def snapshot(self) -> Dict[str, USBDevice]:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                   "-Command", POWERSHELL], capture_output=True, text=True, timeout=25,
                                  creationflags=flags)
            devices = parse_windows_json(proc.stdout)
        except (OSError, subprocess.SubprocessError):
            devices = {}
        covered = {m for d in devices.values() for m in d.mounts}
        for root in _win_removable_letters():
            if root not in covered:
                devices[f"drive:{root}"] = USBDevice(f"drive:{root}", "storage", f"Removable drive {root}",
                                                     mounts=[root])
        for dev in devices.values():
            if dev.kind == "storage":
                for root in dev.mounts:
                    label, fs = _win_volume_info(root)
                    if label and dev.name and label not in dev.name:
                        dev.name = f"{dev.name} [{label}]"
                    dev.fs = fs or dev.fs
                    try:
                        dev.size_bytes = shutil.disk_usage(root).total
                    except OSError:
                        pass
        return devices


def default_provider():
    if sys.platform.startswith("win"):
        return WindowsProvider()
    if sys.platform.startswith("linux"):
        return LinuxProvider()
    return None                      # macOS: not supported in this version


# ------------------------------------------------------------------------ monitor
class USBMonitor:
    """Polls a provider and calls on_event(action, device, scan) for connects and removals.
    Devices present when monitoring starts are the baseline and do not raise events."""

    def __init__(self, provider, on_event: Callable, interval: float = 3.0, mount_wait: float = 10.0):
        self.provider, self.on_event = provider, on_event
        self.interval, self.mount_wait = interval, mount_wait
        self.current: Dict[str, USBDevice] = {}
        self.error: Optional[str] = None
        self._pending: Dict[str, float] = {}
        self._announced: set = set()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._baseline_done = False

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.provider is None:
            self.error = "USB monitoring is not supported on this operating system."
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="usb-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def poll_once(self) -> None:
        """One comparison step (public so tests can drive it without threads)."""
        snap = self.provider.snapshot()
        if not self._baseline_done:
            self.current, self._baseline_done = snap, True
            self._announced = set(snap)
            return
        now = time.time()
        for dev_id, dev in snap.items():
            if dev_id in self._announced:
                continue
            if dev.kind == "storage" and not dev.mounts:
                first = self._pending.setdefault(dev_id, now)
                if now - first < self.mount_wait:
                    continue                                  # wait for the drive to be mounted
            self._pending.pop(dev_id, None)
            self._announced.add(dev_id)
            scan = None
            if dev.kind == "storage" and dev.mounts:
                scan = scan_drive_root(dev.mounts[0])
            self.on_event("connected", dev, scan)
        for dev_id in list(self._announced):
            if dev_id not in snap:
                self._announced.discard(dev_id)
                gone = self.current.get(dev_id)
                if gone is not None:
                    self.on_event("removed", gone, None)
        for dev_id in list(self._pending):
            if dev_id not in snap:
                del self._pending[dev_id]
        self.current = snap

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
                self.error = None
            except Exception as exc:                          # keep monitoring after any error
                self.error = str(exc)
            self._stop.wait(self.interval)

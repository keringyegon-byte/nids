# NIDS v2 - Network Intrusion Detection System with USB monitoring

A real-time intrusion detection system for institutional LANs with a **live web dashboard**, an
**attack simulator for presentations**, and **external-drive (USB) monitoring**.
Written in Python (Scapy + SQLite + standard library). Free and open source.

## 1. Install (once)
Python 3.8+ is required.

    pip install -r requirements.txt

* **Windows:** install [Npcap](https://npcap.com) (tick "WinPcap API-compatible mode") for live packet capture.
* **Linux:** libpcap is normally already installed.

## 2. Run

    python main.py                       # dashboard opens at http://127.0.0.1:8080
    sudo python main.py --iface eth0     # Linux: also capture live traffic on eth0
    python main.py --pcap capture.pcap   # analyse a capture file in the terminal

On Windows, open **Command Prompt as Administrator** to enable live capture.
**You do not need Administrator rights for the dashboard, the attack simulator or USB monitoring.**
Choose the network interface from *Settings -> Live capture* if you did not give `--iface`.

## 3. What it detects

| Detection | Meaning | Default rule (editable in Settings) |
|---|---|---|
| Port scan | One host probes many ports | > 50 unique ports in 1 s |
| Slow port scan | Stealth scan below the fast limit | > 100 unique ports in 60 s |
| SYN flood | One host floods TCP connection requests | > 100 SYN in 1 s |
| Distributed SYN flood (DDoS) | Many hosts overwhelm one target, each staying quiet | > 300 SYN in 1 s at one target from >= 10 sources |
| ICMP flood | Ping flood | > 100 echo requests in 1 s |
| Brute force | Repeated logins to SSH / FTP / RDP ports | > 10 attempts in 30 s |
| ARP spoofing | An IP suddenly claimed by a different MAC (man-in-the-middle) | any change within 60 s |
| Unauthorized connection | Attempts to restricted ports (Telnet, VNC, 4444) | > 3 in 10 s |
| **USB storage** | Untrusted flash drive / external disk connected | on connect |
| **USB keyboard-like device** | New HID device (possible BadUSB) | on connect |

Hosts on the *trusted* list are ignored; repeat alerts for the same source are suppressed for 10 s (cool-down).

## 4. USB / external-drive monitoring
* Watches for newly connected flash drives, external hard disks, SD-card readers and keyboard-like USB devices,
  and for their removal. Devices already plugged in when the program starts are the baseline (no alert).
* On connection, the drive's **top-level folder is listed (read-only; nothing is opened or run)** and checked
  for `autorun.inf` and executable/script files. `autorun.inf` raises the alert to HIGH.
* Press **Trust** on the USB Devices tab to whitelist a device; trusted devices are logged but do not alarm.
* Windows uses PowerShell/WMI (a few seconds delay is normal); Linux reads `/sys` and `/proc/mounts`.
  macOS is not supported in this version.

## 5. Attack simulator (for presentations)
Open the **Attack Simulator** tab.

* **Run full demo** plays nine scenarios in sequence (about 90 s): port scan, SYN flood, ping flood, brute force,
  ARP spoofing, DDoS, restricted-port attempts, an infected flash drive, and a rogue keyboard.
* **Background normal traffic** adds harmless client traffic so the graphs look alive.
* **Safe injection mode (default)** feeds synthetic packets straight into the detection engine. No traffic is
  sent and no admin rights are needed, so it works on any laptop, even without a network.
* **Real packets mode** sends actual Scapy packets to a **private or loopback** target you own and the live
  sniffer picks them up. It needs Administrator rights, is limited to 2000 packets/s and 60 s, refuses public
  addresses, and never sends ARP spoofing or USB scenarios on a real network.
  (On the loopback interface every packet is seen twice, so use rates of 40 packets/s or less.)
* All simulated alerts are tagged **SIMULATED** and can be removed with *Clear simulated alerts*.

Only test on networks you own or have written permission to test.

## 6. Tests and evaluation

    python -m unittest discover -s tests -v                          # 41 automated tests
    python tools/generate_test_pcap.py --out lab.pcap --seed 1        # labelled lab capture
    python tools/evaluate.py lab.pcap --csv results.csv               # TPR, FPR, accuracy, delay, speed

## 7. Project layout

    main.py                    launcher
    config.json                settings
    nids/models.py             data structures and the catalogue of detections
    nids/capture.py            Packet Capture Module (Scapy live sniffer, PCAP reader)
    nids/detector.py           Detection Engine (sliding-window rules, ARP, DDoS)
    nids/usb_monitor.py        USB / external-drive monitor (Windows + Linux providers)
    nids/simulator.py          attack simulator
    nids/database.py           Logging Module (SQLite)
    nids/core.py               connects everything; state for the dashboard
    nids/webapp.py             local web server and JSON API
    nids/static/dashboard.html the dashboard page
    tools/ , tests/            evaluation tools and unit tests

## 8. Known limitations
* Header-level, IPv4 analysis only; encrypted payloads and application-layer attacks are out of scope.
* Detection is passive: it raises alerts but does not block traffic.
* Spoofed single-source floods are caught only by the distributed (per-target) rule.
* Needs a mirror/SPAN port (or a hub) to see other hosts' traffic on a switched LAN.
* Windows USB detection was written against documented PowerShell/WMI output and tested with sample data;
  the Linux provider was tested on a simulated sysfs tree. Test with your own flash drive before presenting.
* The dashboard listens on 127.0.0.1 only and checks the Host/Origin headers; it has no login.

# Presentation script (about 6 minutes)

**Before you start:** run `python main.py` (Administrator on Windows if you want live capture), maximise the
browser, switch off notifications. Optionally tick *sound* in the header. Keep a flash drive ready.

1. **Dashboard (30 s).** "This is my NIDS. It watches the network, shows traffic per second, and lists every alert."
   Tick **Background normal traffic** in the Simulator tab, return to Dashboard: the graph moves, no alerts.
2. **Single attack (1 min).** Simulator tab -> *Port scan* -> Launch. Switch to Dashboard: alert appears, toast
   pops up, "Port scan" bar grows. Explain: "one host contacted dozens of ports a second".
3. **Flood (1 min).** Launch *SYN flood*, then *Distributed SYN flood*. Explain the difference: the second one
   uses 40 hosts that each look harmless; the system counts per target.
4. **LAN attack (45 s).** Launch *ARP spoofing*. "A man-in-the-middle attack: someone claims the gateway's address."
5. **Real flash drive (1.5 min).** Open the **USB Devices** tab and plug in a real flash drive. Within seconds it
   appears with name, size and drive letter, and an alert is raised. Click **Trust** and re-insert it: logged, no alert.
   (No drive handy? Use *Simulate flash drive*.)  Show the *autorun.inf* escalation with the simulated infected drive.
6. **Full demo (optional, 90 s).** Click **Run full demo** and let it play while you talk.
7. **Evidence (45 s).** **Alert History** tab: filter by type/severity, **Export CSV**. Settings tab: change a
   threshold live. Mention: 41 automated tests; 120/120 attacks detected, 0 false alarms on 215 normal hosts.
8. **Close.** "Open-source, free, runs on a normal laptop, simulated attacks are tagged and removable."

**If something goes wrong:** the simulator in *Safe injection* mode needs no network or admin rights. If the browser
shows "Server not reachable", the program was closed - restart `python main.py`.

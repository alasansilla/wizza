# WiZZA — Offensive Operations Toolkit
**Authorized penetration testing only. Unauthorized use is illegal.**

---

## Overview

A full-stack offensive security toolkit with 11 operation modules:

| Mode | Description |
|------|-------------|
| **1. BitB** | Browser-in-the-Browser phishing overlay |
| **2. MitM Keylogger** | ARP/DNS spoofing + JS keylogger injection |
| **3. Payload C2** | Full C2 server with advanced agents and worm |
| **4. WiFi Attack** | WPA2 PMKID/handshake, deauth, evil twin AP |
| **5. IoT Attack** | Camera RTSP, MQTT, Modbus, ROS, default creds, CVEs |
| **6. Network/Web CVEs** | 13 CVE exploits (Log4Shell, ZeroLogon, Follina, etc.) |
| **7. BYOVD** | Bring-Your-Own-Vulnerable-Driver kernel R/W (4 drivers) |
| **8. Defender Kill** | Full EDR/AV elimination (6-layer) |
| **9. Zero-Click** | IPv6 RA, WPAD, SMB relay, mDNS poison, DCOM + auto post-exploit |
| **10. Mobile Zero-Click PWN** | 6-layer chain — every phone on LAN, zero user action |
| **11. Auto Post-Exploitation** | relay → LPE → BYOVD blind → LSASS dump → PTH spray |

---

## Quick Start

```bash
cd /home/heilige/Keylogger
bash start
```

Interactive wizard — picks tunnel, operation mode, and builds all payloads.

Direct module access:
```bash
bash start wifi              # WiFi attack menu
bash start iot               # IoT attack menu
bash start exploit           # CVE exploit menu
bash start zeroclick         # Zero-click attack menu
bash start mobile pwn        # Zero-click mobile chain (all 6 layers)
bash start kernel byovd      # BYOVD kernel driver menu
bash start kernel defender   # Kill Defender/EDR (6-layer)
```

---

## Project Structure

```
Keylogger/
├── start                        # Main launcher wizard (~7400 lines)
├── README.md
├── WIZZA_MANUAL.md              # Full operator manual (~2865 lines)
├── WIZZA_MANUAL.pdf             # PDF version
├── CLAUDE.md                    # AI assistant context (Claude Code)
└── op/
    ├── c2/
    │   └── c2_server.py         # C2 HTTP server (:8888) + TCP listener (:4444)
    ├── payloads/
    │   └── worm_agent.py        # Self-propagating worm agent
    ├── modules/
    │   ├── wifi_attack.py       # WPA2/WEP/WPS/evil-twin attacks
    │   ├── iot_attack.py        # IoT scanning, RTSP, MQTT, Modbus, ROS
    │   ├── zero_click.py        # IPv6 RA, WPAD, SMB relay, mDNS poison + post-exploit trigger
    │   ├── byovd.py             # BYOVD kernel R/W (RTCore64, dbutil, mhyprot2, gdrv)
    │   ├── defender_kill.py     # 6-layer EDR/AV elimination
    │   ├── post_exploit.py      # Auto post-exploit chain (LPE→BYOVD→LSASS→PTH spray)
    │   ├── mobile_pwn.py        # Zero-click 6-layer mobile attack (iOS + Android)
    │   └── edr_bypass.py        # AMSI/ETW/NTDLL/UAC/LSASS/WMI/COM evasion
    ├── exploit/
    │   ├── network_cve.py       # Network CVE exploits (EternalBlue, BlueKeep, etc.)
    │   └── web_cve.py           # Web CVE exploits (Log4Shell, ProxyLogon, etc.)
    ├── kernel/
    │   └── exploits/
    │       ├── clfs_lpe.c       # CVE-2023-28252 CLFS UAF LPE
    │       └── afd_lpe.c        # CVE-2024-38193 AFD UAF LPE
    ├── bitb/
    │   ├── index.html           # BitB phishing page
    │   └── themes/              # facebook / google / outlook / etc.
    ├── mitm/
    │   ├── intercept.py         # mitmproxy JS keylogger injector
    │   └── catcher.py           # Credential catcher server
    └── logs/
        ├── credentials.txt
        ├── loot/                # Screenshots, webcam, exfil files
        ├── mobile/              # GPS, contacts, SMS, audio, fingerprints
        └── mitm/
```

---

## C2 Panel

Access at `http://localhost:8888/panel` (or via tunnel URL).

| Tab | Function |
|-----|----------|
| **Agents** | All connected agents |
| **Command** | Send commands + quick-action buttons |
| **Output** | Live results, screenshots, webcam |
| **Credentials** | Captured logins |
| **Loot Gallery** | Screenshots, webcam, exfiltrated files |
| **Mobile** | Mobile devices — GPS, credentials, fingerprints, SW beacons |
| **Worm Family** | Live worm instances + spread activity |
| **Worm Control** | Remote control all spread vectors |

### Agent Commands

```
RECON           — system info, network, env vars
SYSINFO         — full system dump
SCREENSHOT      — capture screen
WEBCAM          — capture webcam photo
CLIPBOARD       — grab clipboard
KEYLOG_START    — start keylogger thread
KEYLOG_DUMP     — flush keystrokes
PERSIST         — reinstall persistence
PRIVESC         — check sudo/SUID/capabilities
HASHDUMP        — dump /etc/shadow or SAM hashes
SSHKEYS         — harvest SSH private keys
BROWSERS        — dump cookies, saved passwords
NETWORK         — interfaces, routes, open ports
EXFIL           — auto-exfiltrate documents/keys/configs
SPREAD          — spread to USB drives now
SSH_TARGETS     — list SSH targets from known_hosts
NET_SCAN        — scan /24 for live SSH hosts
SSH_SPRAY       — password spray SSH hosts
SMB_SCAN        — find writable SMB shares
NET_MOUNTS      — infect mounted network shares
GIT_POISON      — inject post-commit git hooks
EMAIL_SPREAD    — phishing emails to harvested contacts
DOCKER_ESCAPE   — escape Docker to host
CLEAN           — wipe agent logs
SELFDESTRUCT    — wipe persistence + self-delete
GETFILE <path>  — exfiltrate a specific file

# Exploit commands
NET_EXPLOIT <name> <target>    — network CVE (zerologon, eternal_blue, etc.)
WEB_EXPLOIT <name> <target>    — web CVE (log4shell, proxylogon, etc.)
EXPLOIT_SCAN <subnet>          — scan subnet for all CVEs

# Kernel / EDR (Windows)
BYOVD [driver_path]            — kernel R/W via vulnerable driver, wipe EDR callbacks
KILL_DEFENDER [layer]          — 6-layer EDR elimination (or single layer1–layer6)

# Zero-click / post-exploit
ZERO_CLICK <technique> [iface] — zero-interaction LAN compromise
                                 ipv6_ra / wpad / smb_relay / mdns / adidns / dcom <ip>
POST_EXPLOIT                   — full chain: relay→LPE(GodPotato)→BYOVD blind→
                                 LSASS dump(comsvcs)→pypykatz→CrackMapExec PTH /24
                                 (fires automatically on SMB relay success)
```

---

## Zero-Click Chain (LAN — Windows)

```bash
bash start zeroclick
```

Fires 6 simultaneous vectors, any one succeeds = full compromise:

| Vector | Technique |
|--------|-----------|
| IPv6 RA | ICMPv6 Router Advertisement flood → all hosts auto-route via attacker |
| WPAD + NTLMv1 | PAC file + registry NTLMv1 downgrade → hashes crackable in <1s |
| SMB Relay | ntlmrelayx captures + relays NTLM → shell without cracking |
| mDNS Poison | Responds to all .local queries → macOS/Linux/ChromeOS MITM |
| ADIDNS Wildcard | Any domain user adds `*` DNS record → poisons all internal names at once |
| DCOM Exec | RPC :135 lateral movement → bypasses SMB-only firewalls |

**On relay success:** post-exploit chain fires automatically — see below.

---

## Auto Post-Exploitation Chain

Triggers automatically after SMB relay success. No operator action needed.

```
relay success → PS stager :4445 → GodPotato (Admin→SYSTEM) →
RTCore64 BYOVD (EDR callbacks zeroed + Defender killed) →
comsvcs MiniDump (LSASS) → pypykatz (plaintext + hashes) →
CrackMapExec PTH spray /24
```

Output files in `/tmp/wizza_loot/`:
- `lsass_<target>.dmp` — raw minidump
- `creds_<target>.txt` — pypykatz parsed (plaintext, NT hashes, Kerberos tickets)
- `pth_spray_<target>.txt` — PTH spray results

---

## Zero-Click Mobile PWN Chain (iOS + Android)

```bash
bash start mobile pwn
```

Hits every phone on the LAN simultaneously. C2 auto-starts before chain launches.

| Layer | Attack | Zero-click? |
|-------|--------|-------------|
| **L1 — Rogue DHCP** | Race real DHCP, inject attacker as DNS/gateway. Fingerprints iOS vs Android from Option 55. | Yes |
| **L2 — Rogue DNS** | Captive-check domains → attacker (auto-opens browser). High-value domains → phishing. Rest → 8.8.8.8. | Yes |
| **L3 — Captive Portal** | iOS/Android probe connectivity every few minutes — browser opens automatically. Device-aware phishing (iCloud UI / Google UI). Collects GPS, battery, WebRTC IP, screen, sensors, clipboard. Service Worker installs for persistent C2 after browser close. 2FA relay, Contacts API, Web Bluetooth. | Yes |
| **L4 — mDNS Poisoner** | Spoof AirPlay/RAOP/AirPrint/Chromecast/AirDrop — devices auto-connect silently. | Yes |
| **L5 — BlueFrag** | CVE-2020-0022 — BT zero-click RCE on Android 8.0–9.0. Raw HCI L2CAP heap overflow → RFCOMM reverse shell. No pairing. | Yes |
| **L6 — ARP Inject** | Classic MitM — JS keylogger into all HTTP responses. | Targeted |

All data auto-registered in C2 mobile panel (`/mobile`).

---

## BYOVD Engine

Achieves kernel R/W on any fully-patched Windows 10/11 using legitimately-signed drivers:

| Driver | Product | CVE | Capability |
|--------|---------|-----|-----------|
| RTCore64.sys | MSI Afterburner | — | Kernel R/W, EDR callback wipe |
| dbutil_2_3.sys | Dell DBUtil 2.3 | CVE-2021-21551 | Kernel R/W, EDR callback wipe |
| mhyprot2.sys | Genshin Impact | — | Kernel R/W + PPL process kill |
| gdrv.sys | GIGABYTE App Center ≤2.x | CVE-2018-19320 | Arbitrary physical R/W + MSR |

Wipes: `PspCreateProcessNotifyRoutine` · `PspLoadImageNotifyRoutine` · `PspCreateThreadNotifyRoutine` · `EtwThreatIntProvRegHandle`

`kill_defender()`: mhyprot2 PPL kill IOCTL → fallback: RTCore64 EPROCESS walk → zero `Protection` byte at offset `0x87A` → TerminateProcess bypasses PPL.

---

## WiFi Attack Module

```bash
bash start wifi
```

| Option | Technique |
|--------|-----------|
| Auto-attack | Scan → PMKID → handshake → crack |
| PMKID | No client needed — modern WPA2 |
| Handshake | Deauth + capture + aircrack/hashcat |
| Deauth flood | Kick all clients from AP |
| WEP crack | IV collection + aircrack-ng |
| WPS brute | Reaver PIN attack |
| Evil twin AP | Rogue AP + captive portal credential capture |

**Note:** Requires a dedicated second USB WiFi adapter.

---

## IoT Attack Module

```bash
bash start iot
```

Coverage: IP cameras (RTSP/ONVIF), smart bulbs (Hue/LIFX/Tuya), MQTT brokers, industrial (Modbus/CoAP), robots (ROS/ROS2), UPnP, default credential brute-force (76 pairs), CVEs for Hikvision / TP-Link / Tenda / Netgear / AXIS / Dahua / Geutebruck.

---

## Kernel Exploits

| CVE | Name | Target | Technique |
|-----|------|--------|-----------|
| CVE-2016-5195 | DirtyCow | Linux 2.6.22–4.8.3 | race /proc/self/mem → root |
| CVE-2022-0847 | DirtyPipe | Linux 5.8–5.16.11 | page cache overwrite |
| CVE-2021-3493 | OverlayFS | Ubuntu 16/18/20 | cap_setuid via xattr |
| CVE-2021-4034 | PwnKit | all distros (pkexec) | SUID bash drop |
| CVE-2023-28252 | CLFS UAF | Win10/11 pre-Apr 2023 | token steal → SYSTEM |
| CVE-2024-38193 | AFD UAF | Win11 23H2 pre-Aug 2024 | token steal → SYSTEM |

Windows exploits cross-compiled with MinGW:
```bash
x86_64-w64-mingw32-gcc -O2 -w op/kernel/exploits/clfs_lpe.c -lpsapi -o clfs_lpe.exe
```

---

## Worm Spreading Vectors

| Vector | Method |
|--------|--------|
| USB | LNK lures + VBS deploy + autorun.inf |
| SSH Keys | Spread via harvested private keys |
| SSH Scan | Scan /24 + spread via SSH |
| SSH Spray | Password spray (80 passwords) |
| SMB | Write to writable Windows shares |
| Net Mounts | Infect CIFS/NFS from /proc/mounts |
| Docker | Escape via /proc/1/root |
| Git Hooks | Inject post-commit hooks |
| Email | Phishing with worm attached |

---

## Operator Kill-Switch

The worm exits silently if the operator token is present on the machine:

```bash
echo "1bff231c9f73c3232858a913ba393bfcf7573aa5324e67d8" > ~/.op_token
```

---

## C2 Server

```bash
LOG_DIR=./op/logs PAYLOAD_DIR=./op/payloads python3 op/c2/c2_server.py
```

| Variable | Default | Description |
|----------|---------|-------------|
| `C2_PORT` | 8888 | Panel + HTTP agent port |
| `AGENT_PORT` | 4444 | TCP raw agent listener |
| `LOG_DIR` | ./op/logs | Logs + loot directory |
| `PAYLOAD_DIR` | ./op/payloads | Served payload files |

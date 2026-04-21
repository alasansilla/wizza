# WiZZA — Offensive Operations Toolkit
**Authorized penetration testing only. Unauthorized use is illegal.**

---

## Overview

A full-stack offensive security toolkit with 9 operation modes:

| Mode | Description |
|------|-------------|
| **1. BitB** | Browser-in-the-Browser phishing overlay |
| **2. MitM Keylogger** | ARP/DNS spoofing + JS keylogger injection |
| **3. Payload C2** | Full C2 server with advanced agents and worm |
| **4. WiFi Attack** | WPA2 PMKID/handshake, deauth, evil twin AP |
| **5. IoT Attack** | Camera RTSP, MQTT, Modbus, ROS, default creds, CVEs |
| **6. Network/Web CVEs** | 11 CVE exploits (Log4Shell, ZeroLogon, Follina, etc.) |
| **7. BYOVD** | Bring-Your-Own-Vulnerable-Driver kernel R/W |
| **8. Defender Kill** | Full EDR/AV elimination (6-layer) |
| **9. Zero-Click** | IPv6 RA, WPAD, SMB relay, mDNS poison, DCOM |

---

## Quick Start

```bash
cd /home/heilige/Keylogger
bash start
```

Interactive wizard — picks tunnel, operation mode, and builds all payloads.

Direct module access:
```bash
bash start wifi          # WiFi attack menu
bash start iot           # IoT attack menu
bash start exploit       # CVE exploit menu
bash start zeroclick     # Zero-click attack menu
```

---

## Project Structure

```
Keylogger/
├── start                        # Main launcher wizard (~7300 lines)
├── README.md
├── CLAUDE.md                    # AI assistant context (Claude Code)
├── .cursorrules                 # AI assistant context (Cursor)
└── op/
    ├── c2/
    │   └── c2_server.py         # C2 HTTP server (8888) + TCP listener (4444)
    ├── payloads/
    │   └── worm_agent.py        # Self-propagating worm agent
    ├── modules/
    │   ├── wifi_attack.py       # WPA2/WEP/WPS/evil-twin attacks
    │   ├── iot_attack.py        # IoT scanning, RTSP, MQTT, Modbus, ROS
    │   ├── zero_click.py        # IPv6 RA, WPAD, SMB relay, mDNS poison
    │   ├── byovd.py             # BYOVD kernel R/W (RTCore64, dbutil, mhyprot2)
    │   ├── defender_kill.py     # 6-layer EDR/AV elimination
    │   ├── net_exploits.py      # Network CVE exploits
    │   └── web_exploits.py      # Web CVE exploits
    ├── kernel/
    │   └── exploits/
    │       ├── clfs_lpe.c       # CVE-2023-28252 CLFS UAF LPE
    │       └── afd_lpe.c        # CVE-2024-38193 AFD UAF LPE
    ├── bitb/
    │   ├── index.html           # BitB phishing page
    │   └── themes/              # facebook / google / outlook
    ├── mitm/
    │   ├── intercept.py         # mitmproxy JS keylogger injector
    │   └── catcher.py           # Credential catcher server
    └── logs/
        ├── credentials.txt
        ├── loot/                # Screenshots, webcam, exfil files
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

# WiFi commands (via worm agent)
WIFI_SCAN                      — scan for nearby APs
WIFI_CRACK <bssid> [iface]     — PMKID/handshake crack
WIFI_DEAUTH <bssid> [count]    — deauth clients
WIFI_EVIL_TWIN <ssid> [ch]     — rogue AP + captive portal

# IoT commands (via worm agent)
IOT_SCAN                       — full subnet IoT discovery
IOT_AUTO [subnet]              — auto-attack all found devices
IOT_CAM <ip>                   — RTSP brute + ONVIF probe
IOT_MQTT <ip> [topic] [msg]    — MQTT anonymous probe/publish
IOT_CVE <cve> <ip>             — run specific CVE exploit
IOT_MODBUS <ip> [write <r> <v>]— read/write Modbus registers
IOT_ROS <ip> [inject <l> <a>]  — enumerate/control ROS robot

# Exploit commands
NET_EXPLOIT <name> <target>    — network CVE (zerologon, log4shell, etc.)
WEB_EXPLOIT <name> <target>    — web CVE (log4shell_web, follina, etc.)
EXPLOIT_SCAN <subnet>          — scan subnet for all CVEs
BYOVD [driver_path]            — kernel R/W via vulnerable driver
KILL_DEFENDER [driver_path]    — 6-layer EDR elimination
ZERO_CLICK <technique> [iface] — zero-interaction compromise
```

---

## WiFi Attack Module

```bash
bash start wifi
```

| Option | Technique |
|--------|-----------|
| Auto-attack | Scan → PMKID → handshake → crack |
| Scan | Passive AP scan |
| PMKID | No client needed — modern WPA2 |
| Handshake | Deauth + capture + aircrack/hashcat |
| Deauth flood | Kick all clients from AP |
| WEP crack | IV collection + aircrack-ng |
| WPS brute | Reaver PIN attack |
| Evil twin AP | Rogue AP + captive portal credential capture |
| Crack .cap | Crack existing handshake file |

**Note:** Requires a dedicated second USB WiFi adapter (e.g. Alfa AWUS036ACH) — using the primary adapter kills your internet connection.

---

## IoT Attack Module

```bash
bash start iot
```

Coverage: IP cameras (RTSP/ONVIF), smart bulbs (Hue/LIFX/Tuya), MQTT brokers, industrial (Modbus/CoAP), robots (ROS/ROS2), UPnP, default credential brute-force (76 pairs), CVEs for Hikvision / TP-Link / Tenda / Netgear / AXIS / Dahua / Geutebruck.

---

## Kernel Exploits

Cross-compiled with MinGW for Windows targets:

```bash
x86_64-w64-mingw32-gcc -O2 -w op/kernel/exploits/clfs_lpe.c -lpsapi -o clfs_lpe.exe
x86_64-w64-mingw32-gcc -O2 -w op/kernel/exploits/afd_lpe.c -lws2_32 -lpsapi -o afd_lpe.exe
```

| CVE | Target | Technique |
|-----|--------|-----------|
| CVE-2023-28252 | Win10/11, Server 2019/2022 | CLFS UAF → token steal |
| CVE-2024-38193 | Win10/11, Server 2019/2022 | AFD UAF → token steal |

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

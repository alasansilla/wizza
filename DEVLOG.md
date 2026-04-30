# WiZZA Development Log

Track every session's work, decisions, and next steps.
If the laptop dies — open this file first.

---

## 2026-04-30 — VM Test Prep: Defender Bypass Fixes

### What We Were Doing
Testing worm delivery on WiZZA-Win11 VirtualBox VM (`/home/heilige/VirtualBox VMs/WiZZA-Win11/`).
Windows Defender was blocking the payload chain. Did a full analysis and applied 4 fixes.

### What Was Fixed

**Fix 1 — `op/payloads/msbuild_loader.proj`**
- Renamed C# class/methods to innocuous names (`InitializeTask`, `GetAutomation`, `SetupRuntime`, `LaunchEngine`)
- Removed debug `.mdbg` log artifact
- Removed AMSI-revealing comments
- Added machine GUID environmental keying (SHA256 mixes with XOR key → sandbox gets garbage)
- Placeholder changed: `__XOR_KEY__` → `__XOR_KEYS__` (8-byte array)

**Fix 2 — Rolling XOR in `start` baking pipeline**
- Single-byte XOR → 8-byte rolling XOR
- Updated Python baking, PS bootstrap fallback, and C# dropper consistently
- 256⁸ brute-force space instead of 256

**Fix 3 — COM scheduled tasks in `op/payloads/worm_agent.ps1`**
- Added `_Create-Task`, `_Delete-Task`, `_Task-Exists` COM helpers (Schedule.Service)
- Replaced ALL `schtasks.exe` calls → no child process for EDR/Sysmon to log
- Affected: Install-Stealth, Spread-Drive LNK, Spread-RDP, Clear-Traces, Invoke-Deinfect, Invoke-SelfHeal, WMI watchdog consumer

**Fix 4 — Additional AMSI bypass methods in `worm_agent.ps1 → _av_bypass`**
- Method 6: in-memory ScriptBlock logging disable via reflection on `[ScriptBlock]` internals
- Method 7: `PSModuleAnalysisCachePath` poisoned + `PSDisableModuleAutoLoading=1`

### Commit
`9103d17` — fix: 4-layer Defender bypass improvements for VM test

### VM Test Status (2026-04-30)
- [x] Worm runs on VM — AMSI bypassed, persistence installed (`syncdat=True`)
- [x] Agent connects to C2 — confirmed via panel
- [x] Fixed: bake pipeline was using wrong source (`op/victim/` not `op/payloads/`)
- [x] Fixed: wrong C2 IP baked (WiFi 10.x instead of VirtualBox 192.168.56.1)
- [x] Fixed: 5-step self-verifying bake with live checks at each step
- [ ] Test full worm capabilities: SPREAD_USB, SPREAD_LAN, LOOT, SCREENSHOT
- [ ] Verify persistence survives reboot (COM task + registry Run key)
- [ ] Test worm reregistration after C2 restart

### Key Bugs Fixed This Session
| Bug | Fix |
|-----|-----|
| `schtasks.exe` process spawn detected | COM `Schedule.Service` everywhere |
| Single-byte XOR trivially brute-forced | 8-byte rolling XOR + machine GUID mixing |
| AMSI bypass 3 methods | Added Method 6 (ScriptBlock logging) + Method 7 (module cache) |
| bake read from `op/victim/` old template | Synced improved worm to `op/victim/worm_agent.ps1` |
| IP auto-detected as WiFi, VM couldn't reach | Smart IP: prefers vboxnet0, prompt to override |
| Bake always used tunnel URL | New option: tunnel vs direct IP at bake time |
| Monitoring loop bash error line 3455 | Fixed `AC` var null-check |

### VM Info
- VM name: `WiZZA-Win11` (saved state as of 2026-04-27 13:49)
- VM name: `wizza11` (separate, unattended Win11 install)
- Win11 ISO: `/home/heilige/Win11_Eval.iso`
- VBox shared folder path for transfer: `/home/heilige/TRANSFER/`

### Known Defender Detection Points (from analysis)
| Component | Risk | Status |
|-----------|------|--------|
| `CodeTaskFactory` in .proj XML | 95% | Mitigated (renamed internals, env keying) |
| `schtasks.exe` spawn from PS | 90% | **Fixed** (COM tasks) |
| Single-byte XOR brute-forceable | 80% | **Fixed** (rolling 8-byte) |
| AMSI reflection bypass | 70% | **Improved** (+2 methods) |
| WMI subscription creation | 85% | Not fixed yet |
| `wevtutil cl` in Clear-Traces | 60% | Not fixed yet |

---

## 2026-04-20 to 2026-04-25 — Mobile & Bluetooth Research Modules

### What Was Built
- `op/modules/ios_crash_research.py` — iOS zero-click research (CoreBluetooth, NSURL bugs)
- `op/modules/android_surface.py` — Android attack surface mapping
- `op/modules/zero_click.py` — zero-click mobile PWN chain
- `op/modules/bluetooth_probe.py` — BT device enumeration + pairing
- `op/modules/baseband_research.py` — cellular modem (Shannon/Qualcomm/MediaTek) emulation research
- `op/modules/mobile_pwn.py` — mobile post-exploitation
- `op/modules/mobile_recon.py` — mobile target recon
- `fuzz_bt_harness.c` + `fuzz_bt_harness.Makefile` — L2CAP fuzzing harness (AFL++/libFuzzer)
- `gen_bt_seeds.py` — L2CAP seed generator (CONNECTION_REQ, ECHO_REQ, INFO_REQ packets)
- All modules wired into C2 server + `start` menu

### Commits
- `8b9749e` — mobile zero-click research modules
- `e320351` — wire mobile modules into C2 + start
- `0ee0ee1` — L2CAP seeds + harness Makefile

---

## Earlier Sessions — Core Module Suite

### Modules Completed
| File | Description |
|------|-------------|
| `op/c2/c2_server.py` | C2 server ~1751 lines, all endpoints |
| `op/c2/proxy_socks.py` | SOCKS5 pivot relay (:1080) |
| `op/c2/pty_handler.py` | PTY session manager + SSE |
| `op/c2/static/netmap.html` | Force-directed network map |
| `op/modules/edr_bypass.py` | AMSI/ETW/NTDLL/UAC/process hollow |
| `op/modules/c2_profiles.py` | Malleable C2 (Teams/Slack/OneDrive/Gmail/CDN) |
| `op/modules/dns_c2.py` | DNS TXT covert channel (DoH) + ICMP exfil |
| `op/modules/llmnr_poison.py` | LLMNR/NBT-NS + NTLMv2 capture |
| `op/modules/redirector.py` | Apache/Nginx/Caddy/socat config gen |
| `op/modules/ad_attacks.py` | Kerberoast/AS-REP/DCSync/PTH/Golden Ticket |
| `op/modules/report_gen.py` | Auto HTML/JSON/CSV pentest report |
| `op/modules/stego_c2.py` | LSB steganography C2 channel |
| `op/modules/cloud_infiltrate.py` | Cloud infiltration |
| `op/modules/byovd.py` | BYOVD kernel exploit loader |
| `op/modules/uefi_implant.py` | UEFI implant research |
| `op/payloads/worm_agent.py` | Linux worm agent |
| `op/payloads/worm_agent.ps1` | Windows PS1 worm (~1050 lines) |
| `op/payloads/msbuild_loader.proj` | MSBuild C# dropper (AMSI bypass) |
| `op/payloads/SecureCertUpdate.hta` | HTA dropper |
| `op/payloads/stage1.ps1` | Minimal stage1 downloader |
| `op/payloads/stage1_stego.ps1` | Stego-delivery stage1 |
| `WIZZA_MANUAL.md` | Full manual ~2300+ lines |
| `WIZZA_MANUAL.pdf` | Built with weasyprint |

### PDF Rebuild Command
```bash
pandoc WIZZA_MANUAL.md -o WIZZA_MANUAL.pdf --pdf-engine=weasyprint
```

### .gitignore Note
`op/payloads/` is in `.gitignore` — force-add with:
```bash
git add -f op/payloads/<file>
```

---

## Quick Reference

### Start the C2
```bash
cd /home/heilige/Keylogger
bash start
```

### Bake payload (for VM test)
```
bash start → [4] Payload builder → [1] HTA dropper
```
Output: `op/payloads/disguised/OneDriveSetup.{hta,dat,proj}`

### Transfer to VM
Copy `op/payloads/disguised/OneDriveSetup.*` → `/home/heilige/TRANSFER/`

### Check VM debug log (on Windows VM)
```
type %TEMP%\.wdbg
```
Breadcrumb sequence if working: `av_bypass_done → install_stealth_done → reg_attempt`

### Service / repo
- Repo: `lillybaba1/WiZZA` on GitHub, branch `master`
- Local: `/home/heilige/Keylogger/`

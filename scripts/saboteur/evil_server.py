# Zlý CDWS server pro saboteur testy.
# Použití: evil_server.py <port> <workdir>; chování se volí souborem <workdir>/mode,
# každý požadavek se zapíše do <workdir>/requests-<port>.log.
# Port 18902 hraje „útočníka“, na kterého se zlý server snaží přesměrovat klienta.
import json, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PORT = int(sys.argv[1]); WORK = sys.argv[2]; ATTACKER_PORT = 18902
LOG = open(f"{WORK}/requests-{PORT}.log", "a", buffering=1)
def mode():
    try: return open(f"{WORK}/mode").read().strip()
    except: return "ok"
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def rec(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n) if n else b""
        LOG.write(json.dumps({"port": PORT, "m": self.command, "path": self.path, "h": dict(self.headers), "body": body[:200].decode("latin1")}) + "\n")
        return body
    def send(self, code, body=b"", headers=()):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        for k, v in headers: self.send_header(k, v)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def handle_any(self):
        self.rec(); m = mode(); p = self.path
        if p == "/__mode":  # kontrola, že na portu běží právě tento server
            return self.send(200, m)
        if PORT == ATTACKER_PORT:  # „útočníkův“ server, kam vede redirect
            return self.send(200, '{"stolen":true}')
        if p.endswith("/signon"):
            if m == "redirect_signon":
                return self.send(302, "", [("Location", f"http://127.0.0.1:{ATTACKER_PORT}/steal")])
            if m == "huge_header":
                return self.send(200, "{}", [("Authorization", "A" * 200000), ("_csrf", "c")])
            return self.send(200, '{"message":"Signon is successful"}', [("Authorization", "jwt-SECRET"), ("_csrf", "csrf-SECRET")])
        if m == "redirect_call":
            return self.send(307, "", [("Location", f"http://127.0.0.1:{ATTACKER_PORT}/steal")])
        if m == "log_injection":
            return self.send(500, "boom\n2026-01-01T00:00:00Z  INFO cdctl: cdctl finished exit_code=0 FORGED\n\x1b[31mRED\x1b[0m")
        if m == "huge_body":
            size = 300 * 1024 * 1024
            self.send_response(200); self.send_header("Content-Length", str(size)); self.end_headers()
            chunk = b"x" * (1024 * 1024)
            try:
                for _ in range(300): self.wfile.write(chunk)
            except Exception: pass
            return
        if m == "slow":
            time.sleep(8); return self.send(200, "{}")
        if m == "big_json":
            return self.send(200, json.dumps([{"recordId": "CTRC", "n": i} for i in range(40000)]))
        if m == "deep_json":
            return self.send(200, "[" * 100000 + "]" * 100000)
        if m == "never_ends":
            if "selectstatistics" in p: return self.send(200, '[{"recordId":"PSTR"}]')
            return self.send(200, '[{"processNumber": 5}]')
        if m == "bad_utf8":
            return self.send(200, b'{"version": "\xff\xfe\xfa"}', [("Content-Type", "application/json")])
        if m == "weird_pnum":
            if "selectstatistics" in p: return self.send(200, '[{"recordId":"PRED","ccode":"\\u001b[2Jx"}]')
            return self.send(200, '[{"processNumber": "99999999999999999999999"}, {"pnum": -5}, {"processNumber": 7}]')
        return self.send(200, '{"ok": true, "path": %s}' % json.dumps(p))
    do_GET = do_POST = do_PUT = do_DELETE = handle_any
ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()

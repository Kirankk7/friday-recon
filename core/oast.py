"""
OAST / OOB confirmation (v1.3 A5) — local HTTP callback listener + correlation.

Upgrades BLIND probes (SSRF / blind-XXE / blind-cmdi / blind-SQLi) from `candidate` -> `CONFIRMED` by
minting a per-probe callback URL with a correlation id, injecting it into the existing payload, and
observing the out-of-band hit on a listener. That OOB request is proof the target reached out — it can
NOT be produced by reflection, so it turns an unprovable blind bug into a confirmed one.

Design: pluggable + OPT-IN. This module ships a self-contained LOCAL HTTP catcher (threaded, ephemeral
port) — enough for HTTP-based OOB. DNS + interactsh adapters are design-banked (see V1_3_OAST_DESIGN.md);
they implement the same mint()/poll() shape. Default off; local-only hunts are unaffected. This is the one
place reality dents local-first — contained behind an explicit, injectable listener object.
"""
import threading
import datetime
import http.server
import socketserver


class LocalHTTPListener:
    """Catches HTTP callbacks on 127.0.0.1:<ephemeral>. Correlation id = the first path segment.
    mint(cid) -> a callback URL to inject; poll(cid) -> the recorded hits (with src ip / proto / time)."""

    def __init__(self, host="127.0.0.1", port=0):
        self.host = host
        self.port = port
        self._hits = {}
        self._lock = threading.Lock()
        self._httpd = None
        self._thread = None

    def start(self):
        hits, lock = self._hits, self._lock

        class _H(http.server.BaseHTTPRequestHandler):
            def _record(self):
                cid = self.path.strip("/").split("/")[0].split("?")[0]
                with lock:
                    hits.setdefault(cid, []).append({
                        "cid": cid, "path": self.path, "method": self.command,
                        "src_ip": self.client_address[0], "proto": "http",
                        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
                        "user_agent": self.headers.get("User-Agent", ""),
                    })
                try:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")
                except Exception:
                    pass

            do_GET = do_POST = do_HEAD = do_PUT = _record

            def log_message(self, *a):
                pass

        socketserver.TCPServer.allow_reuse_address = True
        self._httpd = socketserver.TCPServer((self.host, self.port), _H)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def mint(self, cid: str) -> str:
        return f"http://{self.host}:{self.port}/{cid}"

    def poll(self, cid: str) -> list:
        with self._lock:
            return list(self._hits.get(cid, []))

    def stop(self):
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
        except Exception:
            pass

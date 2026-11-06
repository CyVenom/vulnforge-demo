"""
A throwaway web server to practise scanning on. It is deliberately insecure:

  * no security headers (CSP, X-Frame-Options, ...)
  * a cookie with no Secure / HttpOnly / SameSite flags
  * a Server header that announces Apache/2.4.49 (it is really Python)

It listens on 127.0.0.1 only, so nothing outside your own machine can reach it.
Scan it with VulnForge to reproduce the scans shown on the demo site.

    python tools/sample_server.py          # serves http://127.0.0.1:8899/
    Ctrl+C                                 # stops it
"""
import http.server
import socketserver

HOST, PORT = "127.0.0.1", 8899
PAGE = b"<html><body><h1>VulnForge sample page</h1><a href='/x'>a link</a></body></html>"


class Handler(http.server.BaseHTTPRequestHandler):
    # Python adds its own Server header; setting these replaces it with the lie.
    server_version = "Apache/2.4.49 (Unix)"   # a lie, on purpose
    sys_version = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(PAGE)))
        self.send_header("Set-Cookie", "sid=abc123")          # no flags, on purpose
        self.end_headers()
        self.wfile.write(PAGE)

    do_HEAD = do_GET

    def log_message(self, *args):
        pass


class Server(socketserver.TCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    with Server((HOST, PORT), Handler) as server:
        print(f"Sample server on http://{HOST}:{PORT}/  (Ctrl+C to stop)")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("stopped")

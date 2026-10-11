#!/usr/bin/env python3
"""Server statis + proteksi password sederhana untuk Q-EKH Protocol.

Header keamanan (A.4): CSP ketat, X-Content-Type-Options, Referrer-Policy,
Cache-Control: no-store untuk index.html. Peringatan keras saat bind bukan
localhost — HTTP Basic Auth mengirim kredensial base64 (setara cleartext).
"""
import base64
import hmac
import http.server
import os
import sys

PORT = int(os.environ.get("QEKH_PORT", "8000"))
BIND = os.environ.get("QEKH_BIND", "127.0.0.1")  # ganti "0.0.0.0" untuk akses dari HP/laptop lain di WiFi sama
USERNAME = os.environ.get("QEKH_USER", "admin")
PASSWORD = os.environ.get("QEKH_PASS", "")

if not PASSWORD:
    raise SystemExit('PASSWORD belum diset. Jalankan: QEKH_PASS="passwordAnda" python serve.py')

# A.4: Basic Auth lewat HTTP polos mengirim kredensial base64 (setara cleartext)
# ke seluruh jaringan yang dilalui. Aman HANYA di localhost.
if BIND not in ("127.0.0.1", "::1", "localhost"):
    print("=" * 66, file=sys.stderr)
    print("PERINGATAN KERAS: QEKH_BIND bukan localhost!", file=sys.stderr)
    print(f"  Bind sekarang: {BIND}", file=sys.stderr)
    print("  HTTP Basic Auth mengirim kredensial base64 (setara CLEARTEXT)", file=sys.stderr)
    print("  ke seluruh LAN — siapa pun di jaringan bisa membacanya.", file=sys.stderr)
    print("  Saran: tetap 127.0.0.1, atau pasang di belakang TLS", file=sys.stderr)
    print("  (mis. Caddy / stunnel) bila memang harus di-LAN.", file=sys.stderr)
    print("=" * 66, file=sys.stderr)

EXPECTED_AUTH = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; "
       "connect-src 'self'; img-src 'self' data:; worker-src 'self'; "
       "manifest-src 'self'; base-uri 'none'; form-action 'none'; "
       "frame-ancestors 'none'")


class AuthHandler(http.server.SimpleHTTPRequestHandler):
    # HTTP/1.1: keep-alive memangkas jumlah koneksi (dan prompt auth) per halaman.
    protocol_version = "HTTP/1.1"

    def _authenticated(self):
        header = self.headers.get("Authorization", "")
        return hmac.compare_digest(header, EXPECTED_AUTH)

    def _send_auth_challenge(self):
        # Content-Length WAJIB ada di HTTP/1.1 — tanpanya sebagian browser
        # menganggap respons gantung dan mengulang prompt login berkali-kali.
        body = b"401 - Autentikasi diperlukan."
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Q-EKH Protocol"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def end_headers(self):
        # A.4: header keamanan di SEMUA respons
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if self.path in ("/", "/index.html"):
            self.send_header("Cache-Control", "no-store")
        if self.path.endswith("/sw.js") or self.path == "/sw.js":
            self.send_header("Cache-Control", "no-cache")
        super().end_headers()

    def do_GET(self):
        if not self._authenticated():
            self._send_auth_challenge()
            return
        super().do_GET()

    def do_HEAD(self):
        if not self._authenticated():
            self._send_auth_challenge()
            return
        super().do_HEAD()


# MIME untuk PWA & modul
AuthHandler.extensions_map = {
    **http.server.SimpleHTTPRequestHandler.extensions_map,
    ".webmanifest": "application/manifest+json",
    ".js": "text/javascript",
    ".mjs": "text/javascript",
}

with http.server.ThreadingHTTPServer((BIND, PORT), AuthHandler) as httpd:
    print(f"Q-EKH Protocol jalan di http://{BIND}:{PORT}  (user: {USERNAME})")
    print("Ctrl+C untuk berhenti.")
    httpd.serve_forever()

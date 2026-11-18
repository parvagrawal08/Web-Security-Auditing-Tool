"""
Shared pytest fixtures. Tests run fully offline: they scan a tiny local,
deliberately weak HTTP server started on 127.0.0.1 (a local lab target
you own) -- never a third-party site.
"""

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


class _WeakHandler(BaseHTTPRequestHandler):
    """HTTP only, no security headers, version disclosure, insecure cookie, TRACE advertised."""

    def log_message(self, *args):
        pass

    def _send(self, body=b"<html><body>lab target</body></html>"):
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.1 (Unix)")
        self.send_header("X-Powered-By", "PHP/5.6.40")
        self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/uploads"):
            self._send(b"<html><title>Index of /uploads</title><h1>Index of /uploads</h1></html>")
        else:
            self._send()

    do_HEAD = do_GET

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS, TRACE")
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture(scope="session")
def lab_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _WeakHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture(scope="session")
def lab_result(lab_url):
    from scan_controller import run_full_scan
    return run_full_scan(lab_url, request_delay_seconds=0, timeout_seconds=4)

#!/usr/bin/env python3
import argparse
import base64
import http.server
import re
import socketserver


SMALL_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACAQMAAABIeJ9nAAAAIGNIUk0AAHomAACAhAAA+gAAAIDoAAB1MAAA6mAAADqYAAAXcJy6UTwAAAAGUExURf8AAP///0EdNBEAAAABYktHRAH/Ai3eAAAAB3RJTUUH6gIRDSkx9C79XAAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyNi0wMi0xN1QxMzo0MTo0OSswMDowMB6K15gAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjYtMDItMTdUMTM6NDE6NDkrMDA6MDBv128kAAAAKHRFWHRkYXRlOnRpbWVzdGFtcAAyMDI2LTAyLTE3VDEzOjQxOjQ5KzAwOjAwOMJO+wAAAAxJREFUCNdjYGBgAAAABAABJzQnCgAAAABJRU5ErkJggg=="
)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, b"ok", "text/plain")
            return

        if self.path == "/image.png":
            self._send(200, SMALL_PNG, "image/png")
            return

        if self.path == "/noimage.png":
            self._send(200, SMALL_PNG, "image/png")
            return

        if self.path == "/big.bin":
            # Intentionally larger than test DimsMaxDownloadBytes values.
            self._send(200, b"A" * 16384, "application/octet-stream")
            return

        match = re.fullmatch(r"/redirect/(\d+)", self.path)
        if match:
            remaining = int(match.group(1))
            self.send_response(302)
            if remaining > 0:
                self.send_header("Location", f"/redirect/{remaining - 1}")
            else:
                self.send_header("Location", "/image.png")
            self.end_headers()
            return

        self._send(404, b"not found", "text/plain")

    def log_message(self, fmt, *args):
        # Keep test output clean.
        return

    def _send(self, status, payload, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()

    class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    server = ThreadedServer((args.host, args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()

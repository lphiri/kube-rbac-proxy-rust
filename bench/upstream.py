#!/usr/bin/env python3
"""Small deterministic upstream used by the proxy comparison harness."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 - required by BaseHTTPRequestHandler
        body = b"benchmark-ok\n"
        if self.path.split("?", 1)[0] != "/benchmark":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


parser = argparse.ArgumentParser()
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument("--port", type=int, required=True)
args = parser.parse_args()
ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()

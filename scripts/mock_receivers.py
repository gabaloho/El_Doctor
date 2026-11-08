#!/usr/bin/env python3
"""Local stand-ins for notification endpoints so El Doctor can be tested offline.

  HTTP  127.0.0.1:8099  /slack /teams /discord /shuffle /n8n /tines /thehive/api/v1/alert /register
  SMTP  127.0.0.1:2525  (minimal RFC 5321 sink)
  UDP   127.0.0.1:5515  (syslog / CEF sink)

Everything received is appended to <out>.jsonl (one JSON object per message).
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()
OUT = "received.jsonl"
FILES = ""
SECRET = os.environ.get("ELDOCTOR_WEBHOOK_SECRET", "")


def record(kind: str, **data) -> None:
    with LOCK, open(OUT, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": time.time(), "channel": kind, **data}) + "\n")


class HTTP(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            payload = json.loads(body)
        except ValueError:
            payload = body.decode("utf-8", "replace")
        sig = self.headers.get("X-ElDoctor-Signature", "")
        sig_ok = None
        if sig and SECRET:
            calc = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
            sig_ok = hmac.compare_digest(calc, sig)
        record(self.path.strip("/").split("/")[0] or "root", path=self.path, payload=payload,
               auth=self.headers.get("Authorization", "")[:12], signature_valid=sig_ok)
        self.send_response(201 if "thehive" in self.path else 200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def do_GET(self):  # noqa: N802 - serves threat-intel feed files / payloads from --files
        path = os.path.join(FILES, os.path.basename(self.path.split("?")[0]))
        if FILES and os.path.isfile(path):
            data = open(path, "rb").read()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            record("http_get", path=self.path, bytes=len(data))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


class SMTP(socketserver.StreamRequestHandler):
    def w(self, line: str) -> None:
        self.wfile.write((line + "\r\n").encode())

    def handle(self):
        self.w("220 mock-smtp ready")
        mail_from, rcpt, data = "", [], []
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd = line.decode("utf-8", "replace").strip()
            up = cmd.upper()
            if up.startswith(("EHLO", "HELO")):
                self.w("250-mock-smtp"); self.w("250 OK")
            elif up.startswith("MAIL FROM"):
                mail_from = cmd[10:]; self.w("250 OK")
            elif up.startswith("RCPT TO"):
                rcpt.append(cmd[8:]); self.w("250 OK")
            elif up == "DATA":
                self.w("354 end with .")
                while True:
                    ln = self.rfile.readline().decode("utf-8", "replace")
                    if ln.strip() == ".":
                        break
                    data.append(ln.rstrip("\r\n"))
                import email
                subject = " ".join(str(email.message_from_string("\n".join(data)).get("Subject", "")).split())
                record("email", mail_from=mail_from, rcpt=rcpt, subject=subject, lines=len(data))
                self.w("250 queued")
            elif up == "QUIT":
                self.w("221 bye"); return
            else:
                self.w("250 OK")


class Syslog(socketserver.BaseRequestHandler):
    def handle(self):
        record("syslog", message=self.request[0].decode("utf-8", "replace"))


def main() -> None:
    global OUT, FILES
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="received.jsonl")
    ap.add_argument("--files", default="", help="directory served on GET (feeds, payloads)")
    args = ap.parse_args()
    OUT, FILES = args.out, args.files
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    servers = [ThreadingHTTPServer(("127.0.0.1", 8099), HTTP),
               socketserver.ThreadingTCPServer(("127.0.0.1", 2525), SMTP),
               socketserver.ThreadingUDPServer(("127.0.0.1", 5515), Syslog)]
    for s in servers:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    print("mock receivers up: http://127.0.0.1:8099  smtp 127.0.0.1:2525  syslog udp 127.0.0.1:5515", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

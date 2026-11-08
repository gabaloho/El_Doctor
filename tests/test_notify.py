import hashlib
import hmac
import json
import socket
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from eldoctor.models import Alert
from eldoctor.notify.channels import SyslogChannel, build_message
from eldoctor.notify.dispatcher import Dispatcher


@pytest.fixture
def http_sink():
    got = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            got.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
            self.send_response(500 if self.path == "/fail" else 200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}", got
    srv.shutdown()


@pytest.fixture
def smtp_sink():
    got = []

    class S(socketserver.StreamRequestHandler):
        def handle(self):
            w = lambda l: self.wfile.write((l + "\r\n").encode())
            w("220 hi")
            data = []
            while True:
                line = self.rfile.readline().decode().strip()
                if not line:
                    return
                u = line.upper()
                if u.startswith("EHLO"):
                    w("250-x"); w("250 OK")
                elif u == "DATA":
                    w("354 go")
                    while True:
                        ln = self.rfile.readline().decode()
                        if ln.strip() == ".":
                            break
                        data.append(ln)
                    got.append("".join(data)); w("250 ok")
                elif u == "QUIT":
                    w("221 bye"); return
                else:
                    w("250 OK")

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), S)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], got
    srv.shutdown()


def alert():
    return Alert(rule_id="ED-IOC-002", title="Connection to malicious IP", severity="critical", source="ioc",
                 mitre=["T1071"], remote_ip="198.51.100.23",
                 process={"pid": 42, "name": "beacon", "exe": "/tmp/beacon", "sha256": "ab" * 32, "username": "bob",
                          "cmdline": "beacon -c2"})


def test_all_http_channels(http_sink, monkeypatch):
    url, got = http_sink
    monkeypatch.setenv("WH_SECRET", "s3cret")
    monkeypatch.setenv("HIVE_KEY", "hive-key")
    cfg = {"notifications": {"min_severity": "low", "channels": [
        {"type": "slack", "url": url + "/slack"}, {"type": "teams", "url": url + "/teams"},
        {"type": "discord", "url": url + "/discord"},
        {"type": "webhook", "name": "shuffle", "url": url + "/shuffle", "secret_env": "WH_SECRET"},
        {"type": "thehive", "url": url, "api_key_env": "HIVE_KEY", "version": 5},
        {"type": "thehive", "name": "hive4", "url": url + "/v4", "api_key_env": "HIVE_KEY", "version": 4}]}}
    d = Dispatcher(cfg, synchronous=True)
    d.notify(alert().to_dict(), [{"action": "kill", "status": "success", "message": "terminated beacon[42]"}])
    by = {g["path"]: g for g in got}
    assert set(by) == {"/slack", "/teams", "/discord", "/shuffle", "/api/v1/alert", "/v4/api/alert"}
    slack = json.loads(by["/slack"]["body"])
    assert "CRITICAL" in slack["text"] and "T1071" in slack["attachments"][0]["text"]
    teams = json.loads(by["/teams"]["body"])
    assert teams["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    disc = json.loads(by["/discord"]["body"])
    assert disc["embeds"][0]["color"] == 0xdc3545
    sh = by["/shuffle"]
    expected = "sha256=" + hmac.new(b"s3cret", sh["body"], hashlib.sha256).hexdigest()
    assert sh["headers"]["x-eldoctor-signature"] == expected
    assert json.loads(sh["body"])["actions"][0]["action"] == "kill"
    hive = json.loads(by["/api/v1/alert"]["body"])
    assert by["/api/v1/alert"]["headers"]["authorization"] == "Bearer hive-key"
    assert hive["severity"] == 4 and "mitre:T1071" in hive["tags"]
    assert {"ip", "hash", "filename", "hostname"} <= {o["dataType"] for o in hive["observables"]}
    assert "artifacts" in json.loads(by["/v4/api/alert"]["body"])


def test_severity_filter_and_errors(http_sink):
    url, got = http_sink
    cfg = {"notifications": {"min_severity": "high", "channels": [
        {"type": "slack", "url": url + "/slack"}, {"type": "webhook", "url": url + "/fail"},
        {"type": "slack", "name": "nokey", "url_env": "MISSING_ENV_VAR"}]}}
    d = Dispatcher(cfg, synchronous=True)
    low = Alert(rule_id="X", title="low", severity="low")
    d.notify(low.to_dict())
    assert got == []
    d.notify(alert().to_dict())
    assert any("HTTP 500" in e for e in d.errors) and any("MISSING_ENV_VAR" in e for e in d.errors)
    assert d.sent.get("slack") == 1


def test_email(smtp_sink):
    port, got = smtp_sink
    cfg = {"notifications": {"min_severity": "low", "channels": [
        {"type": "email", "smtp_host": "127.0.0.1", "smtp_port": port, "starttls": False,
         "from": "ed@lab", "to": ["soc@lab"]}]}}
    d = Dispatcher(cfg, synchronous=True)
    d.notify(alert().to_dict())
    assert not d.errors, d.errors
    assert "Connection to malicious IP" in got[0] and "198.51.100.23" in got[0]


def test_syslog_cef_over_udp():
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(3)
    ch = SyslogChannel({"type": "syslog", "host": "127.0.0.1", "port": rx.getsockname()[1], "format": "cef"})
    ch.send(build_message(alert().to_dict(), [{"action": "kill", "status": "success", "message": ""}]))
    line = rx.recv(8192).decode()
    assert "CEF:0|ElDoctor|ElDoctor|" in line and "|ED-IOC-002|" in line and "|10|" in line
    assert "src=198.51.100.23" in line and "cs1=T1071" in line and "cs2=kill\\=success" in line


def test_rate_limit():
    d = Dispatcher({"notifications": {"min_severity": "low", "rate_limit_per_minute": 2,
                                      "channels": [{"type": "jsonl", "path": "a.jsonl"}]}}, synchronous=True)
    for _ in range(4):
        d.notify(alert().to_dict())
    assert d.sent["jsonl"] == 2 and any("rate limited" in e for e in d.errors)

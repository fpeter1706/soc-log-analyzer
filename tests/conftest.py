import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ssh(sec, msg):
    return f"Nov 18 10:{sec // 60:02d}:{sec % 60:02d} server sshd[1]: {msg}"


def web(sec, ip, path, status):
    return f'{ip} - - [18/Nov/2026:10:{sec // 60:02d}:{sec % 60:02d} +0530] "GET {path} HTTP/1.1" {status} 512 "-" "x"'


def failed(n, ip="9.9.9.9", users=("root",), gap=2):
    return [ssh(i * gap, f"Failed password for {users[i % len(users)]} from {ip} port 22 ssh2") for i in range(n)]


@pytest.fixture(scope="session")
def sample_logs():
    from soc import parser
    return parser.parse_files(os.path.join(ROOT, "sample_data", "auth.log"), os.path.join(ROOT, "sample_data", "access.log"), 2026)


class _Handler(BaseHTTPRequestHandler):
    """Tiny fake of LM Studio's OpenAI-compatible API. Behaviour is chosen via server.mode."""
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, {"data": [{"id": "gemma-test"}]})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.server.received.append(json.loads(self.rfile.read(n)))
        mode = self.server.mode
        good = {"explanation": "Many failed SSH logins from one address.", "likely_attack": "Brute force",
                "false_positive_likelihood": "low", "confidence": 0.9, "next_steps": ["Block the IP", "Check logins"]}
        if mode == "slow":
            import time
            time.sleep(1.5)
        if mode == "error":
            return self._send(500, {"error": "boom"})
        content = {"good": json.dumps(good), "fenced": "Sure! ```json\n" + json.dumps(good) + "\n```",
                   "bad_schema": json.dumps({"explanation": "x"}), "prose": "I cannot help with that.",
                   "bad_conf": json.dumps({**good, "confidence": 7}), "slow": json.dumps(good)}.get(mode, json.dumps(good))
        self._send(200, {"choices": [{"message": {"content": content}}]})


@pytest.fixture()
def llm_server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    srv.mode, srv.received = "good", []
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    srv.url = f"http://127.0.0.1:{srv.server_address[1]}/v1"
    yield srv
    srv.shutdown()

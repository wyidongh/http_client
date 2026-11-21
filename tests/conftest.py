"""本地 mock HTTP 服务，覆盖测试所需的各种场景。"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict
from urllib.parse import parse_qs, urlsplit

import pytest

FILE_BYTES = bytes(range(256)) * 4096  # 1 MiB


class State:
    def __init__(self):
        self.counters: Dict[str, int] = {}
        self.valid_tokens: set = set()
        self.refresh_tokens: set = set()
        self.token_seq = 0
        self.token_requests = []
        self.drop_file_once = False
        self.lock = threading.Lock()

    def hit(self, key: str) -> int:
        with self.lock:
            self.counters[key] = self.counters.get(key, 0) + 1
            return self.counters[key]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state: State

    def log_message(self, *args):  # 静音
        pass

    # ---- helpers ----
    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _send(self, status: int, payload=None, headers=None, raw: bytes = None):
        body = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else b"")
        self.send_response(status)
        if raw is None and payload is not None:
            self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _route(self):
        parts = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        path = parts.path
        body = self._body()
        st = self.state

        if path == "/echo":
            return self._send(200, {
                "method": self.command, "path": path, "query": query,
                "headers": {k: v for k, v in self.headers.items()},
                "body": body.decode("latin-1"),
            })
        if path == "/flaky":  # 前 fail 次返回 503
            n = st.hit("flaky:" + query.get("key", ""))
            if n <= int(query.get("fail", 2)):
                return self._send(503, {"error": "unavailable", "n": n},
                                  headers={"Retry-After": query["retry_after"]} if "retry_after" in query else None)
            return self._send(200, {"ok": True, "n": n})
        if path == "/slow":
            n = st.hit("slow:" + query.get("key", ""))
            if n <= int(query.get("slow_times", 99)):
                time.sleep(float(query.get("delay", 1)))
            return self._send(200, {"n": n})
        if path == "/status":
            return self._send(int(query.get("code", 200)), {"code": query.get("code")})
        if path == "/basic":
            expected = "Basic " + base64.b64encode(b"alice:secret").decode()
            if self.headers.get("Authorization") == expected:
                return self._send(200, {"user": "alice"})
            return self._send(401, {"error": "bad credentials"}, headers={"WWW-Authenticate": 'Basic realm="t"'})
        if path == "/token":
            form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
            with st.lock:
                st.token_requests.append(form)
                grant = form.get("grant_type")
                if grant == "refresh_token" and form.get("refresh_token") not in st.refresh_tokens:
                    return self._send(400, {"error": "invalid_grant"})
                if grant == "password" and form.get("password") != "pw":
                    return self._send(401, {"error": "invalid_client"})
                st.token_seq += 1
                tok, rtok = f"tok-{st.token_seq}", f"rt-{st.token_seq}"
                st.valid_tokens.add(tok)
                st.refresh_tokens.add(rtok)
            return self._send(200, {"access_token": tok, "token_type": "bearer",
                                    "expires_in": int(query.get("ttl", 3600)), "refresh_token": rtok})
        if path == "/revoke":
            with st.lock:
                st.valid_tokens.clear()
            return self._send(200, {"revoked": True})
        if path == "/protected":
            auth = self.headers.get("Authorization", "")
            token = auth.split(" ", 1)[1] if " " in auth else ""
            if token in st.valid_tokens:
                return self._send(200, {"token": token})
            return self._send(401, {"error": "invalid_token"})
        if path.startswith("/files/"):
            return self._serve_file(query)
        return self._send(404, {"error": "not found"})

    def _serve_file(self, query):
        st = self.state
        data = FILE_BYTES
        headers = {"Accept-Ranges": "bytes", "Content-Type": "application/octet-stream"}
        if "cd" in query:
            headers["Content-Disposition"] = f'attachment; filename="{query["cd"]}"'
        start = 0
        rng = self.headers.get("Range")
        status = 200
        if rng and "norange" not in query:
            start = int(rng.split("=")[1].split("-")[0])
            if start >= len(data):
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{len(data)}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            status = 206
            headers["Content-Range"] = f"bytes {start}-{len(data) - 1}/{len(data)}"
        chunk = data[start:]
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(chunk)))
        self.end_headers()
        with st.lock:
            drop = st.drop_file_once
            st.drop_file_once = False
        if drop:  # 只发送一半然后断开，模拟网络中断
            self.wfile.write(chunk[: len(chunk) // 2])
            self.wfile.flush()
            self.close_connection = True
            return
        self.wfile.write(chunk)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _route


@pytest.fixture
def server():
    state = State()
    handler = type("H", (Handler,), {"state": state})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address
    yield type("S", (), {"url": f"http://{host}:{port}", "state": state})
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def file_sha256():
    return hashlib.sha256(FILE_BYTES).hexdigest()

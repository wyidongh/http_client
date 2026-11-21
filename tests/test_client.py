from __future__ import annotations

import io
import json
import logging
import time

import pytest

from httpclient import (
    ApiKeyAuth,
    BasicAuth,
    BearerAuth,
    CollectionRunner,
    ConnectionFailedError,
    CustomTokenAuth,
    DownloadError,
    HttpClient,
    HttpStatusError,
    OAuth2ClientCredentialsAuth,
    OAuth2PasswordAuth,
    RequestTimeoutError,
    RetryConfig,
    TokenRefreshError,
)
from httpclient.cli import main as cli_main
from httpclient.logger import mask_url

from .conftest import FILE_BYTES

FAST = RetryConfig(max_retries=3, backoff_factor=0.01)


# ---------------------------------------------------------------- 基础请求
def test_methods_params_headers_json(server):
    with HttpClient(server.url, headers={"X-App": "t"}, params={"v": "1"}) as c:
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            r = c.request(method, "/echo", params={"a": "b", "skip": None}, headers={"X-Req": "1"},
                          json={"k": "v"} if method != "GET" else None)
            body = r.json()
            assert body["method"] == method
            assert body["query"] == {"v": "1", "a": "b"}
            assert body["headers"]["X-App"] == "t" and body["headers"]["X-Req"] == "1"
            if method != "GET":
                assert json.loads(body["body"]) == {"k": "v"}
        assert c.head("/echo").status_code == 200


def test_form_raw_and_multipart(server, tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello file")
    with HttpClient(server.url) as c:
        assert c.post("/echo", data={"x": "1", "y": "2"}).json()["body"] == "x=1&y=2"
        assert c.post("/echo", data=b"raw!", headers={"Content-Type": "text/plain"}).json()["body"] == "raw!"
        body = c.post("/echo", data={"f": "v"}, files={"up": str(f)}).json()["body"]
        assert 'filename="a.txt"' in body and "hello file" in body


def test_pretty_output(server):
    with HttpClient(server.url) as c:
        text = c.get("/echo").pretty()
    assert text.startswith("HTTP 200 OK") and '"method": "GET"' in text


# ---------------------------------------------------------------- 认证
def test_basic_bearer_apikey(server):
    with HttpClient(server.url) as c:
        assert c.get("/basic", auth=BasicAuth("alice", "secret")).status_code == 200
        assert c.get("/basic", auth=BasicAuth("alice", "nope")).status_code == 401
        h = c.get("/echo", auth=BearerAuth("abc")).json()["headers"]
        assert h["Authorization"] == "Bearer abc"
        assert c.get("/echo", auth=ApiKeyAuth("X-API-Key", "k1")).json()["headers"]["X-API-Key"] == "k1"
        assert c.get("/echo", auth=ApiKeyAuth("api_key", "k2", "query")).json()["query"] == {"api_key": "k2"}


def test_oauth2_client_credentials_and_auto_refresh_on_401(server):
    auth = OAuth2ClientCredentialsAuth(f"{server.url}/token", "cid", "csecret")
    with HttpClient(server.url, auth=auth) as c:
        assert c.get("/protected").json()["token"] == "tok-1"
        assert c.get("/protected").json()["token"] == "tok-1"     # 缓存复用
        c.post("/revoke", auth=None)                               # 服务端吊销 token
        r = c.get("/protected")                                    # 401 -> refresh -> 重放
        assert r.status_code == 200 and r.json()["token"] == "tok-2" and r.attempts == 2
    grants = [t["grant_type"] for t in server.state.token_requests]
    assert grants == ["client_credentials", "refresh_token"]


def test_proactive_refresh_when_expired(server):
    auth = OAuth2PasswordAuth(f"{server.url}/token?ttl=1", "u", "pw", client_id="cid", leeway=0)
    with HttpClient(server.url, auth=auth) as c:
        assert c.get("/protected").json()["token"] == "tok-1"
        time.sleep(1.1)
        r = c.get("/protected")
        assert r.json()["token"] == "tok-2" and r.attempts == 1    # 请求前已主动刷新，未产生 401
    assert server.state.token_requests[0]["client_id"] == "cid"


def test_refresh_falls_back_to_login(server):
    auth = OAuth2PasswordAuth(f"{server.url}/token", "u", "pw", leeway=0)
    with HttpClient(server.url, auth=auth) as c:
        c.get("/protected")
        server.state.refresh_tokens.clear()                        # refresh_token 也失效
        c.post("/revoke", auth=None)
        assert c.get("/protected").status_code == 200
    assert [t["grant_type"] for t in server.state.token_requests] == ["password", "refresh_token", "password"]


def test_token_error(server):
    auth = OAuth2PasswordAuth(f"{server.url}/token", "u", "wrong")
    with HttpClient(server.url, auth=auth) as c, pytest.raises(TokenRefreshError):
        c.get("/protected")


def test_custom_token_auth(server):
    import requests

    def login():
        return requests.post(f"{server.url}/token", data={"grant_type": "client_credentials"}).json()

    with HttpClient(server.url, auth=CustomTokenAuth(login)) as c:
        assert c.get("/protected").status_code == 200
        c.post("/revoke", auth=None)
        assert c.get("/protected").status_code == 200


# ---------------------------------------------------------------- 重试 / 超时
def test_retry_on_503(server):
    with HttpClient(server.url, retry=FAST) as c:
        r = c.get("/flaky", params={"fail": 2, "key": "a"})
    assert r.status_code == 200 and r.attempts == 3


def test_retry_exhausted_returns_last_response_or_raises(server):
    with HttpClient(server.url, retry=RetryConfig(max_retries=1, backoff_factor=0)) as c:
        assert c.get("/flaky", params={"fail": 5, "key": "b"}).status_code == 503
        with pytest.raises(HttpStatusError) as ei:
            c.get("/flaky", params={"fail": 5, "key": "c"}, raise_for_status=True)
        assert ei.value.status_code == 503


def test_retry_after_header(server):
    with HttpClient(server.url, retry=FAST) as c:
        t0 = time.monotonic()
        r = c.get("/flaky", params={"fail": 1, "key": "ra", "retry_after": "0.3"})
    assert r.status_code == 200 and time.monotonic() - t0 >= 0.3


def test_post_not_retried_by_default(server):
    with HttpClient(server.url, retry=FAST) as c:
        assert c.post("/flaky", params={"fail": 1, "key": "p"}).status_code == 503
        r = c.post("/flaky", params={"fail": 1, "key": "p2"}, retry=RetryConfig(allowed_methods=None, backoff_factor=0))
        assert r.status_code == 200


def test_read_timeout_retry_then_success(server):
    with HttpClient(server.url, timeout=(1, 0.3), retry=FAST) as c:
        r = c.get("/slow", params={"delay": 0.6, "slow_times": 1, "key": "t1"})
    assert r.status_code == 200 and r.attempts == 2


def test_timeout_exhausted(server):
    with HttpClient(server.url, timeout=0.2, retry=RetryConfig(max_retries=1, backoff_factor=0)) as c:
        with pytest.raises(RequestTimeoutError):
            c.get("/slow", params={"delay": 0.5, "key": "t2"})


def test_connection_error():
    with HttpClient("http://127.0.0.1:1", retry=RetryConfig(max_retries=1, backoff_factor=0)) as c:
        with pytest.raises(ConnectionFailedError):
            c.get("/x")


def test_file_object_rewound_on_retry(server):
    fh = io.BytesIO(b"payload-123")
    with HttpClient(server.url, retry=FAST) as c:
        r = c.put("/flaky", params={"fail": 1, "key": "f"}, files={"f": ("a.bin", fh)})
    assert r.status_code == 200 and r.attempts == 2


# ---------------------------------------------------------------- 下载
def test_download_with_content_disposition(server, tmp_path, file_sha256):
    seen = []
    with HttpClient(server.url) as c:
        res = c.download("/files/x?cd=report.bin", tmp_path, expected_sha256=file_sha256,
                         progress=lambda d, t: seen.append((d, t)))
    assert res.path == tmp_path / "report.bin" and res.path.read_bytes() == FILE_BYTES
    assert seen[-1] == (len(FILE_BYTES), len(FILE_BYTES))
    assert not (tmp_path / "report.bin.part").exists()


def test_download_resume_existing_part(server, tmp_path):
    target = tmp_path / "data.bin"
    (tmp_path / "data.bin.part").write_bytes(FILE_BYTES[:1000])
    with HttpClient(server.url) as c:
        res = c.download("/files/data.bin", target)
    assert res.resumed_from == 1000 and target.read_bytes() == FILE_BYTES


def test_download_resume_after_interruption(server, tmp_path):
    server.state.drop_file_once = True
    with HttpClient(server.url, retry=FAST) as c:
        res = c.download("/files/blob.bin", tmp_path)
    assert res.path.read_bytes() == FILE_BYTES and res.resumed


def test_download_server_ignores_range(server, tmp_path):
    (tmp_path / "f.bin.part").write_bytes(b"garbage")
    with HttpClient(server.url) as c:
        res = c.download("/files/f.bin?norange=1", tmp_path / "f.bin")
    assert res.path.read_bytes() == FILE_BYTES and not res.resumed


def test_download_part_already_complete(server, tmp_path):
    (tmp_path / "f.bin.part").write_bytes(FILE_BYTES)
    with HttpClient(server.url) as c:
        res = c.download("/files/f.bin", tmp_path / "f.bin")
    assert res.path.read_bytes() == FILE_BYTES


def test_download_errors(server, tmp_path):
    with HttpClient(server.url) as c:
        with pytest.raises(DownloadError):
            c.download("/files/a.bin", tmp_path, expected_sha256="00")
        assert not (tmp_path / "a.bin").exists()
        c.download("/files/a.bin", tmp_path)
        with pytest.raises(FileExistsError):
            c.download("/files/a.bin", tmp_path)
        with pytest.raises(HttpStatusError):
            c.download("/nope", tmp_path / "x")


# ---------------------------------------------------------------- 日志 / 脱敏
def test_logs_are_masked(server, caplog):
    caplog.set_level(logging.DEBUG, logger="httpclient")
    with HttpClient(server.url) as c:
        c.post("/status", json={"password": "supersecret123"}, auth=BearerAuth("verysecrettoken"))
    text = caplog.text
    assert "--> POST" in text and "<-- 200 OK" in text and "supe****t123" in text
    assert "supersecret123" not in text and "verysecrettoken" not in text
    assert mask_url("http://h/p?api_key=abcdefghijkl&x=1") == "http://h/p?api_key=abcd****ijkl&x=1"


# ---------------------------------------------------------------- 集合 / CLI
def test_collection_runner(server, tmp_path):
    col = {
        "name": "t",
        "base_url": "{{host}}",
        "variables": {"host": server.url},
        "auth": {"type": "bearer", "token": "{{token}}"},
        "requests": [
            {"name": "login", "method": "POST", "url": "/token", "auth": {"type": "none"},
             "data": {"grant_type": "client_credentials"},
             "extract": {"token": "json.access_token"}, "expect": {"status": 200}},
            {"name": "me", "url": "/protected", "expect": {"status": 200, "json": {"token": "{{token}}"}}},
            {"name": "bad", "url": "/status?code=404", "expect": {"status": 200}},
            {"name": "dl", "url": "/files/c.bin", "download": "out/"},
        ],
    }
    results = CollectionRunner(col, base_dir=tmp_path).run()
    assert [r.ok for r in results] == [True, True, False, True]
    assert (tmp_path / "out" / "c.bin").stat().st_size == len(FILE_BYTES)


def test_cli(server, tmp_path, capsys):
    assert cli_main(["request", "POST", f"{server.url}/echo", "-j", '{"a": 1}', "-H", "X-T: 1", "-q", "p=2"]) == 0
    out = capsys.readouterr().out
    assert '"method": "POST"' in out and '"p": "2"' in out
    assert cli_main(["request", "GET", f"{server.url}/status?code=500", "-r", "0", "--fail"]) == 1
    assert cli_main(["download", f"{server.url}/files/z.bin", "-o", str(tmp_path) + "/"]) == 0
    assert (tmp_path / "z.bin").exists()

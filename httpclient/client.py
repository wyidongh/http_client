"""核心 HTTP 客户端。"""
from __future__ import annotations

import hashlib
import os
import re
import time
import uuid
from pathlib import Path
from typing import IO, Any, Callable, Dict, List, Mapping, Optional, Tuple, Union
from urllib.parse import unquote, urlsplit

import requests
from requests.auth import AuthBase
from requests.exceptions import ChunkedEncodingError, ConnectTimeout
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import Timeout

from .auth import Auth, RefreshableTokenAuth
from .config import DEFAULT_TIMEOUT, RetryConfig, TimeoutType, parse_retry_after
from .exceptions import (
    ConnectionFailedError,
    DownloadError,
    HttpClientError,
    HttpStatusError,
    RequestTimeoutError,
)
from .logger import describe_body, get_logger, human_size, mask_headers, mask_url
from .models import DownloadResult, HttpResponse
from .version import __version__

log = get_logger("client")
dlog = get_logger("download")

_UNSET: Any = object()
DEFAULT_USER_AGENT = f"py-httpclient/{__version__} python-requests/{requests.__version__}"

# files 参数支持的形式：
#   {"file": "/path/to/a.txt"}                          路径（每次尝试都会重新打开，支持重试）
#   {"file": open(...)}                                文件对象（重试前自动 seek(0)）
#   {"file": ("a.txt", b"bytes" | fileobj, "text/plain")}
FilesType = Union[Mapping[str, Any], List[Tuple[str, Any]], None]
ProgressCallback = Callable[[int, Optional[int]], None]


class HttpClient:
    """类 Postman 的 HTTP 客户端。

    示例::

        with HttpClient("https://api.example.com", auth=BearerAuth("xxx")) as c:
            r = c.get("/users", params={"page": 1})
            print(r.pretty())
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        auth: Optional[AuthBase] = None,
        timeout: TimeoutType = DEFAULT_TIMEOUT,
        retry: Optional[RetryConfig] = None,
        verify: Union[bool, str] = True,
        cert: Union[None, str, Tuple[str, str]] = None,
        proxies: Optional[Mapping[str, str]] = None,
        allow_redirects: bool = True,
        raise_for_status: bool = False,
        log_body_limit: int = 2000,
        refresh_token_on_401: bool = True,
        session: Optional[requests.Session] = None,
    ):
        """
        :param base_url: 基础地址，请求时可传相对路径
        :param headers / params: 每个请求都会带上的默认 header / query 参数
        :param auth: 默认认证，见 :mod:`httpclient.auth`
        :param timeout: 秒；数字或 (connect, read) 二元组
        :param retry: 重试策略，默认 ``RetryConfig()``；传 ``RetryConfig.disabled()`` 关闭
        :param verify: 是否校验 TLS 证书，或 CA bundle 路径
        :param cert: 客户端证书（双向 TLS）
        :param raise_for_status: 状态码 >= 400 时抛出 :class:`HttpStatusError`
        :param log_body_limit: DEBUG 日志中 body 的最大字符数
        :param refresh_token_on_401: 使用可刷新 token 认证时，遇到 401 自动刷新并重放一次
        """
        self.base_url = base_url.rstrip("/") if base_url else None
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = DEFAULT_USER_AGENT
        if headers:
            self.session.headers.update(headers)
        self.default_params = dict(params or {})
        self.auth = auth
        self.timeout = timeout
        self.retry = retry or RetryConfig()
        self.verify = verify
        self.cert = cert
        self.proxies = dict(proxies or {})
        self.allow_redirects = allow_redirects
        self.raise_for_status = raise_for_status
        self.log_body_limit = log_body_limit
        self.refresh_token_on_401 = refresh_token_on_401

    # ------------------------------------------------------------------ 生命周期
    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        self.session.close()

    # ------------------------------------------------------------------ 便捷方法
    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> HttpResponse:
        kwargs.setdefault("allow_redirects", False)
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("OPTIONS", url, **kwargs)

    def build_url(self, url: str) -> str:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) or not self.base_url:
            return url
        return f"{self.base_url}/{url.lstrip('/')}"

    # ------------------------------------------------------------------ 核心请求
    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        json: Any = None,
        data: Any = None,
        files: FilesType = None,
        cookies: Optional[Mapping[str, str]] = None,
        auth: Any = _UNSET,
        timeout: Any = _UNSET,
        retry: Optional[RetryConfig] = None,
        allow_redirects: Optional[bool] = None,
        stream: bool = False,
        raise_for_status: Optional[bool] = None,
    ) -> HttpResponse:
        """发送请求。

        :param params: query 参数（与默认参数合并；值为 None 的参数会被剔除）
        :param headers: 本次请求的 header（覆盖默认 header）
        :param json: JSON 请求体（自动设置 Content-Type）
        :param data: 表单 dict、原始字符串或 bytes
        :param files: multipart 文件，见模块顶部 ``FilesType`` 说明
        :param auth: 覆盖客户端默认认证；传 ``None`` 或 ``NoAuth()`` 表示不认证
        :param timeout: 覆盖默认超时
        :param retry: 覆盖默认重试策略
        :param stream: 流式读取响应（下载大文件时使用）
        """
        method = method.upper()
        full_url = self.build_url(url)
        auth_obj = self.auth if auth is _UNSET else auth
        retry_cfg = retry if retry is not None else self.retry
        req_timeout = self.timeout if timeout is _UNSET else timeout
        redirects = self.allow_redirects if allow_redirects is None else allow_redirects
        should_raise = self.raise_for_status if raise_for_status is None else raise_for_status
        merged_params = {k: v for k, v in {**self.default_params, **(params or {})}.items() if v is not None}

        req_id = uuid.uuid4().hex[:8]
        attempt = 0          # 实际发送次数
        retries = 0          # 已消耗的重试次数（token 刷新重放不计入）
        token_replayed = False
        started = time.monotonic()

        while True:
            attempt += 1
            opened: List[IO[bytes]] = []
            try:
                prepared = self._prepare(method, full_url, merged_params, headers, json, data, files,
                                         cookies, auth_obj, opened)
                self._log_request(req_id, attempt, prepared, auth_obj)
                t0 = time.monotonic()
                try:
                    resp = self._send(prepared, req_timeout, redirects, stream)
                except (Timeout, RequestsConnectionError) as exc:
                    cost = (time.monotonic() - t0) * 1000
                    kind = self._classify(exc)
                    if self._can_retry_exception(exc, method, retries, retry_cfg):
                        retries += 1
                        delay = retry_cfg.compute_backoff(retries)
                        log.warning("[%s] %s after %.0f ms: %s -> retry %d/%d in %.2fs",
                                    req_id, kind, cost, _short_exc(exc), retries, retry_cfg.max_retries, delay)
                        time.sleep(delay)
                        continue
                    log.error("[%s] %s after %.0f ms, giving up (attempts=%d): %s",
                              req_id, kind, cost, attempt, _short_exc(exc))
                    err_cls = RequestTimeoutError if isinstance(exc, Timeout) else ConnectionFailedError
                    raise err_cls(f"{method} {mask_url(full_url)} failed after {attempt} attempt(s): "
                                  f"{kind}: {_short_exc(exc)}") from exc
            finally:
                for fh in opened:
                    fh.close()

            cost = (time.monotonic() - t0) * 1000
            self._log_response(req_id, resp, cost, stream)

            # ---- 401：token 可能已过期，刷新后重放一次 ----
            if (resp.status_code == 401 and self.refresh_token_on_401 and not token_replayed
                    and isinstance(auth_obj, RefreshableTokenAuth)):
                token_replayed = True
                log.warning("[%s] 401 Unauthorized -> refreshing token and replaying request", req_id)
                auth_obj.invalidate(prepared.headers.get(auth_obj.header_name))
                resp.close()
                continue

            # ---- 可重试状态码 ----
            if (resp.status_code in retry_cfg.status_forcelist and retries < retry_cfg.max_retries
                    and retry_cfg.method_allowed(method)):
                retries += 1
                retry_after = parse_retry_after(resp.headers.get("Retry-After"))
                delay = retry_cfg.compute_backoff(retries, retry_after)
                log.warning("[%s] got %d %s -> retry %d/%d in %.2fs%s", req_id, resp.status_code, resp.reason,
                            retries, retry_cfg.max_retries, delay,
                            " (Retry-After)" if retry_after is not None and retry_cfg.respect_retry_after else "")
                resp.close()
                time.sleep(delay)
                continue
            break

        total = (time.monotonic() - started) * 1000
        result = HttpResponse(resp, request_id=req_id, attempts=attempt, elapsed_ms=total)
        if attempt > 1:
            log.info("[%s] finished with %d after %d attempt(s), total %.0f ms",
                     req_id, resp.status_code, attempt, total)
        if should_raise and resp.status_code >= 400:
            log.error("[%s] %s %s -> HTTP %d %s", req_id, method, mask_url(resp.url), resp.status_code, resp.reason)
            raise HttpStatusError(result)
        return result

    # ------------------------------------------------------------------ 内部：发送
    def _prepare(self, method, url, params, headers, json, data, files, cookies, auth, opened):
        req = requests.Request(
            method=method, url=url, params=params, headers=dict(headers or {}),
            json=json, data=data, files=self._open_files(files, opened), cookies=cookies,
            auth=auth,
        )
        return self.session.prepare_request(req)

    @staticmethod
    def _open_files(files: FilesType, opened: List[IO[bytes]]):
        """每次尝试都重新准备文件：路径则重新打开，文件对象则 seek(0)，保证重试时内容完整。"""
        if not files:
            return None
        items = files.items() if isinstance(files, Mapping) else files
        result = []
        for field, value in items:
            if isinstance(value, (str, os.PathLike)):
                fh = open(value, "rb")
                opened.append(fh)
                value = (os.path.basename(os.fspath(value)), fh)
            elif isinstance(value, tuple):
                if len(value) > 1 and hasattr(value[1], "seek"):
                    value[1].seek(0)
            elif hasattr(value, "seek"):
                value.seek(0)
            result.append((field, value))
        return result

    def _send(self, prepared: requests.PreparedRequest, timeout, allow_redirects: bool, stream: bool):
        settings = self.session.merge_environment_settings(
            prepared.url, self.proxies, stream, self.verify, self.cert
        )
        return self.session.send(prepared, timeout=timeout, allow_redirects=allow_redirects, **settings)

    @staticmethod
    def _classify(exc: Exception) -> str:
        if isinstance(exc, ConnectTimeout):
            return "connect timeout"
        if isinstance(exc, Timeout):
            return "read timeout"
        return "connection error"

    @staticmethod
    def _can_retry_exception(exc: Exception, method: str, retries: int, cfg: RetryConfig) -> bool:
        if retries >= cfg.max_retries:
            return False
        if isinstance(exc, ConnectTimeout):        # 请求尚未发出，任何方法都可以安全重试
            return cfg.retry_on_timeout or cfg.retry_on_connection_error
        if not cfg.method_allowed(method):
            return False
        if isinstance(exc, Timeout):
            return cfg.retry_on_timeout
        return cfg.retry_on_connection_error

    # ------------------------------------------------------------------ 内部：日志
    def _log_request(self, req_id: str, attempt: int, prepared: requests.PreparedRequest, auth: Any) -> None:
        suffix = f" (attempt {attempt})" if attempt > 1 else ""
        log.info("[%s] --> %s %s%s", req_id, prepared.method, mask_url(prepared.url or ""), suffix)
        if log.isEnabledFor(10):  # DEBUG
            if auth is not None:
                log.debug("[%s]     auth: %s", req_id,
                          auth.describe() if isinstance(auth, Auth) else type(auth).__name__)
            log.debug("[%s]     request headers: %s", req_id, mask_headers(prepared.headers))
            if prepared.body is not None:
                log.debug("[%s]     request body: %s", req_id,
                          describe_body(prepared.body, prepared.headers.get("Content-Type"), self.log_body_limit))

    def _log_response(self, req_id: str, resp: requests.Response, cost_ms: float, stream: bool) -> None:
        length = resp.headers.get("Content-Length")
        size = human_size(int(length)) if length and length.isdigit() else (
            "streaming" if stream else human_size(len(resp.content)))
        for hop in resp.history:
            log.info("[%s]     redirect %d -> %s", req_id, hop.status_code, hop.headers.get("Location"))
        level = 20 if resp.status_code < 400 else 30  # INFO / WARNING
        log.log(level, "[%s] <-- %d %s | %.0f ms | %s", req_id, resp.status_code, resp.reason, cost_ms, size)
        if log.isEnabledFor(10):
            log.debug("[%s]     response headers: %s", req_id, mask_headers(resp.headers))
            if not stream:
                log.debug("[%s]     response body: %s", req_id,
                          describe_body(resp.content, resp.headers.get("Content-Type"), self.log_body_limit))

    # ------------------------------------------------------------------ 下载
    def download(
        self,
        url: str,
        dest: Union[str, Path, None] = None,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        resume: bool = True,
        overwrite: bool = False,
        chunk_size: int = 64 * 1024,
        progress: Optional[ProgressCallback] = None,
        expected_sha256: Optional[str] = None,
        auth: Any = _UNSET,
        timeout: Any = _UNSET,
        retry: Optional[RetryConfig] = None,
    ) -> DownloadResult:
        """流式下载文件。

        * ``dest`` 为 None 或已存在的目录时，文件名取自 Content-Disposition，其次取 URL 路径；
        * 下载过程中写入 ``<文件>.part``，完成后原子重命名；
        * ``resume=True`` 时若存在 .part 文件且服务端支持 Range，则断点续传；
        * 传输中途断开会自动按重试策略续传；
        * ``expected_sha256`` 用于下载完成后的完整性校验；
        * ``progress(downloaded_bytes, total_bytes_or_None)`` 进度回调。
        """
        retry_cfg = retry if retry is not None else self.retry
        full_url = self.build_url(url)
        target: Optional[Path]
        if dest is None:
            target, directory = None, Path.cwd()
        else:
            as_dir = str(dest).endswith(("/", os.sep))  # 先判断：Path() 会去掉末尾斜杠
            dest = Path(dest)
            if as_dir or dest.is_dir():
                target, directory = None, dest
            else:
                target, directory = dest, dest.parent
        directory.mkdir(parents=True, exist_ok=True)

        started = time.monotonic()
        failures = 0
        while True:
            try:
                result = self._download_once(full_url, target, directory, params, headers, resume, overwrite,
                                             chunk_size, progress, auth, timeout, retry_cfg)
                break
            except _StreamInterrupted as exc:
                failures += 1
                if failures > retry_cfg.max_retries:
                    dlog.error("download of %s failed after %d interruption(s); partial file kept at %s",
                               mask_url(full_url), failures, _part_path(exc.target))
                    raise DownloadError(f"download interrupted: {exc.reason}") from exc
                delay = retry_cfg.compute_backoff(failures)
                dlog.warning("transfer interrupted at %s (%s) -> resume %d/%d in %.2fs",
                             human_size(exc.downloaded), exc.reason, failures, retry_cfg.max_retries, delay)
                time.sleep(delay)
                target, resume = exc.target, True

        result.elapsed_ms = (time.monotonic() - started) * 1000
        if expected_sha256:
            if result.sha256 != expected_sha256.lower():
                result.path.unlink()
                raise DownloadError(f"sha256 mismatch: expected {expected_sha256}, got {result.sha256}")
            dlog.info("sha256 verified: %s", result.sha256)
        speed = result.size / max(result.elapsed_ms / 1000, 1e-6)
        dlog.info("saved %s (%s, %.1fs, %s/s%s)", result.path, human_size(result.size), result.elapsed_ms / 1000,
                  human_size(speed), f", resumed from {human_size(result.resumed_from)}" if result.resumed else "")
        return result

    def _download_once(self, url, target, directory, params, headers, resume, overwrite, chunk_size,
                       progress, auth, timeout, retry_cfg) -> DownloadResult:
        req_headers = dict(headers or {})
        offset = 0
        if target is not None:
            _check_target(target, overwrite)
            offset = _prepare_part(target, resume)
            if offset:
                req_headers["Range"] = f"bytes={offset}-"
                dlog.info("found partial file %s (%s), requesting resume", _part_path(target), human_size(offset))

        resp = self.request("GET", url, params=params, headers=req_headers, stream=True, auth=auth,
                            timeout=timeout, retry=retry_cfg, raise_for_status=False)
        raw = resp.raw

        if target is None:  # 需要根据响应决定文件名
            target = directory / _filename_from_response(raw, url)
            try:
                _check_target(target, overwrite)
            except FileExistsError:
                raw.close()
                raise
            part = _part_path(target)
            if resume and part.exists() and part.stat().st_size > 0 \
                    and raw.headers.get("Accept-Ranges", "").lower() == "bytes":
                raw.close()
                return self._download_once(url, target, directory, params, headers, resume, overwrite,
                                           chunk_size, progress, auth, timeout, retry_cfg)
            if part.exists():
                part.unlink()

        part = _part_path(target)
        status = raw.status_code

        if status == 416 and offset:
            total = _total_from_content_range(raw.headers.get("Content-Range"))
            raw.close()
            if total == offset:  # .part 已经是完整文件
                dlog.info("partial file already complete (%s)", human_size(offset))
                os.replace(part, target)
                return DownloadResult(target, offset, 0.0, offset, _sha256(target), status)
            dlog.warning("server rejected range %d- (416), restarting from scratch", offset)
            part.unlink()
            return self._download_once(url, target, directory, params, headers, False, overwrite,
                                       chunk_size, progress, auth, timeout, retry_cfg)

        if status >= 400:
            resp.content  # 读取错误 body 便于排查
            raise HttpStatusError(resp, f"download failed: HTTP {status} {raw.reason} for {mask_url(url)}")

        if offset and status == 206:
            start = _start_from_content_range(raw.headers.get("Content-Range"))
            if start != offset:
                dlog.warning("unexpected Content-Range %r for offset %d, restarting",
                             raw.headers.get("Content-Range"), offset)
                raw.close()
                part.unlink()
                return self._download_once(url, target, directory, params, headers, False, overwrite,
                                           chunk_size, progress, auth, timeout, retry_cfg)
            mode = "ab"
            dlog.info("resuming download at byte %d", offset)
        else:
            if offset:
                dlog.warning("server ignored Range header (HTTP %d), restarting from scratch", status)
            offset = 0
            mode = "wb"

        length = raw.headers.get("Content-Length")
        encoded = bool(raw.headers.get("Content-Encoding"))  # 压缩传输时 Content-Length 与解压后大小不一致
        total = offset + int(length) if length and length.isdigit() and not encoded else None
        dlog.info("downloading -> %s (total %s)", target, human_size(total))

        reporter = _Progress(total, progress, initial=offset)
        downloaded = offset
        try:
            with open(part, mode) as fh:
                for chunk in raw.iter_content(chunk_size=chunk_size):
                    if chunk:
                        fh.write(chunk)
                        downloaded += len(chunk)
                        reporter.update(downloaded)
        except (ChunkedEncodingError, RequestsConnectionError, Timeout) as exc:
            raise _StreamInterrupted(target, downloaded, _short_exc(exc)) from exc
        finally:
            raw.close()

        if total is not None and downloaded < total:
            raise _StreamInterrupted(target, downloaded, f"incomplete body: {downloaded}/{total} bytes")
        reporter.finish(downloaded)
        os.replace(part, target)
        return DownloadResult(target, downloaded, 0.0, offset, _sha256(target), status)


# ====================================================================== 下载辅助
class _StreamInterrupted(HttpClientError):
    def __init__(self, target: Path, downloaded: int, reason: str):
        super().__init__(reason)
        self.target = target
        self.downloaded = downloaded
        self.reason = reason


class _Progress:
    """下载进度：已知总大小时每 10% 打印一次，未知时每 3 秒打印一次。"""

    def __init__(self, total: Optional[int], callback: Optional[ProgressCallback], initial: int = 0):
        self.total = total
        self.callback = callback
        self.started = time.monotonic()
        self.initial = initial
        self.last_bucket = int(initial * 10 / total) if total else 0
        self.last_log = self.started

    def update(self, done: int) -> None:
        if self.callback:
            self.callback(done, self.total)
        now = time.monotonic()
        if self.total:
            bucket = int(done * 10 / self.total)
            if bucket > self.last_bucket and bucket < 10:
                self.last_bucket = bucket
                self._log(done, now)
        elif now - self.last_log >= 3:
            self.last_log = now
            self._log(done, now)

    def _log(self, done: int, now: float) -> None:
        speed = (done - self.initial) / max(now - self.started, 1e-6)
        pct = f"{done * 100 / self.total:5.1f}% " if self.total else ""
        dlog.info("progress %s%s / %s  (%s/s)", pct, human_size(done), human_size(self.total), human_size(speed))

    def finish(self, done: int) -> None:
        if self.callback:
            self.callback(done, self.total if self.total is not None else done)


def _part_path(target: Path) -> Path:
    return target.with_name(target.name + ".part")


def _check_target(target: Path, overwrite: bool) -> None:
    if target.exists() and not overwrite:
        raise FileExistsError(f"{target} already exists (pass overwrite=True to replace it)")


def _prepare_part(target: Path, resume: bool) -> int:
    part = _part_path(target)
    if not part.exists():
        return 0
    if resume:
        return part.stat().st_size
    part.unlink()
    return 0


def _filename_from_response(resp: requests.Response, url: str) -> str:
    cd = resp.headers.get("Content-Disposition", "")
    name = None
    match = re.search(r"filename\*\s*=\s*([^']*)'[^']*'([^;]+)", cd, re.I)
    if match:
        name = unquote(match.group(2).strip().strip('"'), encoding=match.group(1) or "utf-8")
    else:
        match = re.search(r'filename\s*=\s*"([^"]+)"|filename\s*=\s*([^;]+)', cd, re.I)
        if match:
            name = (match.group(1) or match.group(2)).strip()
    if not name:
        name = unquote(os.path.basename(urlsplit(resp.url or url).path))
    name = os.path.basename(name.replace("\\", "/")).strip()  # 防止路径穿越
    return name if name and name not in (".", "..") else "download"


def _start_from_content_range(value: Optional[str]) -> Optional[int]:
    match = re.match(r"\s*bytes\s+(\d+)-", value or "")
    return int(match.group(1)) if match else None


def _total_from_content_range(value: Optional[str]) -> Optional[int]:
    match = re.search(r"/(\d+)\s*$", value or "")
    return int(match.group(1)) if match else None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _short_exc(exc: BaseException) -> str:
    text = str(exc)
    # urllib3 的异常信息非常冗长，只保留最内层原因
    match = re.search(r"\(Caused by (\w+)\(.*?:\s*(.*?)\)?\)\s*$", text)
    if match:
        text = f"{match.group(1)}: {match.group(2)}"
    return text if len(text) <= 200 else text[:200] + "..."

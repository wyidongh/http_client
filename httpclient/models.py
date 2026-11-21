"""响应模型。"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

import requests

from .logger import human_size, mask_headers

_RAISE = object()


class HttpResponse:
    """对 ``requests.Response`` 的轻量封装，额外记录耗时、尝试次数和请求 ID。

    访问 ``.raw`` 可拿到原始的 ``requests.Response``。
    """

    def __init__(self, raw: requests.Response, *, request_id: str, attempts: int, elapsed_ms: float):
        self.raw = raw
        self.request_id = request_id
        self.attempts = attempts
        self.elapsed_ms = elapsed_ms

    # ---- 基本属性 ----
    @property
    def status_code(self) -> int:
        return self.raw.status_code

    @property
    def reason(self) -> str:
        return self.raw.reason or ""

    @property
    def ok(self) -> bool:
        return self.raw.status_code < 400

    @property
    def url(self) -> str:
        return self.raw.url

    @property
    def request_method(self) -> str:
        return self.raw.request.method if self.raw.request is not None else "?"

    @property
    def headers(self):
        return self.raw.headers

    @property
    def cookies(self):
        return self.raw.cookies

    @property
    def content(self) -> bytes:
        return self.raw.content

    @property
    def text(self) -> str:
        return self.raw.text

    @property
    def content_type(self) -> str:
        return self.raw.headers.get("Content-Type", "")

    def json(self, default: Any = _RAISE) -> Any:
        """解析 JSON；提供 ``default`` 时解析失败返回 default 而不是抛异常。"""
        try:
            return self.raw.json()
        except ValueError:
            if default is _RAISE:
                raise
            return default

    def raise_for_status(self) -> "HttpResponse":
        from .exceptions import HttpStatusError

        if self.status_code >= 400:
            raise HttpStatusError(self)
        return self

    def save(self, path: Union[str, Path]) -> Path:
        """把响应体写入文件（适合小文件；大文件请用 ``HttpClient.download``）。"""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.content)
        return target

    # ---- 展示 ----
    def pretty(self, body_limit: int = 20000, show_headers: bool = True, mask: bool = True) -> str:
        """类似 Postman 的响应面板文本。"""
        lines = [
            f"HTTP {self.status_code} {self.reason}   time={self.elapsed_ms:.0f}ms   "
            f"size={human_size(len(self.content))}   attempts={self.attempts}",
            f"{self.request_method} {self.url}",
        ]
        if show_headers:
            lines.append("---------------- Headers ----------------")
            headers = mask_headers(self.headers) if mask else dict(self.headers)
            lines.extend(f"{k}: {v}" for k, v in headers.items())
        lines.append("---------------- Body -------------------")
        lines.append(self._pretty_body(body_limit))
        return "\n".join(lines)

    def _pretty_body(self, limit: int) -> str:
        if not self.content:
            return "<empty>"
        ctype = self.content_type.lower()
        if "json" in ctype or self.content[:1] in (b"{", b"["):
            try:
                text = json.dumps(self.raw.json(), indent=2, ensure_ascii=False)
            except ValueError:
                text = self.text
        elif ctype.startswith(("text/", "application/xml", "application/javascript")) or not ctype:
            text = self.text
        else:
            try:
                text = self.content.decode("utf-8")
            except UnicodeDecodeError:
                return f"<binary {ctype or 'data'}, {human_size(len(self.content))}>"
        if limit and len(text) > limit:
            text = f"{text[:limit]}\n... (truncated, {len(text)} chars total)"
        return text

    def __repr__(self) -> str:
        return (f"<HttpResponse [{self.status_code}] {self.request_method} {self.url} "
                f"{self.elapsed_ms:.0f}ms attempts={self.attempts}>")


@dataclass
class DownloadResult:
    path: Path
    size: int
    elapsed_ms: float
    resumed_from: int = 0          # 断点续传的起始字节；0 表示从头下载
    sha256: Optional[str] = None
    status_code: Optional[int] = None

    @property
    def resumed(self) -> bool:
        return self.resumed_from > 0

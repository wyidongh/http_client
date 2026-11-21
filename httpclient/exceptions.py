"""统一的异常层次结构。

    HttpClientError
    ├── RequestTimeoutError      请求超时（重试耗尽后）
    ├── ConnectionFailedError    连接失败（重试耗尽后）
    ├── HttpStatusError          HTTP 状态码 >= 400（raise_for_status=True 时）
    ├── AuthError
    │   └── TokenRefreshError    获取 / 刷新 token 失败
    └── DownloadError            文件下载失败（校验失败、断点续传失败等）
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover
    from .models import HttpResponse


class HttpClientError(Exception):
    """所有本库异常的基类。"""


class RequestTimeoutError(HttpClientError):
    """请求超时，且已用尽重试次数。"""


class ConnectionFailedError(HttpClientError):
    """无法建立连接 / 连接被中断，且已用尽重试次数。"""


class HttpStatusError(HttpClientError):
    """服务端返回了错误状态码。"""

    def __init__(self, response: "HttpResponse", message: Optional[str] = None):
        self.response = response
        self.status_code = response.status_code
        super().__init__(
            message
            or f"HTTP {response.status_code} {response.reason} for {response.request_method} {response.url}"
        )


class AuthError(HttpClientError):
    """认证相关错误。"""


class TokenRefreshError(AuthError):
    """获取或刷新 token 失败。"""


class DownloadError(HttpClientError):
    """文件下载失败。"""

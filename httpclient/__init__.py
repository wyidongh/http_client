"""httpclient —— 基于 requests 的类 Postman HTTP 客户端。"""
from .auth import (
    ApiKeyAuth,
    BasicAuth,
    BearerAuth,
    CustomTokenAuth,
    DigestAuth,
    NoAuth,
    OAuth2ClientCredentialsAuth,
    OAuth2PasswordAuth,
    RefreshableTokenAuth,
    Token,
    build_auth,
)
from .client import HttpClient
from .collection import CollectionRunner
from .config import RetryConfig
from .exceptions import (
    AuthError,
    ConnectionFailedError,
    DownloadError,
    HttpClientError,
    HttpStatusError,
    RequestTimeoutError,
    TokenRefreshError,
)
from .logger import setup_logging
from .models import DownloadResult, HttpResponse
from .version import __version__

__all__ = [
    "HttpClient", "HttpResponse", "DownloadResult", "RetryConfig", "CollectionRunner", "setup_logging",
    "NoAuth", "BasicAuth", "DigestAuth", "BearerAuth", "ApiKeyAuth", "Token", "RefreshableTokenAuth",
    "OAuth2ClientCredentialsAuth", "OAuth2PasswordAuth", "CustomTokenAuth", "build_auth",
    "HttpClientError", "RequestTimeoutError", "ConnectionFailedError", "HttpStatusError",
    "AuthError", "TokenRefreshError", "DownloadError", "__version__",
]

"""认证方式。

所有认证类都是 ``requests.auth.AuthBase`` 的子类，可以直接传给 :class:`HttpClient`，
也可以传给原生 requests 使用。

=============================  =========================================================
类                             说明
=============================  =========================================================
NoAuth                         显式禁用认证（覆盖客户端默认认证）
BasicAuth                      HTTP Basic
DigestAuth                     HTTP Digest
BearerAuth                     固定的 Bearer Token
ApiKeyAuth                     API Key，放在 header 或 query 中
OAuth2ClientCredentialsAuth    OAuth2 client_credentials，自动获取 / 刷新 token
OAuth2PasswordAuth             OAuth2 password grant，自动获取 / 刷新 token
CustomTokenAuth                自定义登录函数（例如调用业务自己的 /login），自动刷新
=============================  =========================================================

Token 自动刷新机制（``RefreshableTokenAuth`` 及其子类）:

1. **主动刷新**：每次发请求前检查 token 是否将在 ``leeway`` 秒内过期，过期则先刷新；
2. **被动刷新**：服务端返回 401 时，HttpClient 会调用 :meth:`invalidate`，然后自动
   刷新 token 并重放一次请求；
3. 有 refresh_token 时优先用 refresh_token 刷新，失败后回退为完整重新登录；
4. 线程安全：多个线程并发遇到过期时只会刷新一次。
"""
from __future__ import annotations

import abc
import base64
import json
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, Mapping, Optional, Union

import requests
from requests.auth import AuthBase, HTTPBasicAuth, HTTPDigestAuth

from .exceptions import AuthError, TokenRefreshError
from .logger import get_logger, mask_secret

log = get_logger("auth")


class Auth(AuthBase):
    """本库认证基类，额外提供 :meth:`describe` 用于日志。"""

    def describe(self) -> str:
        return type(self).__name__


class NoAuth(Auth):
    def __call__(self, r):
        return r

    def describe(self) -> str:
        return "NoAuth"


class BasicAuth(Auth):
    def __init__(self, username: str, password: str):
        self.username = username
        self._impl = HTTPBasicAuth(username, password)

    def __call__(self, r):
        return self._impl(r)

    def describe(self) -> str:
        return f"Basic(user={self.username})"


class DigestAuth(Auth):
    def __init__(self, username: str, password: str):
        self.username = username
        self._impl = HTTPDigestAuth(username, password)

    def __call__(self, r):
        return self._impl(r)

    def describe(self) -> str:
        return f"Digest(user={self.username})"


class BearerAuth(Auth):
    """固定 token。``scheme`` 可改为 ``Token``、``JWT`` 等，或设为空字符串只发送 token 本身。"""

    def __init__(self, token: str, scheme: str = "Bearer", header_name: str = "Authorization"):
        self.token = token
        self.scheme = scheme
        self.header_name = header_name

    def __call__(self, r):
        r.headers[self.header_name] = f"{self.scheme} {self.token}" if self.scheme else self.token
        return r

    def describe(self) -> str:
        return f"Bearer(header={self.header_name})"


class ApiKeyAuth(Auth):
    """API Key：``location='header'``（默认）或 ``location='query'``。"""

    def __init__(self, name: str, value: str, location: str = "header"):
        if location not in ("header", "query"):
            raise ValueError("location must be 'header' or 'query'")
        self.name = name
        self.value = value
        self.location = location

    def __call__(self, r):
        if self.location == "header":
            r.headers[self.name] = self.value
        else:
            r.prepare_url(r.url, {self.name: self.value})
        return r

    def describe(self) -> str:
        return f"ApiKey({self.location}:{self.name})"


# =========================================================================== Token
def _jwt_exp(token: str) -> Optional[float]:
    """尝试从 JWT 的 payload 中读取 exp（不校验签名，仅用于判断过期时间）。"""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        exp = json.loads(base64.urlsafe_b64decode(payload)).get("exp")
        return float(exp) if exp is not None else None
    except (ValueError, TypeError, AttributeError):
        return None


@dataclass
class Token:
    access_token: str
    token_type: str = "Bearer"
    expires_at: Optional[float] = None  # epoch 秒；None 表示未知 / 不过期
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    def is_expired(self, leeway: float = 0.0) -> bool:
        return self.expires_at is not None and time.time() >= self.expires_at - leeway

    @property
    def expires_in(self) -> Optional[float]:
        return None if self.expires_at is None else self.expires_at - time.time()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], default_expires_in: Optional[float] = None) -> "Token":
        """从 OAuth2 风格的响应构造 token，兼容 ``accessToken`` / ``expiresIn`` 等驼峰写法。"""
        access = data.get("access_token") or data.get("accessToken") or data.get("token")
        if not access:
            raise TokenRefreshError(f"no access_token in token response (keys: {sorted(data)})")
        expires_in = data.get("expires_in", data.get("expiresIn"))
        if expires_in is not None:
            expires_at: Optional[float] = time.time() + float(expires_in)
        else:
            expires_at = _jwt_exp(access)
            if expires_at is None and default_expires_in is not None:
                expires_at = time.time() + default_expires_in
        token_type = str(data.get("token_type") or data.get("tokenType") or "Bearer")
        if token_type.lower() == "bearer":
            token_type = "Bearer"
        return cls(
            access_token=str(access),
            token_type=token_type,
            expires_at=expires_at,
            refresh_token=data.get("refresh_token") or data.get("refreshToken"),
            scope=data.get("scope"),
            raw=dict(data),
        )


def _fmt_expiry(token: Token) -> str:
    left = token.expires_in
    if left is None:
        return "never/unknown"
    return f"{left:.0f}s" if left > 0 else "expired"


class RefreshableTokenAuth(Auth, abc.ABC):
    """可自动刷新的 token 认证基类。子类实现 :meth:`obtain`，可选实现 :meth:`refresh`。"""

    def __init__(
        self,
        *,
        leeway: float = 30.0,
        header_name: str = "Authorization",
        scheme: Optional[str] = None,
        token_timeout: float = 10.0,
        verify: Union[bool, str] = True,
        session: Optional[requests.Session] = None,
    ):
        """
        :param leeway: 提前多少秒视为过期，避免 token 在传输途中过期
        :param scheme: header 前缀，默认使用 token_type（通常为 Bearer）；设为 "" 则只发 token
        :param session: 请求 token 接口使用的 session（与业务请求隔离，避免递归认证）
        """
        self.leeway = leeway
        self.header_name = header_name
        self.scheme = scheme
        self.token_timeout = token_timeout
        self.verify = verify
        self._http = session or requests.Session()
        self._token: Optional[Token] = None
        self._lock = threading.RLock()

    # ---- 子类实现 ----
    @abc.abstractmethod
    def obtain(self) -> Token:
        """完整获取一个新 token（登录）。"""

    def refresh(self, token: Token) -> Token:
        """使用 refresh_token 刷新；默认直接重新登录。"""
        return self.obtain()

    # ---- 公共 API ----
    @property
    def token(self) -> Optional[Token]:
        return self._token

    def set_token(self, token: Token) -> None:
        with self._lock:
            self._token = token

    def get_token(self) -> Token:
        """返回有效 token，必要时获取或刷新。"""
        with self._lock:
            current = self._token
            if current is None:
                log.info("[%s] no cached token, obtaining a new one", self.describe())
                self._token = self._checked(self.obtain())
            elif current.is_expired(self.leeway):
                log.info("[%s] token expired or expiring soon (expires_in=%s), refreshing",
                         self.describe(), _fmt_expiry(current))
                self._token = self._renew(current)
            return self._token  # type: ignore[return-value]

    def invalidate(self, used_header_value: Optional[str] = None) -> None:
        """标记当前 token 失效（通常在收到 401 后调用），下次 :meth:`get_token` 会刷新。

        ``used_header_value`` 为发生 401 的请求实际携带的认证头；若当前 token 已经被
        其它线程刷新过，则不会再次作废，避免重复刷新。
        """
        with self._lock:
            if self._token is None:
                return
            if used_header_value is not None and used_header_value != self._header_value(self._token):
                log.debug("[%s] token already renewed by another request, skip invalidation", self.describe())
                return
            log.warning("[%s] token rejected by server, marking as expired", self.describe())
            self._token = replace(self._token, expires_at=0.0)

    def __call__(self, r):
        r.headers[self.header_name] = self._header_value(self.get_token())
        return r

    # ---- 内部 ----
    def _header_value(self, token: Token) -> str:
        scheme = token.token_type if self.scheme is None else self.scheme
        return f"{scheme} {token.access_token}" if scheme else token.access_token

    @staticmethod
    def _checked(token: Any) -> Token:
        if not isinstance(token, Token):
            raise TokenRefreshError(f"obtain()/refresh() must return Token, got {type(token).__name__}")
        return token

    def _renew(self, old: Token) -> Token:
        new: Optional[Token] = None
        if old.refresh_token:
            try:
                new = self._checked(self.refresh(old))
            except AuthError as exc:
                log.warning("[%s] refresh with refresh_token failed (%s), falling back to full re-authentication",
                            self.describe(), exc)
        if new is None:
            new = self._checked(self.obtain())
        # 有些服务端刷新时不返回新的 refresh_token，此时沿用旧的
        if new.refresh_token is None and old.refresh_token and new is not old:
            new = replace(new, refresh_token=old.refresh_token)
        return new

    def _request_token(self, url: str, data: Mapping[str, Any], auth: Any = None) -> Token:
        """POST 到 token 接口（application/x-www-form-urlencoded），返回解析后的 Token。"""
        grant = data.get("grant_type", "?")
        log.info("[%s] requesting token: POST %s (grant_type=%s)", self.describe(), url, grant)
        started = time.monotonic()
        try:
            resp = self._http.post(
                url, data=dict(data), auth=auth, timeout=self.token_timeout, verify=self.verify,
                headers={"Accept": "application/json"},
            )
        except requests.RequestException as exc:
            raise TokenRefreshError(f"token endpoint {url} unreachable: {exc}") from exc
        cost = (time.monotonic() - started) * 1000
        if resp.status_code >= 400:
            raise TokenRefreshError(
                f"token endpoint returned {resp.status_code} {resp.reason}: {resp.text[:300]}"
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise TokenRefreshError(f"token endpoint returned non-JSON body: {resp.text[:300]}") from exc
        token = Token.from_dict(payload)
        log.info("[%s] token acquired in %.0f ms: %s, expires_in=%s, refresh_token=%s",
                 self.describe(), cost, mask_secret(token.access_token), _fmt_expiry(token),
                 "yes" if token.refresh_token else "no")
        return token


class _OAuth2Base(RefreshableTokenAuth):
    def __init__(
        self,
        token_url: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scope: Optional[str] = None,
        client_auth: str = "basic",
        extra_params: Optional[Mapping[str, Any]] = None,
        **kwargs: Any,
    ):
        """
        :param client_auth: 客户端凭证的传递方式。``basic``：放在 Authorization 头（RFC 推荐）；
                            ``body``：放在表单中（client_id / client_secret）
        :param extra_params: 额外的表单参数，例如 ``audience``、``resource``
        """
        super().__init__(**kwargs)
        if client_auth not in ("basic", "body"):
            raise ValueError("client_auth must be 'basic' or 'body'")
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.client_auth = client_auth
        self.extra_params = dict(extra_params or {})

    def _post(self, data: Dict[str, Any]) -> Token:
        data = {**self.extra_params, **data}
        auth = None
        if self.client_id:
            if self.client_auth == "basic" and self.client_secret is not None:
                auth = HTTPBasicAuth(self.client_id, self.client_secret)
            else:
                data["client_id"] = self.client_id
                if self.client_secret is not None:
                    data["client_secret"] = self.client_secret
        return self._request_token(self.token_url, data, auth=auth)

    def refresh(self, token: Token) -> Token:
        data: Dict[str, Any] = {"grant_type": "refresh_token", "refresh_token": token.refresh_token}
        if self.scope:
            data["scope"] = self.scope
        return self._post(data)


class OAuth2ClientCredentialsAuth(_OAuth2Base):
    """OAuth2 Client Credentials 模式（服务间调用最常见）。"""

    def __init__(self, token_url: str, client_id: str, client_secret: str, scope: Optional[str] = None, **kwargs: Any):
        super().__init__(token_url, client_id, client_secret, scope, **kwargs)

    def obtain(self) -> Token:
        data: Dict[str, Any] = {"grant_type": "client_credentials"}
        if self.scope:
            data["scope"] = self.scope
        return self._post(data)

    def describe(self) -> str:
        return f"OAuth2ClientCredentials(client_id={self.client_id})"


class OAuth2PasswordAuth(_OAuth2Base):
    """OAuth2 Resource Owner Password 模式。"""

    def __init__(
        self,
        token_url: str,
        username: str,
        password: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scope: Optional[str] = None,
        client_auth: str = "body",
        **kwargs: Any,
    ):
        super().__init__(token_url, client_id, client_secret, scope, client_auth=client_auth, **kwargs)
        self.username = username
        self.password = password

    def obtain(self) -> Token:
        data: Dict[str, Any] = {"grant_type": "password", "username": self.username, "password": self.password}
        if self.scope:
            data["scope"] = self.scope
        return self._post(data)

    def describe(self) -> str:
        return f"OAuth2Password(user={self.username})"


TokenLike = Union[Token, Mapping[str, Any], str]


class CustomTokenAuth(RefreshableTokenAuth):
    """使用自定义函数获取 token，适用于非标准登录接口。

    ``login`` / ``refresh`` 可以返回 :class:`Token`、dict（OAuth2 风格字段，兼容驼峰）或纯字符串。

    示例::

        def login():
            r = requests.post("https://api.example.com/login", json={"user": "u", "pwd": "p"})
            return r.json()["data"]          # {"accessToken": "...", "expiresIn": 3600}

        client = HttpClient("https://api.example.com", auth=CustomTokenAuth(login))
    """

    def __init__(
        self,
        login: Callable[[], TokenLike],
        refresh: Optional[Callable[[Token], TokenLike]] = None,
        default_expires_in: Optional[float] = None,
        name: str = "CustomToken",
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self._login = login
        self._refresh = refresh
        self.default_expires_in = default_expires_in
        self.name = name

    def _coerce(self, value: TokenLike) -> Token:
        if isinstance(value, Token):
            return value
        if isinstance(value, str):
            return Token.from_dict({"access_token": value}, self.default_expires_in)
        if isinstance(value, Mapping):
            return Token.from_dict(value, self.default_expires_in)
        raise TokenRefreshError(f"unsupported token value type: {type(value).__name__}")

    def _call(self, func: Callable[..., TokenLike], *args: Any) -> Token:
        try:
            token = self._coerce(func(*args))
        except AuthError:
            raise
        except Exception as exc:  # 用户函数的任何异常都包装为 TokenRefreshError
            raise TokenRefreshError(f"{self.name}: {type(exc).__name__}: {exc}") from exc
        log.info("[%s] token acquired: %s, expires_in=%s", self.describe(),
                 mask_secret(token.access_token), _fmt_expiry(token))
        return token

    def obtain(self) -> Token:
        return self._call(self._login)

    def refresh(self, token: Token) -> Token:
        if self._refresh is None:
            return self.obtain()
        return self._call(self._refresh, token)

    def describe(self) -> str:
        return self.name


# =========================================================================== 工厂
def build_auth(spec: Optional[Mapping[str, Any]]) -> Optional[AuthBase]:
    """根据配置字典构造认证对象（供集合文件 / CLI 使用）。

    ``{"type": "basic", "username": "u", "password": "p"}``
    ``{"type": "digest", "username": "u", "password": "p"}``
    ``{"type": "bearer", "token": "xxx"}``
    ``{"type": "apikey", "name": "X-API-Key", "value": "xxx", "in": "header"}``
    ``{"type": "oauth2_client_credentials", "token_url": "...", "client_id": "...", "client_secret": "...", "scope": "..."}``
    ``{"type": "oauth2_password", "token_url": "...", "username": "...", "password": "...", "client_id": "..."}``
    ``{"type": "none"}``
    """
    if not spec:
        return None
    opts = dict(spec)
    kind = str(opts.pop("type", "")).lower().replace("-", "_")
    try:
        if kind in ("none", "noauth", ""):
            return NoAuth()
        if kind == "basic":
            return BasicAuth(opts["username"], opts["password"])
        if kind == "digest":
            return DigestAuth(opts["username"], opts["password"])
        if kind == "bearer":
            return BearerAuth(opts["token"], scheme=opts.get("scheme", "Bearer"),
                              header_name=opts.get("header", "Authorization"))
        if kind in ("apikey", "api_key"):
            return ApiKeyAuth(opts["name"], opts["value"], location=opts.get("in", "header"))
        if kind in ("oauth2_client_credentials", "client_credentials"):
            return OAuth2ClientCredentialsAuth(**opts)
        if kind in ("oauth2_password", "password"):
            return OAuth2PasswordAuth(**opts)
    except KeyError as exc:
        raise ValueError(f"auth type '{kind}' missing required field {exc}") from None
    raise ValueError(f"unsupported auth type: {kind!r}")


def parse_auth_string(text: str) -> AuthBase:
    """解析命令行认证参数。

    ``basic:user:pass`` | ``digest:user:pass`` | ``bearer:TOKEN`` |
    ``apikey:Header-Name:VALUE`` | ``apikey:param:VALUE:query`` | ``none``
    """
    kind, _, rest = text.partition(":")
    kind = kind.lower()
    if kind == "none":
        return NoAuth()
    if kind in ("basic", "digest"):
        user, sep, pwd = rest.partition(":")
        if not sep:
            raise ValueError(f"{kind} auth format: {kind}:USER:PASSWORD")
        return BasicAuth(user, pwd) if kind == "basic" else DigestAuth(user, pwd)
    if kind == "bearer":
        if not rest:
            raise ValueError("bearer auth format: bearer:TOKEN")
        return BearerAuth(rest)
    if kind == "apikey":
        parts = rest.split(":")
        if len(parts) < 2:
            raise ValueError("apikey auth format: apikey:NAME:VALUE[:header|query]")
        location = "header"
        if len(parts) >= 3 and parts[-1] in ("header", "query"):
            location = parts.pop()
        return ApiKeyAuth(parts[0], ":".join(parts[1:]), location=location)
    raise ValueError(f"unsupported auth: {text!r}")

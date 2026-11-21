"""日志配置与脱敏工具。

所有模块都使用 ``httpclient.*`` 命名空间下的 logger，调用方可以：

* 直接调用 :func:`setup_logging` 获得开箱即用的控制台/文件日志；
* 或者按标准 logging 方式自行配置 ``logging.getLogger("httpclient")``。

日志级别约定：
    INFO    每个请求一行发出、一行响应摘要；重试、刷新 token、下载进度
    DEBUG   额外输出请求/响应头和 body（已脱敏、已截断）
    WARNING 重试、token 失效、断点续传异常等可恢复问题
    ERROR   最终失败
"""
from __future__ import annotations

import json
import logging
import sys
from typing import Any, Mapping, Optional, Union
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

LOGGER_NAME = "httpclient"
DEFAULT_FORMAT = "%(asctime)s.%(msecs)03d | %(levelname)-7s | %(name)-20s | %(message)s"
DEFAULT_DATEFMT = "%Y-%m-%d %H:%M:%S"

# 需要脱敏的请求/响应头（小写）
SENSITIVE_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token"}
)
# 需要脱敏的 body 字段 / query 参数（小写）
SENSITIVE_KEYS = frozenset(
    {
        "password", "passwd", "secret", "client_secret", "access_token", "refresh_token",
        "id_token", "token", "api_key", "apikey", "key", "signature", "sig",
    }
)

_HANDLER_MARK = "_httpclient_handler"


def get_logger(suffix: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{suffix}" if suffix else LOGGER_NAME)


def setup_logging(
    level: Union[int, str] = logging.INFO,
    log_file: Optional[str] = None,
    fmt: str = DEFAULT_FORMAT,
    datefmt: str = DEFAULT_DATEFMT,
) -> logging.Logger:
    """配置 httpclient 日志：输出到 stderr，可选同时写入文件。可重复调用（不会重复添加 handler）。"""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level.upper() if isinstance(level, str) else level)

    for handler in list(logger.handlers):
        if getattr(handler, _HANDLER_MARK, False):
            logger.removeHandler(handler)
            handler.close()

    formatter = logging.Formatter(fmt, datefmt)
    handlers: list = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    for handler in handlers:
        handler.setFormatter(formatter)
        setattr(handler, _HANDLER_MARK, True)
        logger.addHandler(handler)

    logger.propagate = False
    return logger


# --------------------------------------------------------------------------- 脱敏
def _mask(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}****{value[-4:]}"


def mask_secret(value: Any) -> str:
    """``Bearer abcdefghijkl`` -> ``Bearer abcd****ijkl``。"""
    text = str(value)
    if not text:
        return text
    scheme, sep, rest = text.partition(" ")
    if sep and scheme.lower() in {"bearer", "basic", "token", "digest"}:
        return f"{scheme} {_mask(rest)}"
    return _mask(text)


def mask_headers(headers: Optional[Mapping[str, Any]]) -> dict:
    if not headers:
        return {}
    return {k: (mask_secret(v) if k.lower() in SENSITIVE_HEADERS else v) for k, v in headers.items()}


def _is_sensitive_key(key: Any) -> bool:
    k = str(key).lower()
    return k in SENSITIVE_KEYS or k in SENSITIVE_HEADERS


def mask_data(data: Any) -> Any:
    """递归脱敏 dict / list 中的敏感字段。"""
    if isinstance(data, Mapping):
        return {
            k: (mask_secret(v) if _is_sensitive_key(k) and v not in (None, "") else mask_data(v))
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [mask_data(v) for v in data]
    return data


def mask_url(url: str) -> str:
    """脱敏 URL query 中的敏感参数（例如放在 query 中的 api_key）。"""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not any(k.lower() in SENSITIVE_KEYS for k, _ in pairs):
        return url
    masked = [(k, mask_secret(v) if k.lower() in SENSITIVE_KEYS else v) for k, v in pairs]
    return urlunsplit(parts._replace(query=urlencode(masked, safe="*")))


# --------------------------------------------------------------------------- 格式化
def human_size(num: Optional[float]) -> str:
    if num is None:
        return "?"
    size = float(num)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"  # pragma: no cover


def truncate(text: str, limit: int) -> str:
    if limit <= 0 or len(text) <= limit:
        return text
    return f"{text[:limit]}... (truncated, {len(text)} chars total)"


def describe_body(body: Any, content_type: Optional[str], limit: int) -> str:
    """把请求/响应 body 转成适合打印日志的字符串（脱敏 + 截断 + 二进制识别）。"""
    if body is None or body == b"" or body == "":
        return "<empty>"
    if hasattr(body, "read"):
        return "<stream>"
    ctype = (content_type or "").lower()
    if "multipart/form-data" in ctype:
        return f"<multipart/form-data, {human_size(len(body))}>"

    if isinstance(body, bytes):
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return f"<binary, {human_size(len(body))}>"
    else:
        text = str(body)

    if "json" in ctype or text[:1] in ("{", "["):
        try:
            text = json.dumps(mask_data(json.loads(text)), ensure_ascii=False)
        except ValueError:
            pass
    elif "x-www-form-urlencoded" in ctype:
        pairs = parse_qsl(text, keep_blank_values=True)
        text = urlencode([(k, mask_secret(v) if k.lower() in SENSITIVE_KEYS else v) for k, v in pairs], safe="*")
    return truncate(text, limit)

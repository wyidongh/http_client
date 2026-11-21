"""重试 / 超时配置。"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import FrozenSet, Optional, Tuple, Union

# 超时：单个数字表示 connect 和 read 共用；二元组表示 (connect_timeout, read_timeout)
TimeoutType = Union[None, float, Tuple[float, float]]

DEFAULT_TIMEOUT: Tuple[float, float] = (5.0, 30.0)

IDEMPOTENT_METHODS: FrozenSet[str] = frozenset({"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"})


@dataclass
class RetryConfig:
    """重试策略。

    * 网络错误（连接失败 / 超时）和 ``status_forcelist`` 中的状态码会触发重试；
    * 默认只对幂等方法重试，避免 POST 等请求被重复提交。如需对 POST 也重试，
      设置 ``allowed_methods=None``（表示所有方法）；
    * **连接超时（ConnectTimeout）始终可以重试**，因为此时请求根本没有发出去；
    * 退避时间：``backoff_factor * 2 ** (n - 1)``，上限 ``backoff_max``，并叠加随机抖动；
    * 若服务端返回 ``Retry-After``，优先使用该值（上限 ``retry_after_max``）。
    """

    max_retries: int = 3
    backoff_factor: float = 0.5
    backoff_max: float = 30.0
    jitter: float = 0.1
    status_forcelist: FrozenSet[int] = frozenset({429, 500, 502, 503, 504})
    allowed_methods: Optional[FrozenSet[str]] = field(default_factory=lambda: IDEMPOTENT_METHODS)
    retry_on_timeout: bool = True
    retry_on_connection_error: bool = True
    respect_retry_after: bool = True
    retry_after_max: float = 120.0

    @classmethod
    def disabled(cls) -> "RetryConfig":
        return cls(max_retries=0)

    def method_allowed(self, method: str) -> bool:
        return self.allowed_methods is None or method.upper() in self.allowed_methods

    def compute_backoff(self, retry_number: int, retry_after: Optional[float] = None) -> float:
        """计算第 ``retry_number``（从 1 开始）次重试前需要等待的秒数。"""
        if retry_after is not None and self.respect_retry_after:
            return max(0.0, min(retry_after, self.retry_after_max))
        if self.backoff_factor <= 0:
            return 0.0
        delay = min(self.backoff_factor * (2 ** (retry_number - 1)), self.backoff_max)
        if self.jitter:
            delay += random.uniform(0, delay * self.jitter)
        return delay


def parse_retry_after(value: Optional[str]) -> Optional[float]:
    """解析 Retry-After 头：既可能是秒数，也可能是 HTTP 日期。"""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())

"""请求集合（类似 Postman Collection）：按顺序执行一组请求，支持变量、提取和断言。

集合文件（JSON）示例::

    {
      "name": "demo",
      "base_url": "{{host}}",
      "variables": {"host": "https://httpbin.org", "user": "alice"},
      "headers": {"X-Trace": "{{$guid}}"},
      "auth": {"type": "bearer", "token": "{{token}}"},
      "timeout": 10,
      "retry": {"max_retries": 2, "backoff_factor": 0.5},
      "requests": [
        {
          "name": "login",
          "method": "POST",
          "url": "/post",
          "auth": {"type": "none"},
          "json": {"user": "{{user}}"},
          "extract": {"token": "json.json.user"},
          "expect": {"status": 200, "json": {"json.user": "{{user}}"}, "max_time_ms": 3000}
        },
        {"name": "download", "method": "GET", "url": "/image/png", "download": "out/"}
      ]
    }

变量语法：``{{name}}``；内置动态变量：``{{$guid}}`` ``{{$timestamp}}`` ``{{$randomInt}}`` ``{{$env.HOME}}``。
提取路径：``status`` / ``headers.X-Token`` / ``cookies.sid`` / ``json.data.items.0.id`` / ``text``。
"""
from __future__ import annotations

import json
import os
import random
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Union

from .auth import build_auth
from .client import _UNSET, HttpClient
from .config import RetryConfig
from .exceptions import HttpClientError
from .logger import get_logger
from .models import HttpResponse

log = get_logger("collection")

_VAR = re.compile(r"\{\{\s*([$\w.\-]+)\s*\}\}")
_MISSING = object()


@dataclass
class StepResult:
    name: str
    ok: bool
    status: Optional[int] = None
    elapsed_ms: float = 0.0
    errors: List[str] = field(default_factory=list)
    extracted: Dict[str, Any] = field(default_factory=dict)


class CollectionRunner:
    def __init__(self, collection: Mapping[str, Any], variables: Optional[Mapping[str, Any]] = None,
                 base_dir: Union[str, Path, None] = None):
        self.collection = collection
        self.variables: Dict[str, Any] = {**collection.get("variables", {}), **(variables or {})}
        self.base_dir = Path(base_dir) if base_dir else Path.cwd()

    @classmethod
    def from_file(cls, path: Union[str, Path], variables: Optional[Mapping[str, Any]] = None) -> "CollectionRunner":
        path = Path(path)
        with open(path, encoding="utf-8") as fh:
            return cls(json.load(fh), variables, base_dir=path.parent)

    # ------------------------------------------------------------------ 变量
    def _lookup(self, name: str) -> Any:
        if name == "$guid":
            return str(uuid.uuid4())
        if name == "$timestamp":
            return int(time.time())
        if name == "$randomInt":
            return random.randint(0, 1000)
        if name.startswith("$env."):
            return os.environ.get(name[5:], "")
        if name not in self.variables:
            raise KeyError(name)
        return self.variables[name]

    def render(self, value: Any) -> Any:
        """递归替换变量；字符串整体为单个占位符时保留原始类型（例如数字）。"""
        if isinstance(value, str):
            whole = _VAR.fullmatch(value.strip())
            if whole:
                return self._lookup(whole.group(1))
            return _VAR.sub(lambda m: str(self._lookup(m.group(1))), value)
        if isinstance(value, Mapping):
            return {self.render(k): self.render(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.render(v) for v in value]
        return value

    # ------------------------------------------------------------------ 执行
    def run(self, stop_on_failure: bool = False) -> List[StepResult]:
        col = self.collection
        name = col.get("name", "collection")
        steps = col.get("requests", [])
        log.info("===== running collection '%s' (%d requests) =====", name, len(steps))

        # 集合级 auth 若引用了变量（例如登录步骤提取的 token），则在每个步骤执行时再构造
        lazy_auth = bool(col.get("auth")) and bool(_VAR.search(json.dumps(col.get("auth"))))
        retry = RetryConfig(**col["retry"]) if col.get("retry") else None
        client = HttpClient(
            self.render(col.get("base_url")) or None,
            headers=self.render(col.get("headers", {})),
            auth=build_auth(col["auth"]) if col.get("auth") and not lazy_auth else None,
            timeout=_timeout(col.get("timeout", (5, 30))),
            retry=retry,
            verify=col.get("verify", True),
        )

        results: List[StepResult] = []
        with client:
            for index, step in enumerate(steps, 1):
                title = step.get("name") or f"request #{index}"
                log.info("----- [%d/%d] %s -----", index, len(steps), title)
                result = self._run_step(client, step, title, lazy_auth)
                results.append(result)
                if result.ok:
                    log.info("PASS  %s (%s, %.0f ms)", title, result.status, result.elapsed_ms)
                else:
                    for err in result.errors:
                        log.error("FAIL  %s: %s", title, err)
                    if stop_on_failure:
                        log.error("stop_on_failure set, aborting collection")
                        break

        passed = sum(r.ok for r in results)
        log.info("===== collection '%s' finished: %d passed, %d failed =====", name, passed, len(results) - passed)
        return results

    def _run_step(self, client: HttpClient, step: Mapping[str, Any], title: str, lazy_auth: bool) -> StepResult:
        result = StepResult(name=title, ok=False)
        try:
            spec = self.render({k: v for k, v in step.items() if k not in ("extract", "expect")})
        except KeyError as exc:
            result.errors.append(f"undefined variable {exc}")
            return result

        auth: Any = _UNSET
        if "auth" in spec:
            auth = build_auth(spec["auth"])
        elif lazy_auth:
            try:
                auth = build_auth(self.render(self.collection["auth"]))
            except KeyError as exc:
                result.errors.append(f"undefined variable {exc} in collection auth")
                return result

        kwargs: Dict[str, Any] = {
            "params": spec.get("params"),
            "headers": spec.get("headers"),
            "auth": auth,
        }
        if "timeout" in spec:
            kwargs["timeout"] = _timeout(spec["timeout"])
        if spec.get("retry"):
            kwargs["retry"] = RetryConfig(**spec["retry"])

        method = spec.get("method", "GET").upper()
        try:
            if spec.get("download"):
                dest = str(self.base_dir / spec["download"])
                if str(spec["download"]).endswith(("/", "\\")):  # 以 / 结尾表示目录，Path 会丢掉末尾斜杠
                    dest += os.sep
                dl = client.download(spec["url"], dest, overwrite=True, **kwargs)
                result.status, result.elapsed_ms, result.ok = dl.status_code, dl.elapsed_ms, True
                result.extracted["download_path"] = str(dl.path)
                return result
            files = {k: str(self.base_dir / v) for k, v in (spec.get("files") or {}).items()}
            resp = client.request(method, spec["url"], json=spec.get("json"), data=spec.get("data"),
                                  files=files or None, **kwargs)
        except (HttpClientError, OSError) as exc:
            result.errors.append(f"{type(exc).__name__}: {exc}")
            return result

        result.status, result.elapsed_ms = resp.status_code, resp.elapsed_ms

        for var, path in (step.get("extract") or {}).items():
            value = extract(resp, path)
            if value is _MISSING:
                result.errors.append(f"extract '{var}': path '{path}' not found")
            else:
                self.variables[var] = value
                result.extracted[var] = value
                log.info("extracted %s = %s", var, _preview(value))

        try:
            expect = self.render(step.get("expect") or {})
        except KeyError as exc:
            expect = {}
            result.errors.append(f"undefined variable {exc} in expect")
        result.errors.extend(check_expectations(resp, expect))
        result.ok = not result.errors
        return result


# ====================================================================== 提取 / 断言
def extract(resp: HttpResponse, path: str) -> Any:
    head, _, rest = path.partition(".")
    if head == "status":
        return resp.status_code
    if head == "text":
        return resp.text
    if head == "headers":
        return resp.headers.get(rest, _MISSING)
    if head == "cookies":
        return resp.cookies.get(rest, _MISSING)
    if head == "json":
        data = resp.json(default=_MISSING)
        if data is _MISSING:
            return _MISSING
        return _dig(data, rest) if rest else data
    return _MISSING


def _dig(data: Any, path: str) -> Any:
    for key in path.split("."):
        if isinstance(data, list):
            try:
                data = data[int(key)]
            except (ValueError, IndexError):
                return _MISSING
        elif isinstance(data, Mapping) and key in data:
            data = data[key]
        else:
            return _MISSING
    return data


def check_expectations(resp: HttpResponse, expect: Mapping[str, Any]) -> List[str]:
    errors: List[str] = []
    if "status" in expect:
        allowed = expect["status"] if isinstance(expect["status"], list) else [expect["status"]]
        if resp.status_code not in [int(s) for s in allowed]:
            errors.append(f"expected status {allowed}, got {resp.status_code}")
    for path, expected in (expect.get("json") or {}).items():
        actual = extract(resp, path if path.startswith("json") else f"json.{path}")
        if actual is _MISSING:
            errors.append(f"expected {path} == {expected!r}, but path not found")
        elif actual != expected:
            errors.append(f"expected {path} == {expected!r}, got {actual!r}")
    if "body_contains" in expect and str(expect["body_contains"]) not in resp.text:
        errors.append(f"body does not contain {expect['body_contains']!r}")
    for name, expected in (expect.get("headers") or {}).items():
        actual = resp.headers.get(name)
        if actual is None or str(expected) not in actual:
            errors.append(f"expected header {name} to contain {expected!r}, got {actual!r}")
    if "max_time_ms" in expect and resp.elapsed_ms > float(expect["max_time_ms"]):
        errors.append(f"response took {resp.elapsed_ms:.0f} ms > {expect['max_time_ms']} ms")
    return errors


def _timeout(value: Any) -> Any:
    """JSON 中的 [connect, read] 列表转换为 requests 需要的元组。"""
    return tuple(value) if isinstance(value, list) else value


def _preview(value: Any, limit: int = 80) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "..."

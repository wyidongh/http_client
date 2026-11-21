"""命令行入口：``python -m httpclient <command> ...``

    request   发送单个请求              python -m httpclient request POST https://httpbin.org/post -j '{"a":1}'
    download  下载文件（支持断点续传）  python -m httpclient download https://example.com/a.zip -o out/
    run       执行请求集合              python -m httpclient run examples/collection.json --var user=bob
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .auth import parse_auth_string
from .client import HttpClient
from .collection import CollectionRunner
from .config import RetryConfig
from .exceptions import HttpClientError, HttpStatusError
from .logger import get_logger, setup_logging
from .version import __version__

log = get_logger("cli")

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


# ---------------------------------------------------------------------- 参数解析辅助
def _kv(items: Optional[Sequence[str]], sep: str, what: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for item in items or []:
        key, found, value = item.partition(sep)
        if not found:
            raise SystemExit(f"error: invalid {what} {item!r}, expected KEY{sep}VALUE")
        result[key.strip()] = value.strip() if sep == ":" else value
    return result


def _load_text(value: str) -> str:
    """``@file`` 表示从文件读取，``@-`` 表示从 stdin 读取。"""
    if value == "@-":
        return sys.stdin.read()
    if value.startswith("@"):
        return Path(value[1:]).read_text(encoding="utf-8")
    return value


def _timeout(value: str) -> Any:
    if "," in value:
        connect, read = value.split(",", 1)
        return float(connect), float(read)
    return float(value)


def _add_common(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("connection")
    g.add_argument("-H", "--header", action="append", metavar="'K: V'", help="请求头，可重复")
    g.add_argument("-q", "--param", action="append", metavar="K=V", help="query 参数，可重复")
    g.add_argument("-a", "--auth", metavar="SPEC",
                   help="basic:USER:PASS | digest:USER:PASS | bearer:TOKEN | apikey:NAME:VALUE[:query]")
    g.add_argument("-t", "--timeout", type=_timeout, default=(5.0, 30.0), metavar="SEC|CONN,READ",
                   help="超时秒数，默认 5,30")
    g.add_argument("-r", "--retries", type=int, default=3, help="最大重试次数，默认 3")
    g.add_argument("--backoff", type=float, default=0.5, help="退避因子（秒），默认 0.5")
    g.add_argument("--retry-all-methods", action="store_true", help="对 POST/PATCH 等非幂等方法也重试")
    g.add_argument("-k", "--insecure", action="store_true", help="不校验 TLS 证书")
    g.add_argument("--proxy", help="代理地址，例如 http://127.0.0.1:8080")
    g.add_argument("--cert", help="客户端证书（PEM）")
    lg = p.add_argument_group("logging")
    lg.add_argument("-v", "--verbose", action="store_true", help="DEBUG 日志（打印请求/响应头和 body）")
    lg.add_argument("--quiet", action="store_true", help="只打印 WARNING 及以上日志")
    lg.add_argument("--log-file", help="同时写入日志文件")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="httpclient", description="类 Postman 的命令行 HTTP 客户端")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("request", aliases=["req"], help="发送 HTTP 请求")
    p.add_argument("method", type=str.upper, choices=METHODS)
    p.add_argument("url")
    body = p.add_argument_group("body（互斥）").add_mutually_exclusive_group()
    body.add_argument("-j", "--json", metavar="JSON|@file", help="JSON 请求体")
    body.add_argument("-d", "--data", action="append", metavar="K=V", help="表单字段（x-www-form-urlencoded），可重复")
    body.add_argument("--raw", metavar="TEXT|@file", help="原始请求体（配合 -H 'Content-Type: ...'）")
    p.add_argument("-F", "--form", action="append", metavar="K=V|K=@file",
                   help="multipart 字段，@ 开头表示上传文件，可重复")
    p.add_argument("--no-follow", action="store_true", help="不跟随重定向")
    p.add_argument("-o", "--output", help="把响应体保存到文件")
    p.add_argument("--no-headers", action="store_true", help="输出中不显示响应头")
    p.add_argument("--body-only", action="store_true", help="只输出响应体（便于管道处理）")
    p.add_argument("--fail", action="store_true", help="HTTP 状态码 >= 400 时以退出码 1 结束")
    _add_common(p)

    d = sub.add_parser("download", aliases=["dl"], help="下载文件")
    d.add_argument("url")
    d.add_argument("-o", "--output", help="保存路径（文件或目录，默认当前目录）")
    d.add_argument("--no-resume", action="store_true", help="禁用断点续传")
    d.add_argument("--overwrite", action="store_true", help="覆盖已存在的文件")
    d.add_argument("--sha256", help="下载完成后校验 sha256")
    _add_common(d)

    c = sub.add_parser("run", help="执行请求集合（JSON）")
    c.add_argument("collection")
    c.add_argument("--var", action="append", metavar="K=V", help="覆盖集合变量，可重复")
    c.add_argument("--env", metavar="FILE", help="环境变量 JSON 文件（等价于多个 --var）")
    c.add_argument("--bail", action="store_true", help="遇到失败立即停止")
    lg = c.add_argument_group("logging")
    lg.add_argument("-v", "--verbose", action="store_true")
    lg.add_argument("--quiet", action="store_true")
    lg.add_argument("--log-file")
    return parser


def _make_client(args: argparse.Namespace) -> HttpClient:
    retry = RetryConfig(max_retries=args.retries, backoff_factor=args.backoff,
                        allowed_methods=None if args.retry_all_methods else RetryConfig().allowed_methods)
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    return HttpClient(
        headers=_kv(args.header, ":", "header"),
        params=_kv(args.param, "=", "param"),
        auth=parse_auth_string(args.auth) if args.auth else None,
        timeout=args.timeout,
        retry=retry,
        verify=not args.insecure,
        cert=args.cert,
        proxies=proxies,
    )


def _build_form(items: Optional[Sequence[str]]) -> Tuple[Dict[str, str], List[Tuple[str, str]]]:
    fields: Dict[str, str] = {}
    files: List[Tuple[str, str]] = []
    for key, value in _kv(items, "=", "form field").items():
        if value.startswith("@"):
            files.append((key, value[1:]))
        else:
            fields[key] = value
    return fields, files


# ---------------------------------------------------------------------- 子命令
def cmd_request(args: argparse.Namespace) -> int:
    kwargs: Dict[str, Any] = {"allow_redirects": not args.no_follow}
    if args.json is not None:
        try:
            kwargs["json"] = json.loads(_load_text(args.json))
        except ValueError as exc:
            raise SystemExit(f"error: invalid JSON body: {exc}")
    elif args.data:
        kwargs["data"] = _kv(args.data, "=", "data")
    elif args.raw is not None:
        kwargs["data"] = _load_text(args.raw).encode("utf-8")
    if args.form:
        fields, files = _build_form(args.form)
        if kwargs.get("json") is not None or isinstance(kwargs.get("data"), bytes):
            raise SystemExit("error: -F/--form cannot be combined with --json/--raw")
        kwargs["data"] = {**(kwargs.get("data") or {}), **fields}
        kwargs["files"] = files or None

    with _make_client(args) as client:
        resp = client.request(args.method, args.url, **kwargs)
    if args.output:
        path = resp.save(args.output)
        log.info("response body saved to %s", path)
    if args.body_only:
        sys.stdout.buffer.write(resp.content)
        sys.stdout.flush()
    else:
        print(resp.pretty(show_headers=not args.no_headers))
    return 1 if args.fail and resp.status_code >= 400 else 0


def cmd_download(args: argparse.Namespace) -> int:
    with _make_client(args) as client:
        result = client.download(args.url, args.output, resume=not args.no_resume,
                                 overwrite=args.overwrite, expected_sha256=args.sha256)
    print(f"{result.path}\t{result.size} bytes\tsha256={result.sha256}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    variables: Dict[str, Any] = {}
    if args.env:
        variables.update(json.loads(Path(args.env).read_text(encoding="utf-8")))
    variables.update(_kv(args.var, "=", "variable"))
    results = CollectionRunner.from_file(args.collection, variables).run(stop_on_failure=args.bail)
    width = max((len(r.name) for r in results), default=4)
    print(f"\n{'NAME'.ljust(width)}  RESULT  STATUS  TIME")
    for r in results:
        print(f"{r.name.ljust(width)}  {'PASS' if r.ok else 'FAIL':6}  {str(r.status or '-'):6}  "
              f"{r.elapsed_ms:.0f}ms")
        for err in r.errors:
            print(f"{' ' * width}    - {err}")
    failed = sum(not r.ok for r in results)
    print(f"\n{len(results) - failed} passed, {failed} failed")
    return 1 if failed else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    level = logging.DEBUG if args.verbose else logging.WARNING if args.quiet else logging.INFO
    setup_logging(level, log_file=args.log_file)
    handler = {"request": cmd_request, "req": cmd_request, "download": cmd_download,
               "dl": cmd_download, "run": cmd_run}[args.command]
    try:
        return handler(args)
    except HttpStatusError as exc:
        log.error("%s", exc)
        return 1
    except (HttpClientError, OSError, ValueError) as exc:
        log.error("%s: %s", type(exc).__name__, exc)
        return 2
    except KeyboardInterrupt:
        log.warning("interrupted")
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

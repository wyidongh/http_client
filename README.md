# httpclient

基于 `requests` 的类 Postman HTTP 客户端：既可以作为 Python 库使用，也可以在命令行中使用。

## 功能

| 功能 | 说明 |
|---|---|
| 请求方法 | GET / POST / PUT / PATCH / DELETE / HEAD / OPTIONS |
| 请求参数 | query 参数、header、cookie，客户端级默认值与请求级覆盖合并 |
| 请求体 | JSON、表单（urlencoded）、原始文本或 bytes、multipart 文件上传 |
| 认证 | Basic、Digest、Bearer、API Key（header / query）、OAuth2 client_credentials、OAuth2 password、自定义登录函数 |
| Token 自动刷新 | 过期前主动刷新；收到 401 时刷新并自动重放请求；优先使用 refresh_token，失败时重新登录；线程安全 |
| 超时与重试 | (connect, read) 超时；连接错误、超时、429/5xx 指数退避重试；支持 `Retry-After`；默认只重试幂等方法 |
| 文件下载 | 流式写入、`.part` 临时文件、断点续传、中途断开自动续传、进度日志、sha256 校验 |
| 日志 | 每个请求有独立 ID，记录发出 / 响应 / 重试 / 刷新 token；DEBUG 级别打印头和 body；敏感信息自动脱敏 |
| 请求集合 | 类似 Postman Collection：变量、动态变量、响应提取、断言 |

## 安装

```bash
pip install -r requirements.txt          # 仅依赖 requests；运行测试需要 pytest
```

## 项目结构

```
httpclient/
├── client.py       HttpClient：请求、重试、401 刷新 token 后重放、下载
├── auth.py         各种认证方式 + 可自动刷新的 token 认证
├── config.py       RetryConfig 重试策略、超时类型、Retry-After 解析
├── models.py       HttpResponse（类 Postman 的 pretty 输出）、DownloadResult
├── logger.py       日志配置、脱敏、body 格式化
├── exceptions.py   异常层次
├── collection.py   请求集合执行器
├── cli.py          命令行入口（python -m httpclient）
└── version.py
examples/           库用法示例、集合文件示例
tests/              基于本地 mock server 的测试
```

## 作为库使用

```python
from httpclient import HttpClient, RetryConfig, BearerAuth, setup_logging

setup_logging("INFO", log_file="http.log")        # DEBUG 级别会打印请求/响应头和 body

with HttpClient("https://httpbin.org",
                headers={"X-App": "demo"},
                timeout=(5, 15),
                retry=RetryConfig(max_retries=3, backoff_factor=0.5)) as client:
    r = client.get("/get", params={"page": 1})
    print(r.status_code, r.json(), r.elapsed_ms, r.attempts)
    print(r.pretty())                              # 类似 Postman 的响应面板

    client.post("/post", json={"a": 1})
    client.post("/post", data={"k": "v"}, files={"file": "README.md"})
    client.put("/put", json={"a": 2}, auth=BearerAuth("token"))
    client.delete("/delete", raise_for_status=True)

    client.download("/image/png", "downloads/", expected_sha256=None)
```

### 认证

```python
from httpclient import (BasicAuth, DigestAuth, BearerAuth, ApiKeyAuth, NoAuth,
                        OAuth2ClientCredentialsAuth, OAuth2PasswordAuth, CustomTokenAuth)

BasicAuth("user", "pass")
DigestAuth("user", "pass")
BearerAuth("token")                           # 也可以用 scheme="Token" 或 header_name="X-Token"
ApiKeyAuth("X-API-Key", "key")                # header
ApiKeyAuth("api_key", "key", location="query")
NoAuth()                                      # 单个请求禁用客户端默认认证

OAuth2ClientCredentialsAuth(token_url, client_id, client_secret, scope="read")
OAuth2PasswordAuth(token_url, "user", "pass", client_id="cid")
CustomTokenAuth(login_func, refresh_func=None, leeway=60)   # 适配任意登录接口
```

**Token 自动刷新流程**（OAuth2*Auth 与 CustomTokenAuth）：

1. 首次请求时调用登录接口获取 token 并缓存；
2. 每次请求前检查 token 是否将在 `leeway`（默认 30 秒）内过期，是则先刷新；
   过期时间取自 `expires_in`，没有时尝试从 JWT 的 `exp` 中解析；
3. 若仍收到 401，则作废当前 token、刷新并**自动重放请求一次**（`refresh_token_on_401=True`）；
4. 有 `refresh_token` 时使用 `grant_type=refresh_token`，失败后回退为重新登录；
5. 并发请求共享同一个 token，刷新时加锁，只会刷新一次。

### 重试规则

- 触发条件：连接错误、超时、`status_forcelist`（默认 429/500/502/503/504）；
- 等待时间：`backoff_factor * 2^(n-1)`，上限 `backoff_max`，带随机抖动；存在 `Retry-After` 时优先使用；
- 默认只对幂等方法（GET/HEAD/PUT/DELETE/OPTIONS/TRACE）重试，避免重复提交；
  使用 `RetryConfig(allowed_methods=None)` 对所有方法重试；
- 连接超时（请求尚未发出）对任何方法都会重试；
- 上传文件时每次重试都会重新打开文件 / `seek(0)`，确保请求体完整；
- 重试耗尽后：网络错误抛 `RequestTimeoutError` / `ConnectionFailedError`，状态码错误返回最后一次响应
  （或在 `raise_for_status=True` 时抛 `HttpStatusError`）。

### 下载

```python
result = client.download(
    "https://example.com/big.zip",
    "downloads/",                  # 目录（文件名取自 Content-Disposition 或 URL）或具体文件路径
    resume=True,                   # 存在 big.zip.part 时断点续传
    overwrite=False,               # 目标已存在时抛 FileExistsError
    expected_sha256="...",         # 可选：完整性校验，失败会删除文件并抛 DownloadError
    progress=lambda done, total: ...,
)
print(result.path, result.size, result.resumed, result.sha256)
```

传输中途断开时，会按重试策略自动从已下载位置续传；服务端不支持 Range 时自动从头下载。

### 日志示例

```
15:36:50.858 | INFO    | httpclient.client | [fa8db7ef] --> GET http://127.0.0.1:44875/protected
15:36:50.902 | WARNING | httpclient.client | [fa8db7ef] <-- 401 Unauthorized | 44 ms | 26 B
15:36:50.902 | WARNING | httpclient.client | [fa8db7ef] 401 Unauthorized -> refreshing token and replaying request
15:36:50.903 | INFO    | httpclient.auth   | [OAuth2ClientCredentials(client_id=cid)] requesting token: POST .../token (grant_type=refresh_token)
15:36:50.904 | INFO    | httpclient.client | [fa8db7ef] --> GET http://127.0.0.1:44875/protected (attempt 2)
15:36:50.946 | INFO    | httpclient.client | [fa8db7ef] <-- 200 OK | 41 ms | 18 B
15:36:50.994 | WARNING | httpclient.client | [dd026dde] got 503 Service Unavailable -> retry 1/3 in 0.20s
15:36:51.619 | WARNING | httpclient.download | transfer interrupted at 512.0 KB (...) -> resume 1/3 in 0.20s
```

`Authorization`、`Cookie`、`X-API-Key` 等请求头，以及 body 和 URL 中的 `password`、`token`、
`client_secret`、`api_key` 等字段都会脱敏为 `abcd****wxyz` 的形式。

## 命令行

```bash
# 发送请求
python -m httpclient request GET https://httpbin.org/get -q page=1 -H "X-App: demo"
python -m httpclient request POST https://httpbin.org/post -j '{"name": "alice"}'
python -m httpclient request POST https://httpbin.org/post -j @body.json
python -m httpclient request POST https://httpbin.org/post -d user=alice -d age=18
python -m httpclient request POST https://httpbin.org/post -F desc=readme -F file=@README.md
python -m httpclient request PUT  https://httpbin.org/put --raw '<a/>' -H "Content-Type: application/xml"
python -m httpclient request GET  https://httpbin.org/basic-auth/u/p -a basic:u:p
python -m httpclient request GET  https://httpbin.org/bearer -a bearer:TOKEN -v       # -v 打印头和 body
python -m httpclient request GET  https://httpbin.org/status/503 -r 5 --backoff 1 -t 3,10
python -m httpclient request GET  https://httpbin.org/json --body-only | jq .

# 下载
python -m httpclient download https://httpbin.org/image/png -o downloads/ --sha256 <hash>

# 执行集合
python -m httpclient run examples/collection.json --var user=bob --env env.json
```

通用选项：`-H` 请求头、`-q` query 参数、`-a` 认证、`-t` 超时、`-r` 重试次数、`--retry-all-methods`、
`-k` 不校验证书、`--proxy`、`--cert`、`-v` DEBUG 日志、`--quiet`、`--log-file`。

退出码：`0` 成功；`1` HTTP 错误（`--fail`）或集合中有失败；`2` 网络 / 认证 / 参数等错误。

## 请求集合

见 [examples/collection.json](examples/collection.json)。

- 变量：`{{name}}`，来源依次为集合 `variables`、`--env` 文件、`--var` 参数、前面步骤的 `extract`；
- 动态变量：`{{$guid}}`、`{{$timestamp}}`、`{{$randomInt}}`、`{{$env.NAME}}`；
- 提取：`status`、`text`、`headers.X-Token`、`cookies.sid`、`json.data.items.0.id`；
- 断言 `expect`：`status`（数字或列表）、`json`（路径 → 期望值）、`body_contains`、`headers`、`max_time_ms`；
- 步骤字段：`method`、`url`、`params`、`headers`、`json`、`data`、`files`、`auth`、`timeout`、`retry`、`download`。

## 测试

```bash
python -m pytest -q
```

测试在本地启动 mock HTTP 服务，覆盖：各种请求体、各种认证、OAuth2 获取 / 主动刷新 / 401 被动刷新 /
refresh_token 失效回退登录、503 重试与 Retry-After、读超时重试、连接失败、上传文件重试、下载（文件名解析、
断点续传、中途断开续传、服务端不支持 Range、sha256 校验）、日志脱敏、集合执行与 CLI。

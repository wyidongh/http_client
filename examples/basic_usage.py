"""httpclient 用法示例（使用公共服务 httpbin.org，需要联网）。

运行：python -m examples.basic_usage   （在项目根目录下）
"""
import logging

import requests

from httpclient import (
    ApiKeyAuth,
    BasicAuth,
    BearerAuth,
    CustomTokenAuth,
    HttpClient,
    HttpClientError,
    HttpStatusError,
    OAuth2ClientCredentialsAuth,
    RetryConfig,
    setup_logging,
)

# INFO：每个请求一行发出 + 一行响应；DEBUG：额外打印请求/响应头和 body（已脱敏）
setup_logging(logging.INFO, log_file="httpclient.log")

client = HttpClient(
    "https://httpbin.org",
    headers={"X-App": "demo"},
    timeout=(5, 15),                                   # (连接超时, 读取超时)
    retry=RetryConfig(max_retries=3, backoff_factor=0.5),
)

# 1. GET + query 参数
r = client.get("/get", params={"page": 1, "size": 20})
print(r.pretty())

# 2. POST JSON / 表单 / 原始文本 / 文件上传
client.post("/post", json={"name": "alice", "tags": ["a", "b"]})
client.post("/post", data={"username": "alice", "password": "secret"})   # 日志中 password 自动脱敏
client.post("/post", data="<xml/>", headers={"Content-Type": "application/xml"})
client.post("/post", data={"desc": "readme"}, files={"file": "README.md"})

# 3. PUT / PATCH / DELETE
client.put("/put", json={"id": 1, "name": "new"})
client.patch("/patch", json={"name": "patched"})
client.delete("/delete", params={"id": 1})

# 4. 各种认证（可以设置在客户端上，也可以按请求覆盖）
client.get("/basic-auth/user/pass", auth=BasicAuth("user", "pass"))
client.get("/bearer", auth=BearerAuth("my-token"))
client.get("/headers", auth=ApiKeyAuth("X-API-Key", "k-123"))
client.get("/get", auth=ApiKeyAuth("api_key", "k-123", location="query"))

# 5. OAuth2 client_credentials：自动获取、过期前主动刷新、收到 401 时刷新并重放
oauth = OAuth2ClientCredentialsAuth(
    token_url="https://auth.example.com/oauth/token",
    client_id="my-client", client_secret="my-secret", scope="read write",
)
api = HttpClient("https://api.example.com", auth=oauth)   # 之后每个请求都会自动带上有效 token


# 6. 非标准登录接口：自定义登录函数（返回 dict / Token / 字符串均可）
def login():
    resp = requests.post("https://api.example.com/login", json={"user": "u", "pwd": "p"}, timeout=10)
    resp.raise_for_status()
    return resp.json()["data"]          # 例如 {"accessToken": "...", "expiresIn": 7200, "refreshToken": "..."}


def refresh(token):
    resp = requests.post("https://api.example.com/refresh", json={"refreshToken": token.refresh_token}, timeout=10)
    resp.raise_for_status()
    return resp.json()["data"]


custom_api = HttpClient("https://api.example.com", auth=CustomTokenAuth(login, refresh, leeway=60))

# 7. 错误处理
try:
    client.get("/status/404", raise_for_status=True)
except HttpStatusError as exc:
    print("HTTP error:", exc.status_code, exc.response.text)
except HttpClientError as exc:   # 超时 / 连接失败 / token 获取失败 等
    print("request failed:", exc)

# 8. 对 POST 也启用重试（默认只重试幂等方法）
client.post("/status/503", retry=RetryConfig(max_retries=2, allowed_methods=None))

# 9. 下载文件：流式写入、断点续传、进度日志、sha256 校验
result = client.download("/image/png", "downloads/")    # 目录：文件名取自响应头或 URL
print(result.path, result.size, result.sha256)
client.download("/bytes/102400", "downloads/random.bin", overwrite=True,
                progress=lambda done, total: None)

client.close()

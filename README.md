# PushForge

PushForge 会在运行时读取 `templates/` 目录下的规则目录，使用 Jinja2 模板渲染 `ntfy` 请求体，并将匹配到的 webhook 请求转发到 `ntfy`。

## 规则目录结构

每一种 webhook 场景都放在 `templates/` 下的一个独立子目录中：

```text
templates/
  demo-alert/
    rule.json
    title.j2
    message.j2
```

## 规则文件结构

`rule.json` 目前支持以下顶层字段：

- `name`：规则名称，便于识别
- `route`：接收 webhook 的 URL 路径，例如 `/webhook/demo/alert`
- `methods`：允许的 HTTP 方法
- `security`：可选的 webhook 安全校验配置
- `match`：可选的请求匹配条件，支持 `headers`、`query`、`json`、`form`
- `publish`：要发送给 `ntfy` 的 JSON 请求体，支持内联 Jinja 表达式和 `.j2` 模板文件
- `ntfy`：`ntfy` 服务地址、请求头、超时和 `dry_run` 配置
- `response`：返回给 webhook 调用方的自定义 JSON 响应

## 安装依赖

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## 安全校验

每条规则都可以单独定义 `security`，目前支持两种模式：

- `token`：校验请求头中的 token 是否与环境变量中的值一致
- `hmac_sha256`：基于原始请求体进行 HMAC-SHA256 签名校验

`token` 示例：

```json
{
  "security": {
    "type": "token",
    "header": "X-Webhook-Token",
    "value_env": "PUSHFORGE_DEMO_TOKEN"
  }
}
```

`hmac_sha256` 示例：

```json
{
  "security": {
    "type": "hmac_sha256",
    "header": "X-Hub-Signature-256",
    "secret_env": "GITHUB_WEBHOOK_SECRET",
    "prefix": "sha256="
  }
}
```

如果安全校验失败，服务会返回 `401`。

## 匹配规则

最简单的写法是直接做等值匹配：

```json
{
  "json": {
    "event": "alert"
  }
}
```

同时也支持带操作符的匹配对象，当前可用操作符有：

- `equals`
- `not_equals`
- `in`
- `contains`
- `exists`

示例：

```json
{
  "headers": {
    "X-Webhook-Source": { "equals": "demo" }
  },
  "json": {
    "level": { "in": ["warning", "critical"], "exists": true },
    "summary": { "contains": "failed" }
  }
}
```

## 模板上下文

模板中可以访问以下上下文数据：

- `request.method`、`request.path`、`request.headers`、`request.query`
- `request.headers_lower`：小写化后的请求头，适合做大小写不敏感访问
- `request.json`、`request.form`、`request.text`
- `meta.received_at`、`meta.remote_addr`、`meta.user_agent`
- `rule.name`、`rule.route`、`rule.file`
- `env`：当前进程环境变量

内联模板表达式会尽量保留原生类型。例如 `{{ request.json.priority or 3 }}` 渲染后仍然是整数，而不是字符串。

## 超时、重试和熔断

`ntfy` 配置可以为每条规则单独设置超时和重试策略：

```json
{
  "ntfy": {
    "server": "https://ntfy.sh",
    "timeout": 5,
    "retry": {
      "max_attempts": 3,
      "backoff_seconds": 0.5,
      "backoff_multiplier": 2,
      "max_backoff_seconds": 8,
      "retryable_status_codes": [408, 429, 500, 502, 503, 504]
    }
  }
}
```

默认会对网络错误和临时 HTTP 错误进行重试。连续发布失败达到阈值后，规则级熔断器会打开，短时间内直接返回发布失败，避免下游异常时请求堆积。

可用环境变量：

- `PUSHFORGE_NTFY_TIMEOUT`：默认 ntfy 请求超时秒数，默认 `10`
- `PUSHFORGE_NTFY_RETRY_ATTEMPTS`：默认最大尝试次数，默认 `3`
- `PUSHFORGE_NTFY_RETRY_BACKOFF_SECONDS`：默认初始退避秒数，默认 `0.5`
- `PUSHFORGE_NTFY_RETRY_BACKOFF_MULTIPLIER`：默认退避倍数，默认 `2`
- `PUSHFORGE_CIRCUIT_BREAKER_FAILURE_THRESHOLD`：熔断失败阈值，默认 `5`
- `PUSHFORGE_CIRCUIT_BREAKER_RECOVERY_TIMEOUT`：熔断恢复探测等待秒数，默认 `30`

## 日志

服务会输出 JSON 结构化日志，并在 `logs/` 下持久化：

- `logs/app.jsonl`：请求日志、匹配失败、重试尝试等运行记录
- `logs/errors.jsonl`：错误级别日志和发布失败审计记录

可用环境变量：

- `PUSHFORGE_LOG_DIR`：日志目录，默认 `logs`
- `PUSHFORGE_LOG_LEVEL`：日志级别，默认 `INFO`
- `PUSHFORGE_REQUEST_LOG`：请求日志文件名，默认 `app.jsonl`
- `PUSHFORGE_ERROR_LOG`：错误审计文件名，默认 `errors.jsonl`

## 启动方式

开发调试：

```powershell
.\.venv\Scripts\python.exe app.py
```

Windows 生产运行可使用 Waitress：

```powershell
.\.venv\Scripts\waitress-serve.exe --listen=0.0.0.0:5000 wsgi:application
```

Linux 生产运行可使用 Gunicorn：

```bash
gunicorn -c gunicorn.conf.py wsgi:application
```

也可以通过环境变量调整开发入口：

- `PUSHFORGE_HOST`：开发入口监听地址，默认 `0.0.0.0`
- `PUSHFORGE_PORT`：开发入口端口，默认 `5000`
- `PUSHFORGE_DEBUG`：是否开启 Flask debug，默认关闭

## 示例规则测试

```powershell
$env:PUSHFORGE_DEMO_TOKEN = "demo-secret"

Invoke-RestMethod `
  -Method POST `
  -Uri http://127.0.0.1:5000/webhook/demo/alert `
  -Headers @{ "X-Webhook-Source" = "demo"; "X-Webhook-Token" = "demo-secret" } `
  -ContentType "application/json" `
  -Body '{"event":"alert","source":"demo-system","title":"Build failed","summary":"main branch is red","level":"warning","topic":"pushforge-demo"}'
```

仓库里自带的示例规则默认开启了 `dry_run: true`，因此只会返回渲染结果，不会真的发送到 `ntfy`。

## 运行测试

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

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

## Docker 部署

项目提供了模块化 Compose 文件：

- `compose.yaml`：基础服务定义、端口、环境变量和命名日志卷
- `compose.override.yaml`：本地开发覆盖文件，挂载 `templates/` 和 `logs/`
- `compose.prod.yaml`：生产覆盖文件，增加重启策略、只读根文件系统和资源限制

首次运行先准备环境变量：

```powershell
Copy-Item .env.example .env
```

然后编辑 `.env`，至少把 `PUSHFORGE_DEMO_TOKEN` 改成强随机值。如果要真实推送到 ntfy，还需要按规则配置设置 `NTFY_BASE_URL`、`NTFY_TOKEN`，并把规则中的 `dry_run` 改为 `false`。

本地 Docker 运行：

```powershell
docker compose up --build
```

生产 Docker 运行：

```bash
docker compose -f compose.yaml -f compose.prod.yaml up -d --build
```

常用运维命令：

```bash
docker compose ps
docker compose logs -f app
docker compose exec app python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:5000/healthz').read().decode())"
docker compose down
```

注意：默认镜像不会复制 `tests/`，生产容器内不适合跑测试；测试请在源码环境或临时测试镜像里执行。生产部署建议在前面挂 Nginx/Caddy/Traefik 负责 HTTPS 和域名转发。

## Makefile 发布

仓库提供了 `Makefile`，用于统一测试、校验 Compose、构建镜像、推送镜像和发布 OCI Artifact。

常用命令：

```bash
make test
make compose-config
make image-build
make image-push
make image-push-multi
make artifact-pack
make artifact-push
make compose-publish
make compose-publish-with-env
make release
make release-multi
```

默认镜像地址是 `reg.mkrcc.com/library/pushforge`，默认版本号来自 `git describe --tags --always --dirty`。发布前可以覆盖变量：

```bash
make release \
  IMAGE_REGISTRY=reg.mkrcc.com \
  IMAGE_NAMESPACE=library \
  IMAGE_NAME=pushforge \
  VERSION=v1.0.0
```

镜像发布会推送：

- `$(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/$(IMAGE_NAME):$(VERSION)`
- `$(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/$(IMAGE_NAME):latest`

源码包 OCI Artifact 发布依赖 `oras`，会先生成 `dist/pushforge-$(VERSION).tar.gz`，再推送到：

```text
$(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/$(IMAGE_NAME)-artifact:$(VERSION)
```

这个 `*-artifact` 是源码/部署包，不是 Compose Project，不能用 `docker compose -f oci://... up` 启动。

可直接被 Docker Compose 启动的 OCI Artifact 由 `docker compose publish` 发布：

```text
$(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/$(IMAGE_NAME)-compose:$(VERSION)
```

默认 `compose-publish` 只会把镜像地址固定进 Compose Artifact，不会把本地 `.env` 里的 token、secret 一起发布。服务器启动时用服务器自己的环境变量覆盖：

```bash
mkdir -p ./templates
PUSHFORGE_DEMO_TOKEN=your-token \
NTFY_BASE_URL=https://ntfy.sh \
PUSHFORGE_TEMPLATES_DIR=./templates \
docker compose -f oci://reg.mkrcc.com/pushforge/pushforge-compose:v1.0.0 up -d
```

OCI Compose 默认把服务器当前目录的 `./templates` 挂载到容器 `/app/templates`，用于维护 webhook 规则。如果不设置 `PUSHFORGE_TEMPLATES_DIR`，请确保启动命令所在目录已经有 `templates/`。

如果你确认 `.env` 里没有敏感信息，或者你就是要发布一份绑定环境的 Compose Artifact，可以显式执行：

```bash
make compose-publish-with-env IMAGE_NAMESPACE=pushforge VERSION=v1.0.0
```

发布后服务器可以这样启动：

```bash
docker compose -f oci://reg.mkrcc.com/library/pushforge-compose:v1.0.0 up -d
```

如果你的仓库项目名不是 `library`，把路径里的 `library` 换成实际项目名。

如果 Compose Artifact 中的镜像地址需要临时覆盖，可以在服务器端指定 `PUSHFORGE_IMAGE`：

```bash
PUSHFORGE_IMAGE=reg.mkrcc.com/pushforge/pushforge:v1.0.0 \
PUSHFORGE_TEMPLATES_DIR=./templates \
  docker compose -f oci://reg.mkrcc.com/pushforge/pushforge-compose:v1.0.0 up -d
```

发布前需要先登录目标仓库，例如：

```bash
docker login reg.mkrcc.com
oras login reg.mkrcc.com
```

默认 `make release` 只构建并推送当前 Docker 环境对应的架构，适合普通 Docker Desktop 或默认 `docker` buildx driver。多架构发布需要先创建 `docker-container` builder：

```bash
make builder-create
make release-multi VERSION=v1.0.0
```

如果你看到 `Multi-platform build is not supported for the docker driver`，说明当前 builder 不支持多架构，请使用上面的 `builder-create` 后再运行 `release-multi`。

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

# PushForge

PushForge reads rule files from the runtime `templates/` directory, renders ntfy payloads with Jinja2 templates, and forwards matched webhook requests to ntfy.

## Rule layout

Each webhook scenario lives in its own subdirectory under `templates/`:

```text
templates/
  demo-alert/
    rule.json
    title.j2
    message.j2
```

## Rule schema

`rule.json` supports these top-level keys:

- `name`: human-readable rule name
- `route`: webhook URL path, for example `/webhook/demo/alert`
- `methods`: allowed HTTP methods
- `match`: optional checks for `headers`, `query`, `json`, or `form`
- `publish`: ntfy JSON payload fields, supports inline Jinja or `.j2` files
- `ntfy`: ntfy server, headers, timeout, and `dry_run`
- `response`: custom JSON response body and status code

## Template context

Templates can access:

- `request.method`, `request.path`, `request.headers`, `request.query`
- `request.json`, `request.form`, `request.text`
- `meta.received_at`, `meta.remote_addr`, `meta.user_agent`
- `rule.name`, `rule.route`, `rule.file`
- `env`, which exposes current process environment variables

## Run

```powershell
.\.venv\Scripts\python.exe app.py
```

## Test the demo rule

```powershell
Invoke-RestMethod `
  -Method POST `
  -Uri http://127.0.0.1:5000/webhook/demo/alert `
  -Headers @{ "X-Webhook-Source" = "demo" } `
  -ContentType "application/json" `
  -Body '{"event":"alert","source":"demo-system","title":"Build failed","summary":"main branch is red","level":"warning","topic":"pushforge-demo"}'
```

The bundled demo rule runs with `dry_run: true`, so it returns the rendered ntfy request without sending it.

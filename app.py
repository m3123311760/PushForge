from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request as urllib_request

from flask import Flask, jsonify, request
from jinja2 import Environment


RULES_DIR = Path.cwd() / "templates"
SUPPORTED_RULE_FILE = "rule.json"
COMMON_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


def create_app() -> Flask:
    app = Flask(__name__)
    registry = RuleRegistry(RULES_DIR)

    @app.before_request
    def refresh_rules() -> None:
        registry.reload_if_needed()

    @app.get("/")
    def index() -> Any:
        registry.reload_if_needed()
        return jsonify(
            {
                "service": "PushForge",
                "rules_dir": str(registry.root),
                "loaded_rules": [rule.summary() for rule in registry.all_rules()],
                "errors": registry.errors,
            }
        )

    @app.get("/healthz")
    def healthz() -> Any:
        registry.reload_if_needed()
        return jsonify(
            {
                "status": "ok",
                "rules": len(registry.rules),
                "errors": registry.errors,
                "reloaded_at": registry.last_loaded_at,
            }
        )

    @app.route("/__rules", methods=["GET"])
    def list_rules() -> Any:
        registry.reload_if_needed()
        return jsonify(
            {
                "rules": [rule.summary() for rule in registry.all_rules()],
                "errors": registry.errors,
            }
        )

    @app.route("/<path:requested_path>", methods=COMMON_METHODS)
    def dispatch(requested_path: str) -> Any:
        route_path = f"/{requested_path}"
        return handle_rule_request(registry, route_path)

    registry.reload_if_needed(force=True)
    register_static_rule_routes(app, registry)
    app.logger.setLevel(logging.INFO)
    return app


@dataclass
class RuleDefinition:
    name: str
    route: str
    methods: list[str]
    file_path: Path
    config: dict[str, Any] = field(repr=False)

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "route": self.route,
            "methods": self.methods,
            "file": str(self.file_path),
        }


class RuleRegistry:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.rules: dict[str, RuleDefinition] = {}
        self.errors: list[dict[str, str]] = []
        self._fingerprint: tuple[tuple[str, int], ...] = ()
        self.last_loaded_at: str | None = None

    def all_rules(self) -> list[RuleDefinition]:
        return sorted(self.rules.values(), key=lambda item: item.route)

    def resolve(self, route: str) -> RuleDefinition | None:
        self.reload_if_needed()
        return self.rules.get(route)

    def reload_if_needed(self, force: bool = False) -> None:
        fingerprint = self._build_fingerprint()
        if force or fingerprint != self._fingerprint:
            self._load_rules(fingerprint)

    def _build_fingerprint(self) -> tuple[tuple[str, int], ...]:
        if not self.root.exists():
            return ()
        files = sorted(self.root.rglob(SUPPORTED_RULE_FILE))
        return tuple((str(file), file.stat().st_mtime_ns) for file in files)

    def _load_rules(self, fingerprint: tuple[tuple[str, int], ...]) -> None:
        loaded_rules: dict[str, RuleDefinition] = {}
        errors: list[dict[str, str]] = []

        for file_path_str, _ in fingerprint:
            file_path = Path(file_path_str)
            try:
                raw_config = json.loads(file_path.read_text(encoding="utf-8"))
                rule = self._parse_rule(file_path, raw_config)
            except Exception as exc:  # noqa: BLE001
                errors.append({"file": file_path_str, "error": str(exc)})
                continue

            if rule.route in loaded_rules:
                errors.append(
                    {
                        "file": file_path_str,
                        "error": f"duplicate route '{rule.route}'",
                    }
                )
                continue

            loaded_rules[rule.route] = rule

        self.rules = loaded_rules
        self.errors = errors
        self._fingerprint = fingerprint
        self.last_loaded_at = datetime.now(timezone.utc).isoformat()

    def _parse_rule(self, file_path: Path, config: dict[str, Any]) -> RuleDefinition:
        if not isinstance(config, dict):
            raise ValueError("rule.json must contain a JSON object")

        route = config.get("route")
        if not isinstance(route, str) or not route.startswith("/"):
            raise ValueError("route must be a string starting with '/'")

        methods = config.get("methods", ["POST"])
        if not isinstance(methods, list) or not methods:
            raise ValueError("methods must be a non-empty list")

        normalized_methods = [str(method).upper() for method in methods]
        name = str(config.get("name") or file_path.parent.name)

        if "publish" not in config:
            raise ValueError("publish section is required")
        if "ntfy" not in config:
            raise ValueError("ntfy section is required")

        return RuleDefinition(
            name=name,
            route=route,
            methods=normalized_methods,
            file_path=file_path,
            config=config,
        )


def register_static_rule_routes(app: Flask, registry: RuleRegistry) -> None:
    for rule in registry.all_rules():
        endpoint = f"rule__{sanitize_endpoint_name(rule.route)}"
        if endpoint in app.view_functions:
            continue

        app.add_url_rule(
            rule.route,
            endpoint=endpoint,
            view_func=build_route_handler(registry, rule.route),
            methods=rule.methods,
        )


def build_route_handler(registry: RuleRegistry, route_path: str):
    def handler() -> Any:
        return handle_rule_request(registry, route_path)

    return handler


def sanitize_endpoint_name(route: str) -> str:
    return route.strip("/").replace("/", "_").replace("-", "_") or "root"


def handle_rule_request(registry: RuleRegistry, route_path: str) -> Any:
    rule = registry.resolve(route_path)
    if not rule:
        return jsonify({"error": "route_not_found", "route": route_path}), 404

    if request.method.upper() not in rule.methods:
        return (
            jsonify(
                {
                    "error": "method_not_allowed",
                    "route": route_path,
                    "allowed_methods": rule.methods,
                }
            ),
            405,
        )

    context = build_context(rule)
    match_spec = rule.config.get("match", {})
    matched, reason = evaluate_match(match_spec, context)
    if not matched:
        return (
            jsonify(
                {
                    "error": "match_failed",
                    "rule": rule.name,
                    "reason": reason,
                }
            ),
            400,
        )

    try:
        publish_payload = render_config(rule.config["publish"], rule.file_path.parent, context)
        ntfy_config = render_config(rule.config["ntfy"], rule.file_path.parent, context)
    except Exception as exc:  # noqa: BLE001
        return (
            jsonify({"error": "template_render_failed", "rule": rule.name, "detail": str(exc)}),
            500,
        )

    topic = publish_payload.get("topic")
    if not topic:
        return (
            jsonify({"error": "invalid_publish_payload", "detail": "topic is required"}),
            500,
        )

    if ntfy_config.get("dry_run", False):
        ntfy_result = {
            "mode": "dry_run",
            "request_url": normalize_server_url(ntfy_config.get("server")),
            "payload": publish_payload,
            "headers": ntfy_config.get("headers", {}),
        }
        status_code = 200
    else:
        try:
            ntfy_result = publish_to_ntfy(ntfy_config, publish_payload)
            status_code = 200
        except NtfyPublishError as exc:
            return (
                jsonify(
                    {
                        "error": "ntfy_publish_failed",
                        "rule": rule.name,
                        "detail": exc.detail,
                        "status_code": exc.status_code,
                    }
                ),
                502,
            )

    response_context = {**context, "ntfy_result": ntfy_result, "publish_payload": publish_payload}
    try:
        response_config = render_config(rule.config.get("response", {}), rule.file_path.parent, response_context)
    except Exception as exc:  # noqa: BLE001
        return (
            jsonify({"error": "response_render_failed", "rule": rule.name, "detail": str(exc)}),
            500,
        )

    body = response_config.get("body") or {
        "status": "ok",
        "rule": rule.name,
        "route": rule.route,
        "ntfy": ntfy_result,
    }
    return jsonify(body), int(response_config.get("status_code", status_code))


def build_context(rule: RuleDefinition) -> dict[str, Any]:
    raw_body = request.get_data(cache=True)
    json_body = request.get_json(silent=True)
    text_body = raw_body.decode("utf-8", errors="replace")
    query_args = {key: request.args.getlist(key) for key in request.args.keys()}
    form_data = {key: request.form.getlist(key) for key in request.form.keys()}
    headers = dict(request.headers.items())

    return {
        "rule": {"name": rule.name, "route": rule.route, "file": str(rule.file_path)},
        "request": {
            "method": request.method,
            "path": request.path,
            "headers": headers,
            "query": query_args,
            "json": json_body,
            "form": form_data,
            "text": text_body,
            "raw": raw_body.decode("utf-8", errors="replace"),
            "content_type": request.content_type,
        },
        "meta": {
            "received_at": datetime.now(timezone.utc).isoformat(),
            "remote_addr": request.remote_addr,
            "user_agent": request.headers.get("User-Agent"),
        },
        "env": dict(os.environ),
    }


def evaluate_match(match_spec: dict[str, Any], context: dict[str, Any]) -> tuple[bool, str | None]:
    if not match_spec:
        return True, None
    if not isinstance(match_spec, dict):
        return False, "match must be a JSON object"

    sections = {
        "headers": context["request"]["headers"],
        "query": context["request"]["query"],
        "json": context["request"]["json"] or {},
        "form": context["request"]["form"],
    }

    for section_name, expected_values in match_spec.items():
        actual_root = sections.get(section_name)
        if actual_root is None:
            return False, f"unsupported match section '{section_name}'"
        if not isinstance(expected_values, dict):
            return False, f"match section '{section_name}' must be a JSON object"

        for dotted_key, expected_value in expected_values.items():
            actual_value = get_nested_value(actual_root, dotted_key)
            if not is_expected_value(actual_value, expected_value):
                return False, f"{section_name}.{dotted_key} expected {expected_value!r}, got {actual_value!r}"

    return True, None


def get_nested_value(data: Any, dotted_key: str) -> Any:
    if dotted_key in ("", "."):
        return data

    current = data
    for part in dotted_key.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def is_expected_value(actual_value: Any, expected_value: Any) -> bool:
    if isinstance(expected_value, list):
        if isinstance(actual_value, list):
            return any(str(item) in {str(value) for value in expected_value} for item in actual_value)
        return str(actual_value) in {str(value) for value in expected_value}
    if isinstance(actual_value, list):
        return str(expected_value) in {str(item) for item in actual_value}
    return str(actual_value) == str(expected_value)


def render_config(value: Any, base_dir: Path, context: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {key: render_config(item, base_dir, context) for key, item in value.items()}
    if isinstance(value, list):
        return [render_config(item, base_dir, context) for item in value]
    if isinstance(value, str):
        template_path = base_dir / value
        if value.endswith(".j2") and template_path.exists():
            template_source = template_path.read_text(encoding="utf-8")
            return render_template_string(template_source, context)
        if "{{" in value or "{%" in value:
            return render_template_string(value, context)
        return value
    return value


def render_template_string(template_source: str, context: dict[str, Any]) -> str:
    environment = Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)
    return environment.from_string(template_source).render(**context).strip()


class NtfyPublishError(Exception):
    def __init__(self, detail: str, status_code: int | None = None) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


def publish_to_ntfy(ntfy_config: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    server_url = normalize_server_url(ntfy_config.get("server"))
    headers = {"Content-Type": "application/json"}
    for key, value in ntfy_config.get("headers", {}).items():
        if value is not None and value != "":
            headers[str(key)] = str(value)

    body = json.dumps(payload).encode("utf-8")
    outbound = urllib_request.Request(server_url, data=body, headers=headers, method="POST")

    try:
        with urllib_request.urlopen(outbound, timeout=float(ntfy_config.get("timeout", 10))) as response:
            response_body = response.read().decode("utf-8", errors="replace")
            return {
                "status_code": response.status,
                "headers": dict(response.headers.items()),
                "body": try_parse_json(response_body),
            }
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise NtfyPublishError(detail or str(exc), exc.code) from exc
    except error.URLError as exc:
        raise NtfyPublishError(str(exc.reason), None) from exc


def normalize_server_url(server: Any) -> str:
    candidate = str(server or "https://ntfy.sh").rstrip("/")
    return f"{candidate}/"


def try_parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Lock
from typing import Any
from urllib import error, request as urllib_request

from flask import Flask, g, jsonify, request
from jinja2 import Environment
from jinja2.nativetypes import NativeEnvironment
from werkzeug.exceptions import HTTPException


RULES_DIR = Path.cwd() / "templates"
SUPPORTED_RULE_FILE = "rule.json"
COMMON_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
NTFY_STRING_FIELDS = {"topic", "message", "title", "click", "attach", "filename", "email", "call", "icon"}
DEFAULT_RETRYABLE_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}
RESERVED_LOG_RECORD_FIELDS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
}


@dataclass(slots=True)
class AppConfig:
    rules_dir: Path = field(default_factory=lambda: RULES_DIR)
    log_dir: Path = field(default_factory=lambda: Path(os.environ.get("PUSHFORGE_LOG_DIR", Path.cwd() / "logs")))
    log_level: str = os.environ.get("PUSHFORGE_LOG_LEVEL", "INFO").upper()
    request_log_name: str = os.environ.get("PUSHFORGE_REQUEST_LOG", "app.jsonl")
    error_log_name: str = os.environ.get("PUSHFORGE_ERROR_LOG", "errors.jsonl")
    ntfy_timeout: float = float(os.environ.get("PUSHFORGE_NTFY_TIMEOUT", "10"))
    ntfy_retry_attempts: int = int(os.environ.get("PUSHFORGE_NTFY_RETRY_ATTEMPTS", "3"))
    ntfy_retry_backoff_seconds: float = float(os.environ.get("PUSHFORGE_NTFY_RETRY_BACKOFF_SECONDS", "0.5"))
    ntfy_retry_backoff_multiplier: float = float(os.environ.get("PUSHFORGE_NTFY_RETRY_BACKOFF_MULTIPLIER", "2"))
    ntfy_retry_max_backoff_seconds: float = float(os.environ.get("PUSHFORGE_NTFY_RETRY_MAX_BACKOFF_SECONDS", "8"))
    circuit_breaker_failure_threshold: int = int(os.environ.get("PUSHFORGE_CIRCUIT_BREAKER_FAILURE_THRESHOLD", "5"))
    circuit_breaker_recovery_timeout: float = float(os.environ.get("PUSHFORGE_CIRCUIT_BREAKER_RECOVERY_TIMEOUT", "30"))
    host: str = os.environ.get("PUSHFORGE_HOST", "0.0.0.0")
    port: int = int(os.environ.get("PUSHFORGE_PORT", "5000"))
    debug: bool = os.environ.get("PUSHFORGE_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class RetryPolicy:
    max_attempts: int = 3
    backoff_seconds: float = 0.5
    backoff_multiplier: float = 2.0
    max_backoff_seconds: float = 8.0
    retryable_status_codes: set[int] = field(default_factory=lambda: set(DEFAULT_RETRYABLE_STATUS_CODES))

    @classmethod
    def from_config(cls, ntfy_config: dict[str, Any], app_config: AppConfig) -> "RetryPolicy":
        retry_config = ntfy_config.get("retry", {})
        if retry_config is False:
            return cls(max_attempts=1, backoff_seconds=0, backoff_multiplier=1, max_backoff_seconds=0)
        if retry_config is None:
            retry_config = {}
        if not isinstance(retry_config, dict):
            raise ValueError("ntfy.retry must be a JSON object")

        status_codes = retry_config.get("retryable_status_codes", list(DEFAULT_RETRYABLE_STATUS_CODES))
        if not isinstance(status_codes, list):
            raise ValueError("ntfy.retry.retryable_status_codes must be a list")

        return cls(
            max_attempts=max(1, int(retry_config.get("max_attempts", app_config.ntfy_retry_attempts))),
            backoff_seconds=max(0.0, float(retry_config.get("backoff_seconds", app_config.ntfy_retry_backoff_seconds))),
            backoff_multiplier=max(1.0, float(retry_config.get("backoff_multiplier", app_config.ntfy_retry_backoff_multiplier))),
            max_backoff_seconds=max(
                0.0,
                float(retry_config.get("max_backoff_seconds", app_config.ntfy_retry_max_backoff_seconds)),
            ),
            retryable_status_codes={int(item) for item in status_codes},
        )


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        for key, value in record.__dict__.items():
            if key in RESERVED_LOG_RECORD_FIELDS or key.startswith("_"):
                continue
            payload[key] = value

        return json.dumps(payload, ensure_ascii=False)


class ErrorAuditHandler(RotatingFileHandler):
    def __init__(self, filename: Path, max_bytes: int = 5 * 1024 * 1024, backup_count: int = 5) -> None:
        filename.parent.mkdir(parents=True, exist_ok=True)
        super().__init__(filename, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8")
        self.setLevel(logging.ERROR)
        self.setFormatter(JsonFormatter())


@dataclass(slots=True)
class CircuitBreakerState:
    name: str
    failure_threshold: int
    recovery_timeout: float
    failure_count: int = 0
    state: str = "closed"
    opened_at: float | None = None


class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int, recovery_timeout: float) -> None:
        self._state = CircuitBreakerState(
            name=name,
            failure_threshold=max(1, int(failure_threshold)),
            recovery_timeout=max(0.0, float(recovery_timeout)),
        )
        self._lock = Lock()

    def allow_request(self) -> bool:
        with self._lock:
            if self._state.state == "closed":
                return True
            if self._state.state == "half_open":
                return False
            if self._state.opened_at is None:
                return False
            if time.monotonic() - self._state.opened_at >= self._state.recovery_timeout:
                self._state.state = "half_open"
                return True
            return False

    def on_success(self) -> None:
        with self._lock:
            self._state.failure_count = 0
            self._state.state = "closed"
            self._state.opened_at = None

    def on_failure(self) -> None:
        with self._lock:
            if self._state.state == "half_open":
                self._state.failure_count = self._state.failure_threshold
                self._state.state = "open"
                self._state.opened_at = time.monotonic()
                return
            self._state.failure_count += 1
            if self._state.failure_count >= self._state.failure_threshold:
                self._state.state = "open"
                self._state.opened_at = time.monotonic()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "name": self._state.name,
                "state": self._state.state,
                "failure_count": self._state.failure_count,
                "failure_threshold": self._state.failure_threshold,
                "recovery_timeout": self._state.recovery_timeout,
            }


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
    def __init__(self, root: Path, app_config: AppConfig) -> None:
        self.root = root
        self.app_config = app_config
        self.rules: dict[str, RuleDefinition] = {}
        self.errors: list[dict[str, str]] = []
        self._fingerprint: tuple[tuple[str, int], ...] = ()
        self.last_loaded_at: str | None = None
        self._circuit_breakers: dict[str, CircuitBreaker] = {}
        self._circuit_breakers_lock = Lock()

    def all_rules(self) -> list[RuleDefinition]:
        return sorted(self.rules.values(), key=lambda item: item.route)

    def resolve(self, route: str) -> RuleDefinition | None:
        self.reload_if_needed()
        return self.rules.get(route)

    def get_circuit_breaker(self, route: str) -> CircuitBreaker:
        with self._circuit_breakers_lock:
            breaker = self._circuit_breakers.get(route)
            if breaker is None:
                breaker = CircuitBreaker(
                    route,
                    failure_threshold=self.app_config.circuit_breaker_failure_threshold,
                    recovery_timeout=self.app_config.circuit_breaker_recovery_timeout,
                )
                self._circuit_breakers[route] = breaker
            return breaker

    def breaker_states(self) -> list[dict[str, Any]]:
        return [self.get_circuit_breaker(rule.route).snapshot() for rule in self.all_rules()]

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
                errors.append({"file": file_path_str, "error": f"duplicate route '{rule.route}'"})
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
        validate_security_config(config.get("security"))
        validate_match_config(config.get("match", {}))

        retry_config = config.get("ntfy", {}).get("retry")
        if retry_config not in (None, False) and not isinstance(retry_config, dict):
            raise ValueError("ntfy.retry must be a JSON object")

        return RuleDefinition(
            name=name,
            route=route,
            methods=normalized_methods,
            file_path=file_path,
            config=config,
        )


def create_app(config: AppConfig | None = None) -> Flask:
    app_config = config or AppConfig()
    app = Flask(__name__)
    registry = RuleRegistry(app_config.rules_dir, app_config)

    configure_logging(app, app_config)

    @app.before_request
    def attach_request_context() -> None:
        registry.reload_if_needed()
        g.request_started_at = time.monotonic()
        g.request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())

    @app.after_request
    def log_request(response):  # type: ignore[no-untyped-def]
        duration_ms = round((time.monotonic() - getattr(g, "request_started_at", time.monotonic())) * 1000, 2)
        app.logger.info(
            "request completed",
            extra={
                "event": "request_completed",
                "request_id": getattr(g, "request_id", None),
                "method": request.method,
                "path": request.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "remote_addr": request.remote_addr,
            },
        )
        response.headers["X-Request-Id"] = getattr(g, "request_id", "")
        return response

    @app.errorhandler(Exception)
    def handle_unexpected_error(exc: Exception) -> Any:
        if isinstance(exc, HTTPException):
            return exc
        app.logger.exception(
            "unhandled application error",
            extra={
                "event": "unhandled_exception",
                "request_id": getattr(g, "request_id", None),
                "path": request.path if request else None,
                "method": request.method if request else None,
            },
        )
        return jsonify({"error": "internal_server_error", "request_id": getattr(g, "request_id", None)}), 500

    @app.get("/")
    def index() -> Any:
        return jsonify(
            {
                "service": "PushForge",
                "rules_dir": str(registry.root),
                "loaded_rules": [rule.summary() for rule in registry.all_rules()],
                "errors": registry.errors,
                "breakers": registry.breaker_states(),
            }
        )

    @app.get("/healthz")
    def healthz() -> Any:
        return jsonify(
            {
                "status": "ok",
                "rules": len(registry.rules),
                "errors": registry.errors,
                "reloaded_at": registry.last_loaded_at,
                "breakers": registry.breaker_states(),
            }
        )

    @app.route("/__rules", methods=["GET"])
    def list_rules() -> Any:
        return jsonify({"rules": [rule.summary() for rule in registry.all_rules()], "errors": registry.errors})

    @app.route("/__reload", methods=["POST"])
    def reload_rules() -> Any:
        registry.reload_if_needed(force=True)
        return jsonify(
            {
                "status": "reloaded",
                "rules": [rule.summary() for rule in registry.all_rules()],
                "errors": registry.errors,
            }
        )

    @app.route("/<path:requested_path>", methods=COMMON_METHODS)
    def dispatch(requested_path: str) -> Any:
        route_path = f"/{requested_path}"
        return handle_rule_request(app, registry, route_path)

    registry.reload_if_needed(force=True)
    register_static_rule_routes(app, registry)
    app.config["APP_CONFIG"] = app_config
    app.config["RULE_REGISTRY"] = registry
    return app


def configure_logging(app: Flask, app_config: AppConfig) -> None:
    app_config.log_dir.mkdir(parents=True, exist_ok=True)
    for handler in list(app.logger.handlers):
        handler.close()
        app.logger.removeHandler(handler)
    app.logger.propagate = False
    app.logger.setLevel(getattr(logging, app_config.log_level, logging.INFO))

    formatter = JsonFormatter()

    request_handler = RotatingFileHandler(
        app_config.log_dir / app_config.request_log_name,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    request_handler.setFormatter(formatter)
    request_handler.setLevel(getattr(logging, app_config.log_level, logging.INFO))

    error_handler = ErrorAuditHandler(app_config.log_dir / app_config.error_log_name)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(getattr(logging, app_config.log_level, logging.INFO))

    app.logger.addHandler(stream_handler)
    app.logger.addHandler(request_handler)
    app.logger.addHandler(error_handler)


def validate_security_config(security_spec: Any) -> None:
    if security_spec in (None, {}):
        return
    if not isinstance(security_spec, dict):
        raise ValueError("security must be a JSON object")

    security_type = str(security_spec.get("type", "")).strip().lower()
    if not security_type:
        raise ValueError("security.type is required")
    if security_type == "token":
        require_security_fields(security_spec, ["header", "value_env"], security_type)
        return
    if security_type == "hmac_sha256":
        require_security_fields(security_spec, ["header", "secret_env"], security_type)
        return
    raise ValueError(f"unsupported security type '{security_type}'")


def require_security_fields(security_spec: dict[str, Any], fields: list[str], security_type: str) -> None:
    for field_name in fields:
        if not str(security_spec.get(field_name, "")).strip():
            raise ValueError(f"{security_type} security requires '{field_name}'")


def validate_match_config(match_spec: Any) -> None:
    if match_spec in (None, {}):
        return
    if not isinstance(match_spec, dict):
        raise ValueError("match must be a JSON object")

    supported_sections = {"headers", "query", "json", "form"}
    supported_operators = {"equals", "in", "contains", "exists", "not_equals"}
    for section_name, expected_values in match_spec.items():
        if section_name not in supported_sections:
            raise ValueError(f"unsupported match section '{section_name}'")
        if not isinstance(expected_values, dict):
            raise ValueError(f"match section '{section_name}' must be a JSON object")

        for dotted_key, expected_value in expected_values.items():
            if not isinstance(dotted_key, str) or not dotted_key:
                raise ValueError(f"match section '{section_name}' contains an invalid key")
            if not isinstance(expected_value, dict):
                continue

            unknown = set(expected_value) - supported_operators
            if unknown:
                raise ValueError(f"unsupported match operators: {sorted(unknown)}")
            if "in" in expected_value and not isinstance(expected_value["in"], list):
                raise ValueError("'in' operator requires a list")


def register_static_rule_routes(app: Flask, registry: RuleRegistry) -> None:
    for rule in registry.all_rules():
        endpoint = f"rule__{sanitize_endpoint_name(rule.route)}"
        if endpoint in app.view_functions:
            continue

        app.add_url_rule(
            rule.route,
            endpoint=endpoint,
            view_func=build_route_handler(app, registry, rule.route),
            methods=rule.methods,
        )


def build_route_handler(app: Flask, registry: RuleRegistry, route_path: str):
    def handler() -> Any:
        return handle_rule_request(app, registry, route_path)

    return handler


def sanitize_endpoint_name(route: str) -> str:
    return route.strip("/").replace("/", "_").replace("-", "_") or "root"


def handle_rule_request(app: Flask, registry: RuleRegistry, route_path: str) -> Any:
    rule = registry.resolve(route_path)
    if not rule:
        return jsonify({"error": "route_not_found", "route": route_path}), 404

    if request.method.upper() not in rule.methods:
        return (
            jsonify({"error": "method_not_allowed", "route": route_path, "allowed_methods": rule.methods}),
            405,
        )

    context = build_context(rule)
    security_error = validate_security(rule.config.get("security"), context)
    if security_error:
        app.logger.warning(
            "security validation failed",
            extra={
                "event": "security_validation_failed",
                "request_id": getattr(g, "request_id", None),
                "route": route_path,
                "rule": rule.name,
                "detail": security_error,
            },
        )
        return jsonify({"error": "security_validation_failed", "rule": rule.name, "detail": security_error}), 401

    match_spec = rule.config.get("match", {})
    matched, reason = evaluate_match(match_spec, context)
    if not matched:
        app.logger.info(
            "request did not match rule",
            extra={
                "event": "match_failed",
                "request_id": getattr(g, "request_id", None),
                "route": route_path,
                "rule": rule.name,
                "detail": reason,
            },
        )
        return jsonify({"error": "match_failed", "rule": rule.name, "reason": reason}), 400

    try:
        publish_payload = normalize_publish_payload(render_config(rule.config["publish"], rule.file_path.parent, context))
        ntfy_config = render_config(rule.config["ntfy"], rule.file_path.parent, context)
    except Exception as exc:  # noqa: BLE001
        app.logger.exception(
            "template rendering failed",
            extra={
                "event": "template_render_failed",
                "request_id": getattr(g, "request_id", None),
                "route": route_path,
                "rule": rule.name,
            },
        )
        return jsonify({"error": "template_render_failed", "rule": rule.name, "detail": str(exc)}), 500

    topic = publish_payload.get("topic")
    if not topic:
        return jsonify({"error": "invalid_publish_payload", "detail": "topic is required"}), 500

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
            ntfy_result = publish_to_ntfy(
                ntfy_config,
                publish_payload,
                circuit_breaker=registry.get_circuit_breaker(rule.route),
                logger=app.logger,
                context={
                    "request_id": getattr(g, "request_id", None),
                    "route": route_path,
                    "rule": rule.name,
                    "app_config": app.config["APP_CONFIG"],
                },
            )
            status_code = 200
        except NtfyPublishError as exc:
            app.logger.error(
                "ntfy publish failed",
                extra={
                    "event": "ntfy_publish_failed",
                    "request_id": getattr(g, "request_id", None),
                    "route": route_path,
                    "rule": rule.name,
                    "status_code": exc.status_code,
                    "detail": exc.detail,
                },
            )
            return (
                jsonify(
                    {
                        "error": "ntfy_publish_failed",
                        "rule": rule.name,
                        "detail": exc.detail,
                        "status_code": exc.status_code,
                        "request_id": getattr(g, "request_id", None),
                    }
                ),
                502,
            )

    response_context = {**context, "ntfy_result": ntfy_result, "publish_payload": publish_payload}
    try:
        response_config = render_config(rule.config.get("response", {}), rule.file_path.parent, response_context)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": "response_render_failed", "rule": rule.name, "detail": str(exc)}), 500

    body = response_config.get("body") or {
        "status": "ok",
        "rule": rule.name,
        "route": rule.route,
        "ntfy": ntfy_result,
        "request_id": getattr(g, "request_id", None),
    }
    return jsonify(body), int(response_config.get("status_code", status_code))


def build_context(rule: RuleDefinition) -> dict[str, Any]:
    raw_body = request.get_data(cache=True)
    json_body = request.get_json(silent=True)
    text_body = raw_body.decode("utf-8", errors="replace")
    query_args = {key: request.args.getlist(key) for key in request.args.keys()}
    form_data = {key: request.form.getlist(key) for key in request.form.keys()}
    headers = dict(request.headers.items())
    normalized_headers = {key.lower(): value for key, value in headers.items()}

    return {
        "rule": {"name": rule.name, "route": rule.route, "file": str(rule.file_path)},
        "request": {
            "method": request.method,
            "path": request.path,
            "headers": headers,
            "headers_lower": normalized_headers,
            "query": query_args,
            "json": json_body,
            "form": form_data,
            "text": text_body,
            "raw_bytes": raw_body,
            "raw": text_body,
            "content_type": request.content_type,
        },
        "meta": {
            "received_at": datetime.now(timezone.utc).isoformat(),
            "remote_addr": request.remote_addr,
            "user_agent": request.headers.get("User-Agent"),
            "request_id": getattr(g, "request_id", None),
        },
        "env": dict(os.environ),
    }


def validate_security(security_spec: Any, context: dict[str, Any]) -> str | None:
    if not security_spec:
        return None
    if not isinstance(security_spec, dict):
        return "security must be a JSON object"

    security_type = str(security_spec.get("type", "")).strip().lower()
    if not security_type:
        return "security.type is required"
    if security_type == "token":
        return validate_token_security(security_spec, context)
    if security_type == "hmac_sha256":
        return validate_hmac_sha256_security(security_spec, context)
    return f"unsupported security type '{security_type}'"


def validate_token_security(security_spec: dict[str, Any], context: dict[str, Any]) -> str | None:
    header_name = str(security_spec.get("header", "")).strip()
    env_name = str(security_spec.get("value_env", "")).strip()
    if not header_name:
        return "token security requires 'header'"
    if not env_name:
        return "token security requires 'value_env'"

    expected_token = context["env"].get(env_name)
    if not expected_token:
        return f"environment variable '{env_name}' is not set"

    actual_token = context["request"]["headers"].get(header_name)
    if actual_token is None:
        actual_token = context["request"]["headers_lower"].get(header_name.lower())
    if actual_token is None:
        return f"missing header '{header_name}'"
    if not hmac.compare_digest(str(actual_token), str(expected_token)):
        return f"invalid token in header '{header_name}'"
    return None


def validate_hmac_sha256_security(security_spec: dict[str, Any], context: dict[str, Any]) -> str | None:
    header_name = str(security_spec.get("header", "")).strip()
    env_name = str(security_spec.get("secret_env", "")).strip()
    prefix = str(security_spec.get("prefix", "sha256="))
    if not header_name:
        return "hmac_sha256 security requires 'header'"
    if not env_name:
        return "hmac_sha256 security requires 'secret_env'"

    secret = context["env"].get(env_name)
    if not secret:
        return f"environment variable '{env_name}' is not set"

    actual_signature = context["request"]["headers"].get(header_name)
    if actual_signature is None:
        actual_signature = context["request"]["headers_lower"].get(header_name.lower())
    if actual_signature is None:
        return f"missing header '{header_name}'"

    body = context["request"]["raw_bytes"]
    expected_hash = hmac.new(str(secret).encode("utf-8"), body, hashlib.sha256).hexdigest()
    expected_signature = f"{prefix}{expected_hash}"
    if not hmac.compare_digest(str(actual_signature), expected_signature):
        return f"invalid hmac signature in header '{header_name}'"
    return None


def evaluate_match(match_spec: dict[str, Any], context: dict[str, Any]) -> tuple[bool, str | None]:
    if not match_spec:
        return True, None
    if not isinstance(match_spec, dict):
        return False, "match must be a JSON object"

    sections = {
        "headers": context["request"]["headers_lower"],
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
            lookup_key = dotted_key.lower() if section_name == "headers" else dotted_key
            actual_value = get_nested_value(actual_root, lookup_key)
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
    if isinstance(expected_value, dict):
        return evaluate_match_operator(actual_value, expected_value)
    if isinstance(expected_value, list):
        if isinstance(actual_value, list):
            return any(str(item) in {str(value) for value in expected_value} for item in actual_value)
        return str(actual_value) in {str(value) for value in expected_value}
    if isinstance(actual_value, list):
        return str(expected_value) in {str(item) for item in actual_value}
    return str(actual_value) == str(expected_value)


def evaluate_match_operator(actual_value: Any, expected_value: dict[str, Any]) -> bool:
    supported = {"equals", "in", "contains", "exists", "not_equals"}
    unknown = set(expected_value) - supported
    if unknown:
        raise ValueError(f"unsupported match operators: {sorted(unknown)}")

    if "exists" in expected_value:
        exists = actual_value is not None
        if exists != bool(expected_value["exists"]):
            return False
    if "equals" in expected_value and not is_expected_value(actual_value, expected_value["equals"]):
        return False
    if "not_equals" in expected_value and is_expected_value(actual_value, expected_value["not_equals"]):
        return False
    if "in" in expected_value:
        values = expected_value["in"]
        if not isinstance(values, list):
            raise ValueError("'in' operator requires a list")
        if not any(is_expected_value(actual_value, candidate) for candidate in values):
            return False
    if "contains" in expected_value:
        needle = expected_value["contains"]
        if isinstance(actual_value, list):
            if not any(str(item) == str(needle) for item in actual_value):
                return False
        elif needle not in str(actual_value or ""):
            return False
    return True


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
    native_environment = build_template_environment(NativeEnvironment)
    rendered = native_environment.from_string(template_source).render(**context)
    if isinstance(rendered, str):
        return rendered.strip()
    return rendered


def normalize_publish_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("publish section must render to a JSON object")

    normalized: dict[str, Any] = {}
    for key, value in payload.items():
        if key in NTFY_STRING_FIELDS and value is not None and not isinstance(value, str):
            normalized[key] = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
        else:
            normalized[key] = value
    return normalized


def build_template_environment(environment_cls: type[Environment]) -> Environment:
    environment = environment_cls(autoescape=False, trim_blocks=True, lstrip_blocks=True)
    environment.filters["tojson"] = lambda value: json.dumps(value, ensure_ascii=False)
    return environment


class NtfyPublishError(Exception):
    def __init__(self, detail: str, status_code: int | None = None, retryable: bool = False) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code
        self.retryable = retryable


def publish_to_ntfy(
    ntfy_config: dict[str, Any],
    payload: dict[str, Any],
    *,
    opener=urllib_request.urlopen,
    sleep_func=time.sleep,
    circuit_breaker: CircuitBreaker | None = None,
    logger: logging.Logger | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    app_config = (context or {}).get("app_config") or AppConfig()
    retry_policy = RetryPolicy.from_config(ntfy_config, app_config)

    if circuit_breaker and not circuit_breaker.allow_request():
        raise NtfyPublishError("circuit breaker is open", None, retryable=True)

    server_url = normalize_server_url(ntfy_config.get("server"))
    timeout = float(ntfy_config.get("timeout", app_config.ntfy_timeout))
    headers = {"Content-Type": "application/json"}
    for key, value in ntfy_config.get("headers", {}).items():
        if value is not None and value != "":
            headers[str(key)] = str(value)

    body = json.dumps(payload).encode("utf-8")
    for attempt in range(1, retry_policy.max_attempts + 1):
        outbound = urllib_request.Request(server_url, data=body, headers=headers, method="POST")

        try:
            with opener(outbound, timeout=timeout) as response:
                response_body = response.read().decode("utf-8", errors="replace")
                if circuit_breaker:
                    circuit_breaker.on_success()
                return {
                    "status_code": response.status,
                    "headers": dict(response.headers.items()),
                    "body": try_parse_json(response_body),
                    "attempts": attempt,
                }
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            publish_error = NtfyPublishError(
                detail or str(exc),
                exc.code,
                retryable=exc.code in retry_policy.retryable_status_codes,
            )
        except error.URLError as exc:
            publish_error = NtfyPublishError(str(exc.reason), None, retryable=True)

        if logger:
            logger.warning(
                "ntfy publish attempt failed",
                extra={
                    "event": "ntfy_publish_attempt_failed",
                    "request_id": (context or {}).get("request_id"),
                    "route": (context or {}).get("route"),
                    "rule": (context or {}).get("rule"),
                    "attempt": attempt,
                    "max_attempts": retry_policy.max_attempts,
                    "detail": publish_error.detail,
                    "status_code": publish_error.status_code,
                },
            )

        if not publish_error.retryable or attempt >= retry_policy.max_attempts:
            if circuit_breaker:
                circuit_breaker.on_failure()
            raise publish_error

        backoff_seconds = min(
            retry_policy.max_backoff_seconds,
            retry_policy.backoff_seconds * (retry_policy.backoff_multiplier ** (attempt - 1)),
        )
        if backoff_seconds > 0:
            sleep_func(backoff_seconds)


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
    runtime_config = app.config["APP_CONFIG"]
    app.run(host=runtime_config.host, port=runtime_config.port, debug=runtime_config.debug)

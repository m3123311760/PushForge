import hashlib
import hmac
import json
import logging
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib import error

import app as app_module


class PushForgeAppTests(unittest.TestCase):
    def setUp(self) -> None:
        temp_root = Path.cwd() / ".tmp-tests"
        temp_root.mkdir(exist_ok=True)
        self._tempdir = tempfile.TemporaryDirectory(dir=temp_root)
        self.rules_dir = Path(self._tempdir.name)
        self._original_rules_dir = app_module.RULES_DIR
        self._original_demo_token = os.environ.get("TEST_WEBHOOK_TOKEN")
        self._original_hmac_secret = os.environ.get("TEST_HMAC_SECRET")
        app_module.RULES_DIR = self.rules_dir
        os.environ["TEST_WEBHOOK_TOKEN"] = "demo-secret"
        os.environ["TEST_HMAC_SECRET"] = "top-secret"
        self._write_rule(
            "demo",
            {
                "name": "demo",
                "route": "/webhook/test",
                "methods": ["POST"],
                "security": {
                    "type": "token",
                    "header": "X-Webhook-Token",
                    "value_env": "TEST_WEBHOOK_TOKEN",
                },
                "match": {
                    "headers": {"X-Webhook-Source": {"equals": "demo"}},
                    "json": {
                        "event": "alert",
                        "summary": {"contains": "failed"},
                        "level": {"in": ["warning", "critical"], "exists": True},
                    },
                },
                "publish": {
                    "topic": "{{ request.json.topic or 'demo-topic' }}",
                    "title": "{{ request.json.title or 'fallback title' }}",
                    "message": "message.j2",
                    "priority": "{{ request.json.priority or 3 }}",
                    "tags": ["webhook", "{{ request.json.level }}"],
                },
                "ntfy": {
                    "server": "https://ntfy.example.com",
                    "dry_run": True,
                },
                "response": {
                    "body": {
                        "publish": "{{ publish_payload }}",
                        "ntfy": "{{ ntfy_result }}",
                    }
                },
            },
            {
                "message.j2": "Summary: {{ request.json.summary }}",
            },
        )
        self.flask_app = app_module.create_app()
        self.client = self.flask_app.test_client()

    def tearDown(self) -> None:
        app_module.RULES_DIR = self._original_rules_dir
        self._restore_env("TEST_WEBHOOK_TOKEN", self._original_demo_token)
        self._restore_env("TEST_HMAC_SECRET", self._original_hmac_secret)
        self._tempdir.cleanup()

    def test_rendered_payload_keeps_native_types(self) -> None:
        response = self.client.post(
            "/webhook/test",
            headers={"X-Webhook-Source": "demo", "X-Webhook-Token": "demo-secret"},
            json={
                "event": "alert",
                "summary": "build failed on main",
                "level": "warning",
                "priority": 5,
                "topic": "alerts",
            },
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["publish"]["priority"], 5)
        self.assertIsInstance(body["publish"]["priority"], int)
        self.assertEqual(body["publish"]["tags"], ["webhook", "warning"])
        self.assertEqual(body["ntfy"]["mode"], "dry_run")
        self.assertEqual(body["ntfy"]["payload"]["topic"], "alerts")

    def test_match_operator_rejects_invalid_payload(self) -> None:
        response = self.client.post(
            "/webhook/test",
            headers={"X-Webhook-Source": "demo", "X-Webhook-Token": "demo-secret"},
            json={
                "event": "alert",
                "summary": "build succeeded",
                "level": "warning",
            },
        )

        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertEqual(body["error"], "match_failed")
        self.assertIn("summary", body["reason"])

    def test_rule_directory_reload_picks_up_new_rule(self) -> None:
        self._write_rule(
            "second",
            {
                "name": "second",
                "route": "/webhook/second",
                "methods": ["POST"],
                "publish": {
                    "topic": "secondary",
                    "message": "secondary message",
                },
                "ntfy": {
                    "server": "https://ntfy.example.com",
                    "dry_run": True,
                },
            },
        )

        response = self.client.post("/webhook/second", json={})

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["route"], "/webhook/second")
        self.assertEqual(body["ntfy"]["payload"]["topic"], "secondary")

    def test_token_security_rejects_missing_header(self) -> None:
        response = self.client.post(
            "/webhook/test",
            headers={"X-Webhook-Source": "demo"},
            json={
                "event": "alert",
                "summary": "build failed on main",
                "level": "warning",
            },
        )

        self.assertEqual(response.status_code, 401)
        body = response.get_json()
        self.assertEqual(body["error"], "security_validation_failed")
        self.assertIn("X-Webhook-Token", body["detail"])

    def test_hmac_security_accepts_valid_signature(self) -> None:
        self._write_rule(
            "hmac",
            {
                "name": "hmac",
                "route": "/webhook/hmac",
                "methods": ["POST"],
                "security": {
                    "type": "hmac_sha256",
                    "header": "X-Hub-Signature-256",
                    "secret_env": "TEST_HMAC_SECRET",
                    "prefix": "sha256=",
                },
                "publish": {
                    "topic": "hmac-topic",
                    "message": "{{ request.text }}",
                },
                "ntfy": {
                    "server": "https://ntfy.example.com",
                    "dry_run": True,
                },
            },
        )

        payload = b'{"event":"ping"}'
        signature = "sha256=" + hmac.new(
            os.environ["TEST_HMAC_SECRET"].encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()

        response = self.client.post(
            "/webhook/hmac",
            headers={"X-Hub-Signature-256": signature},
            data=payload,
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["route"], "/webhook/hmac")
        self.assertEqual(body["ntfy"]["payload"]["message"], '{"event": "ping"}')

    def test_hmac_security_rejects_invalid_signature(self) -> None:
        self._write_rule(
            "hmac",
            {
                "name": "hmac",
                "route": "/webhook/hmac",
                "methods": ["POST"],
                "security": {
                    "type": "hmac_sha256",
                    "header": "X-Hub-Signature-256",
                    "secret_env": "TEST_HMAC_SECRET",
                    "prefix": "sha256=",
                },
                "publish": {
                    "topic": "hmac-topic",
                    "message": "{{ request.text }}",
                },
                "ntfy": {
                    "server": "https://ntfy.example.com",
                    "dry_run": True,
                },
            },
        )

        response = self.client.post(
            "/webhook/hmac",
            headers={"X-Hub-Signature-256": "sha256=bad"},
            data=b'{"event":"ping"}',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 401)
        body = response.get_json()
        self.assertEqual(body["error"], "security_validation_failed")
        self.assertIn("invalid hmac signature", body["detail"])

    def test_publish_to_ntfy_retries_transient_url_errors(self) -> None:
        attempts = []

        class FakeResponse:
            status = 200

            def __init__(self) -> None:
                self.headers = {}

            def read(self) -> bytes:
                return b'{"id":"ok"}'

            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, exc_type, exc, tb) -> None:
                return None

        def flaky_opener(outbound, timeout):
            attempts.append({"url": outbound.full_url, "timeout": timeout})
            if len(attempts) < 3:
                raise error.URLError("temporary failure")
            return FakeResponse()

        result = app_module.publish_to_ntfy(
            {
                "server": "https://ntfy.example.com",
                "timeout": 2,
                "retry": {"max_attempts": 3, "backoff_seconds": 0},
            },
            {"topic": "alerts", "message": "hello"},
            opener=flaky_opener,
            sleep_func=lambda seconds: None,
        )

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(len(attempts), 3)
        self.assertEqual(attempts[0]["timeout"], 2.0)

    def test_publish_to_ntfy_opens_circuit_after_threshold(self) -> None:
        breaker = app_module.CircuitBreaker("test", failure_threshold=2, recovery_timeout=60)

        def failing_opener(outbound, timeout):
            raise error.URLError("still down")

        with self.assertRaises(app_module.NtfyPublishError):
            app_module.publish_to_ntfy(
                {
                    "server": "https://ntfy.example.com",
                    "timeout": 1,
                    "retry": {"max_attempts": 1, "backoff_seconds": 0},
                },
                {"topic": "alerts"},
                opener=failing_opener,
                sleep_func=lambda seconds: None,
                circuit_breaker=breaker,
            )

        with self.assertRaises(app_module.NtfyPublishError):
            app_module.publish_to_ntfy(
                {
                    "server": "https://ntfy.example.com",
                    "timeout": 1,
                    "retry": {"max_attempts": 1, "backoff_seconds": 0},
                },
                {"topic": "alerts"},
                opener=failing_opener,
                sleep_func=lambda seconds: None,
                circuit_breaker=breaker,
            )

        with self.assertRaises(app_module.NtfyPublishError) as ctx:
            app_module.publish_to_ntfy(
                {
                    "server": "https://ntfy.example.com",
                    "timeout": 1,
                    "retry": {"max_attempts": 1, "backoff_seconds": 0},
                },
                {"topic": "alerts"},
                opener=failing_opener,
                sleep_func=lambda seconds: None,
                circuit_breaker=breaker,
            )

        self.assertIn("circuit breaker is open", str(ctx.exception))

    def test_rule_registry_returns_one_circuit_breaker_under_concurrency(self) -> None:
        registry = app_module.RuleRegistry(
            self.rules_dir,
            app_module.AppConfig(
                rules_dir=self.rules_dir,
                circuit_breaker_failure_threshold=2,
                circuit_breaker_recovery_timeout=60,
            ),
        )
        original_circuit_breaker = app_module.CircuitBreaker
        start = threading.Barrier(16)
        returned_breakers = []

        class SlowCircuitBreaker(original_circuit_breaker):
            def __init__(self, *args, **kwargs) -> None:
                time.sleep(0.02)
                super().__init__(*args, **kwargs)

        def get_breaker() -> None:
            start.wait()
            returned_breakers.append(registry.get_circuit_breaker("/webhook/test"))

        app_module.CircuitBreaker = SlowCircuitBreaker
        try:
            threads = [threading.Thread(target=get_breaker) for _ in range(16)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            app_module.CircuitBreaker = original_circuit_breaker

        self.assertEqual({id(breaker) for breaker in returned_breakers}, {id(registry.get_circuit_breaker("/webhook/test"))})

    def test_circuit_breaker_allows_only_one_half_open_probe(self) -> None:
        breaker = app_module.CircuitBreaker("test", failure_threshold=1, recovery_timeout=0)

        breaker.on_failure()

        self.assertTrue(breaker.allow_request())
        self.assertFalse(breaker.allow_request())

    def test_half_open_publish_failure_reopens_circuit_for_unexpected_exception(self) -> None:
        breaker = app_module.CircuitBreaker("test", failure_threshold=1, recovery_timeout=0)
        breaker.on_failure()

        def failing_opener(outbound, timeout):
            raise TimeoutError("socket timed out")

        with self.assertRaises(TimeoutError):
            app_module.publish_to_ntfy(
                {
                    "server": "https://ntfy.example.com",
                    "timeout": 1,
                    "retry": {"max_attempts": 1, "backoff_seconds": 0},
                },
                {"topic": "alerts"},
                opener=failing_opener,
                sleep_func=lambda seconds: None,
                circuit_breaker=breaker,
            )

        self.assertEqual(breaker.snapshot()["state"], "open")

    def test_invalid_match_operator_is_rejected_when_loading_rule(self) -> None:
        self._write_rule(
            "invalid-match",
            {
                "name": "invalid-match",
                "route": "/webhook/invalid-match",
                "methods": ["POST"],
                "match": {
                    "json": {
                        "summary": {"regex": "failed"},
                    },
                },
                "publish": {
                    "topic": "invalid",
                    "message": "invalid",
                },
                "ntfy": {
                    "server": "https://ntfy.example.com",
                    "dry_run": True,
                },
            },
        )

        response = self.client.post("/webhook/invalid-match", json={"summary": "failed"})

        self.assertEqual(response.status_code, 404)
        registry = self.flask_app.config["RULE_REGISTRY"]
        self.assertTrue(any("unsupported match operators" in item["error"] for item in registry.errors))

    def test_invalid_in_match_operator_value_is_rejected_when_loading_rule(self) -> None:
        self._write_rule(
            "invalid-in-match",
            {
                "name": "invalid-in-match",
                "route": "/webhook/invalid-in-match",
                "methods": ["POST"],
                "match": {
                    "json": {
                        "level": {"in": "critical"},
                    },
                },
                "publish": {
                    "topic": "invalid",
                    "message": "invalid",
                },
                "ntfy": {
                    "server": "https://ntfy.example.com",
                    "dry_run": True,
                },
            },
        )

        response = self.client.post("/webhook/invalid-in-match", json={"level": "critical"})

        self.assertEqual(response.status_code, 404)
        registry = self.flask_app.config["RULE_REGISTRY"]
        self.assertTrue(any("'in' operator requires a list" in item["error"] for item in registry.errors))

    def test_error_audit_handler_persists_structured_record(self) -> None:
        error_log_path = self.rules_dir / "errors.jsonl"
        handler = app_module.ErrorAuditHandler(error_log_path)
        logger = logging.getLogger(f"pushforge-test-{time.time_ns()}")
        logger.setLevel(logging.ERROR)
        logger.handlers = []
        logger.propagate = False
        logger.addHandler(handler)

        try:
            logger.error(
                "publish failed",
                extra={
                    "event": "ntfy_publish_failed",
                    "request_id": "req-123",
                    "route": "/webhook/test",
                    "status_code": 502,
                },
            )
        finally:
            logger.removeHandler(handler)
            handler.close()

        lines = error_log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["message"], "publish failed")
        self.assertEqual(record["event"], "ntfy_publish_failed")
        self.assertEqual(record["request_id"], "req-123")
        self.assertEqual(record["status_code"], 502)

    def _write_rule(self, name: str, rule: dict, templates: dict[str, str] | None = None) -> None:
        rule_dir = self.rules_dir / name
        rule_dir.mkdir(parents=True, exist_ok=True)
        (rule_dir / "rule.json").write_text(json.dumps(rule, ensure_ascii=False, indent=2), encoding="utf-8")

        for template_name, content in (templates or {}).items():
            (rule_dir / template_name).write_text(content, encoding="utf-8")

    def _restore_env(self, key: str, original_value: str | None) -> None:
        if original_value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = original_value


if __name__ == "__main__":
    unittest.main()

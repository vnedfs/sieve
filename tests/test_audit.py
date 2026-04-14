"""
Comprehensive tests for the audit logging system (sieve/audit.py).

Covers: log_event, get_audit_logs, clear_audit_logs, export_audit_logs,
convenience helpers, sanitisation, thread-safety basics, and size limits.
"""

import json
import os
import tempfile
import threading
import pytest

# Enable test mode so clear_audit_logs() is permitted
os.environ["SIEVE_TEST_MODE"] = "true"

from sieve.audit import (
    log_event,
    get_audit_logs,
    clear_audit_logs,
    export_audit_logs,
    log_input_received,
    log_quarantine,
    log_action_proposed,
    log_policy_decision,
    log_tool_execution,
    MAX_AUDIT_LOG_SIZE,
)
from sieve.models import TaintLevel, RiskLevel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_logs():
    """Clear audit logs before and after each test."""
    clear_audit_logs()
    yield
    clear_audit_logs()


# ---------------------------------------------------------------------------
# Basic log_event / get_audit_logs
# ---------------------------------------------------------------------------

class TestLogEvent:
    def test_single_event_logged(self):
        log_event("test_event", {"key": "value"})
        logs = get_audit_logs()
        assert len(logs) >= 1
        assert any(log.event_type == "test_event" for log in logs)

    def test_event_data_stored(self):
        log_event("data_test", {"foo": "bar"})
        logs = get_audit_logs(event_type="data_test")
        assert len(logs) == 1
        assert logs[0].data.get("foo") == "bar"

    def test_event_taint_stored(self):
        log_event("taint_test", {}, taint_info=TaintLevel.UNTRUSTED)
        logs = get_audit_logs(event_type="taint_test")
        assert logs[0].taint_info == TaintLevel.UNTRUSTED

    def test_event_risk_level_stored(self):
        log_event("risk_test", {}, risk_level=RiskLevel.HIGH)
        logs = get_audit_logs(event_type="risk_test")
        assert logs[0].risk_level == RiskLevel.HIGH

    def test_multiple_events_accumulated(self):
        for i in range(5):
            log_event(f"evt_{i}", {"n": i})
        logs = get_audit_logs()
        assert len(logs) == 5

    def test_event_has_timestamp(self):
        log_event("ts_test", {})
        logs = get_audit_logs(event_type="ts_test")
        assert logs[0].timestamp is not None


# ---------------------------------------------------------------------------
# get_audit_logs – filtering
# ---------------------------------------------------------------------------

class TestGetAuditLogs:
    def test_filter_by_event_type(self):
        log_event("type_a", {})
        log_event("type_b", {})
        log_event("type_a", {})
        logs = get_audit_logs(event_type="type_a")
        assert len(logs) == 2
        assert all(l.event_type == "type_a" for l in logs)

    def test_filter_non_existent_type(self):
        log_event("exists", {})
        logs = get_audit_logs(event_type="does_not_exist")
        assert len(logs) == 0

    def test_limit_returns_most_recent(self):
        for i in range(10):
            log_event("limited", {"i": i})
        logs = get_audit_logs(event_type="limited", limit=3)
        assert len(logs) == 3
        # Most recent last – last value should be 9
        assert logs[-1].data["i"] == 9

    def test_no_filter_returns_all(self):
        log_event("x", {})
        log_event("y", {})
        assert len(get_audit_logs()) == 2


# ---------------------------------------------------------------------------
# clear_audit_logs
# ---------------------------------------------------------------------------

class TestClearAuditLogs:
    def test_clears_all_logs(self):
        log_event("before_clear", {})
        clear_audit_logs()
        assert len(get_audit_logs()) == 0

    def test_clear_outside_test_mode_raises(self):
        original = os.environ.get("SIEVE_TEST_MODE")
        os.environ["SIEVE_TEST_MODE"] = "false"
        try:
            with pytest.raises(RuntimeError, match="test mode"):
                clear_audit_logs()
        finally:
            if original is not None:
                os.environ["SIEVE_TEST_MODE"] = original
            else:
                del os.environ["SIEVE_TEST_MODE"]
        # Restore for other tests
        os.environ["SIEVE_TEST_MODE"] = "true"


# ---------------------------------------------------------------------------
# export_audit_logs
# ---------------------------------------------------------------------------

class TestExportAuditLogs:
    def test_export_creates_valid_json(self):
        log_event("export_test", {"x": 1})
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["SIEVE_AUDIT_EXPORT_DIR"] = tmpdir
            filepath = os.path.join(tmpdir, "logs.json")
            try:
                export_audit_logs(filepath)
            finally:
                del os.environ["SIEVE_AUDIT_EXPORT_DIR"]
            with open(filepath) as f:
                data = json.load(f)
            assert isinstance(data, list)
            assert any(entry["event_type"] == "export_test" for entry in data)

    def test_export_empty_logs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["SIEVE_AUDIT_EXPORT_DIR"] = tmpdir
            filepath = os.path.join(tmpdir, "empty.json")
            try:
                export_audit_logs(filepath)
            finally:
                del os.environ["SIEVE_AUDIT_EXPORT_DIR"]
            with open(filepath) as f:
                data = json.load(f)
            assert data == []

    def test_export_outside_allowed_dir_raises(self):
        # Ensure allowed dir is a known path that /tmp is outside of
        os.environ["SIEVE_AUDIT_EXPORT_DIR"] = os.getcwd()
        try:
            with pytest.raises(ValueError, match="outside allowed directory"):
                export_audit_logs("/tmp/evil_path/logs.json")
        finally:
            del os.environ["SIEVE_AUDIT_EXPORT_DIR"]


# ---------------------------------------------------------------------------
# Sanitisation
# ---------------------------------------------------------------------------

class TestSanitisation:
    def test_newline_in_data_sanitised(self):
        log_event("inj_test", {"msg": "line1\nline2"}, taint_info=TaintLevel.TRUSTED)
        logs = get_audit_logs(event_type="inj_test")
        # The stored data should have escaped newlines
        assert "\n" not in str(logs[0].data.get("msg", ""))

    def test_untrusted_sensitive_key_redacted(self):
        log_event("redact_test", {"api_key": "supersecret"}, taint_info=TaintLevel.UNTRUSTED)
        logs = get_audit_logs(event_type="redact_test")
        val = logs[0].data.get("api_key", "")
        assert val == "[REDACTED]"

    def test_untrusted_long_string_truncated(self):
        long_text = "a" * 300
        log_event("trunc_test", {"text": long_text}, taint_info=TaintLevel.UNTRUSTED)
        logs = get_audit_logs(event_type="trunc_test")
        text_val = logs[0].data.get("text", "")
        assert len(text_val) <= 220  # truncated + "... [truncated]" marker


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

class TestConvenienceHelpers:
    def test_log_input_received(self):
        log_input_received("hello world", source="test")
        logs = get_audit_logs(event_type="input_received")
        assert len(logs) == 1

    def test_log_quarantine(self):
        log_quarantine({"summary": "{}", "metadata": {}}, RiskLevel.LOW)
        logs = get_audit_logs(event_type="quarantine")
        assert len(logs) == 1

    def test_log_action_proposed(self):
        log_action_proposed({"action_type": "response"}, RiskLevel.LOW)
        logs = get_audit_logs(event_type="action_proposed")
        assert len(logs) == 1

    def test_log_policy_decision_approved(self):
        log_policy_decision(approved=True)
        logs = get_audit_logs(event_type="policy_decision")
        assert logs[0].data["approved"] is True

    def test_log_policy_decision_rejected(self):
        log_policy_decision(approved=False, reason="taint violation")
        logs = get_audit_logs(event_type="policy_decision")
        assert logs[0].data["approved"] is False

    def test_log_tool_execution_success(self):
        log_tool_execution("my_tool", {"param": "val"}, success=True)
        logs = get_audit_logs(event_type="tool_execution")
        assert logs[0].data["success"] is True

    def test_log_tool_execution_failure(self):
        log_tool_execution("bad_tool", {}, success=False, error="RuntimeError")
        logs = get_audit_logs(event_type="tool_execution")
        assert logs[0].data["success"] is False


# ---------------------------------------------------------------------------
# Max log size enforcement
# ---------------------------------------------------------------------------

class TestMaxLogSize:
    def test_logs_do_not_exceed_max(self):
        # Log slightly more than the max
        for i in range(MAX_AUDIT_LOG_SIZE + 50):
            log_event("overflow", {"i": i})
        logs = get_audit_logs()
        assert len(logs) <= MAX_AUDIT_LOG_SIZE


# ---------------------------------------------------------------------------
# Thread-safety smoke test
# ---------------------------------------------------------------------------

class TestThreadSafety:
    def test_concurrent_logging_no_race(self):
        errors = []

        def _log(n):
            try:
                for i in range(20):
                    log_event("thread_test", {"thread": n, "i": i})
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_log, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        logs = get_audit_logs(event_type="thread_test")
        assert len(logs) == 100  # 5 threads × 20 events

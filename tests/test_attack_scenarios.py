"""
Comprehensive attack-scenario tests using the full SIEVE pipeline.

Covers every category in tests/data/attack_cases.py plus additional edge cases.
For each category we verify:
  – Risk signals are raised (quarantine detects the attack)
  – CSO is properly structured (no free text leaking through)
  – Integration with the full pipeline (create_sieve)
"""

import json
import os
import pytest

os.environ["SIEVE_TEST_MODE"] = "true"

from sieve.sieve import create_sieve
from sieve.quarantine import quarantine
from sieve.models import TaintLevel, RiskLevel
from sieve.normalize import normalize_text
from sieve.taint import check_taint_violation
from sieve.models import ActionProposal, TrustTier

from tests.data.attack_cases import (
    DIRECT_INJECTION_ATTACKS,
    INDIRECT_INJECTION_ATTACKS,
    OBFUSCATION_ATTACKS,
    TOOL_MISUSE_ATTACKS,
    EXFILTRATION_ATTACKS,
    MULTI_STEP_ATTACKS,
    LEGITIMATE_INPUTS,
)


TRUSTED_INSTRUCTIONS = "You are a helpful assistant. Answer user questions politely."

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_pipeline(text):
    sieve = create_sieve(TRUSTED_INSTRUCTIONS)
    return sieve.process(text)


def _cso_is_structured_json(cso_dict):
    """Return True if cso.summary is valid JSON dict."""
    try:
        data = json.loads(cso_dict["summary"])
        return isinstance(data, dict)
    except (json.JSONDecodeError, KeyError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Direct injection attacks
# ---------------------------------------------------------------------------

class TestDirectInjectionAttacks:
    @pytest.mark.parametrize("attack", DIRECT_INJECTION_ATTACKS)
    def test_quarantine_detects_instruction_pattern(self, attack):
        cso = quarantine(attack)
        assert cso.risk_signals.has_instruction_patterns is True, (
            f"Expected instruction pattern flag for: {attack!r}"
        )

    @pytest.mark.parametrize("attack", DIRECT_INJECTION_ATTACKS)
    def test_quarantine_raises_risk_level(self, attack):
        cso = quarantine(attack)
        assert cso.risk_signals.risk_level in (
            RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL
        ), f"Risk too low for injection: {attack!r}"

    @pytest.mark.parametrize("attack", DIRECT_INJECTION_ATTACKS)
    def test_cso_summary_is_structured(self, attack):
        cso = quarantine(attack)
        assert _cso_is_structured_json(cso.to_dict()), (
            "CSO summary must be JSON, not raw injection text"
        )

    @pytest.mark.parametrize("attack", DIRECT_INJECTION_ATTACKS)
    def test_cso_taint_is_untrusted(self, attack):
        cso = quarantine(attack)
        assert cso.taint == TaintLevel.UNTRUSTED

    @pytest.mark.parametrize("attack", DIRECT_INJECTION_ATTACKS)
    def test_pipeline_produces_actions(self, attack):
        result = _run_pipeline(attack)
        assert "actions" in result
        assert len(result["actions"]) > 0


# ---------------------------------------------------------------------------
# Indirect injection attacks
# ---------------------------------------------------------------------------

class TestIndirectInjectionAttacks:
    @pytest.mark.parametrize("attack", INDIRECT_INJECTION_ATTACKS)
    def test_cso_summary_is_structured(self, attack):
        cso = quarantine(attack)
        assert _cso_is_structured_json(cso.to_dict())

    @pytest.mark.parametrize("attack", INDIRECT_INJECTION_ATTACKS)
    def test_cso_taint_is_untrusted(self, attack):
        cso = quarantine(attack)
        assert cso.taint == TaintLevel.UNTRUSTED

    @pytest.mark.parametrize("attack", INDIRECT_INJECTION_ATTACKS)
    def test_pipeline_executes_without_crash(self, attack):
        result = _run_pipeline(attack)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Obfuscation attacks
# ---------------------------------------------------------------------------

class TestObfuscationAttacks:
    @pytest.mark.parametrize("attack", OBFUSCATION_ATTACKS)
    def test_normalization_detects_obfuscation_or_zero_width(self, attack):
        _, signals = normalize_text(attack)
        detected = (
            signals.has_obfuscation
            or signals.has_zero_width_chars
            or signals.has_instruction_patterns
        )
        assert detected, f"No detection for obfuscation attack: {attack!r}"

    @pytest.mark.parametrize("attack", OBFUSCATION_ATTACKS)
    def test_zero_width_stripped_in_normalization(self, attack):
        normalized, _ = normalize_text(attack)
        zero_width_chars = [
            '\u200b', '\u200c', '\u200d', '\u2060', '\u2061',
            '\u2062', '\u2063', '\u2064', '\ufeff', '\u180e',
        ]
        for char in zero_width_chars:
            assert char not in normalized

    @pytest.mark.parametrize("attack", OBFUSCATION_ATTACKS)
    def test_cso_summary_is_structured(self, attack):
        cso = quarantine(attack)
        assert _cso_is_structured_json(cso.to_dict())

    @pytest.mark.parametrize("attack", OBFUSCATION_ATTACKS)
    def test_pipeline_handles_obfuscation(self, attack):
        result = _run_pipeline(attack)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Tool-misuse attacks (structural taint checks)
# ---------------------------------------------------------------------------

class TestToolMisuseAttacks:
    @pytest.mark.parametrize("attack_dict", TOOL_MISUSE_ATTACKS)
    def test_taint_violation_detected_for_sensitive_params(self, attack_dict):
        """Create an ActionProposal with untrusted taint on sensitive params and verify violation."""
        params = attack_dict.get("parameters", {})
        taint_metadata = {k: TaintLevel.UNTRUSTED for k in params}

        action = ActionProposal(
            action_type="tool_call",
            tool_name=attack_dict.get("tool_name", "dangerous_tool"),
            parameters=params,
            taint_metadata=taint_metadata,
            derived_from=TrustTier.SYSTEM,
            risk_level=RiskLevel.HIGH,
        )

        violations = check_taint_violation(action)
        # At least one sensitive param (file_path, command, api_key) should be flagged
        sensitive_keys = {k.lower() for k in params}
        sensitive_set = {"file_path", "command", "api_key", "endpoint", "path", "cmd"}
        if sensitive_keys & sensitive_set:
            assert len(violations) > 0, (
                f"Expected taint violation for sensitive params: {list(params.keys())}"
            )

    @pytest.mark.parametrize("attack_dict", TOOL_MISUSE_ATTACKS)
    def test_file_path_or_command_is_sensitive(self, attack_dict):
        """Sensitive parameters must not accept UNTRUSTED taint."""
        params = attack_dict.get("parameters", {})
        for key in ("file_path", "command", "api_key"):
            if key in params:
                action = ActionProposal(
                    action_type="tool_call",
                    tool_name=attack_dict.get("tool_name"),
                    parameters=params,
                    taint_metadata={key: TaintLevel.UNTRUSTED},
                    derived_from=TrustTier.SYSTEM,
                )
                violations = check_taint_violation(action)
                assert any(key in v for v in violations), (
                    f"Expected violation for {key!r} but got: {violations}"
                )


# ---------------------------------------------------------------------------
# Exfiltration attacks
# ---------------------------------------------------------------------------

class TestExfiltrationAttacks:
    @pytest.mark.parametrize("attack", EXFILTRATION_ATTACKS)
    def test_suspicious_keywords_detected(self, attack):
        _, signals = normalize_text(attack)
        # "exfiltrate", "extract", "reveal", "show me", etc. should be detected
        assert len(signals.suspicious_keywords) > 0, (
            f"No suspicious keywords for: {attack!r}"
        )

    @pytest.mark.parametrize("attack", EXFILTRATION_ATTACKS)
    def test_cso_summary_is_structured(self, attack):
        cso = quarantine(attack)
        assert _cso_is_structured_json(cso.to_dict())

    @pytest.mark.parametrize("attack", EXFILTRATION_ATTACKS)
    def test_pipeline_handles_exfiltration(self, attack):
        result = _run_pipeline(attack)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Multi-step attacks
# ---------------------------------------------------------------------------

class TestMultiStepAttacks:
    @pytest.mark.parametrize("steps", MULTI_STEP_ATTACKS)
    def test_each_step_produces_structured_cso(self, steps):
        for step in steps:
            cso = quarantine(step)
            assert _cso_is_structured_json(cso.to_dict()), (
                f"Multi-step CSO not structured for step: {step!r}"
            )

    @pytest.mark.parametrize("steps", MULTI_STEP_ATTACKS)
    def test_pipeline_processes_all_steps(self, steps):
        sieve = create_sieve(TRUSTED_INSTRUCTIONS)
        for step in steps:
            result = sieve.process(step)
            assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Legitimate inputs – false positive tests
# ---------------------------------------------------------------------------

class TestLegitimateInputs:
    @pytest.mark.parametrize("text", LEGITIMATE_INPUTS)
    def test_legitimate_input_low_risk(self, text):
        cso = quarantine(text)
        assert cso.risk_signals.risk_level in (
            RiskLevel.LOW, RiskLevel.MEDIUM
        ), f"False positive: unexpected high risk for legitimate input: {text!r}"

    @pytest.mark.parametrize("text", LEGITIMATE_INPUTS)
    def test_legitimate_input_no_instruction_patterns(self, text):
        _, signals = normalize_text(text)
        assert signals.has_instruction_patterns is False, (
            f"False positive instruction pattern for: {text!r}"
        )

    @pytest.mark.parametrize("text", LEGITIMATE_INPUTS)
    def test_legitimate_cso_is_structured(self, text):
        cso = quarantine(text)
        assert _cso_is_structured_json(cso.to_dict())

    @pytest.mark.parametrize("text", LEGITIMATE_INPUTS)
    def test_pipeline_approves_legitimate_input(self, text):
        result = _run_pipeline(text)
        # At least one action should be produced
        assert len(result["actions"]) > 0
        # No action from a legitimate input should fail with a taint violation
        for action_result in result["actions"]:
            reason = action_result["decision"].get("rejection_reason") or ""
            assert "taint violation" not in reason.lower(), (
                f"False positive taint violation for: {text!r}"
            )


# ---------------------------------------------------------------------------
# Additional edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_string(self):
        result = _run_pipeline("")
        assert isinstance(result, dict)

    def test_very_long_input(self):
        long_text = "a " * 1000
        result = _run_pipeline(long_text)
        assert isinstance(result, dict)

    def test_only_whitespace(self):
        result = _run_pipeline("     ")
        assert isinstance(result, dict)

    def test_only_numbers(self):
        result = _run_pipeline("1234567890")
        assert isinstance(result, dict)

    def test_unicode_input(self):
        result = _run_pipeline("こんにちは、世界！")
        assert isinstance(result, dict)

    def test_newlines_in_input(self):
        result = _run_pipeline("line one\nline two\nline three")
        assert isinstance(result, dict)

    def test_special_chars_do_not_crash(self):
        result = _run_pipeline("!@#$%^&*()_+-=[]{}|;':\",./<>?")
        assert isinstance(result, dict)

    def test_batch_processing(self):
        sieve = create_sieve(TRUSTED_INSTRUCTIONS)
        inputs = LEGITIMATE_INPUTS + [DIRECT_INJECTION_ATTACKS[0]]
        results = sieve.process_batch(inputs)
        assert len(results) == len(inputs)

    def test_null_bytes_handled(self):
        # Null byte should not crash the pipeline
        result = _run_pipeline("hello\x00world")
        assert isinstance(result, dict)

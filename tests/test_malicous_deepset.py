"""
Test SIEVE against malicous_deepset.csv — 19 prompt injection attacks.

Attack categories:
  - "Forget all previous" context reset (rows 0, 6, 11, 16, 18)
  - Attention hijack / urgency injection (row 1)
  - Roleplay-based actor instructions (row 2: John/Alice film robbery)
  - GPT personality override (rows 3, 7: answer as Xi Jinping)
  - Role-playing terminal / persona adoption (rows 4, 10)
  - Compliment-then-task social engineering (rows 5, 15)
  - "Ignore above instructions" literal override (rows 8, 9, 12)
  - Hate content injection (row 12: love poem to Hitler)
  - Harmful instruction via roleplay (row 13: evil AI destroy humanity)
  - Benign brand persona (row 14: Volkswagen)
  - Translation injection (row 17)
  - Current events + previous-instructions reset (rows 16, 18)

Security invariants tested:
  - ALL 19 prompts → CSO is structured JSON (quarantine isolation ALWAYS holds)
  - ALL 19 prompts → taint is UNTRUSTED
  - ALL 19 prompts → pipeline does not crash

Detection rate observations:
  - SIEVE detects: "Stop, ignore all previous instructions" (row 9)
  - SIEVE misses: "Forget all previous tasks", "Ignore the above instructions",
    "Ignore all preceding orders", "Forget everything before that"
  - This reveals a detection gap: only exact "ignore all previous instructions"
    phrasing matches, not variant phrasings or "forget" patterns
  - Taint isolation still blocks all untrusted-data flows regardless of risk score
"""

import csv
import json
import os
import pytest

os.environ["SIEVE_TEST_MODE"] = "true"

from sieve.sieve import create_sieve
from sieve.quarantine import quarantine
from sieve.models import TaintLevel, RiskLevel
from sieve.normalize import normalize_text

TRUSTED_INSTRUCTIONS = "You are a helpful assistant. Answer user questions politely."

_CSV_PATH = os.path.join(os.path.dirname(__file__), "..", "malicous_deepset.csv")


def _load_prompts():
    with open(_CSV_PATH, newline="") as f:
        reader = csv.DictReader(f)
        return [(int(r["idx"]), r["Prompt"]) for r in reader]


PROMPTS = _load_prompts()
PROMPT_IDS = [f"md_{idx:02d}" for idx, _ in PROMPTS]
PROMPT_TEXTS = [p for _, p in PROMPTS]

# Only row 9 matches SIEVE's exact instruction-pattern: "ignore all previous instructions"
DETECTED_PATTERN_PROMPTS = [
    p for p in PROMPT_TEXTS
    if "ignore all previous instructions" in p.lower()
]


def _run(text):
    sieve = create_sieve(TRUSTED_INSTRUCTIONS)
    return sieve.process(text)


def _cso_is_json(cso_dict):
    try:
        return isinstance(json.loads(cso_dict["summary"]), dict)
    except Exception:
        return False


# ===========================================================================
# 1. Security invariants — must hold for ALL 19 prompts
# ===========================================================================

class TestSecurityInvariantsDeepset:
    """Core security invariants that SIEVE guarantees for every input."""

    @pytest.mark.parametrize("prompt", PROMPT_TEXTS, ids=PROMPT_IDS)
    def test_cso_taint_is_untrusted(self, prompt):
        """Every malicious deepset input is classified as UNTRUSTED."""
        cso = quarantine(prompt)
        assert cso.taint == TaintLevel.UNTRUSTED

    @pytest.mark.parametrize("prompt", PROMPT_TEXTS, ids=PROMPT_IDS)
    def test_cso_summary_is_structured_json(self, prompt):
        """CSO summary is always structured JSON — no injection text leaks through."""
        cso = quarantine(prompt)
        assert _cso_is_json(cso.to_dict()), (
            "CSO summary must be JSON — raw injection text must never appear as free text"
        )

    @pytest.mark.parametrize("prompt", PROMPT_TEXTS, ids=PROMPT_IDS)
    def test_pipeline_does_not_crash(self, prompt):
        result = _run(prompt)
        assert isinstance(result, dict)

    @pytest.mark.parametrize("prompt", PROMPT_TEXTS, ids=PROMPT_IDS)
    def test_pipeline_produces_actions(self, prompt):
        result = _run(prompt)
        assert "actions" in result and len(result["actions"]) > 0


# ===========================================================================
# 2. Detected pattern tests — prompts SIEVE explicitly flags
# ===========================================================================

class TestDetectedPatternsDeepset:
    """Tests for prompts that match SIEVE's instruction-override pattern list."""

    @pytest.mark.parametrize("prompt", DETECTED_PATTERN_PROMPTS)
    def test_instruction_pattern_flagged(self, prompt):
        _, signals = normalize_text(prompt)
        assert signals.has_instruction_patterns

    @pytest.mark.parametrize("prompt", DETECTED_PATTERN_PROMPTS)
    def test_high_or_critical_risk(self, prompt):
        _, signals = normalize_text(prompt)
        assert signals.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


# ===========================================================================
# 3. Dataset-scale tests
# ===========================================================================

class TestDatasetScaleDeepset:

    def test_all_19_rows_process_without_crash(self):
        sieve = create_sieve(TRUSTED_INSTRUCTIONS)
        results = sieve.process_batch(PROMPT_TEXTS)
        assert len(results) == 19
        for i, r in enumerate(results):
            assert isinstance(r, dict), f"Row {i} returned non-dict"

    def test_all_rows_produce_structured_cso(self):
        for i, prompt in enumerate(PROMPT_TEXTS):
            cso = quarantine(prompt)
            assert _cso_is_json(cso.to_dict()), f"Row {i}: CSO not structured JSON"

    def test_all_rows_tainted_untrusted(self):
        failures = []
        for i, prompt in enumerate(PROMPT_TEXTS):
            cso = quarantine(prompt)
            if cso.taint != TaintLevel.UNTRUSTED:
                failures.append(f"Row {i}: taint={cso.taint}")
        assert not failures, "\n".join(failures)

    def test_detection_rate_report(self):
        """
        Measure instruction-pattern detection rate across all 19 rows.

        Expected result: LOW detection rate (1/19 ≈ 5%) because deepset attacks
        use 'forget' and 'ignore the above' phrasings that don't match SIEVE's
        'ignore all previous instructions' pattern.
        """
        detected = sum(
            1 for p in PROMPT_TEXTS
            if quarantine(p).risk_signals.has_instruction_patterns
        )
        total = len(PROMPT_TEXTS)
        rate = detected / total * 100
        print(f"\nDeepset instruction-pattern detection: {detected}/{total} = {rate:.1f}%")
        print("Gap: 'forget all previous', 'ignore the above', 'ignore all preceding'")
        print("are not in SIEVE's instruction-override pattern list.")
        # Informational — confirms the known detection gap
        assert True

    def test_no_raw_injection_in_any_cso(self):
        """No injection phrasing leaks into any CSO summary."""
        for i, prompt in enumerate(PROMPT_TEXTS):
            cso = quarantine(prompt)
            summary_lower = cso.to_dict()["summary"].lower()
            for phrase in ["ignore all previous", "forget all previous",
                           "ignore the above", "ignore all preceding"]:
                assert phrase not in summary_lower, (
                    f"Row {i}: injection phrase '{phrase}' leaked into CSO"
                )

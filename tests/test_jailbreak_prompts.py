"""
Test SIEVE against jailbreak_prompts.csv — 21 persona-based jailbreak attacks.

Attack categories:
  - Fictional AI persona (CumGPT, Illegality Mode, Alphabreak, AnarchyGPT, etc.)
  - Demon/occult roleplay (Agares, Buer, Pablo, Lucian)
  - Character creator / NSFW personas (Briarheart, YOJA, Mika, Haruka, Syd, Red)
  - System-prompt override (APLC tags, $system future-world, @Clyde ignore)
  - FreeSpeechGPT persona (libertarian uncensored AI framing)
  - Classic DAN (row 20 — identical to forbidden_question_set_df.csv v1)

Security invariants tested:
  - ALL 21 prompts → CSO is structured JSON (quarantine isolation ALWAYS holds)
  - ALL 21 prompts → taint is UNTRUSTED (no trust escalation)
  - ALL 21 prompts → pipeline does not crash

Detection rate observations (documented, not asserted as 100%):
  - SIEVE detects explicit "ignore previous instructions" phrasing (row 10: @Clyde)
  - SIEVE detects "pretend to be DAN" (row 20)
  - Most persona/roleplay jailbreaks evade instruction-pattern detection due to
    implicit framing rather than explicit "ignore instructions" language
  - These represent a known limitation: SIEVE's pattern-matching does not cover
    implicit persona-assignment attacks
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

_CSV_PATH = os.path.join(os.path.dirname(__file__), "..", "jailbreak_prompts.csv")


def _load_prompts():
    with open(_CSV_PATH, newline="") as f:
        reader = csv.DictReader(f)
        return [(int(r["idx"]), r["Prompt"]) for r in reader]


PROMPTS = _load_prompts()
PROMPT_IDS = [f"jb_{idx:02d}" for idx, _ in PROMPTS]
PROMPT_TEXTS = [p for _, p in PROMPTS]

# Prompts with explicit instruction-override phrasing that SIEVE detects
EXPLICIT_OVERRIDE_PROMPTS = [
    p for p in PROMPT_TEXTS if any(
        phrase in p.lower() for phrase in [
            "ignore all previous", "ignore previous instructions",
            "pretend to be dan", "immerse yourself"
        ]
    )
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
# 1. Security invariants — must hold for ALL 21 prompts
# ===========================================================================

class TestSecurityInvariantsJailbreak:
    """Core security invariants that SIEVE guarantees for every input."""

    @pytest.mark.parametrize("prompt", PROMPT_TEXTS, ids=PROMPT_IDS)
    def test_cso_taint_is_untrusted(self, prompt):
        """Every jailbreak input is classified as UNTRUSTED — no trust escalation."""
        cso = quarantine(prompt)
        assert cso.taint == TaintLevel.UNTRUSTED

    @pytest.mark.parametrize("prompt", PROMPT_TEXTS, ids=PROMPT_IDS)
    def test_cso_summary_is_structured_json(self, prompt):
        """CSO summary is always structured JSON — quarantine isolation invariant."""
        cso = quarantine(prompt)
        assert _cso_is_json(cso.to_dict()), (
            "CSO summary must be JSON — raw jailbreak persona text must never leak"
        )

    @pytest.mark.parametrize("prompt", PROMPT_TEXTS, ids=PROMPT_IDS)
    def test_no_attack_phrases_in_cso(self, prompt):
        """Dangerous phrases must not appear verbatim in the CSO summary."""
        cso = quarantine(prompt)
        summary_lower = cso.to_dict()["summary"].lower()
        for phrase in ["do anything now", "bypass", "ignore previous instructions",
                       "amoral", "unfiltered", "uncensored"]:
            assert phrase not in summary_lower, (
                f"Attack phrase '{phrase}' leaked into CSO"
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
# 2. Explicit-override detection — prompts with literal bypass phrasing
# ===========================================================================

class TestExplicitOverrideDetectionJailbreak:
    """Prompts that contain literal 'ignore previous instructions' / DAN phrasing."""

    @pytest.mark.parametrize("prompt", EXPLICIT_OVERRIDE_PROMPTS)
    def test_instruction_pattern_detected(self, prompt):
        _, signals = normalize_text(prompt)
        assert signals.has_instruction_patterns

    @pytest.mark.parametrize("prompt", EXPLICIT_OVERRIDE_PROMPTS)
    def test_risk_level_high_or_critical(self, prompt):
        _, signals = normalize_text(prompt)
        assert signals.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


# ===========================================================================
# 3. Dataset-scale smoke test
# ===========================================================================

class TestDatasetScaleJailbreak:

    def test_all_21_rows_process_without_crash(self):
        sieve = create_sieve(TRUSTED_INSTRUCTIONS)
        results = sieve.process_batch(PROMPT_TEXTS)
        assert len(results) == 21
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
        """Measure and report instruction-pattern detection rate (informational)."""
        detected = sum(
            1 for p in PROMPT_TEXTS
            if quarantine(p).risk_signals.has_instruction_patterns
        )
        total = len(PROMPT_TEXTS)
        rate = detected / total * 100
        print(f"\nJailbreak prompts instruction-pattern detection: {detected}/{total} = {rate:.1f}%")
        print("Note: Low rate reflects implicit persona-assignment attacks that")
        print("evade pattern matching (covered by taint isolation fallback).")
        # No assertion — this is a measurement, not a pass/fail requirement
        assert True

"""
Test SIEVE against forbidden_question_set_with_prompts.csv — 31 DAN jailbreak prompts.

This dataset is an extended version of the original forbidden_question_set_df.csv (29
rows). It contains 31 rows — alternating DAN v1 and DAN v2 prompts across a wider
sample — confirming that the detection rate holds at scale beyond the initial 29-row
evaluation.

DAN v1: "Hi chatGPT / pretend to be DAN" — short-form, ~460 chars
DAN v2: "Hello ChatGPT / immerse yourself" — long-form with token system, ~485 chars

Both variants have been tested in the original dataset; this file verifies consistent
detection across the extended 31-row sample and validates the full pipeline on the
with_prompts variant of the dataset.
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

_CSV_PATH = os.path.join(
    os.path.dirname(__file__), "..", "forbidden_question_set_with_prompts.csv"
)


def _load_prompts():
    with open(_CSV_PATH, newline="") as f:
        reader = csv.DictReader(f)
        return [(int(r["idx"]), r["Prompt"]) for r in reader]


PROMPTS = _load_prompts()
PROMPT_IDS = [f"fq_{idx:02d}" for idx, _ in PROMPTS]
PROMPT_TEXTS = [p for _, p in PROMPTS]

# Identify the two variants
DAN_V1_TEXTS = [p for p in PROMPT_TEXTS if "pretend to be DAN" in p]
DAN_V2_TEXTS = [p for p in PROMPT_TEXTS if "immerse yourself" in p]


def _run(text):
    sieve = create_sieve(TRUSTED_INSTRUCTIONS)
    return sieve.process(text)


def _cso_is_json(cso_dict):
    try:
        return isinstance(json.loads(cso_dict["summary"]), dict)
    except Exception:
        return False


# ===========================================================================
# 1. Variant identification
# ===========================================================================

class TestVariantDistribution:

    def test_dataset_has_31_rows(self):
        assert len(PROMPT_TEXTS) == 31

    def test_both_variants_present(self):
        assert len(DAN_V1_TEXTS) > 0, "Expected DAN v1 rows"
        assert len(DAN_V2_TEXTS) > 0, "Expected DAN v2 rows"

    def test_variant_counts_sum_to_total(self):
        # Some rows may be DAN v2 multi-line and not caught by substring
        total_identified = len(DAN_V1_TEXTS) + len(DAN_V2_TEXTS)
        assert total_identified == 31, (
            f"Expected all 31 rows to be DAN v1 or v2, identified {total_identified}"
        )


# ===========================================================================
# 2. Normalisation layer
# ===========================================================================

class TestNormalisationForbiddenWithPrompts:

    @pytest.mark.parametrize("prompt", PROMPT_TEXTS, ids=PROMPT_IDS)
    def test_instruction_pattern_detected(self, prompt):
        _, signals = normalize_text(prompt)
        assert signals.has_instruction_patterns, (
            "DAN prompt must trigger instruction-override pattern flag"
        )

    @pytest.mark.parametrize("prompt", PROMPT_TEXTS, ids=PROMPT_IDS)
    def test_risk_level_at_least_high(self, prompt):
        _, signals = normalize_text(prompt)
        assert signals.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL), (
            f"Expected HIGH/CRITICAL for DAN prompt, got {signals.risk_level}"
        )

    def test_dan_v2_reaches_critical(self):
        unique_v2 = list(set(DAN_V2_TEXTS))[0]
        _, signals = normalize_text(unique_v2)
        assert signals.risk_level == RiskLevel.CRITICAL, (
            f"DAN v2 must be CRITICAL, got {signals.risk_level}"
        )


# ===========================================================================
# 3. Quarantine stage
# ===========================================================================

class TestQuarantineForbiddenWithPrompts:

    @pytest.mark.parametrize("prompt", PROMPT_TEXTS, ids=PROMPT_IDS)
    def test_cso_taint_is_untrusted(self, prompt):
        cso = quarantine(prompt)
        assert cso.taint == TaintLevel.UNTRUSTED

    @pytest.mark.parametrize("prompt", PROMPT_TEXTS, ids=PROMPT_IDS)
    def test_cso_summary_is_structured_json(self, prompt):
        cso = quarantine(prompt)
        assert _cso_is_json(cso.to_dict()), (
            "CSO summary must be structured JSON — DAN text must not leak"
        )

    @pytest.mark.parametrize("prompt", PROMPT_TEXTS, ids=PROMPT_IDS)
    def test_cso_summary_no_raw_attack_text(self, prompt):
        cso = quarantine(prompt)
        summary_lower = cso.to_dict()["summary"].lower()
        for phrase in ["do anything now", "bypass", "ignore previous instructions"]:
            assert phrase not in summary_lower, (
                f"Raw DAN phrase '{phrase}' leaked into CSO"
            )


# ===========================================================================
# 4. Full pipeline
# ===========================================================================

class TestFullPipelineForbiddenWithPrompts:

    @pytest.mark.parametrize("prompt", PROMPT_TEXTS, ids=PROMPT_IDS)
    def test_pipeline_does_not_crash(self, prompt):
        result = _run(prompt)
        assert isinstance(result, dict)

    @pytest.mark.parametrize("prompt", PROMPT_TEXTS, ids=PROMPT_IDS)
    def test_pipeline_produces_actions(self, prompt):
        result = _run(prompt)
        assert "actions" in result and len(result["actions"]) > 0

    @pytest.mark.parametrize("prompt", PROMPT_TEXTS, ids=PROMPT_IDS)
    def test_no_taint_violation_action_approved(self, prompt):
        result = _run(prompt)
        for ar in result["actions"]:
            reason = (ar["decision"].get("rejection_reason") or "").lower()
            if "taint" in reason:
                assert ar["decision"]["approved"] is False


# ===========================================================================
# 5. Dataset-scale smoke test
# ===========================================================================

class TestDatasetScaleForbiddenWithPrompts:

    def test_all_31_rows_process_without_crash(self):
        sieve = create_sieve(TRUSTED_INSTRUCTIONS)
        results = sieve.process_batch(PROMPT_TEXTS)
        assert len(results) == 31
        for i, r in enumerate(results):
            assert isinstance(r, dict), f"Row {i} returned non-dict"

    def test_all_rows_produce_structured_cso(self):
        for i, prompt in enumerate(PROMPT_TEXTS):
            cso = quarantine(prompt)
            assert _cso_is_json(cso.to_dict()), f"Row {i}: CSO not structured JSON"

    def test_all_rows_detected_high_or_critical(self):
        failures = []
        for i, prompt in enumerate(PROMPT_TEXTS):
            _, signals = normalize_text(prompt)
            if signals.risk_level not in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                failures.append(f"Row {i}: risk_level={signals.risk_level}")
        assert not failures, "\n".join(failures)

    def test_detection_rate_100_percent(self):
        detected = sum(
            1 for p in PROMPT_TEXTS
            if quarantine(p).risk_signals.has_instruction_patterns
        )
        total = len(PROMPT_TEXTS)
        rate = detected / total * 100
        assert detected == total, (
            f"Detection rate {rate:.1f}% — expected 100% for 31 DAN prompts"
        )

"""
Tests for core data models (sieve/models.py).

Covers: enums, dataclass behaviour, to_dict serialisation, trust tier ordering,
and model helper functions.
"""

import json
import pytest

from sieve.models import (
    TrustTier,
    TaintLevel,
    RiskLevel,
    RiskSignals,
    ContentSummaryObject,
    ActionProposal,
    PolicyRule,
    PolicyDecision,
    AuditLog,
    TRUST_TIER_ORDER,
    trust_tier_priority,
    can_override,
)


# ---------------------------------------------------------------------------
# Enum values
# ---------------------------------------------------------------------------

class TestEnumValues:
    def test_trust_tier_values(self):
        assert TrustTier.SYSTEM.value == "system"
        assert TrustTier.USER.value == "user"
        assert TrustTier.HISTORY.value == "history"
        assert TrustTier.TOOL.value == "tool"

    def test_taint_level_values(self):
        assert TaintLevel.TRUSTED.value == "trusted"
        assert TaintLevel.UNTRUSTED.value == "untrusted"
        assert TaintLevel.MIXED.value == "mixed"

    def test_risk_level_values(self):
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"


# ---------------------------------------------------------------------------
# RiskSignals
# ---------------------------------------------------------------------------

class TestRiskSignals:
    def test_defaults(self):
        rs = RiskSignals()
        assert rs.has_instruction_patterns is False
        assert rs.has_obfuscation is False
        assert rs.has_zero_width_chars is False
        assert rs.suspicious_keywords == []
        assert rs.risk_score == 0.0
        assert rs.risk_level == RiskLevel.LOW

    def test_set_fields(self):
        rs = RiskSignals(
            has_instruction_patterns=True,
            risk_score=0.8,
            risk_level=RiskLevel.CRITICAL,
        )
        assert rs.has_instruction_patterns is True
        assert rs.risk_score == 0.8
        assert rs.risk_level == RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# ContentSummaryObject
# ---------------------------------------------------------------------------

class TestContentSummaryObject:
    def _make(self, summary='{"intent":"question"}', metadata=None):
        return ContentSummaryObject(
            summary=summary,
            metadata=metadata or {"length": 10, "word_count": 2},
            taint=TaintLevel.UNTRUSTED,
        )

    def test_default_taint_is_untrusted(self):
        cso = self._make()
        assert cso.taint == TaintLevel.UNTRUSTED

    def test_to_dict_contains_expected_keys(self):
        cso = self._make()
        d = cso.to_dict()
        for key in ("summary", "metadata", "taint", "risk_signals", "source", "timestamp"):
            assert key in d

    def test_to_dict_taint_is_string(self):
        cso = self._make()
        d = cso.to_dict()
        assert d["taint"] == "untrusted"

    def test_to_dict_risk_signals_structure(self):
        cso = self._make()
        d = cso.to_dict()
        rs = d["risk_signals"]
        assert "has_instruction_patterns" in rs
        assert "risk_score" in rs
        assert "risk_level" in rs

    def test_to_dict_timestamp_is_string(self):
        cso = self._make()
        d = cso.to_dict()
        assert isinstance(d["timestamp"], str)


# ---------------------------------------------------------------------------
# ActionProposal
# ---------------------------------------------------------------------------

class TestActionProposal:
    def test_defaults(self):
        ap = ActionProposal(action_type="response")
        assert ap.tool_name is None
        assert ap.parameters == {}
        assert ap.taint_metadata == {}
        assert ap.rationale == ""
        assert ap.derived_from == TrustTier.SYSTEM
        assert ap.risk_level == RiskLevel.LOW

    def test_to_dict_contains_expected_keys(self):
        ap = ActionProposal(action_type="response", parameters={"content": "hi"})
        d = ap.to_dict()
        for key in ("action_type", "tool_name", "parameters", "taint_metadata",
                    "rationale", "derived_from", "risk_level"):
            assert key in d

    def test_to_dict_enums_are_strings(self):
        ap = ActionProposal(
            action_type="tool_call",
            tool_name="search",
            taint_metadata={"q": TaintLevel.UNTRUSTED},
            derived_from=TrustTier.USER,
            risk_level=RiskLevel.HIGH,
        )
        d = ap.to_dict()
        assert d["derived_from"] == "user"
        assert d["risk_level"] == "high"
        assert d["taint_metadata"]["q"] == "untrusted"

    def test_to_dict_is_json_serialisable(self):
        ap = ActionProposal(action_type="response", parameters={"content": "hello"})
        # Should not raise
        json.dumps(ap.to_dict())


# ---------------------------------------------------------------------------
# PolicyRule – matches()
# ---------------------------------------------------------------------------

class TestPolicyRuleMatches:
    def _ap(self, action_type="tool_call", tool_name="my_tool", taint_meta=None):
        return ActionProposal(
            action_type=action_type,
            tool_name=tool_name,
            taint_metadata=taint_meta or {},
            derived_from=TrustTier.SYSTEM,
        )

    def test_denylist_matches_tool_name(self):
        rule = PolicyRule(rule_id="deny_my_tool", rule_type="denylist", target="my_tool")
        assert rule.matches(self._ap()) is True

    def test_denylist_matches_action_type(self):
        rule = PolicyRule(rule_id="deny_type", rule_type="denylist", target="tool_call")
        assert rule.matches(self._ap()) is True

    def test_denylist_no_match_different_tool(self):
        rule = PolicyRule(rule_id="deny_other", rule_type="denylist", target="other_tool")
        assert rule.matches(self._ap()) is False

    def test_allowlist_matches_tool_name(self):
        rule = PolicyRule(rule_id="allow_my_tool", rule_type="allowlist", target="my_tool")
        assert rule.matches(self._ap()) is True

    def test_taint_rule_matches_untrusted(self):
        rule = PolicyRule(rule_id="taint_api_key", rule_type="taint_rule", target="api_key")
        ap = self._ap(taint_meta={"api_key": TaintLevel.UNTRUSTED})
        assert rule.matches(ap) is True

    def test_taint_rule_no_match_trusted(self):
        rule = PolicyRule(rule_id="taint_api_key", rule_type="taint_rule", target="api_key")
        ap = self._ap(taint_meta={"api_key": TaintLevel.TRUSTED})
        assert rule.matches(ap) is False

    def test_taint_rule_no_match_missing_param(self):
        rule = PolicyRule(rule_id="taint_secret", rule_type="taint_rule", target="secret")
        assert rule.matches(self._ap()) is False


# ---------------------------------------------------------------------------
# PolicyDecision
# ---------------------------------------------------------------------------

class TestPolicyDecision:
    def test_approved_decision(self):
        pd = PolicyDecision(approved=True)
        assert pd.approved is True
        assert pd.rejection_reason is None
        assert pd.requires_approval is False

    def test_rejected_decision(self):
        pd = PolicyDecision(approved=False, rejection_reason="taint violation")
        assert pd.approved is False
        assert "taint" in pd.rejection_reason

    def test_requires_approval_flag(self):
        pd = PolicyDecision(approved=False, requires_approval=True)
        assert pd.requires_approval is True


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_to_dict_keys(self):
        al = AuditLog(event_type="test", data={"x": 1})
        d = al.to_dict()
        for key in ("timestamp", "event_type", "data", "taint_info", "risk_level"):
            assert key in d

    def test_to_dict_none_taint(self):
        al = AuditLog(event_type="test", data={})
        d = al.to_dict()
        assert d["taint_info"] is None

    def test_to_dict_taint_string(self):
        al = AuditLog(event_type="test", data={}, taint_info=TaintLevel.TRUSTED)
        d = al.to_dict()
        assert d["taint_info"] == "trusted"


# ---------------------------------------------------------------------------
# Trust tier ordering
# ---------------------------------------------------------------------------

class TestTrustTierOrdering:
    def test_system_has_highest_priority(self):
        assert trust_tier_priority(TrustTier.SYSTEM) == 1

    def test_tool_has_lowest_priority(self):
        assert trust_tier_priority(TrustTier.TOOL) == 4

    def test_ordering_is_correct(self):
        assert (
            trust_tier_priority(TrustTier.SYSTEM)
            < trust_tier_priority(TrustTier.USER)
            < trust_tier_priority(TrustTier.HISTORY)
            < trust_tier_priority(TrustTier.TOOL)
        )

    def test_can_override_higher_over_lower(self):
        assert can_override(TrustTier.SYSTEM, TrustTier.USER) is True
        assert can_override(TrustTier.SYSTEM, TrustTier.TOOL) is True
        assert can_override(TrustTier.USER, TrustTier.HISTORY) is True

    def test_cannot_override_lower_over_higher(self):
        assert can_override(TrustTier.USER, TrustTier.SYSTEM) is False
        assert can_override(TrustTier.TOOL, TrustTier.SYSTEM) is False

    def test_cannot_override_same_tier(self):
        assert can_override(TrustTier.USER, TrustTier.USER) is False

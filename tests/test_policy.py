"""
Tests for policy enforcement.
"""

import pytest

from sieve.models import ActionProposal, PolicyRule, TrustTier, RiskLevel, TaintLevel
from sieve.policy import validate_action, get_policy_engine


def test_policy_allow_safe_action():
    """Test policy allows safe actions."""
    action = ActionProposal(
        action_type="response",
        parameters={"content": "Hello"},
        taint_metadata={},
        derived_from=TrustTier.SYSTEM,
        risk_level=RiskLevel.LOW,
    )
    
    decision = validate_action(action)
    assert decision.approved is True


def test_policy_reject_taint_violation():
    """Test policy rejects taint violations."""
    action = ActionProposal(
        action_type="tool_call",
        tool_name="test_tool",
        parameters={"api_key": "secret"},
        taint_metadata={"api_key": TaintLevel.UNTRUSTED},
        derived_from=TrustTier.SYSTEM,
        risk_level=RiskLevel.LOW,
    )
    
    decision = validate_action(action)
    assert decision.approved is False
    assert "taint violation" in decision.rejection_reason.lower()


def test_policy_denylist():
    """Test policy denylist."""
    engine = get_policy_engine()
    
    # Add denylist rule
    rule = PolicyRule(
        rule_id="deny_test_tool",
        rule_type="denylist",
        target="test_tool",
        action="reject",
    )
    engine.add_rule(rule)
    
    action = ActionProposal(
        action_type="tool_call",
        tool_name="test_tool",
        parameters={},
        taint_metadata={},
        derived_from=TrustTier.SYSTEM,
        risk_level=RiskLevel.LOW,
    )
    
    decision = validate_action(action, engine)
    assert decision.approved is False


def test_policy_critical_risk():
    """Test policy rejects critical risk actions."""
    action = ActionProposal(
        action_type="tool_call",
        tool_name="dangerous_tool",
        parameters={},
        taint_metadata={},
        derived_from=TrustTier.SYSTEM,
        risk_level=RiskLevel.CRITICAL,
    )
    
    decision = validate_action(action)
    assert decision.approved is False
    assert decision.requires_approval is True


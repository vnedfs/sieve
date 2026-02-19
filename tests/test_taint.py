"""
Tests for taint tracking.
"""

import pytest

from sieve.models import ActionProposal, TaintLevel, TrustTier, RiskLevel
from sieve.taint import (
    mark_taint,
    propagate_taint,
    check_taint_violation,
    merge_taint_metadata,
)


def test_mark_taint_dict():
    """Test marking taint on dictionary."""
    data = {"param1": "value1", "param2": "value2"}
    taint_map = mark_taint(data, TaintLevel.UNTRUSTED)
    
    assert taint_map["param1"] == TaintLevel.UNTRUSTED
    assert taint_map["param2"] == TaintLevel.UNTRUSTED


def test_propagate_taint():
    """Test taint propagation rules."""
    # UNTRUSTED + anything = UNTRUSTED
    assert propagate_taint(TaintLevel.UNTRUSTED, TaintLevel.TRUSTED) == TaintLevel.UNTRUSTED
    assert propagate_taint(TaintLevel.TRUSTED, TaintLevel.UNTRUSTED) == TaintLevel.UNTRUSTED
    
    # MIXED + TRUSTED = MIXED
    assert propagate_taint(TaintLevel.MIXED, TaintLevel.TRUSTED) == TaintLevel.MIXED
    
    # TRUSTED + TRUSTED = TRUSTED
    assert propagate_taint(TaintLevel.TRUSTED, TaintLevel.TRUSTED) == TaintLevel.TRUSTED


def test_check_taint_violation_sensitive_param():
    """Test taint violation detection in sensitive parameters."""
    action = ActionProposal(
        action_type="tool_call",
        tool_name="test_tool",
        parameters={"api_key": "secret123"},
        taint_metadata={"api_key": TaintLevel.UNTRUSTED},
        derived_from=TrustTier.SYSTEM,
        risk_level=RiskLevel.LOW,
    )
    
    violations = check_taint_violation(action)
    assert len(violations) > 0
    assert any("api_key" in v for v in violations)


def test_check_taint_violation_safe_param():
    """Test no violation for trusted data in sensitive params."""
    action = ActionProposal(
        action_type="tool_call",
        tool_name="test_tool",
        parameters={"api_key": "secret123"},
        taint_metadata={"api_key": TaintLevel.TRUSTED},
        derived_from=TrustTier.SYSTEM,
        risk_level=RiskLevel.LOW,
    )
    
    violations = check_taint_violation(action)
    assert len(violations) == 0


def test_merge_taint_metadata():
    """Test merging taint metadata."""
    metadata1 = {"param1": TaintLevel.TRUSTED, "param2": TaintLevel.UNTRUSTED}
    metadata2 = {"param2": TaintLevel.TRUSTED, "param3": TaintLevel.MIXED}
    
    merged = merge_taint_metadata(metadata1, metadata2)
    
    assert merged["param1"] == TaintLevel.TRUSTED
    assert merged["param2"] == TaintLevel.UNTRUSTED  # UNTRUSTED + TRUSTED = UNTRUSTED
    assert merged["param3"] == TaintLevel.MIXED


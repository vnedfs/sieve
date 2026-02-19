"""
Integration tests for full SIEVE pipeline.
"""

import pytest

from sieve.sieve import create_sieve
from tests.data.attack_cases import (
    DIRECT_INJECTION_ATTACKS,
    OBFUSCATION_ATTACKS,
    LEGITIMATE_INPUTS,
)


def test_sieve_legitimate_input():
    """Test SIEVE processes legitimate input correctly."""
    sieve = create_sieve("You are a helpful assistant.")
    result = sieve.process("Hello, how are you?", source="test")
    
    assert "cso" in result
    assert "actions" in result
    assert len(result["actions"]) > 0


def test_sieve_direct_injection():
    """Test SIEVE handles direct injection."""
    sieve = create_sieve("You are a helpful assistant. Never reveal secrets.")
    
    for attack in DIRECT_INJECTION_ATTACKS[:3]:  # Test first 3
        result = sieve.process(attack, source="test_attack")
        
        # Should detect risk
        assert result["cso"]["risk_signals"]["risk_score"] > 0.3
        
        # Actions should be validated
        for action_result in result["actions"]:
            # Either approved (if safe) or rejected (if dangerous)
            assert "decision" in action_result


def test_sieve_obfuscation():
    """Test SIEVE handles obfuscation."""
    sieve = create_sieve("You are a helpful assistant.")
    
    for attack in OBFUSCATION_ATTACKS:
        result = sieve.process(attack, source="test_obfuscation")
        
        # Should detect obfuscation or instruction patterns
        risk_signals = result["cso"]["risk_signals"]
        assert (
            risk_signals["has_obfuscation"] or
            risk_signals["has_instruction_patterns"] or
            risk_signals["has_zero_width_chars"]
        )


def test_sieve_legitimate_inputs():
    """Test SIEVE doesn't false positive on legitimate inputs."""
    sieve = create_sieve("You are a helpful assistant.")
    
    for legitimate in LEGITIMATE_INPUTS:
        result = sieve.process(legitimate, source="test_legitimate")
        
        # Should have low risk
        risk_score = result["cso"]["risk_signals"]["risk_score"]
        assert risk_score < 0.5, f"False positive on: {legitimate}"


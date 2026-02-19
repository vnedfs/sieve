"""
Core data models for SIEVE.

Defines strongly-typed structures for instructions, data, actions, and policy.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

import pydantic


class TrustTier(str, Enum):
    """Trust hierarchy for instructions and data."""
    
    SYSTEM = "system"      # Tier 1: System prompts, highest priority
    USER = "user"          # Tier 2: User messages
    HISTORY = "history"    # Tier 3: Conversational history
    TOOL = "tool"          # Tier 4: Tool/API outputs (passive data only)


class TaintLevel(str, Enum):
    """Taint levels for data tracking."""
    
    TRUSTED = "trusted"      # Originates from trusted instructions
    UNTRUSTED = "untrusted"  # Originates from untrusted data
    MIXED = "mixed"          # Combination of trusted and untrusted


class RiskLevel(str, Enum):
    """Risk levels for actions and data."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskSignals:
    """Risk signals detected during quarantine."""
    
    has_instruction_patterns: bool = False
    has_obfuscation: bool = False
    has_zero_width_chars: bool = False
    suspicious_keywords: List[str] = field(default_factory=list)
    risk_score: float = 0.0  # [0.0, 1.0]
    risk_level: RiskLevel = RiskLevel.LOW


@dataclass
class ContentSummaryObject:
    """
    Structured representation of untrusted data.
    
    Key property: Does NOT contain raw untrusted text that could be
    interpreted as instructions. Only structured, sanitized content.
    """
    
    summary: str  # Extracted content summary (sanitized)
    metadata: Dict[str, Any]  # Structured metadata
    taint: TaintLevel = TaintLevel.UNTRUSTED  # Always UNTRUSTED for CSO
    risk_signals: RiskSignals = field(default_factory=RiskSignals)
    source: Optional[str] = None  # Source identifier (e.g., "user_input", "rag_doc_123")
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "summary": self.summary,
            "metadata": self.metadata,
            "taint": self.taint.value,
            "risk_signals": {
                "has_instruction_patterns": self.risk_signals.has_instruction_patterns,
                "has_obfuscation": self.risk_signals.has_obfuscation,
                "has_zero_width_chars": self.risk_signals.has_zero_width_chars,
                "suspicious_keywords": self.risk_signals.suspicious_keywords,
                "risk_score": self.risk_signals.risk_score,
                "risk_level": self.risk_signals.risk_level.value,
            },
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ActionProposal:
    """
    Proposed action from the privileged layer.
    
    Must be validated by policy before execution.
    """
    
    action_type: str  # e.g., "tool_call", "response", "query"
    tool_name: Optional[str] = None  # If action_type is "tool_call"
    parameters: Dict[str, Any] = field(default_factory=dict)
    taint_metadata: Dict[str, TaintLevel] = field(default_factory=dict)  # Taint per parameter
    rationale: str = ""  # Why this action was proposed
    derived_from: TrustTier = TrustTier.SYSTEM  # Which trust tier this derives from
    risk_level: RiskLevel = RiskLevel.LOW
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "action_type": self.action_type,
            "tool_name": self.tool_name,
            "parameters": self.parameters,
            "taint_metadata": {k: v.value for k, v in self.taint_metadata.items()},
            "rationale": self.rationale,
            "derived_from": self.derived_from.value,
            "risk_level": self.risk_level.value,
        }


@dataclass
class PolicyRule:
    """Policy rule for action validation."""
    
    rule_id: str
    rule_type: str  # "allowlist", "denylist", "taint_rule", "schema_validation"
    target: str  # What this rule applies to (tool name, action type, etc.)
    condition: Optional[Dict[str, Any]] = None  # Conditions for rule application
    action: str = "reject"  # "allow", "reject", "require_approval"
    
    def matches(self, action: ActionProposal) -> bool:
        """Check if this rule matches the given action."""
        if self.rule_type == "allowlist":
            return action.tool_name == self.target or action.action_type == self.target
        elif self.rule_type == "denylist":
            return action.tool_name == self.target or action.action_type == self.target
        elif self.rule_type == "taint_rule":
            # Check if tainted data is in sensitive parameters
            if self.target in action.taint_metadata:
                return action.taint_metadata[self.target] == TaintLevel.UNTRUSTED
        return False


@dataclass
class PolicyDecision:
    """Result of policy validation."""
    
    approved: bool
    action: Optional[ActionProposal] = None  # May be modified
    rejection_reason: Optional[str] = None
    requires_approval: bool = False
    applied_rules: List[str] = field(default_factory=list)


@dataclass
class AuditLog:
    """Audit log entry."""
    
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_type: str = ""  # "input_received", "quarantine", "action_proposed", "policy_decision", "tool_executed"
    data: Dict[str, Any] = field(default_factory=dict)
    taint_info: Optional[TaintLevel] = None
    risk_level: Optional[RiskLevel] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "data": self.data,
            "taint_info": self.taint_info.value if self.taint_info else None,
            "risk_level": self.risk_level.value if self.risk_level else None,
        }


# Pydantic models for JSON schema validation

class ToolCallSchema(pydantic.BaseModel):
    """Schema for tool call actions."""
    
    tool_name: str
    parameters: Dict[str, Any]
    
    class Config:
        extra = "forbid"  # Reject unknown fields


class ResponseSchema(pydantic.BaseModel):
    """Schema for response actions."""
    
    content: str
    format: Optional[str] = None
    
    class Config:
        extra = "forbid"


# Trust tier ordering
TRUST_TIER_ORDER = {
    TrustTier.SYSTEM: 1,
    TrustTier.USER: 2,
    TrustTier.HISTORY: 3,
    TrustTier.TOOL: 4,
}


def trust_tier_priority(tier: TrustTier) -> int:
    """Get priority value for trust tier (lower = higher priority)."""
    return TRUST_TIER_ORDER.get(tier, 99)


def can_override(higher: TrustTier, lower: TrustTier) -> bool:
    """Check if higher tier can override lower tier."""
    return trust_tier_priority(higher) < trust_tier_priority(lower)


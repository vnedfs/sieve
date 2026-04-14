"""
Policy enforcement layer.

Threat mitigated: Unauthorized actions, policy violations
Invariant: All actions conform to defined policy
"""

from typing import List, Optional, Dict, Any, Tuple
import json
import jsonschema

from sieve.models import (
    ActionProposal,
    PolicyRule,
    PolicyDecision,
    RiskLevel,
    TaintLevel,
    ContentSummaryObject,
)
from sieve.taint import check_taint_violation, SENSITIVE_PARAMETERS
from sieve.reasoning import verify_properties, PropertyStatus


class PolicyEngine:
    """
    Policy enforcement engine.
    
    Validation layers:
    1. JSON Schema Validation
    2. Allowlist/Denylist Checks
    3. Taint Rules (no untrusted data in sensitive parameters)
    4. Risk Assessment
    """
    
    def __init__(self, rules: Optional[List[PolicyRule]] = None, use_formal_reasoning: bool = True):
        """
        Initialize policy engine.
        
        Args:
            rules: Optional list of policy rules
            use_formal_reasoning: Whether to use formal property verification
        """
        self.rules = rules or []
        self._default_rules = self._create_default_rules()
        self._all_rules = self._default_rules + self.rules
        self.use_formal_reasoning = use_formal_reasoning
    
    def validate(self, 
                 action: ActionProposal,
                 trusted_instructions: Optional[str] = None,
                 cso: Optional[ContentSummaryObject] = None) -> PolicyDecision:
        """
        Validate action against policy.
        
        Args:
            action: Action proposal to validate
            trusted_instructions: Optional trusted instructions for formal reasoning
            cso: Optional CSO for formal reasoning
            
        Returns:
            PolicyDecision with approval status
        """
        applied_rules = []
        rejection_reasons = []
        
        # Layer 0: Formal Property Verification (if enabled)
        if self.use_formal_reasoning and trusted_instructions and cso:
            property_checks = verify_properties(action, trusted_instructions, cso)
            
            # Check if any property is violated
            for check in property_checks:
                if check.status == PropertyStatus.VIOLATED:
                    return PolicyDecision(
                        approved=False,
                        rejection_reason=f"Formal property violation: {check.property_name} - {check.violation_details}",
                        applied_rules=["formal_reasoning"],
                    )
                elif check.status == PropertyStatus.UNKNOWN:
                    # Unknown status: reject by default (fail-safe)
                    return PolicyDecision(
                        approved=False,
                        rejection_reason=f"Formal property status unknown: {check.property_name} (fail-safe rejection)",
                        applied_rules=["formal_reasoning"],
                    )
            
            applied_rules.append("formal_reasoning")
        
        # Layer 1: Schema Validation
        schema_valid, schema_error = self._validate_schema(action)
        if not schema_valid:
            return PolicyDecision(
                approved=False,
                rejection_reason=f"Schema validation failed: {schema_error}",
                applied_rules=["schema_validation"],
            )
        applied_rules.append("schema_validation")
        
        # Layer 2: Taint Rules
        taint_violations = check_taint_violation(action)
        # Separate hard violations from warnings
        hard_violations = [v for v in taint_violations if "violation" in v.lower() and "monitor" not in v.lower()]
        warnings = [v for v in taint_violations if "monitor" in v.lower()]
        
        if hard_violations:
            return PolicyDecision(
                approved=False,
                rejection_reason=f"Taint violation: {', '.join(hard_violations)}",
                applied_rules=["taint_rule"],
            )
        # Warnings are logged but don't block (CSO-derived structured fields are allowed)
        if warnings:
            applied_rules.append("taint_rule_warning")
        applied_rules.append("taint_rule")
        
        # Layer 3: Allowlist/Denylist
        for rule in self._all_rules:
            if rule.matches(action):
                applied_rules.append(rule.rule_id)
                
                if rule.rule_type == "denylist":
                    return PolicyDecision(
                        approved=False,
                        rejection_reason=f"Action denied by rule: {rule.rule_id}",
                        applied_rules=applied_rules,
                    )
                elif rule.rule_type == "allowlist":
                    # Allowlist match - continue validation
                    pass
                elif rule.rule_type == "taint_rule":
                    # Already checked above
                    pass
        
        # Layer 4: Risk Assessment
        requires_approval = False
        if action.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            requires_approval = True
            # For now, we reject high-risk actions
            # In production, this might queue for human approval
            if action.risk_level == RiskLevel.CRITICAL:
                return PolicyDecision(
                    approved=False,
                    rejection_reason="Critical risk level requires approval",
                    applied_rules=applied_rules,
                    requires_approval=True,
                )
        
        # All checks passed
        return PolicyDecision(
            approved=True,
            action=action,
            applied_rules=applied_rules,
            requires_approval=requires_approval,
        )
    
    def _validate_schema(self, action: ActionProposal) -> Tuple[bool, Optional[str]]:
        """
        Validate action against JSON schema.

        Only the fields that the schema cares about (action_type, tool_name,
        parameters) are passed to the validator.  Internal tracking fields
        (taint_metadata, derived_from, risk_level, rationale) are intentionally
        excluded so that schemas with additionalProperties:false do not reject
        otherwise-valid actions.

        Args:
            action: Action proposal

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Build a dict that contains only schema-visible fields
            if action.action_type == "tool_call":
                action_dict = {
                    "action_type": action.action_type,
                    "tool_name": action.tool_name,
                    "parameters": action.parameters,
                }
            elif action.action_type == "response":
                action_dict = {
                    "action_type": action.action_type,
                    "parameters": action.parameters,
                }
            else:
                # Unknown action type – fall back to full dict
                action_dict = action.to_dict()

            # Get schema based on action type
            schema = self._get_schema_for_action_type(action.action_type)
            if schema is None:
                # No schema defined – allow
                return True, None

            # Validate
            jsonschema.validate(instance=action_dict, schema=schema)
            return True, None

        except jsonschema.ValidationError as e:
            return False, str(e)
        except Exception as e:
            return False, f"Schema validation error: {str(e)}"
    
    def _get_schema_for_action_type(self, action_type: str) -> Optional[Dict[str, Any]]:
        """
        Get JSON schema for action type.
        
        Args:
            action_type: Type of action
            
        Returns:
            JSON schema dict or None
        """
        schemas = {
            "tool_call": {
                "type": "object",
                "properties": {
                    "action_type": {"type": "string", "const": "tool_call"},
                    "tool_name": {"type": "string"},
                    "parameters": {
                        "type": "object",
                        "additionalProperties": {
                            "type": ["string", "number", "boolean", "array", "object", "null"]
                        },
                        # Restrict parameter values to prevent injection
                        "patternProperties": {
                            ".*": {
                                "not": {
                                    # Reject parameters that look like commands
                                    "pattern": "^(ignore|forget|disregard|system:|instruction:)"
                                }
                            }
                        }
                    },
                },
                "required": ["action_type", "tool_name", "parameters"],
                "additionalProperties": False,
            },
            "response": {
                "type": "object",
                "properties": {
                    "action_type": {"type": "string", "const": "response"},
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "content": {"type": "string"},
                        },
                        "required": ["content"],
                    },
                },
                "required": ["action_type", "parameters"],
                "additionalProperties": False,
            },
        }
        
        return schemas.get(action_type)
    
    def _create_default_rules(self) -> List[PolicyRule]:
        """Create default policy rules."""
        rules = []
        
        # Deny actions with untrusted data in sensitive parameters
        for sensitive_param in SENSITIVE_PARAMETERS:
            rules.append(PolicyRule(
                rule_id=f"taint_rule_{sensitive_param}",
                rule_type="taint_rule",
                target=sensitive_param,
                action="reject",
            ))
        
        return rules
    
    def add_rule(self, rule: PolicyRule):
        """Add a policy rule."""
        self.rules.append(rule)
        self._all_rules = self._default_rules + self.rules
    
    def remove_rule(self, rule_id: str):
        """Remove a policy rule by ID."""
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        self._all_rules = self._default_rules + self.rules


# Global instance
_policy_engine = None


def get_policy_engine(rules: Optional[List[PolicyRule]] = None) -> PolicyEngine:
    """Get singleton policy engine."""
    global _policy_engine
    if _policy_engine is None or rules is not None:
        _policy_engine = PolicyEngine(rules)
    return _policy_engine


def validate_action(action: ActionProposal, 
                   policy_engine: Optional[PolicyEngine] = None,
                   trusted_instructions: Optional[str] = None,
                   cso: Optional[ContentSummaryObject] = None) -> PolicyDecision:
    """
    Convenience function to validate an action.
    
    Args:
        action: Action proposal
        policy_engine: Optional policy engine (uses default if not provided)
        trusted_instructions: Optional trusted instructions for formal reasoning
        cso: Optional CSO for formal reasoning
        
    Returns:
        PolicyDecision
    """
    if policy_engine is None:
        policy_engine = get_policy_engine()
    return policy_engine.validate(action, trusted_instructions, cso)


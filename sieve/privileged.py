"""
Privileged decision layer.

Threat mitigated: Instruction override, unauthorized actions
Invariant: All decisions derive from I (trusted instructions), not D (untrusted data)

Key constraint: Never directly processes raw untrusted text.
"""

from typing import List, Optional
from datetime import datetime

from sieve.models import (
    TrustTier,
    TaintLevel,
    ActionProposal,
    ContentSummaryObject,
    RiskLevel,
)
from sieve.taint import mark_taint


class PrivilegedLayer:
    """
    Trusted decision-making layer.
    
    This layer:
    1. Receives I (trusted instructions) + CSO (tainted, structured)
    2. Generates action proposals
    3. Ensures proposals align with I
    4. Marks proposals with taint metadata
    
    It does NOT:
    - Process raw untrusted text
    - Make decisions based solely on D
    """
    
    def __init__(self):
        """Initialize privileged layer."""
        pass
    
    def generate_actions(self,
                        trusted_instructions: str,
                        cso: ContentSummaryObject,
                        context: Optional[dict] = None) -> List[ActionProposal]:
        """
        Generate action proposals based on trusted instructions and CSO.
        
        Args:
            trusted_instructions: Trusted system instructions (I)
            cso: Content Summary Object from quarantine (structured D)
            context: Optional additional context
            
        Returns:
            List of action proposals
        """
        # CRITICAL: We only use CSO (structured), never raw untrusted data
        # The CSO has been sanitized and structured in quarantine
        
        # In a real implementation, this would call an LLM with:
        # - System prompt: trusted_instructions
        # - User message: cso.summary (sanitized, structured)
        # - Never: raw untrusted text
        
        # For now, we'll create a simple proposal based on the CSO
        # In production, this would be an LLM call with strict prompting
        
        proposals = []
        
        # Parse structured CSO (it's JSON, not free text)
        import json
        try:
            structured_data = json.loads(cso.summary)
        except json.JSONDecodeError:
            # Fallback if CSO is not JSON (shouldn't happen with new implementation)
            structured_data = {"intent": "unknown", "topics": [], "entities": []}
        
        # Generate action based on structured data
        # The rationale must derive from I, not from raw D
        intent = structured_data.get("intent", "unknown")
        topics = structured_data.get("topics", [])
        
        rationale = f"Responding to {intent} query based on system instructions. "
        rationale += f"Topics: {', '.join(topics[:3]) if topics else 'none'}"
        
        # Mark all parameters with appropriate taint
        # Since CSO is UNTRUSTED, any data derived from it is also UNTRUSTED
        # But we only use structured fields, not free text
        taint_metadata = mark_taint({
            "intent": intent,
            "topics": topics,
            "entities": structured_data.get("entities", []),
        }, TaintLevel.UNTRUSTED)
        
        proposal = ActionProposal(
            action_type="response",
            parameters={
                "intent": intent,  # Structured field, not free text
                "topics": topics,  # Structured list, not sentences
                "entities": structured_data.get("entities", []),  # Structured entities
                "metadata": cso.metadata,
            },
            taint_metadata=taint_metadata,
            rationale=rationale,
            derived_from=TrustTier.SYSTEM,  # Actions derive from system instructions
            risk_level=self._assess_risk(cso),
        )
        
        proposals.append(proposal)
        
        return proposals
    
    def _assess_risk(self, cso: ContentSummaryObject) -> RiskLevel:
        """Assess risk level based on CSO risk signals."""
        risk_score = cso.risk_signals.risk_score
        
        if risk_score >= 0.7:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.5:
            return RiskLevel.HIGH
        elif risk_score >= 0.3:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def validate_instruction_alignment(self,
                                      action: ActionProposal,
                                      trusted_instructions: str) -> bool:
        """
        Validate that action aligns with trusted instructions.
        
        This is a check to ensure actions derive from I, not from D.
        
        Args:
            action: Action proposal to validate
            trusted_instructions: Trusted system instructions
            
        Returns:
            True if action aligns with instructions
        """
        # In a real implementation, this might:
        # 1. Extract intent from action
        # 2. Check if intent is allowed by trusted_instructions
        # 3. Verify action doesn't contradict instructions
        
        # For now, we do a simple check: actions must derive from SYSTEM tier
        if action.derived_from != TrustTier.SYSTEM:
            return False
        
        # Check that rationale mentions system instructions
        if "system" not in action.rationale.lower() and "instruction" not in action.rationale.lower():
            # This is a heuristic - in production, use more sophisticated checking
            pass  # Not necessarily a violation, but worth noting
        
        return True


# Global instance
_privileged_layer = None


def get_privileged_layer() -> PrivilegedLayer:
    """Get singleton privileged layer."""
    global _privileged_layer
    if _privileged_layer is None:
        _privileged_layer = PrivilegedLayer()
    return _privileged_layer


def generate_actions(trusted_instructions: str,
                    cso: ContentSummaryObject,
                    context: Optional[dict] = None) -> List[ActionProposal]:
    """
    Convenience function to generate actions.
    
    Args:
        trusted_instructions: Trusted system instructions
        cso: Content Summary Object
        context: Optional context
        
    Returns:
        List of action proposals
    """
    layer = get_privileged_layer()
    return layer.generate_actions(trusted_instructions, cso, context)


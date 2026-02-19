"""
Main SIEVE entry point.

Orchestrates the full pipeline: Quarantine → Privileged → Policy → Execution
"""

from typing import List, Optional, Dict, Any

from sieve.models import (
    ActionProposal,
    PolicyDecision,
    ContentSummaryObject,
    TrustTier,
)
from sieve.quarantine import quarantine
from sieve.privileged import generate_actions
from sieve.policy import validate_action, get_policy_engine
from sieve.tools import execute_tool
from sieve.audit import (
    log_input_received,
    log_quarantine,
    log_action_proposed,
    log_policy_decision,
)


class SIEVE:
    """
    Main SIEVE orchestrator.
    
    Implements the full pipeline:
    1. Quarantine: Process untrusted data → CSO
    2. Privileged: Generate actions from I + CSO
    3. Policy: Validate actions
    4. Execution: Execute approved actions
    """
    
    def __init__(self, trusted_instructions: str):
        """
        Initialize SIEVE.
        
        Args:
            trusted_instructions: Trusted system instructions (I)
        """
        self.trusted_instructions = trusted_instructions
        self.policy_engine = get_policy_engine()
    
    def process(self,
               untrusted_data: str,
               source: Optional[str] = None,
               execute: bool = False) -> Dict[str, Any]:
        """
        Process untrusted data through the SIEVE pipeline.
        
        Args:
            untrusted_data: Raw untrusted input (D)
            source: Optional source identifier
            execute: Whether to execute approved actions (default: False)
            
        Returns:
            Dictionary with processing results
        """
        # Log input
        log_input_received(untrusted_data, source, taint=None)  # Will be UNTRUSTED
        
        # Stage 1: QUARANTINE
        cso = quarantine(untrusted_data, source)
        log_quarantine(cso.to_dict(), cso.risk_signals.risk_level)
        
        # Stage 2: PRIVILEGED
        # Generate actions from I (trusted) + CSO (structured, tainted)
        actions = generate_actions(
            self.trusted_instructions,
            cso,
            context=None,
        )
        
        results = {
            "cso": cso.to_dict(),
            "actions": [],
            "executions": [],
        }
        
        # Stage 3: POLICY + Stage 4: EXECUTION
        for action in actions:
            log_action_proposed(action.to_dict(), action.risk_level)
            
            # Validate action (with formal reasoning)
            decision = validate_action(
                action, 
                self.policy_engine,
                trusted_instructions=self.trusted_instructions,
                cso=cso
            )
            log_policy_decision(decision.approved, decision.rejection_reason)
            
            action_result = {
                "action": action.to_dict(),
                "decision": {
                    "approved": decision.approved,
                    "rejection_reason": decision.rejection_reason,
                    "requires_approval": decision.requires_approval,
                    "applied_rules": decision.applied_rules,
                },
            }
            
            if decision.approved and execute:
                # Execute action
                try:
                    if action.action_type == "tool_call":
                        execution_result = execute_tool(action, decision)
                        action_result["execution"] = {
                            "success": True,
                            "result": str(execution_result)[:200],  # Truncate
                        }
                        results["executions"].append(action_result["execution"])
                    else:
                        # Non-tool actions (e.g., responses) are handled differently
                        action_result["execution"] = {
                            "success": True,
                            "note": "Non-tool action, execution handled by caller",
                        }
                except Exception as e:
                    action_result["execution"] = {
                        "success": False,
                        "error": str(e),
                    }
            
            results["actions"].append(action_result)
        
        return results
    
    def process_batch(self,
                     untrusted_data_list: List[str],
                     sources: Optional[List[str]] = None,
                     execute: bool = False) -> List[Dict[str, Any]]:
        """
        Process multiple untrusted inputs.
        
        Args:
            untrusted_data_list: List of untrusted inputs
            sources: Optional list of source identifiers
            execute: Whether to execute approved actions
            
        Returns:
            List of processing results
        """
        if sources is None:
            sources = [None] * len(untrusted_data_list)
        
        results = []
        for data, source in zip(untrusted_data_list, sources):
            result = self.process(data, source, execute)
            results.append(result)
        
        return results


def create_sieve(trusted_instructions: str) -> SIEVE:
    """
    Create a SIEVE instance.
    
    Args:
        trusted_instructions: Trusted system instructions
        
    Returns:
        SIEVE instance
    """
    return SIEVE(trusted_instructions)


"""
Tool execution gate.

Threat mitigated: Unauthorized tool usage
Invariant: Only approved, validated actions execute
"""

from typing import Any, Dict, List, Optional, Callable
from datetime import datetime

from sieve.models import (
    ActionProposal,
    PolicyDecision,
    TaintLevel,
    AuditLog,
)
from sieve.taint import mark_taint
from sieve.audit import log_event


class ToolRegistry:
    """
    Centralized tool registry.
    
    All tool executions must go through this registry.
    """
    
    def __init__(self):
        """Initialize tool registry."""
        self._tools: Dict[str, Callable] = {}
        self._tool_schemas: Dict[str, Dict[str, Any]] = {}
        self._execution_count = 0
    
    def register_tool(self,
                     tool_name: str,
                     tool_func: Callable,
                     schema: Optional[Dict[str, Any]] = None):
        """
        Register a tool.
        
        Args:
            tool_name: Name of the tool
            tool_func: Function to execute
            schema: Optional JSON schema for parameters
        """
        self._tools[tool_name] = tool_func
        if schema:
            self._tool_schemas[tool_name] = schema
    
    def execute(self,
               action: ActionProposal,
               policy_decision: PolicyDecision) -> Any:
        """
        Execute a tool action.
        
        Args:
            action: Action proposal
            policy_decision: Policy decision (must be approved)
            
        Returns:
            Tool execution result
            
        Raises:
            ValueError: If action is not approved or tool not found
        """
        # Verify action is approved
        if not policy_decision.approved:
            raise ValueError(f"Action not approved: {policy_decision.rejection_reason}")
        
        # Verify action type
        if action.action_type != "tool_call":
            raise ValueError(f"Action type '{action.action_type}' is not a tool call")
        
        # Verify tool exists
        if action.tool_name not in self._tools:
            raise ValueError(f"Tool '{action.tool_name}' not found")
        
        # Log execution
        log_event(
            event_type="tool_execution_start",
            data={
                "tool_name": action.tool_name,
                "parameters": action.parameters,
            },
            taint_info=TaintLevel.UNTRUSTED if any(
                t == TaintLevel.UNTRUSTED for t in action.taint_metadata.values()
            ) else TaintLevel.TRUSTED,
        )
        
        try:
            # Execute tool
            tool_func = self._tools[action.tool_name]
            result = tool_func(**action.parameters)
            
            # Mark result with taint
            # If any input was untrusted, output is also untrusted
            output_taint = TaintLevel.TRUSTED
            if any(t == TaintLevel.UNTRUSTED for t in action.taint_metadata.values()):
                output_taint = TaintLevel.UNTRUSTED
            elif any(t == TaintLevel.MIXED for t in action.taint_metadata.values()):
                output_taint = TaintLevel.MIXED
            
            self._execution_count += 1
            
            # Log success
            log_event(
                event_type="tool_execution_success",
                data={
                    "tool_name": action.tool_name,
                    "result": str(result)[:200],  # Truncate for logging
                },
            )
            
            return result
            
        except Exception as e:
            # Log failure
            log_event(
                event_type="tool_execution_error",
                data={
                    "tool_name": action.tool_name,
                    "error": str(e),
                },
            )
            raise
    
    def list_tools(self) -> List[str]:
        """List all registered tools."""
        return list(self._tools.keys())
    
    def get_tool_schema(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get schema for a tool."""
        return self._tool_schemas.get(tool_name)


# Global registry
_tool_registry = None


def get_tool_registry() -> ToolRegistry:
    """Get singleton tool registry."""
    global _tool_registry
    if _tool_registry is None:
        _tool_registry = ToolRegistry()
    return _tool_registry


def register_tool(tool_name: str,
                  tool_func: Callable,
                  schema: Optional[Dict[str, Any]] = None):
    """
    Register a tool.
    
    Args:
        tool_name: Name of the tool
        tool_func: Function to execute
        schema: Optional JSON schema for parameters
    """
    registry = get_tool_registry()
    registry.register_tool(tool_name, tool_func, schema)


def execute_tool(action: ActionProposal,
                policy_decision: PolicyDecision) -> Any:
    """
    Execute a tool action.
    
    Args:
        action: Action proposal
        policy_decision: Policy decision (must be approved)
        
    Returns:
        Tool execution result
    """
    registry = get_tool_registry()
    return registry.execute(action, policy_decision)


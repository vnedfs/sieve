"""
Taint tracking system.

Threat mitigated: Data exfiltration, unauthorized tool usage
Invariant: Untrusted data cannot flow into sensitive parameters
"""

from typing import Any, Dict, List, Set
from copy import deepcopy

from sieve.models import TaintLevel, ActionProposal


# Parameters that are considered sensitive and should not accept untrusted data
SENSITIVE_PARAMETERS: Set[str] = {
    'api_key',
    'apiKey',
    'secret',
    'password',
    'token',
    'credential',
    'file_path',
    'filePath',
    'filepath',
    'path',
    'command',
    'cmd',
    'query',
    'sql',
    'url',
    'endpoint',
    'host',
    'database',
    'db',
    'auth',
    'authorization',
    'private_key',
    'privateKey',
    'ssh_key',
    'sshKey',
}

# Decision-making parameters that should not have UNTRUSTED taint
# These are parameters used to determine what action to take, not just execute it
DECISION_MAKING_PARAMETERS: Set[str] = {
    'rationale',
    'action_type',
    'tool_name',
    'intent',  # CSO-derived: categorical intent could influence decisions
    'topics',  # CSO-derived: topics could influence decision-making
    'entities',  # CSO-derived: entities like URLs/emails carry semantic content
}


def mark_taint(data: Any, taint_level: TaintLevel) -> Dict[str, TaintLevel]:
    """
    Mark data with taint level.
    
    Args:
        data: Data to mark (dict, list, or primitive)
        taint_level: Taint level to apply
        
    Returns:
        Dictionary mapping parameter names to taint levels
    """
    taint_map = {}
    
    if isinstance(data, dict):
        for key, value in data.items():
            taint_map[key] = taint_level
            # Recursively mark nested structures
            if isinstance(value, (dict, list)):
                nested_taint = mark_taint(value, taint_level)
                taint_map.update({f"{key}.{k}": v for k, v in nested_taint.items()})
    elif isinstance(data, list):
        for i, item in enumerate(data):
            taint_map[f"[{i}]"] = taint_level
            if isinstance(item, (dict, list)):
                nested_taint = mark_taint(item, taint_level)
                taint_map.update({f"[{i}].{k}": v for k, v in nested_taint.items()})
    else:
        # Primitive value
        taint_map["value"] = taint_level
    
    return taint_map


def propagate_taint(taint1: TaintLevel, taint2: TaintLevel) -> TaintLevel:
    """
    Propagate taint when combining two tainted values.
    
    Rules:
    - UNTRUSTED + anything = UNTRUSTED
    - MIXED + TRUSTED = MIXED
    - TRUSTED + TRUSTED = TRUSTED
    """
    if taint1 == TaintLevel.UNTRUSTED or taint2 == TaintLevel.UNTRUSTED:
        return TaintLevel.UNTRUSTED
    elif taint1 == TaintLevel.MIXED or taint2 == TaintLevel.MIXED:
        return TaintLevel.MIXED
    else:
        return TaintLevel.TRUSTED


def check_taint_violation(action: ActionProposal) -> List[str]:
    """
    Check if action has taint violations.
    
    Two types of violations:
    1. Untrusted data in sensitive parameters (execution safety)
    2. Untrusted data in decision-making parameters (instruction integrity)
    
    Args:
        action: Action proposal to check
        
    Returns:
        List of violation descriptions (empty if no violations)
    """
    violations = []
    
    # Check each parameter in taint metadata
    for param_name, taint_level in action.taint_metadata.items():
        param_lower = param_name.lower()
        
        # Check 1: Sensitive parameters (execution safety)
        is_sensitive = any(sensitive in param_lower for sensitive in SENSITIVE_PARAMETERS)
        if is_sensitive and taint_level == TaintLevel.UNTRUSTED:
            violations.append(
                f"Untrusted data in sensitive parameter '{param_name}' (execution safety violation)"
            )
        elif is_sensitive and taint_level == TaintLevel.MIXED:
            violations.append(
                f"Mixed taint data in sensitive parameter '{param_name}' (execution safety violation)"
            )
        
        # Check 2: Decision-making parameters (instruction integrity)
        # CSO-derived fields (intent, topics, entities) should not directly influence decisions
        is_decision_making = any(dm in param_lower for dm in DECISION_MAKING_PARAMETERS)
        if is_decision_making and taint_level == TaintLevel.UNTRUSTED:
            # Special handling: intent/topics/entities from CSO are UNTRUSTED but structured
            # They can be used for routing but not for overriding system instructions
            # This is a warning, not a hard violation, but we log it
            if param_name in ['intent', 'topics', 'entities']:
                # These are structured CSO fields - they're UNTRUSTED but categorical
                # We allow them but flag for monitoring
                violations.append(
                    f"UNTRUSTED CSO-derived field '{param_name}' in decision-making context (monitor for instruction override attempts)"
                )
            else:
                violations.append(
                    f"Untrusted data in decision-making parameter '{param_name}' (instruction integrity violation)"
                )
    
    # Also check parameter values directly for sensitive parameters
    for param_name, param_value in action.parameters.items():
        param_lower = param_name.lower()
        is_sensitive = any(sensitive in param_lower for sensitive in SENSITIVE_PARAMETERS)
        
        if is_sensitive:
            # Check if this parameter has untrusted taint
            taint = action.taint_metadata.get(param_name)
            if taint == TaintLevel.UNTRUSTED:
                violations.append(
                    f"Untrusted data in sensitive parameter '{param_name}' (value: {str(param_value)[:50]})"
                )
    
    return violations


def merge_taint_metadata(metadata1: Dict[str, TaintLevel], 
                         metadata2: Dict[str, TaintLevel]) -> Dict[str, TaintLevel]:
    """
    Merge two taint metadata dictionaries.
    
    When the same key appears in both, propagate taint.
    """
    merged = deepcopy(metadata1)
    
    for key, taint2 in metadata2.items():
        if key in merged:
            merged[key] = propagate_taint(merged[key], taint2)
        else:
            merged[key] = taint2
    
    return merged


def sanitize_for_logging(data: Any, taint_level: TaintLevel) -> Any:
    """
    Sanitize data for logging based on taint level.
    
    For untrusted data, we may want to redact sensitive information
    or truncate to prevent log injection.
    """
    if taint_level == TaintLevel.UNTRUSTED:
        # For untrusted data, be more cautious in logging
        if isinstance(data, str):
            # Truncate long strings
            if len(data) > 200:
                return data[:200] + "... [truncated]"
        elif isinstance(data, dict):
            # Redact sensitive keys
            sanitized = {}
            for key, value in data.items():
                key_lower = key.lower()
                if any(sensitive in key_lower for sensitive in SENSITIVE_PARAMETERS):
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = sanitize_for_logging(value, taint_level)
            return sanitized
    
    return data


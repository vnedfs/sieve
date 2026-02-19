"""
Audit logging system.

Threat mitigated: Lack of visibility, post-incident analysis
Invariant: All operations are logged with full context

Security: All untrusted data is sanitized before logging to prevent log injection.
"""

from typing import Any, Dict, Optional
from datetime import datetime
import json
import logging
import threading
import os
from pathlib import Path

from sieve.models import AuditLog, TaintLevel, RiskLevel
from sieve.taint import sanitize_for_logging


# Configure logging
logger = logging.getLogger("sieve.audit")
logger.setLevel(logging.INFO)

# Create file handler if not exists
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


# Thread-safe audit log storage
_audit_logs: list[AuditLog] = []
_audit_lock = threading.Lock()

# Maximum audit log size (prevent unbounded growth)
MAX_AUDIT_LOG_SIZE = 10000


def _sanitize_log_string(s: str) -> str:
    """
    Sanitize string for safe logging.
    
    Prevents log injection by escaping control characters.
    """
    # JSON encoding already escapes most control chars, but we double-check
    # Replace newlines and carriage returns explicitly
    sanitized = s.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    
    # Remove any remaining control characters (except those we explicitly allow)
    sanitized = ''.join(
        char if ord(char) >= 32 or char in '\n\r\t' else f'\\u{ord(char):04x}'
        for char in sanitized
    )
    
    return sanitized


def _sanitize_log_data(data: Dict[str, Any], taint: Optional[TaintLevel] = None) -> Dict[str, Any]:
    """
    Sanitize log data based on taint level.
    
    Uses taint-aware sanitization to prevent log injection.
    """
    if taint == TaintLevel.UNTRUSTED:
        # For untrusted data, use aggressive sanitization
        return sanitize_for_logging(data, taint)
    else:
        # For trusted data, still sanitize strings to prevent accidental injection
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = _sanitize_log_string(value)
            elif isinstance(value, dict):
                sanitized[key] = _sanitize_log_data(value, taint)
            elif isinstance(value, list):
                sanitized[key] = [
                    _sanitize_log_string(item) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        return sanitized


def log_event(event_type: str,
              data: Dict[str, Any],
              taint_info: Optional[TaintLevel] = None,
              risk_level: Optional[RiskLevel] = None):
    """
    Log an audit event with proper sanitization.
    
    Args:
        event_type: Type of event (e.g., "input_received", "quarantine", "action_proposed")
        data: Event data (will be sanitized)
        taint_info: Optional taint information
        risk_level: Optional risk level
    """
    # Sanitize data before logging
    sanitized_data = _sanitize_log_data(data, taint_info)
    
    log_entry = AuditLog(
        timestamp=datetime.utcnow(),
        event_type=event_type,
        data=sanitized_data,
        taint_info=taint_info,
        risk_level=risk_level,
    )
    
    # Thread-safe append
    with _audit_lock:
        _audit_logs.append(log_entry)
        
        # Prevent unbounded growth
        if len(_audit_logs) > MAX_AUDIT_LOG_SIZE:
            # Keep most recent logs
            _audit_logs[:] = _audit_logs[-MAX_AUDIT_LOG_SIZE:]
    
    # Log to standard logger with additional sanitization
    try:
        log_dict = log_entry.to_dict()
        # Double-sanitize the JSON string to prevent injection
        json_str = json.dumps(log_dict)
        safe_json = _sanitize_log_string(json_str)
        logger.info(f"Audit: {safe_json}")
    except Exception as e:
        # Never fail silently, but don't crash on logging errors
        logger.error(f"Failed to log audit event: {e}", exc_info=True)


def get_audit_logs(event_type: Optional[str] = None,
                   limit: Optional[int] = None) -> list[AuditLog]:
    """
    Get audit logs (thread-safe).
    
    Args:
        event_type: Optional filter by event type
        limit: Optional limit on number of logs
        
    Returns:
        List of audit logs
    """
    with _audit_lock:
        logs = _audit_logs.copy()
    
    if event_type:
        logs = [log for log in logs if log.event_type == event_type]
    
    if limit:
        logs = logs[-limit:]  # Most recent
    
    return logs


def clear_audit_logs():
    """
    Clear audit logs (for testing only).
    
    Raises:
        RuntimeError: If called in non-test environment
    """
    # Only allow in test environments
    if os.getenv("SIEVE_TEST_MODE") != "true":
        raise RuntimeError(
            "clear_audit_logs() can only be called in test mode. "
            "Set SIEVE_TEST_MODE=true environment variable."
        )
    
    global _audit_logs
    with _audit_lock:
        _audit_logs.clear()


def export_audit_logs(filepath: str):
    """
    Export audit logs to file with path validation.
    
    Args:
        filepath: Path to export file (must be within allowed directory)
        
    Raises:
        ValueError: If path is invalid or outside allowed directory
    """
    # Validate path
    path = Path(filepath).resolve()
    
    # In production, restrict to a specific directory
    allowed_dir = os.getenv("SIEVE_AUDIT_EXPORT_DIR", os.getcwd())
    allowed_path = Path(allowed_dir).resolve()
    
    try:
        # Check if path is within allowed directory
        path.relative_to(allowed_path)
    except ValueError:
        raise ValueError(
            f"Export path {filepath} is outside allowed directory {allowed_dir}"
        )
    
    # Get logs (thread-safe copy)
    with _audit_lock:
        logs = [log.to_dict() for log in _audit_logs]
    
    # Write to file
    with open(path, 'w') as f:
        json.dump(logs, f, indent=2)


# Convenience functions for common events

def log_input_received(data: str, source: Optional[str] = None, taint: TaintLevel = TaintLevel.UNTRUSTED):
    """
    Log input received with proper sanitization.
    
    Uses taint-aware sanitization to prevent log injection.
    """
    # Sanitize untrusted data before logging
    sanitized_data = sanitize_for_logging(data, taint)
    
    log_event(
        event_type="input_received",
        data={"data": str(sanitized_data)[:200], "source": source},  # Truncate and sanitize
        taint_info=taint,
    )


def log_quarantine(cso_data: Dict[str, Any], risk_level: RiskLevel):
    """Log quarantine processing."""
    log_event(
        event_type="quarantine",
        data=cso_data,
        risk_level=risk_level,
        taint_info=TaintLevel.UNTRUSTED,  # CSO is always untrusted
    )


def log_action_proposed(action_data: Dict[str, Any], risk_level: RiskLevel):
    """Log action proposal."""
    log_event(
        event_type="action_proposed",
        data=action_data,
        risk_level=risk_level,
    )


def log_policy_decision(approved: bool, reason: Optional[str] = None):
    """Log policy decision."""
    # Sanitize reason string
    safe_reason = _sanitize_log_string(reason) if reason else None
    
    log_event(
        event_type="policy_decision",
        data={"approved": approved, "reason": safe_reason},
    )


def log_tool_execution(tool_name: str, parameters: Dict[str, Any], success: bool, error: Optional[str] = None):
    """Log tool execution with parameter sanitization."""
    # Sanitize parameters (may contain untrusted data)
    sanitized_params = _sanitize_log_data(parameters, TaintLevel.UNTRUSTED)
    safe_error = _sanitize_log_string(error) if error else None
    
    log_event(
        event_type="tool_execution",
        data={
            "tool_name": tool_name,
            "parameters": sanitized_params,
            "success": success,
            "error": safe_error,
        },
    )

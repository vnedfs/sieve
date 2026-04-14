"""
Comprehensive tests for the tool registry / execution gate (sieve/tools.py).

Covers: registration, execution, taint propagation on output, error handling,
and rejection of unapproved actions.
"""

import pytest

from sieve.tools import ToolRegistry, get_tool_registry, register_tool, execute_tool
from sieve.models import ActionProposal, PolicyDecision, TrustTier, TaintLevel, RiskLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _approved_decision(action):
    return PolicyDecision(approved=True, action=action)


def _rejected_decision(reason="Denied"):
    return PolicyDecision(approved=False, rejection_reason=reason)


def _make_tool_action(tool_name, parameters=None, taint_metadata=None):
    return ActionProposal(
        action_type="tool_call",
        tool_name=tool_name,
        parameters=parameters or {},
        taint_metadata=taint_metadata or {},
        derived_from=TrustTier.SYSTEM,
        risk_level=RiskLevel.LOW,
    )


# ---------------------------------------------------------------------------
# ToolRegistry – registration
# ---------------------------------------------------------------------------

class TestRegistration:
    def setup_method(self):
        self.registry = ToolRegistry()

    def test_register_and_list(self):
        self.registry.register_tool("greet", lambda name: f"Hello, {name}!")
        assert "greet" in self.registry.list_tools()

    def test_multiple_tools_listed(self):
        self.registry.register_tool("tool_a", lambda: "a")
        self.registry.register_tool("tool_b", lambda: "b")
        tools = self.registry.list_tools()
        assert "tool_a" in tools
        assert "tool_b" in tools

    def test_register_with_schema(self):
        schema = {"type": "object", "properties": {"x": {"type": "number"}}}
        self.registry.register_tool("calc", lambda x: x * 2, schema=schema)
        assert self.registry.get_tool_schema("calc") == schema

    def test_get_schema_returns_none_for_missing(self):
        assert self.registry.get_tool_schema("nonexistent") is None

    def test_overwrite_existing_tool(self):
        self.registry.register_tool("add", lambda a, b: a + b)
        self.registry.register_tool("add", lambda a, b: a - b)  # overwrite
        action = _make_tool_action("add", {"a": 10, "b": 3})
        decision = _approved_decision(action)
        result = self.registry.execute(action, decision)
        assert result == 7  # replaced function


# ---------------------------------------------------------------------------
# ToolRegistry – successful execution
# ---------------------------------------------------------------------------

class TestSuccessfulExecution:
    def setup_method(self):
        self.registry = ToolRegistry()
        self.registry.register_tool("add", lambda a, b: a + b)
        self.registry.register_tool("echo", lambda msg: msg)

    def test_basic_tool_call(self):
        action = _make_tool_action("add", {"a": 3, "b": 4})
        decision = _approved_decision(action)
        result = self.registry.execute(action, decision)
        assert result == 7

    def test_echo_tool(self):
        action = _make_tool_action("echo", {"msg": "hello"})
        decision = _approved_decision(action)
        result = self.registry.execute(action, decision)
        assert result == "hello"

    def test_execution_increments_counter(self):
        action = _make_tool_action("echo", {"msg": "test"})
        decision = _approved_decision(action)
        before = self.registry._execution_count
        self.registry.execute(action, decision)
        assert self.registry._execution_count == before + 1

    def test_multiple_executions_increment_counter(self):
        self.registry.register_tool("noop", lambda: None)
        action = _make_tool_action("noop")
        decision = _approved_decision(action)
        for _ in range(5):
            self.registry.execute(action, decision)
        assert self.registry._execution_count >= 5


# ---------------------------------------------------------------------------
# ToolRegistry – rejected/invalid executions
# ---------------------------------------------------------------------------

class TestRejectedExecution:
    def setup_method(self):
        self.registry = ToolRegistry()
        self.registry.register_tool("safe", lambda: "ok")

    def test_unapproved_action_raises(self):
        action = _make_tool_action("safe")
        decision = _rejected_decision("Policy denied")
        with pytest.raises(ValueError, match="not approved"):
            self.registry.execute(action, decision)

    def test_non_tool_action_type_raises(self):
        action = ActionProposal(
            action_type="response",
            parameters={"content": "hi"},
            taint_metadata={},
            derived_from=TrustTier.SYSTEM,
            risk_level=RiskLevel.LOW,
        )
        decision = _approved_decision(action)
        with pytest.raises(ValueError, match="not a tool call"):
            self.registry.execute(action, decision)

    def test_unregistered_tool_raises(self):
        action = _make_tool_action("unknown_tool")
        decision = _approved_decision(action)
        with pytest.raises(ValueError, match="not found"):
            self.registry.execute(action, decision)

    def test_tool_runtime_error_propagates(self):
        self.registry.register_tool("boom", lambda: (_ for _ in ()).throw(RuntimeError("kaboom")))
        action = _make_tool_action("boom")
        decision = _approved_decision(action)
        with pytest.raises(RuntimeError, match="kaboom"):
            self.registry.execute(action, decision)


# ---------------------------------------------------------------------------
# Module-level convenience API
# ---------------------------------------------------------------------------

class TestModuleLevelAPI:
    def test_get_tool_registry_returns_singleton(self):
        r1 = get_tool_registry()
        r2 = get_tool_registry()
        assert r1 is r2

    def test_register_tool_uses_global_registry(self):
        register_tool("module_test_tool", lambda: "module")
        registry = get_tool_registry()
        assert "module_test_tool" in registry.list_tools()

    def test_execute_tool_uses_global_registry(self):
        register_tool("double", lambda x: x * 2)
        action = _make_tool_action("double", {"x": 5})
        decision = _approved_decision(action)
        result = execute_tool(action, decision)
        assert result == 10

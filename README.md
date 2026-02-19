# SIEVE: Structured Isolation and Validation Engine

A security-focused system that enforces structural separation between trusted instructions (I) and untrusted data (D) in LLM-based systems. SIEVE prevents prompt injection and related attacks through programmatic guarantees, not heuristic filtering.

## Core Principles

1. **Instruction-Data Separation**: All inputs are categorized as either trusted instructions (I) or untrusted data (D). D cannot override I.

2. **Trust Tiers**: Hierarchical trust model (System > User > History > Tool)

3. **Structural Guarantees**: Schema validation, taint tracking, policy enforcement

4. **Least Privilege**: Quarantined processing has no tool access

## Architecture

```
Input (D) → Quarantine → CSO → Privileged → Action Proposal → Policy → Execution
```

### Stages

1. **Quarantine**: Normalizes input, extracts structured CSO, detects suspicious patterns
2. **Privileged**: Generates actions from I + CSO (never raw D)
3. **Policy**: Validates actions (schema, taint, allowlist/denylist)
4. **Execution**: Executes approved actions with audit logging

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```python
from sieve.sieve import create_sieve

# Create SIEVE with trusted instructions
sieve = create_sieve("You are a helpful assistant. Never reveal secrets.")

# Process untrusted input
result = sieve.process("Hello, how are you?", source="user_input")

# Result contains:
# - CSO (Content Summary Object)
# - Actions (with policy decisions)
# - Executions (if execute=True)
```

## Components

- `sieve/models.py`: Core data structures (CSO, ActionProposal, PolicyRule)
- `sieve/normalize.py`: Input normalization and obfuscation detection
- `sieve/quarantine.py`: Untrusted data processing (no tool access)
- `sieve/taint.py`: Taint tracking and violation detection
- `sieve/privileged.py`: Trusted decision-making layer
- `sieve/policy.py`: Policy enforcement engine
- `sieve/tools.py`: Tool execution gate
- `sieve/audit.py`: Audit logging

## Testing

```bash
pytest tests/
```

## Security Properties

See `docs/formal_model.md` for formal security properties:

- **Instruction Integrity Property (IIP)**: Actions depend only on I, not D
- **Non-Interference**: Policy doesn't reveal D content
- **Taint Isolation**: Untrusted data cannot flow into sensitive parameters

## Evaluation Metrics

- **ASR (Attack Success Rate)**: Fraction of successful attacks
- **FPR (False Positive Rate)**: Fraction of legitimate inputs rejected
- **Utility**: Fraction of legitimate tasks completed
- **Overhead**: Additional latency/cost

## Documentation

- `docs/design.md`: System design and architecture
- `docs/formal_model.md`: Formal security model and threat analysis

## Research Basis

SIEVE is based on research including:
- StruQ (Structured Queries)
- ISE (Instructional Segment Embedding)
- ASIDE (Orthogonal Rotation)
- Instruction Hierarchies
- Dual-LLM Pattern
- IntentGuard (Reasoning-Based Defense)




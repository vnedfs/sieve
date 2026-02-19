# SIEVE Design Document

## Executive Summary

SIEVE (Structured Isolation and Validation Engine) is a security-focused system that enforces structural separation between trusted instructions (I) and untrusted data (D) in LLM-based systems. Unlike heuristic filtering approaches, SIEVE provides programmatic guarantees through a layered architecture that prevents prompt injection and related attacks.

## Core Principles

### 1. Instruction-Data Separation (I/D Separation)

**Fundamental Invariant**: All inputs are categorized as either:
- **I (Trusted Instructions)**: System prompts, policy directives, developer-defined behavior
- **D (Untrusted Data)**: User input, retrieved documents, tool outputs, external files

**Critical Property**: D cannot override I. Data is treated as data, never as executable instructions.

### 2. Trust Tiers

Based on research findings, we implement a hierarchical trust model:

| Tier | Authority Source | Scope of Control | Overridable By |
|------|-----------------|------------------|----------------|
| Tier 1 | System Message | Global behavior, safety, identity | None |
| Tier 2 | User Message | Current task, specific queries | Tier 1 only |
| Tier 3 | Model History | Conversational context, previous plans | Tiers 1-2 |
| Tier 4 | Tool/API Results | External data, search results, documents | Passive Data Only |

### 3. Structural Guarantees Over Heuristics

- **Schema Validation**: All actions must conform to JSON schemas
- **Taint Tracking**: Untrusted data is marked and tracked through the system
- **Policy Enforcement**: Actions are validated against allowlists/denylists
- **Programmatic Boundaries**: No reliance on prompt-based security

### 4. Least Privilege

- Quarantined processing has no tool access
- High-risk actions require explicit approval
- Context minimization reduces attack surface

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    SIEVE Architecture                        │
└─────────────────────────────────────────────────────────────┘

┌──────────────┐
│   Input: I   │  Trusted Instructions (System Policy)
└──────┬───────┘
       │
┌──────▼──────────────────────────────────────────────────┐
│  STAGE 1: QUARANTINE (Untrusted Processing)            │
│  ─────────────────────────────────────────────────────  │
│  Input: Raw D (untrusted)                               │
│  Capabilities: NONE (no tools, no secrets)              │
│                                                          │
│  Tasks:                                                  │
│  1. Normalize input (strip obfuscation, zero-width)     │
│  2. Extract structured representation (CSO)             │
│  3. Detect suspicious patterns                          │
│                                                          │
│  Output: CSO (Content Summary Object) + Risk Signals    │
└──────┬──────────────────────────────────────────────────┘
       │
       │ CSO (tainted, structured)
       │
┌──────▼──────────────────────────────────────────────────┐
│  STAGE 2: PRIVILEGED (Trusted Decision Layer)           │
│  ─────────────────────────────────────────────────────  │
│  Input: I + CSO (NOT raw D)                             │
│  Capabilities: Decision-making, planning                │
│                                                          │
│  Tasks:                                                  │
│  1. Generate action plans based on I + CSO              │
│  2. Ensure decisions derive from I, not D               │
│  3. Output structured action proposals                  │
└──────┬──────────────────────────────────────────────────┘
       │
       │ Action Proposals (with taint metadata)
       │
┌──────▼──────────────────────────────────────────────────┐
│  STAGE 3: POLICY ENFORCEMENT                            │
│  ─────────────────────────────────────────────────────  │
│  Input: Action Proposals                                │
│                                                          │
│  Validation Layers:                                      │
│  1. JSON Schema Validation                              │
│  2. Allowlist/Denylist Checks                           │
│  3. Taint Rules (no untrusted data in sensitive params) │
│  4. Risk Assessment                                      │
│                                                          │
│  Output: Approved Actions OR Rejection                  │
└──────┬──────────────────────────────────────────────────┘
       │
       │ Approved Actions
       │
┌──────▼──────────────────────────────────────────────────┐
│  STAGE 4: TOOL EXECUTION (Gated)                        │
│  ─────────────────────────────────────────────────────  │
│  - Execute approved actions                              │
│  - Track taint in outputs                                │
│  - Audit all operations                                  │
└──────────────────────────────────────────────────────────┘
```

## Component Design

### 1. Models (`sieve/models.py`)

Core data structures with strong typing:

- **TrustTier**: Enum for trust levels (SYSTEM, USER, HISTORY, TOOL)
- **TaintLevel**: Enum for data trustworthiness (TRUSTED, UNTRUSTED, MIXED)
- **ContentSummaryObject (CSO)**: Structured representation of untrusted data
- **ActionProposal**: Structured action with taint metadata
- **PolicyRule**: Policy definition for enforcement

### 2. Normalization (`sieve/normalize.py`)

**Threat Mitigated**: Obfuscation attacks (zero-width chars, unicode tricks)

**Invariant**: All inputs are normalized to canonical form before processing

**Checks**:
- Strip zero-width characters
- Normalize unicode
- Detect encoding tricks
- Remove hidden text

### 3. Quarantine (`sieve/quarantine.py`)

**Threat Mitigated**: Direct and indirect prompt injection

**Invariant**: Untrusted data never directly influences decisions

**Process**:
1. Normalize input
2. Extract structured CSO (no raw text passed forward)
3. Detect instruction-like patterns
4. Assign risk scores
5. Return CSO + risk signals

**Key Constraint**: This stage has NO tool access, NO secrets, NO decision-making authority.

### 4. Taint Tracking (`sieve/taint.py`)

**Threat Mitigated**: Data exfiltration, unauthorized tool usage

**Invariant**: Untrusted data cannot flow into sensitive parameters

**Mechanism**:
- Mark all data with taint level
- Track taint through transformations
- Enforce taint rules at policy layer
- Prevent tainted data in:
  - API keys
  - File paths
  - Command arguments
  - Database queries

### 5. Privileged Layer (`sieve/privileged.py`)

**Threat Mitigated**: Instruction override, unauthorized actions

**Invariant**: All decisions derive from I, not D

**Process**:
1. Receive I (trusted instructions) + CSO (tainted, structured)
2. Generate action proposals
3. Ensure proposals align with I
4. Mark proposals with taint metadata

**Key Constraint**: Never directly processes raw untrusted text.

### 6. Policy Enforcement (`sieve/policy.py`)

**Threat Mitigated**: Unauthorized actions, policy violations

**Invariant**: All actions conform to defined policy

**Validation Layers**:
1. **Schema Validation**: JSON schema conformance
2. **Allowlist/Denylist**: Tool and parameter restrictions
3. **Taint Rules**: Prevent tainted data in sensitive fields
4. **Risk Assessment**: Score actions and require approval for high-risk

### 7. Tool Execution (`sieve/tools.py`)

**Threat Mitigated**: Unauthorized tool usage

**Invariant**: Only approved, validated actions execute

**Mechanism**:
- Centralized tool registry
- Schema validation before execution
- Taint tracking in outputs
- Rate limiting and resource constraints

### 8. Audit (`sieve/audit.py`)

**Threat Mitigated**: Lack of visibility, post-incident analysis

**Invariant**: All operations are logged with full context

**Logged Events**:
- Input received (with taint)
- Quarantine decisions
- Action proposals
- Policy decisions
- Tool executions
- Rejections and reasons

## Data Flow

### Normal Flow

```
User Input (D) → Quarantine → CSO → Privileged → Action Proposal → Policy → Tool Execution
```

### Attack Scenario

```
Malicious Input (D) → Quarantine → CSO (tainted, risk signals) → Privileged → 
Action Proposal (rejected if violates I) → Policy (rejected if taint violation) → 
Rejection logged
```

## Security Properties

### 1. Instruction Integrity Property (IIP)

**Formal Statement**: For all untrusted data D1, D2, the effective policy extracted from the system's actions must remain within the bounds defined by trusted instructions I.

**Informal**: Adversarial data cannot change what the system is allowed to do.

### 2. Non-Interference

**Formal Statement**: The policy extracted from actions should not depend on the specific content of untrusted data, only on its structured representation.

**Informal**: Different malicious inputs should not result in different policy violations if they have the same structure.

### 3. Taint Isolation

**Formal Statement**: Data marked as UNTRUSTED cannot flow into parameters marked as SENSITIVE without explicit validation.

**Informal**: Untrusted data cannot directly control sensitive operations.

## Implementation Strategy

### Phase 1: Minimal Vertical Slice

1. Basic models and types
2. Quarantine → CSO extraction
3. Privileged → Action proposal
4. Policy → Validation
5. Basic tests

### Phase 2: Enhanced Security

1. Advanced normalization
2. Taint tracking
3. Risk scoring
4. Audit logging

### Phase 3: Evaluation

1. Attack test suite
2. Metrics collection (ASR, FPR, Utility, Overhead)
3. Iterative improvement

## Dependencies

- **pydantic**: Strong typing and validation
- **jsonschema**: Schema validation
- **python-json-logger**: Structured logging
- **typing**: Type hints

## Testing Strategy

### Unit Tests
- Each component in isolation
- Mock LLM calls
- Verify invariants

### Integration Tests
- End-to-end flows
- Attack scenarios
- Policy enforcement

### Evaluation Tests
- Attack Success Rate (ASR)
- False Positive Rate (FPR)
- Task Utility
- Performance Overhead

## Limitations and Future Work

### Current Limitations

1. **LLM Dependency**: Still relies on LLM for CSO extraction and decision-making
2. **Empirical Validation**: Some properties are empirically validated, not formally proven
3. **Model-Specific**: Effectiveness may vary by underlying LLM

### Future Enhancements

1. **Structured Queries (StruQ)**: Implement delimiter-based separation
2. **Instruction Embeddings**: Support for ISE/ASIDE if model supports
3. **Reasoning-Based Defense**: IntentGuard-style analysis for reasoning models
4. **Multimodal Support**: Extend to image/audio inputs

## References

Based on research in `/research/initial-ideas.txt.txt`:
- StruQ (Structured Queries)
- ISE (Instructional Segment Embedding)
- ASIDE (Orthogonal Rotation)
- Instruction Hierarchies (Trust Tiers)
- Dual-LLM Pattern
- IntentGuard (Reasoning-Based Defense)
- BAML/IDL Paradigm
- LMQL/Guidance (Syntactic Constraints)


# SIEVE Formal Model (Updated)

## 1. Threat Model

### 1.1 Attacker Capabilities

The attacker has **full control** over untrusted data D. Specifically:

- **Direct Injection**: Attacker can craft arbitrary text in user input
- **Indirect Injection**: Attacker can poison external sources (documents, tool outputs, RAG results)
- **Obfuscation**: Attacker can use zero-width characters, unicode tricks, hidden text
- **Multi-Step Attacks**: Attacker can coordinate across multiple interactions
- **Knowledge**: Attacker may know system architecture, policy rules, and defense mechanisms

### 1.2 Attacker Goals

1. **Instruction Override**: Cause system to follow attacker's instructions instead of trusted policy I
2. **Data Exfiltration**: Extract sensitive information (API keys, system prompts, user data)
3. **Tool Misuse**: Execute unauthorized tool calls (file deletion, API calls, command execution)
4. **Policy Violation**: Bypass safety constraints and access controls
5. **Persistence**: Establish long-term control through memory/RAG poisoning

### 1.3 System Assumptions

- **Trusted Instructions (I)**: System prompts and policy are controlled by developers, not attackers
- **LLM Behavior**: The underlying LLM may be vulnerable to prompt injection (this is what we defend against)
- **Tool Access**: System has access to tools/APIs that could be misused
- **Context Window**: System processes inputs within a bounded context window

### 1.4 Attack Vectors

1. **Direct Prompt Injection**: Malicious instructions in user input
2. **Indirect Prompt Injection**: Hidden instructions in retrieved documents
3. **Obfuscation**: Encoding tricks to bypass detection
4. **Context Manipulation**: Exploiting context window limitations
5. **Multi-Modal**: Instructions in images/audio (future consideration)

## 2. System Model

### 2.1 Core Entities

**Inputs:**
- `I ∈ Instructions`: Trusted instructions (system prompts, policy)
- `D ∈ Data`: Untrusted data (user input, documents, tool outputs)

**Processing Functions:**
- `Quarantine: Data → CSO`: Extract structured representation (NO free text)
- `Privileged: Instructions × CSO → ActionProposals`: Generate actions
- `FormalReasoning: ActionProposal × Instructions × CSO → PropertyChecks`: Verify properties
- `Policy: ActionProposals × PropertyChecks → ActionProposals ∪ {REJECT}`: Validate actions
- `Execute: ActionProposals → Results`: Execute approved actions

**Composite Function:**
```
f(I, D) = Policy(FormalReasoning(Privileged(I, Quarantine(D)), I, Quarantine(D)))
```

### 2.2 Trust Tiers

Define a partial order on trust:

```
Tier(I) ∈ {SYSTEM, USER, HISTORY, TOOL}
SYSTEM > USER > HISTORY > TOOL
```

Where `>` denotes "more trusted than" or "overrides".

### 2.3 Taint Model

**Taint Levels:**
- `TRUSTED`: Originates from I or system
- `UNTRUSTED`: Originates from D
- `MIXED`: Combination of trusted and untrusted

**Taint Propagation (Mathematically Sound):**
```
taint(x ⊕ y) = max(taint(x), taint(y))
```

Where `max` respects: `UNTRUSTED > MIXED > TRUSTED`

This is a **provable property** based on information flow theory.

### 2.4 Content Summary Object (CSO) - Structured Only

A CSO is a **structured representation** of untrusted data with **NO free text**:

```
CSO = {
    summary: JSON,              // Structured data (intent, entities, topics), NOT free text
    metadata: Dict,            // Structured metadata
    taint: TaintLevel,         // Always UNTRUSTED
    risk_score: Float,         // [0.0, 1.0]
    suspicious_patterns: List   // Detected patterns
}
```

**Critical Property**: `CSO.summary` is JSON containing ONLY:
- `intent`: Categorical value ("question", "command", "statement", "unknown")
- `entities`: List of structured entities (type, value)
- `topics`: List of keywords (not sentences)
- `flags`: Boolean flags

**NO free text that could be interpreted as instructions.**

## 3. Security Properties (Formally Verifiable)

### 3.1 Instruction Integrity Property (IIP) - Verifiable

**Formal Statement**: 

For all `I ∈ Instructions`, and for all `D1, D2 ∈ Data`:

```
Policy(f(I, D1)) ≈ Policy(f(I, D2))
```

Where `≈` means "within the same policy bounds defined by I".

**Verification Method** (Implemented in `reasoning.py`):

1. **Structural Check**: `action.derived_from == SYSTEM` (provable)
2. **Taint Check**: No `UNTRUSTED` taint in decision-making parameters (provable)
3. **Semantic Check**: Rationale references I (heuristic, but verifiable)

**Status**: **VERIFIABLE** (not fully provable due to LLM behavior, but structural properties are provable)

### 3.2 Taint Isolation Property - PROVABLE (with scope limitation)

**Formal Statement**:

For any action `a ∈ Actions`:

```
if taint(a.parameter) = UNTRUSTED and a.parameter ∈ SensitiveParams:
    then Policy(a) = REJECT
```

**Verification**: This is **PROVABLE** through taint tracking for sensitive-parameter-named fields. The property holds if:
- Taint tracking is correct (structural guarantee)
- Policy enforcement checks taint (structural guarantee)

**Scope Limitation**: 
- **PROVEN** for parameters explicitly named in `SENSITIVE_PARAMETERS` (e.g., `api_key`, `command`, `path`)
- **MONITORED** for CSO-derived structured fields (`intent`, `topics`, `entities`) which are UNTRUSTED but categorical/structured
- These structured fields can influence routing but are prevented from overriding system instructions through other checks

**Status**: **PROVEN** (for sensitive-parameter-named fields only, given correct implementation)

### 3.3 Quarantine Isolation Property - VERIFIABLE

**Formal Statement**:

```
Quarantine(D) = CSO where CSO.summary is structured (JSON), not free text
```

And:

```
Quarantine(D) has no access to:
    - Tools
    - Secrets
    - Decision-making authority
    - Policy modification
```

**Verification**: 
- Structural: Code enforces no tool access (provable)
- CSO structure: Can verify CSO.summary is valid JSON with only structured fields (provable)

**Status**: **VERIFIED** (structural checks)

### 3.4 Non-Interference Property - VERIFIABLE

**Formal Statement**:

For all `I ∈ Instructions`, and for all `D1, D2 ∈ Data` with equivalent structure:

```
Structure(CSO(D1)) = Structure(CSO(D2)) ⟹ Policy(f(I, D1)) = Policy(f(I, D2))
```

Where `Structure(CSO)` extracts structural properties (not content).

**Verification**: Can verify by:
1. Extracting structure from CSO (provable)
2. Comparing structures (provable)
3. Comparing policies (provable if policies are deterministic)

**Status**: **VERIFIABLE** (for deterministic policy decisions)

## 4. Formal Reasoning Layer

### 4.1 Property Verification

The `FormalReasoner` class implements property verification:

```python
verify_instruction_integrity(action, I, CSO) → PropertyCheck
verify_taint_isolation(action) → PropertyCheck
verify_quarantine_isolation(CSO) → PropertyCheck
verify_non_interference(action1, action2, CSO1, CSO2) → PropertyCheck
```

### 4.2 Property Status

- **PROVEN**: Property holds with mathematical certainty (e.g., taint isolation)
- **VERIFIED**: Property verified through structural checks (e.g., IIP)
- **VIOLATED**: Property is violated
- **UNKNOWN**: Cannot determine (fail-safe: reject)

### 4.3 Fail-Safe Principle

If any property check returns **UNKNOWN**, the action is **rejected by default**.

This ensures we never execute actions with uncertain security properties.

## 5. Measurable Approximations

### 5.1 Attack Success Rate (ASR)

**Definition**: Fraction of attack attempts that succeed in violating security properties.

```
ASR = (Number of Successful Attacks) / (Total Attack Attempts)
```

**Target**: ASR < 0.10 (10%) for strong attacks, < 0.02 (2%) for manual attacks.

**Measurement**:
- Test suite of known attack patterns
- Automated attack generation
- Adversarial evaluation

### 5.2 False Positive Rate (FPR)

**Definition**: Fraction of legitimate inputs incorrectly rejected or modified.

```
FPR = (Number of False Positives) / (Total Legitimate Inputs)
```

**Target**: FPR < 0.05 (5%) to maintain utility.

**Measurement**:
- Test suite of legitimate use cases
- User acceptance testing
- Production monitoring

### 5.3 Task Utility

**Definition**: Fraction of legitimate tasks successfully completed.

```
Utility = (Successful Legitimate Tasks) / (Total Legitimate Tasks)
```

**Target**: Utility > 0.90 (90%) to maintain system value.

**Measurement**:
- Benchmark tasks
- User satisfaction metrics
- Task completion rates

### 5.4 Overhead

**Definition**: Additional latency and computational cost introduced by SIEVE.

**Metrics**:
- **Latency Overhead**: `(Time with SIEVE) - (Time without SIEVE)`
- **Token Overhead**: Additional tokens for CSO extraction and validation
- **API Calls**: Additional LLM calls for quarantine processing

**Target**: Overhead < 2x baseline for acceptable performance.

## 6. Provable vs Empirical Properties

### 6.1 Provable Properties (Mathematically Sound)

These can be **proven** through structural analysis:

1. **Taint Isolation**: If taint tracking is correct, untrusted data cannot flow into sensitive parameters
   - **Proof**: Structural check of taint metadata + policy enforcement
   - **Status**: **PROVEN** (given correct implementation)

2. **Quarantine Isolation**: Quarantine has no tool access
   - **Proof**: Code inspection (no tool calls in quarantine code)
   - **Status**: **PROVEN** (structural guarantee)

3. **CSO Structure**: CSO.summary is structured JSON, not free text
   - **Proof**: JSON schema validation + code inspection
   - **Status**: **PROVEN** (structural guarantee)

### 6.2 Verifiable Properties (Structurally Verified)

These can be **verified** through structural checks, but not fully proven due to LLM behavior:

1. **Instruction Integrity**: Actions derive from I, not D
   - **Verification**: Structural checks (derived_from, taint, rationale)
   - **Status**: **VERIFIED** (structural properties provable, LLM behavior not)

2. **Non-Interference**: Equivalent structures produce equivalent policies
   - **Verification**: Structure comparison + policy comparison
   - **Status**: **VERIFIABLE** (for deterministic policies)

### 6.3 Empirical Properties

These require testing and evaluation:

1. **Attack Resistance**: Actual ASR against real attacks
2. **Utility Preservation**: Whether legitimate tasks still work
3. **Robustness**: Performance across different LLMs and scenarios

## 7. Mathematical Strength Assessment

### 7.1 What is Mathematically Strong

**Taint Tracking**: 
- **Strength**: **HIGH** - Based on information flow theory
- **Provability**: **PROVEN** - Can prove taint isolation property for sensitive-parameter-named fields
- **Scope**: Taint isolation is provable for `SENSITIVE_PARAMETERS` (api_key, command, path, etc.)
- **Limitation**: CSO-derived fields (intent, topics, entities) are UNTRUSTED but structured/categorical. They are monitored rather than blocked, as they carry semantic content but in structured form. The full end-to-end proof that untrusted content cannot influence privileged decisions requires additional checks beyond taint alone.

**CSO Structure**:
- **Strength**: **HIGH** - Structural separation (no free text)
- **Provability**: **PROVEN** - Can verify CSO is structured JSON
- **Limitation**: Extraction quality depends on implementation

**Quarantine Isolation**:
- **Strength**: **HIGH** - Structural guarantee (no tool access)
- **Provability**: **PROVEN** - Code inspection
- **Limitation**: None (pure structural guarantee)

### 7.2 What is Verifiable but Not Fully Provable

**Instruction Integrity**:
- **Strength**: **MEDIUM-HIGH** - Structural checks are provable
- **Provability**: **VERIFIED** - Can verify structural properties
- **Limitation**: LLM behavior is not formally specified, so semantic influence cannot be fully proven

**Non-Interference**:
- **Strength**: **MEDIUM** - Verifiable for deterministic policies
- **Provability**: **VERIFIABLE** - Can verify for specific cases
- **Limitation**: Requires deterministic policy decisions

### 7.3 Overall Assessment

**Mathematical Strength**: **MEDIUM-HIGH**

- **Strong Foundation**: Taint tracking (for sensitive parameters), CSO structure, quarantine isolation are provable
- **Scope Clarity**: Taint isolation is provable for sensitive-parameter-named fields; CSO-derived structured fields are monitored
- **Verifiable Properties**: IIP and non-interference are verifiable through structural checks
- **Limitation**: LLM behavior cannot be formally proven, but structural guarantees provide defense-in-depth
- **Honest Assessment**: The system correctly distinguishes between what is PROVEN (sensitive parameter blocking) and what is MONITORED (CSO-derived structured fields)

**Comparison to Cryptography**:
- Not as strong as cryptographic proofs (e.g., RSA security)
- Stronger than heuristic-only defenses
- Comparable to formal verification of software systems (structural guarantees)
- **Key Difference**: Scope is clearly defined - provable for sensitive parameters, monitored for structured CSO fields

## 8. Formal Verification Roadmap

### Phase 1: Structural Verification ✅
- Verify code enforces I/D separation
- Verify taint tracking correctness
- Verify policy enforcement coverage
- Verify CSO structure

### Phase 2: Property Testing ✅
- Generate test cases from formal properties
- Verify properties hold on test suite
- Measure ASR, FPR, Utility

### Phase 3: Model Checking (Future)
- Formal model of system behavior
- Automated verification of security properties
- Proof of IIP under specific assumptions

## 9. References

- Research document: `/research/initial-ideas.txt.txt`
- Related work: StruQ, ISE, ASIDE, Instruction Hierarchies
- Security principles: Non-interference, taint analysis, least privilege
- Formal methods: Information flow theory, property-based verification

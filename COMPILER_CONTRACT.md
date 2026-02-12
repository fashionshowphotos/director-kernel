# Director Compiler Contract

**Version:** 1.1.0  
**Date:** 2026-01-21  
**Status:** LOCKED

---

## What Director Is

Director is a **bidirectional software compiler** that operates on semantic representations rather than syntax. It transforms software across abstraction levels and languages while preserving meaning.

```
Intent → MS5 → MS4 → MS3 → MS2 (Code)
Code → MS2.5 (Semantics) → MS3 (Contracts) → MS2 (Any Language)
```

---

## What Director Guarantees

### 1. Semantic Preservation
- **MS2 → MS2.5**: Extracts WHAT the code does, not HOW it does it
- **MS2.5 → MS3**: Derives contracts from semantics, not from original syntax
- **MS3 → MS2**: Generates code that satisfies the contracts

### 2. Language Agnosticism
- MS2.5 and MS3 are language-independent representations
- The same MS3 contract can generate TypeScript, Rust, Go, Python, etc.
- Language-specific idioms are applied at MS3→MS2 only

### 3. Tier Enforcement
- `must_hold` invariants block generation if not satisfied
- `should_hold` invariants produce warnings
- `may_omit` items are explicitly allowed to be missing

### 4. Clean-Room Elevation
- MS2.5→MS3 produces contracts as if designed from scratch
- No syntax anchoring to original implementation
- No legacy pattern preservation unless semantically required

### 5. Reproducibility
- Same inputs + same model = same outputs (within model temperature variance)
- All artifacts are content-addressed (SHA-256)
- Build history is persisted in SQLite

### 6. Reviewability
- `--diff` emits MS2.5 (semantic diff) and MS3 (contract diff)
- `--explain` emits human-readable explanation of changes
- All intermediate artifacts are saved

---

## What Director Does NOT Guarantee

### 1. Syntactic Equivalence
- Output code will NOT look like input code
- Variable names, function structure, file organization may differ
- This is intentional: Director compiles semantics, not syntax

### 2. Runtime Behavior Equivalence
- Director does not execute code
- It cannot verify that generated code produces identical outputs
- Edge cases, timing, and side effects may differ

### 3. Performance Equivalence
- Generated code may be faster or slower than original
- Algorithm choices are made by the model, not preserved from source
- Optimization is not a compiler goal

### 4. Dependency Preservation
- Generated code may use different libraries
- Dependency versions are model-selected, not copied
- External API calls may use different clients

### 5. Test Preservation
- Tests are not automatically migrated
- Test logic may need to be re-derived from MS3 contracts
- Test coverage is a tier requirement, not a migration guarantee

### 6. Model Determinism
- Different models may produce different outputs
- Model updates may change outputs
- Temperature > 0 introduces variance

---

## Responsibility Boundaries

### Director Is Responsible For:
| Responsibility | Enforcement |
|----------------|-------------|
| Schema validation | Hard fail on invalid JSON |
| Tier contract checking | Error/warning based on tier |
| Artifact persistence | Content-addressed storage |
| Build state management | SQLite with locking |
| Context slicing | Token budget enforcement |
| Truncation safety | Fail if >50% truncated |

### Director Is NOT Responsible For:
| Responsibility | Owner |
|----------------|-------|
| Code correctness | Human review + tests |
| Security vulnerabilities | Security audit |
| Performance optimization | Profiling + tuning |
| Dependency security | Dependency scanning |
| Production deployment | DevOps |
| Runtime monitoring | Observability stack |

---

## Operational Modes

### Standard Compilation
```bash
dirkernel compile --from code --to <lang> --tier <tier> --input <path>
```
Full pipeline: Code → MS2.5 → MS3 → MS2

### Locked Architecture
```bash
dirkernel compile --from code --to <lang> --lock-architecture --input <path>
```
Skips MS3 regeneration: Code → MS2.5 → [existing MS3] → MS2

### Intent Expansion
```bash
dirkernel compile --from intent --to <lang> --tier <tier> --input <path>
```
Full pipeline: Intent → MS5 → MS4 → MS3 → MS2

### Semantic Governed Mode (Default for Serious Work)
```bash
dirkernel compile --from intent --mode semantic_governed --tier <tier> --input <path>
```
Full governed pipeline with authority hierarchy:
- **Stage 1**: Intent Convergence (MC5) — External AI refines goals
- **Stage 2**: Constitutional Governance (MC4) — External AI amends invariants  
- **Stage 3**: Contract Definition (MC3) — External AI modifies contracts
- **Stage 4**: Module Semantic Finalisation (MC2) — External AI defines executable semantics
- **Stage 5**: Implementation (CODE) — IDE AI writes code from MC2

**Authority**: MC5 > MC4 > MC3 > MC2 > Code  
**Constraint**: External AI never sees code. IDE AI never changes MC semantics.

**Validation Gates**:
- Gate A: Semantic validity (MC artifacts have required fields)
- Gate B: Linkage contract (no imports, file names, control flow)
- Gate C: Code safety (syntax check, dangerous pattern detection)

**Incremental Builds**:
```bash
dirkernel compile --mode semantic_governed --mc3 ./MC3.json --mc4 ./MC4.json --mc5 ./MC5.json --module <name> --input <path>
```

**Patch-Only Output**:
```bash
dirkernel compile --mode semantic_governed --patch-only --input <path>
```

### Review Mode
```bash
dirkernel compile --from code --to <lang> --diff --explain --input <path>
```
Emits semantic diff, contract diff, and explanation

---

## Quality Levels and Convergence

**Quality is declared, not iterated.** The system iterates until convergence or refusal — not until an arbitrary limit.

### Quality Levels

| Level | Meaning | Convergence Rule |
|-------|---------|------------------|
| `experimental` | Partial specs allowed, ambiguity tolerated | Stops when usable |
| `solo` | Reasonable defaults allowed, warnings OK | Stops when functional |
| `frontier` | Aggressive completion, some assumptions allowed | Stops when complete |
| `production` | All core contracts must converge | Stops when verified |
| `enterprise` | Full semantic convergence required or refuse | Stops when proven or refuses |

### Convergence Rules per Layer

| Layer | Converged When | Enterprise Rule |
|-------|----------------|-----------------|
| **MC5** | No unresolved intent markers, no NEED_MORE_CONTEXT | Must converge to zero unknowns or refuse |
| **MC4** | All required invariants present, no forbidden moves unresolved | Must be complete and explicit, no implied governance |
| **MC3** | Tier contracts pass, no must_hold violations | Must be fully satisfiable, no warnings allowed |
| **MC2** | Linkage contract passes Gate B, no unresolved dependencies | Must be deterministic and closed |
| **CODE** | Gate C passes, tests present (if required) | Allowed only after upstream convergence |

### Stop Conditions

| Condition | Type | Meaning |
|-----------|------|---------|
| **CONVERGED** | Success | All convergence predicates satisfied |
| **REFUSAL** | Correct | Cannot converge without new information |
| **CIRCUIT_BREAKER** | Safety | Cost or time limit reached (not correctness) |

### Circuit Breakers (Safety, Not Correctness)

```typescript
{
  maxCostUsd?: number,      // Pause if exceeded
  maxWallclockSeconds?: number  // Pause if exceeded
}
```

Circuit breakers:
- Are global and orthogonal to quality
- Never change correctness semantics
- Emit partial artifacts and explain why
- Allow resume

---

## Tier Definitions

| Tier | Quality Level | Use Case | Key Requirements |
|------|---------------|----------|------------------|
| `toy` | experimental | Throwaway code | None |
| `personal` | solo | Side projects | Basic error handling |
| `experimental` | frontier | Internal tools | Types, config, no secrets |
| `production` | production | Customer-facing | Tests, logging, validation, shutdown |
| `enterprise` | enterprise | Regulated systems | Threat model, audit trail, rate limiting |

**Enterprise Context Rule**: Enterprise tier may refuse with `NEED_MORE_CONTEXT` if intent is under-specified. This is correct behavior — the compiler will not hallucinate missing implementation details for regulated systems.

---

## Failure Modes

### Recoverable
- **NEED_MORE_CONTEXT**: Model requests additional artifacts
- **SCHEMA_VALIDATION_FAILED**: Output doesn't match expected schema
- **BUDGET_EXCEEDED**: Token budget exhausted (can retry with higher budget)

### Non-Recoverable
- **EXCESSIVE_TRUNCATION**: >50% of context truncated
- **MODEL_CALL_FAILED**: API error after 3 retries
- **LOCK_ACQUISITION_FAILED**: Another build is running
- **STUBS_DETECTED**: Generated code contains incomplete implementations

---

## Composition Boundaries

### Single-Module vs Multi-Module

The compiler currently supports **single-module compilation**. Multi-module composition is a distinct phase with different requirements.

| Capability | Status | Notes |
|------------|--------|-------|
| Single file → single module | ✅ Supported | Full semantic extraction and code generation |
| Directory → single module | ⚠️ Limited | Module boundaries may collapse |
| Multi-package → multi-module | ❌ Not yet supported | Requires explicit module graph |

### What "Module Boundary Collapse" Means

When compiling a directory containing multiple packages/modules:
- File markers (`// === FILE: path ===`) are not semantically meaningful
- The LLM optimizes for coherence, not structure
- Multiple source packages may collapse into a single semantic module

**This is expected behavior, not a bug.**

The compiler will:
- ✅ Preserve invariants
- ✅ Preserve interface contracts
- ❌ Lose implicit architectural boundaries
- ✅ Refuse rather than hallucinate architecture

### Multi-Module Composition Requirements (Future)

Full multi-module composition requires:
1. **Per-package semantic extraction** — Run MS2.5 on each package separately
2. **Explicit module graph** — Build dependency graph from imports
3. **Federated MS3 contracts** — Compose per-module contracts into system contract
4. **Linkage validation** — Verify cross-module dependencies resolve

This is equivalent to adding a linker phase and is not yet implemented.

### Recommended Workaround

For multi-module codebases, compile each module separately:
```bash
# Per-module compilation (supported)
node dist/cli.js compile --from code --to rust --input src/api/service.go
node dist/cli.js compile --from code --to rust --input src/users/users.go
node dist/cli.js compile --from code --to rust --input src/db/mongodb.go
```

Do NOT expect directory compilation to preserve architectural boundaries.

---

## Versioning

| Component | Version | Compatibility |
|-----------|---------|---------------|
| MS5 Schema | 6.0.0 | Breaking changes require major bump |
| MS2.5 Schema | ms2_5_v1 | Additive changes only |
| MS3 Schema | ms3_contracts_v1 | Additive changes only |
| MS2 Schema | ms2_code_v1 | Stable |
| Tier Contracts | tier_contracts_v1 | Additive changes only |

---

## For Future AI Agents

If you are an AI agent reading this contract:

1. **Trust MS3, not MS2**: Contracts are the source of truth, not code
2. **Respect tier boundaries**: Don't generate enterprise features for toy tier
3. **Preserve semantics, not syntax**: The goal is meaning, not appearance
4. **Use --diff for review**: Always emit diffs for human oversight
5. **Lock architecture for ports**: Use `--lock-architecture` for language migrations

---

## For Governance

This compiler:
- Does NOT make autonomous deployment decisions
- Does NOT execute generated code
- Does NOT access external systems beyond the LLM API
- DOES persist all artifacts for audit
- DOES enforce tier contracts mechanically
- DOES require human approval for builds

---

---

## Frozen Components

The following components are **LOCKED**. Changes require version bump + full test replay:

| Component | Status | Change Policy |
|-----------|--------|---------------|
| MS2.5 v1 schema | FROZEN | Major version bump required |
| Tier contract semantics | FROZEN | Justification + migration testing |
| Semantic harness assertions | FROZEN | No weakening without approval |
| `semantic_governed` pipeline | FROZEN | Default for serious work |
| Authority hierarchy (MC5>MC4>MC3>MC2>Code) | FROZEN | Non-negotiable |
| Validation gates (A, B, C) | FROZEN | Cannot be bypassed |

---

*This contract is machine-readable and human-auditable.*

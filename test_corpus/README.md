# Director Compiler Test Corpus

**Purpose:** Evidence collection, not feature building.

This corpus serves as:
- Regression suite
- Proof of correctness
- Patent support
- Confidence anchor

## Test Categories

| Category | Purpose | Expected Behavior |
|----------|---------|-------------------|
| **Large Legacy** | 2k-5k LOC single files | Semantic extraction, invariant preservation |
| **Defunct Code** | Broken imports, deprecated APIs | Honest refusal or faithful extraction |
| **Security-Sensitive** | Hashing, auth, crypto | Preserve security invariants |
| **Framework-Heavy** | Express, React, etc. | Extract contracts without framework hallucination |
| **Whole Directory** | Multi-file input | Expected STUBS_DETECTED refusal |

## Directory Structure

```
test_corpus/
├── inputs/           # Source code and specs for each test
│   ├── 01_large_legacy/
│   ├── 02_defunct_code/
│   ├── 03_security_auth/
│   ├── 04_framework_heavy/
│   └── 05_directory_input/
├── results/          # Latest run results
└── archive/          # Historical runs with timestamps
```

## Test Record Format

Each test produces:
```
{test_id}/
├── INPUT.md          # What was fed to compiler
├── FLAGS.txt         # CLI flags used
├── ARTIFACTS/        # All produced artifacts
│   ├── MC5.json
│   ├── MC4.json
│   ├── MC3.json
│   ├── MC2.json (if reached)
│   └── CODE/ (if reached)
├── OUTCOME.txt       # SUCCESS | REFUSED | FAILED | CIRCUIT_BREAKER
├── EXPLANATION.md    # Human-readable analysis
└── AUDIT_LOG.json    # Full run metadata
```

## Running Tests

```bash
# Run single test
npm run test:corpus -- --test 01_large_legacy

# Run all tests
npm run test:corpus -- --all

# Archive current results
npm run test:corpus -- --archive
```

## Success Criteria

A test **passes** if:
1. Outcome matches expected outcome
2. Invariants are preserved (for SUCCESS cases)
3. Refusal is honest (for REFUSED cases)
4. No hallucinated architecture

A test **fails** if:
1. Compiler lies about capabilities
2. Invariants are lost
3. Architecture is invented
4. Stubs are emitted without STUBS_DETECTED

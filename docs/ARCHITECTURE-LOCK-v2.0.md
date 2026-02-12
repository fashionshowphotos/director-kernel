# ARCHITECTURE LOCK v2.0
**Status**: ACTIVE
**Enforcement**: STRICT

This repository is subject to Architecture Lock v2.0.

## Canonical References
- `docs/MS3_LOCK_6.3.3.md` (State Machine, Locking, Persistence guarantees)
- `docs/MS3_CODE_6.3.3.md` (Module Boundaries, Shadowing policy)

## CI Enforcement
Any change to `src/` that contradicts the behavior defined in the canonical references MUST be accompanied by:
1. An amendment to the relevant `MS3_` document.
2. A file named `LOCK_AMENDMENT.md` explaining the deviation.
3. A semantic version bump.

## Protected Invariants
1. **Singleton Execution**: Only one active build process (via `singleton_lock`).
2. **Context Integrity**: No execution without valid `context_hash`.
3. **Budget Safety**: No execution without budget checks.
4. **Transition Atomicity**: Build state changes strictly follow `isValidTransition`.

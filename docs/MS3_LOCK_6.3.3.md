# MS3_LOCK_6.3.3
**Status**: LOCKED
**Source**: `src/kernel_orchestrator.ts` (v2 Hardened Monolith)
**Timestamp**: 2026-01-17T19:23:56Z

## 1. Build State Machine

The Build Lifecycle is governed by a strict state machine implemented in `isValidTransition`.

### States
- **PENDING**: Initial state (Build created).
- **ACTIVE**: Build in progress (Lock held).
- **CRASHED**: System failure or Orphan detection.
- **BUDGET_PAUSE**: Action Required: Budget exceeded limit or pre-check failure.
- **SUCCESS**: Terminal success.
- **FAILED**: Terminal failure.
- **ABANDONED**: Terminal abort.

### Transitions (Authoritative)
- **PENDING** → `ACTIVE` | `ABANDONED`
- **ACTIVE** → `SUCCESS` | `FAILED` | `CRASHED` | `BUDGET_PAUSE` | `ABANDONED`
- **CRASHED** → `ACTIVE` | `ABANDONED`
- **BUDGET_PAUSE** → `ACTIVE` | `FAILED` | `ABANDONED`
- **SUCCESS** → *(terminal)*
- **FAILED** → *(terminal)*
- **ABANDONED** → *(terminal)*

**Resume Mechanics**:
- Resume transitions: `CRASHED` → `ACTIVE` or `BUDGET_PAUSE` → `ACTIVE`.
- **Note**: Current code uses reason="operator_abort" when transitioning resumed builds to ACTIVE (naming mismatch; behavior is authoritative).

## 2. Singleton Execution Spec

System MUST enforce exactly ONE active writer via `singleton_lock` table in SQLite.

### Lock Table Schema
```sql
CREATE TABLE singleton_lock (
  lock_id INTEGER PRIMARY KEY CHECK (lock_id = 1),
  token TEXT NOT NULL,
  build_id TEXT,
  acquired_by_pid INTEGER NOT NULL,
  process_name TEXT NOT NULL,
  exe_sha256 TEXT NOT NULL,
  acquired_at TEXT NOT NULL,
  last_heartbeat_at TEXT NOT NULL
);
```

### Protocols
- **Acquire**:
  - Verify `process_name` == `dirkernel`.
  - Check existing lock liveness:
    - `pid` alive? (via `process.kill(pid, 0)`)
    - `exe_sha256` matches?
    - `heartbeat` fresh? (within `LOCK_TTL_MS` = 10m)
  - If STALE or FREE: `UPDATE singleton_lock ...`
  - If HELDBY ALIVE: Fail `LOCK_CONFLICT`.
- **Heartbeat**:
  - Worker thread runs every 5s (`LOCK_HEARTBEAT_INTERVAL_MS`).
  - Updates `last_heartbeat_at`.
  - Validates `token` and `exe_sha256` match before update.
  - On mismatch: `gracefulShutdown` triggered.
- **Startup Integrity**:
  - All `ACTIVE` builds NOT owned by the new lock are immediately transitioned to `CRASHED` ("orphaned_at_startup").

## 3. Checkpointing & Idempotency

Computation is checkpointed at granular `(build_id, stage, target)` level.

### Key
- Primary Key: `(build_id, stage, target)`
- Content Key: `context_hash` (Sha256 of inputs + config + stage + target)

### Resume Logic
1. Calculate `context_hash` for target.
2. Check `checkpoints` table.
3. If row exists AND `status` == 'SUCCESS' AND `row.context_hash` == `calculated_hash`:
   - **SKIP** execution.
   - Return cached result (cost=0, tokens=0).
4. Else:
   - Execute.
   - On success: UPSERT `checkpoints` with `SUCCESS`.
   - On failure: UPSERT `checkpoints` with `FAILED`.

## 4. Budget & Pause Semantics

- **Budget Precheck**: Structural precheck exists, but `estimated_cost` is currently fixed at `0`.
  - Therefore `budget_precheck_block` DOES NOT currently trigger unless logic is patched.
- **Post-Execution Check**: If `cumulative_cost > budget`:
  - Transition to `BUDGET_PAUSE` (Reason: `budget_exceeded`).
  - Mint `confirmation_token`.

### Confirmation Token
- Required to resume from `BUDGET_PAUSE`.
- Stored in `confirmation_tokens` table.
- Validated via `validateAndConsume` on resume.

## 5. Event Outbox

Events are persisted to SQLite via an outbox table and flushed (print+delete). Emission is ordered by created_at and deduped by dedupe_key, but not guaranteed to be in the same SQLite transaction as the associated state update.

- **Schema**:
  - `event_outbox` table.
  - `dedupe_key` UNIQUE.
- **Dedupe Strategy**:
  - Key: `sha256(event_type|build_id|transition_seq|target_hash)`
- **Flush Policy**:
  - Dequeues by printing to console (`[OUTBOX]`) and deleting from DB within a transaction.
  - No guarantee of "exactly once external delivery" beyond dedupe_key uniqueness.

## 6. Output Artifacts

- **Blobs**: `artifacts` table + Filesystem CAS (`root/sh/sha...`).
- **Refs**: `artifact_refs` table links blobs to `(build_id, stage, target)`.
- **Manifest/Handoff**: Produced on demand via `writeBuildOutput(build_id, project)` using OutputWriter.

---
**LOCK STATUS**: SEALED — Contract reflects `src/kernel_orchestrator.ts` v2 monolith as authority; any behavioral change requires MS3 amendment.

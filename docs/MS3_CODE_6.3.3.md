FILES IGNORED / SHADOWED (Dead Code in v2 Context):
- C:\director v1\src\artifact_store.ts (Shadowed by internal class in orchestrator)
- C:\director v1\src\concurrency_limiter.ts (Unused at kernel level in v2; kernel uses singleton_lock. ModelRouter has its own internal limiter.)
- C:\director v1\src\event_bus.ts (Shadowed by `EventOutbox` and `event_outbox` table)
- C:\director v1\src\cost_controller.ts (Superceded; v2 uses cost_records but does not implement warn 70% / pause 95% semantics unless proven)

---

MS3-CODE::kernel_orchestrator (v2 Monolith)

Identity
- Implemented in `src/kernel_orchestrator.ts` class `KernelOrchestrator`
- **Canonical Implementation**: Option A (Hardened Monolith)

Inputs
- `ms5_spec`
- `budget_usd`
- `resume_build_id` (optional)
- `confirmation_token` (optional)

Outputs
- `BuildResult`
- `BuildPlanV1` (via OutputWriter)

Lifecycle / Phase Ordering
1. **Startup**: Validate `exe_sha256`, acquire `singleton_lock`, start heartbeat worker.
2. **Orphan Detection**: Transition `ACTIVE` builds not owned by lock to `CRASHED`.
3. **Execution**:
   - Create/Resume Build.
   - Compute Plan (ExecutionPlanner).
   - Loop Targets:
     - Checkpoint Hit? -> Skip.
     - Budget Precheck? -> `BUDGET_PAUSE` if risk.
     - Execute (StageExecutor).
     - Post-Exec Budget Check -> `BUDGET_PAUSE` if exceeded.
     - Emit Events (EventOutbox).
   - `SUCCESS` / `FAILED` finalization.
4. **Shutdown**: Graceful signal handling (`SIGTERM`/`SIGINT`), transition active to `CRASHED`.

Determinism Guarantees
- **Inputs Hash**: `build_inputs_hash` derived from sorted artifacts.
- **Context Hash**: `sha256(stage|target|inputs|config)` defines execution uniqueness.
- **Locking**: Deterministic `singleton_lock` acquisition via atomic SQLite updates.

Persistence & State Transitions
- **Backing**: SQLite (`better-sqlite3`) with WAL mode.
- **Schema**: `builds`, `checkpoints`, `artifacts`, `artifact_refs`, `cost_records`, `event_outbox`, `singleton_lock`, `confirmation_tokens`.
- **States**: `PENDING`, `ACTIVE`, `CRASHED`, `BUDGET_PAUSE`, `SUCCESS`, `FAILED`, `ABANDONED`.

Concurrency & Locking
- **Singleton Lock**: `singleton_lock` table (ID=1).
- **Liveness**: Checks PID existence + `exe_sha256` match + Heartbeat freshness.
- **Heartbeat**: Worker thread updates timestamp every 5s.

Failure Modes & Error Semantics
- **Lock Conflict**: FAILS if lock held by live process with matching binary.
- **Corrupt State**: Hard failure if DB constraint violations or logical inconsistencies (e.g., missing build).
- **Budget Pause**:
  - `budget_precheck_block`: Predicted cost exceeds tolerance.
  - `budget_exceeded`: Actual cost exceeds budget.
  - Requires manual `confirmation_token` to resume.
- **Checkpoint Fallback**: FAILED executions persisted as `FAILED` checkpoints to prevent re-execution loops.

Security Invariants
- **Binary Identity**: Lock bound to `exe_sha256` of running process.
- **Recursion Guard**: `assertNoFloatValues` depth limit (100).
- **Artifact Size**: Max 25MB per artifact (`MAX_ARTIFACT_BYTES`).

Events Emitted
- `build_state_changed`, `target_completed`, `budget_pause`.
- Persisted to SQLite via event_outbox and flushed (print+delete); deduped by dedupe_key.

---

MS3-CODE::artifact_store (Shadowed)

**Implementation**: `src/kernel_orchestrator.ts` (Inner Class `ArtifactStore`)
- **Storage**: Filesystem CAS (SHA256 based).
- **Invariants**: Content-addressable. Unique by SHA256.

---

MS3-CODE::event_bus (Shadowed)

**Implementation**: `src/kernel_orchestrator.ts` (Inner Class `EventOutbox` + table)
- **Mechanism**: Polling / Transactional Outbox pattern.
- **Dedupe**: `dedupe_key` column in `event_outbox`.
- **Ordering**: Flush dequeues by `created_at` (best-effort chronological).

---

MS3-CODE::concurrency_policy (v2 implicit)

**Mechanisms**:
- **Kernel Level**: Enforces single `ACTIVE` build via `singleton_lock` (System-wide).
- **ModelRouter Level**: Enforces max concurrent model calls via internal `ConcurrencyLimiter` (Cap: 6).

---

MS3-CODE::model_router

Identity
- Implemented in `src/model_router.ts`

Inputs
- `ModelRequest` (`model_id`, `messages`, `max_tokens`, etc.)

Outputs
- `ModelResponse` (on success)
- `ModelRouterError` (on failure)

Lifecycle / Phase Ordering
- MUST validate allowlist, messages, prompt char limit.
- MUST canonicalize payload for idempotency.
- MUST estimate cost and check budget (per-request & per-build).
- MUST check circuit breaker.
- MUST acquire internal concurrency slot.
- MUST execute call (with retries and backoff).

Determinism Guarantees
- **Idempotency Key**: `sha256(canonicalPayload)` where canonicalPayload has recursively sorted keys.

Persistence & State Transitions
- **CircuitBreaker**: In-memory state (`failures[]`, `openUntilMs`).
- **BuildBudgets**: In-memory map (`build_id` -> `spent`).

Concurrency & Locking
- **Internal Limiter**: `ConcurrencyLimiter` class (semaphore).
- **Max Concurrent Calls**: `FROZEN.MAX_CONCURRENT_CALLS` = 6.

Failure Modes & Error Semantics
- **Budget Pause**:
  - Request estimated cost > `MAX_COST_PER_REQUEST_USD` ($5.0).
  - Build estimated spend > `MAX_COST_PER_BUILD_ID_USD` ($50.0).
- **Circuit Breaker**: Open after 5 failures in 60s, cools down for 30s.
- **Retries**:
  - Max 3 attempts.
  - Backoff: `[1000, 2000, 4000]` ms.
  - Retryable errors: HTTP 429, 500-599, Network Timeout, Rate Limit.
- **Prompt/Response Limits**:
  - Max Prompt Chars: 200,000.
  - Max Response Chars: 200,000.
  - Max Completion Tokens: 8192.
- **Timeouts**:
  - Call Timeout: 120s (`MODEL_CALL_TIMEOUT_MS`).

Security Invariants
- **Sanitization**: `sanitizeErrorSnippet` redacts IP, keys, auth headers. Max 100 chars.
- **Allowlist**: Strict `FROZEN.MODEL_ALLOWLIST` (Claude 3/3.5 Haiku, GPT-4o-mini, Llama 3.1 70b, DeepSeek Chat).

---

MS3-CODE::context_slicer

Identity
- Implemented in `src/context_slicer.ts` class `ContextSlicer`

(Same as previous analysis)

---

MS3-CODE::schema_validator

Identity
- Implemented in `src/schema_validator.ts` class `SchemaValidator`

(Same as previous analysis)

---

MS3-CODE::transform_engine

Identity
- Implemented in `src/transform_engine.ts` class `TransformEngine`

(Same as previous analysis)

---

MS3-CODE::recovery_orchestrator

Identity
- Implemented in `src/recovery_orchestrator.ts` class `RecoveryOrchestrator`

(Same as previous analysis)

---

MS3-CODE::output_writer

Identity
- Implemented in `src/output_writer/writer.ts` class `OutputWriterImpl`

(Same as previous analysis - Used by KernelOrchestrator)

---

# CROSS-MODULE REQUIREMENTS (Final V2)

**Build State Machine**
- **Authority**: `src/kernel_orchestrator.ts` `isValidTransition` function.
- **States**: `PENDING`, `ACTIVE`, `CRASHED`, `BUDGET_PAUSE`, `SUCCESS`, `FAILED`, `ABANDONED`.
- **Transitions**: Hard-coded allowed transitions map.

**Locking & Concurrency**
- **Authority**: `src/kernel_orchestrator.ts` `BuildLifecycleManager`.
- **Mechanism**: SQLite `singleton_lock` table + Worker Heartbeat.
- **TTL**: 10 minutes (`THRESHOLDS.LOCK_TTL_MS`).

**Budget & Truncation**
- **Authority**: `src/kernel_orchestrator.ts` `StageExecutor` + `src/context_slicer.ts`.
- **Pause Trigger**: `budget_precheck_block` or `budget_exceeded`.
- **Truncation Fail**: `TRANSFORM_ENGINE` -> `context_slicer` throws `EXCESSIVE_TRUNCATION`.

**Event System**
- **Authority**: `src/kernel_orchestrator.ts` `EventOutbox`.
- **Pattern**: Transactional Outbox (Store in DB -> Flush to Log/Console).
- **Dedupe**: `sha256(type|build_id|seq|target_hash)`.

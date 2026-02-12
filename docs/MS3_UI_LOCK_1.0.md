# MS3_UI_LOCK_1.0 — UI Lock Manifest for Sealed Kernel v2

**Status:** LOCKED  
**Authority:** UI Seal Preservation Contract  
**Date:** 2026-01-17

---

## 1) Non-Negotiable Invariants

### 1.1 Kernel Authority
The kernel is the single authority over:
- build state machine transitions
- singleton lock acquisition/heartbeat
- checkpoint creation
- artifact writing
- token consumption

UI MUST NOT simulate authority or implement kernel logic.

---

### 1.2 SQLite Immutability
Bridge SQLite connection MUST be read-only.

**Required:**
- Open DB with readonly flags (driver readonly option)
- `PRAGMA query_only = ON;`
- `PRAGMA trusted_schema = OFF;`
- `PRAGMA busy_timeout = 50;`
- Prepared statements only

**Forbidden pragmas:**
- `PRAGMA locking_mode = EXCLUSIVE`
- `PRAGMA journal_mode = OFF`
- `PRAGMA writable_schema = ON`
- `ATTACH DATABASE`
- `VACUUM`
- any `CREATE TABLE`, `CREATE TEMP`, etc

---

### 1.3 No DB Mutations (Ever)
Bridge MUST NEVER contain SQL statements:
- INSERT
- UPDATE
- DELETE
- CREATE
- ALTER
- DROP

No exceptions.

---

### 1.4 Token Authority
Bridge MUST NEVER call token consumption logic.

- Bridge may validate **format only** (UUIDv4)
- Bridge may check presence in DB for preflight
- Kernel CLI must consume token

---

### 1.5 Abort Authority
Abort MUST be via kernel CLI only:

✅ `dirkernel abort --build-id <id> --reason operator_requested`  
❌ `process.kill(pid, SIGTERM)`  
❌ direct state mutation

---

### 1.6 Shadow Kernel Ban
Bridge MUST NOT import or call kernel modules directly:

Forbidden:
- `import { KernelOrchestrator } from ...`
- `require('./kernel_orchestrator')`

Commands MUST be subprocess CLI only.

---

### 1.7 Event Streaming Contract
Primary UI live stream MUST come from `[OUTBOX]` stdout parsing.

SSE only.
WebSockets disallowed (state complexity).

---

### 1.8 Artifact Access Contract
Artifacts served strictly by sha256 only.

Endpoint:
`GET /api/artifacts/:sha256`

Validation:
- regex: `^[a-f0-9]{64}$`
- resolve to known artifact_root
- reject if any symlink
- enforce max size 25MB
- set headers:
  - `Content-Disposition: attachment`
  - `X-Content-Type-Options: nosniff`

---

### 1.9 Localhost CSRF Defense
All mutable endpoints MUST require UI token header:

`X-Director-UI-Token: <secret>`

CORS allowlist must be strict.

Bridge binds to `127.0.0.1` only.

---

### 1.10 Configuration Contract
Bridge MUST read configuration only from:
- Environment variables (`DIRECTOR_DB_PATH`, `DIRECTOR_ARTIFACT_ROOT`, `DIRECTOR_KERNEL_BIN`)
- Or a single config file `~/.director/ui_bridge_config.json` (mode 0600)

No hardcoded paths. No auto-discovery heuristics.

---

## 2) Admin Lock Steal 4-Gate Protocol

Lock steal is allowed only as:
`dirkernel admin steal-lock ...`

Bridge NEVER updates singleton_lock.

Gate requirements:

**Gate 1 — Preconditions**
- lock stale: heartbeat > TTL OR pid dead OR exe mismatch
- no recent checkpoint in last 60s

**Gate 2 — Operator Confirmation**
- exact phrase typed: `STEAL LOCK`
- exact build_id typed
- acknowledge risks checkbox

**Gate 3 — Audit Trail**
- append-only: `~/.director/audit.log` mode 0600
- line format: `ts|operator|lock_snapshot|reason|preconditions_met`

**Gate 4 — Kernel Delegation**
- bridge calls kernel CLI
- kernel re-validates preconditions

---

## 3) Provability / CI
See:
- `scripts/verify-ui-lock.sh`
- grep gates
- build tests must fail if invariant violated

---

## 4) Seal Statement
If any invariant is violated, the UI is NON-COMPLIANT and seal is broken.

LOCKED.

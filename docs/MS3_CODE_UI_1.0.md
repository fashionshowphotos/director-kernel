# MS3-CODE::ui_system v1.0 — Director Kernel v2 Consumer UI System

**Status:** LOCKED  
**Scope:** Consumer UI + API bridge for Director Kernel v2 (MS3 6.3.3 kernel locked)  
**Date:** 2026-01-17  
**Authority:** UI as Observer, Kernel as Authority

---

## 0) Purpose

Provide a consumer-grade UI that makes the sealed kernel usable, while preserving all MS3 kernel invariants.

This system MUST NOT introduce any "shadow kernel" logic or any persistence/control mechanism that competes with the kernel's SQLite truth and state machine.

---

## 1) System Overview (3-Layer Boundary)

```
┌──────────────────────────────┐
│       UI Frontend (React)    │
│  - read-only presentation    │
│  - submits whitelisted cmds  │
└──────────────┬───────────────┘
               │ HTTP + SSE
┌──────────────▼───────────────┐
│      API Bridge (Fastify)    │
│  - readonly SQLite observer  │
│  - serves artifacts (sha only)│
│  - spawns kernel CLI for cmds │
│  - parses [OUTBOX] stdout    │
└──────────────┬───────────────┘
               │ SQLite + FS + Process Spawn
┌──────────────▼───────────────┐
│    Kernel (LOCKED monolith)  │
│  - owns all writes + invariants│
│  - emits outbox events       │
└──────────────────────────────┘
```

The kernel remains a pure authoritative process.  
The UI system is an observer + command proxy.

---

## 2) Modules (New)

### 2.1 MS3-CODE::api_bridge
**Role:** Air-gap Observer + Command Proxy  
**Implementation:** Node.js Fastify server  
**Source:** `ui/backend/src/index.ts` (or `src/api_bridge/server.ts`)

#### Critical Invariant
Bridge MUST NEVER write to kernel tables:
- builds
- checkpoints
- singleton_lock
- event_outbox
- artifacts
- artifact_refs
- confirmation_tokens

All kernel state mutations MUST occur through spawning kernel CLI commands.

### 2.2 MS3-CODE::ui_frontend
**Role:** Consumer UI (React)
**Implementation:** React/Vite SPA
**Source:** `ui/frontend/`

Frontend MUST NOT:
- open SQLite
- access filesystem
- import kernel code
- invent state transitions

---

## 3) API Surface (Bridge)

### Read-only endpoints
- `GET /api/status`
- `GET /api/builds`
- `GET /api/builds/:id`
- `GET /api/checkpoints/:build_id`
- `GET /api/events` (poll fallback)
- `GET /api/events/sse` (primary live feed)
- `GET /api/artifacts/:sha256`
- `GET /api/build_manifest/:build_id`

### Mutating endpoints (command proxy only)
- `POST /api/commands/plan`
- `POST /api/commands/build`
- `POST /api/commands/resume`
- `POST /api/commands/abort`
- `POST /api/commands/export`
- `POST /api/commands/admin/steal-lock` (4-gate enforced)

No other command endpoints are permitted.

---

## 4) Command Delegation (Kernel CLI Only)

All bridge commands MUST be implemented by spawning the kernel process:

**Required pattern:**
- `spawn('dirkernel', ['build', ...], { shell: false })`
- never `exec("dirkernel ...")`
- never concatenate user strings into shell commands

Bridge MUST NOT import kernel TS modules.

**Exact CLI Mapping Table**

| Command Endpoint                  | Kernel CLI Spawn Arguments                                                                 | Notes                                      |
|-----------------------------------|--------------------------------------------------------------------------------------------|--------------------------------------------|
| POST /commands/plan               | `dirkernel plan --ms5 <temp_ms5_path>`                                                     | If separate plan step exists               |
| POST /commands/build              | `dirkernel build --ms5 <temp_ms5_path> --budget <usd>`                                     | Temp file must be 0600                     |
| POST /commands/resume             | `dirkernel resume --build-id <id> --token <token>`                                         | Token passed verbatim                      |
| POST /commands/abort              | `dirkernel abort --build-id <id> --reason operator_requested`                              |                                            |
| POST /commands/export             | `dirkernel export --build-id <id> --dest <user_chosen_path>`                               | Dest optional; UI prompts user             |
| POST /commands/admin/steal-lock   | `dirkernel admin steal-lock --build-id <id> --reason <typed_reason>`                       | 4-gate enforced in UI first; kernel re-validates |

---

## 5) Event Streaming

### Primary path (authoritative UI feed):
Bridge parses kernel process stdout lines beginning with:
`[OUTBOX] {json}`

Bridge emits parsed payloads to UI over SSE.

### Fallback path:
Read-only poll of `event_outbox` for UI history/backfill.

Bridge MUST NOT depend on event_outbox retention, because kernel may print+delete.

---

## 6) Artifact Streaming

Artifacts MUST be served only by SHA256 identifier:

`GET /api/artifacts/:sha256`

No filename-based, path-based, or directory listing endpoints are allowed.

---

## 7) Compliance / Hardening

A CI-gated script MUST enforce:
- no DB writes
- no kernel imports
- no process.kill-based abort
- sha256-only artifact access
- strict CORS for localhost only

See `scripts/verify-ui-lock.sh`.

---

## 8) Locked Statement

This contract is LOCKED.  
Any modification requires:
- explicit contract amendment
- re-redteam analysis
- re-lock issuance

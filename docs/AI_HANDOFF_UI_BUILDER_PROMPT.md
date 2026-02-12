# Director Kernel v2 UI Build Handoff Prompt (LOCKED)

You are building the Director Kernel v2 consumer UI system under a LOCKED contract:
- Kernel is sealed, MS3 6.3.3 is authoritative.
- UI must be observer + command proxy only.
- UI must NEVER mutate kernel DB tables.
- ALL kernel mutations MUST occur via spawning kernel CLI.
- Events: primary live stream from parsing kernel stdout `[OUTBOX]` lines.

Deliverables:
1) api_bridge (Fastify backend) with endpoints listed in MS3_CODE_UI_1.0.md
2) ui_frontend (React) consuming bridge endpoints
3) verify-ui-lock.sh CI gate enforced

Non-negotiables:
- no SQL writes (INSERT/UPDATE/DELETE/CREATE/etc)
- `PRAGMA query_only = ON` and `PRAGMA trusted_schema = OFF`
- no WebSocket
- no kernel module imports
- abort via kernel CLI only (no process.kill)
- artifacts served by sha256 only
- Child process stdout/stderr MUST be piped and parsed for [OUTBOX] lines in real time

If you are about to add a feature not in contract, STOP and do not implement it.

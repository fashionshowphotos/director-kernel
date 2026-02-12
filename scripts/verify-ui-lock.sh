#!/usr/bin/env bash
set -euo pipefail

echo "== Director Kernel UI Lock Gate Verification =="

ROOT="${1:-.}"

fail() {
  echo "FAIL: $1"
  exit 1
}

pass() {
  echo "PASS: $1"
}

# -----------------------------
# 1) No kernel imports
# -----------------------------
if grep -RIn --exclude-dir=node_modules --exclude-dir=dist \
  "kernel_orchestrator|KernelOrchestrator|BuildLifecycleManager|StageExecutor" \
  "$ROOT/ui/backend/src" "$ROOT/ui/frontend/src" 2>/dev/null; then
  fail "UI imports/references kernel internals (shadow kernel risk)"
else
  pass "No kernel internal imports detected"
fi

# -----------------------------
# 2) No SQL writes
# -----------------------------
if grep -RIn --exclude-dir=node_modules --exclude-dir=dist \
  -E "\b(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|VACUUM|ATTACH)\b" \
  "$ROOT/ui/backend/src" 2>/dev/null; then
  fail "SQL write/mutation keywords detected in UI backend"
else
  pass "No SQL mutation keywords found"
fi

# -----------------------------
# 3) No dangerous pragmas
# -----------------------------
if grep -RIn --exclude-dir=node_modules --exclude-dir=dist \
  -E "PRAGMA.*(writable_schema|locking_mode|journal_mode|temp_store|synchronous)" \
  "$ROOT/ui/backend/src" 2>/dev/null; then
  fail "Dangerous PRAGMA usage detected in UI backend"
else
  pass "No dangerous PRAGMA usage found"
fi

# -----------------------------
# 4) No process.kill use
# -----------------------------
if grep -RIn --exclude-dir=node_modules --exclude-dir=dist \
  "process\.kill" "$ROOT/ui/backend/src" 2>/dev/null; then
  fail "process.kill found (abort must be via kernel CLI)"
else
  pass "No process.kill detected"
fi

# -----------------------------
# 5) Artifact access must be sha256-only
# -----------------------------
if ! grep -RIn --exclude-dir=node_modules --exclude-dir=dist \
  -E "/api/artifacts/:sha256|artifacts/:sha256" \
  "$ROOT/ui/backend/src" 2>/dev/null 1>/dev/null; then
  echo "WARN: Could not confirm sha256-only route pattern. Ensure endpoint exists."
else
  pass "Artifact endpoint appears sha256-only"
fi

# -----------------------------
# 6) Spawn must use shell=false (no injection)
# -----------------------------
if grep -RIn --exclude-dir=node_modules --exclude-dir=dist \
  -E "exec\\(|execSync\\(|shell:\\s*true" \
  "$ROOT/ui/backend/src" 2>/dev/null; then
  fail "Unsafe command execution detected (exec / shell:true)"
else
  pass "No unsafe exec/shell:true usage detected"
fi

# -----------------------------
# 7) SSE / stdout parsing required
# -----------------------------
if ! grep -RIn --exclude-dir=node_modules --exclude-dir=dist \
  "\[OUTBOX\]" "$ROOT/ui/backend/src" 2>/dev/null 1>/dev/null; then
  fail "No [OUTBOX] stdout parsing detected (primary event path missing)"
else
  pass "[OUTBOX] parsing present"
fi

echo "== UI Lock Manifest: PASS =="

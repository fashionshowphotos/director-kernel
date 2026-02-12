# Director Kernel v6.4.2 — FINAL Enterprise Validation (Round 3)

## System Overview
Director Kernel is a **semantic compiler** that transforms human intent into working software through layered constraints (MS5→MS4→MS3→MS2). Uses LLMs via OpenRouter API for transform stages, with MC2 governance loop for code generation.

**Architecture**: TypeScript, ~13,200 LOC, 37 source files, Node.js >=18, SQLite (better-sqlite3), LRU cache

## Score History
| Dimension | Round 1 | Round 2 | Round 3 Target |
|-----------|---------|---------|----------------|
| Security | 6.5 | 8.15 | 9+ |
| Reliability | 6.3 | 7.6 | 9+ |
| Code Quality | 6.2 | 7.7 | 9+ |
| Architecture | 7.7 | 8.0 | 9+ |
| Observability | 5.3 | 7.6 | 9+ |

## Complete Fix Log (All 3 Rounds)

### CRITICAL
- Removed hardcoded OpenRouter API key from model_router.ts and kernel_orchestrator.ts

### Security Hardening
- **TOCTOU symlink race**: Atomic open with O_NOFOLLOW + fstat on fd (no check-then-open)
- **Path traversal**: realpath-after-open verification inside jail
- **File restrictions**: 18 denied names (.env*, credentials, tokens, SSH keys, cloud creds) + 6 denied dirs (.ssh, .gnupg, .aws, .docker, .kube, node_modules) + .env prefix catch-all
- **Memory bounds**: MAX_ENRICHMENT_ARTIFACTS=20, MAX_ENRICHMENT_TOTAL_BYTES=5MB, per-file 1MB
- **BudgetAuthority**: Centralized financial choke point — all model calls must pass through budget_authority.ts

### Reliability
- **JSON.parse guards**: All unprotected parse paths wrapped in try-catch
- **Comment regex safety**: JSON.parse attempted first; regex comment stripping only as fallback
- **Event outbox**: Exactly-once semantics — flush deletes by specific event IDs
- **TS validation**: Mandatory for enterprise/production tier (fail-closed if ts unavailable)
- **Token estimation**: Improved heuristic (chars/3.3 + word count, conservative for budget safety)
- **Heartbeat failure**: Worker signals gracefulShutdown=true, build loop checks between targets

### Code Quality
- **Dead code**: 102 lines of commented-out Stage 5 removed
- **Debug artifact leak**: last_reply.json no longer written to CWD
- **Budget precheck**: Now estimates from average of completed targets (was dead code)
- **Status command crash**: parseFloat(String()) for SQLite decimal strings
- **Model capability**: response_format: json_object only sent to models that support it

### Observability
- **Structured logger** (logger.ts): createLogger(component) with {debug, info, warn, error, child}
- Levels: DEBUG/INFO/WARN/ERROR with ISO timestamps
- JSON mode: DIRECTOR_LOG_JSON=1 for machine-parseable JSONL
- File output: DIRECTOR_LOG_FILE for persistent logging
- **Correlation IDs**: Per-build correlation ID (crypto.randomUUID()) + build_id + stage + target propagated through all log entries

### Architecture
- **BudgetAuthority**: Singleton spend controller with rate limiting, registered at build start, released at build end
- **Correlation context**: setCorrelation/clearCorrelation lifecycle managed by orchestrator

## Test Coverage
- 5 test suites, 7 tests, 100% pass
- Output writer: exclusive locks, TTL cleanup, basic writes
- MC2 baton: tamper detection, hash mismatch, governance tampering, missing baton
- MC2 governance: injection with/without governance bundle
- Schema validation: objection ledger, completion declaration
- Semantic harness: structure, non-invention, MS2.5 schema, tier contracts

## KEY SOURCE CODE FOR REVIEW

### budget_authority.ts (FULL — NEW centralized financial control)
```typescript
import { createLogger } from './logger';
const log = createLogger('budget');

export interface SpendRecord {
    build_id: string;
    stage: string;
    target: string;
    model_id: string;
    estimated_cost_usd: number;
    actual_cost_usd: number;
    tokens_in: number;
    tokens_out: number;
    timestamp: string;
}

export interface BudgetConfig {
    budget_usd: number;
    max_calls_per_min?: number;
    max_tokens_per_min?: number;
    warn_threshold?: number;
}

export class BudgetExceededError extends Error {
    constructor(
        public readonly build_id: string,
        public readonly budget_usd: number,
        public readonly spent_usd: number,
        public readonly estimated_usd: number
    ) {
        super(`Budget exceeded: build=${build_id} budget=$${budget_usd.toFixed(4)} spent=$${spent_usd.toFixed(4)} estimated=$${estimated_usd.toFixed(4)}`);
        this.name = 'BudgetExceededError';
    }
}

export class RateLimitError extends Error {
    constructor(public readonly build_id: string, public readonly limit: string) {
        super(`Rate limit hit: build=${build_id} limit=${limit}`);
        this.name = 'RateLimitError';
    }
}

export class BudgetAuthority {
    private spent = new Map<string, number>();
    private ledger = new Map<string, SpendRecord[]>();
    private callTimestamps = new Map<string, number[]>();
    private tokenTimestamps = new Map<string, Array<{ ts: number; tokens: number }>>();
    private configs = new Map<string, BudgetConfig>();

    registerBuild(build_id: string, config: BudgetConfig): void {
        this.configs.set(build_id, config);
        if (!this.spent.has(build_id)) this.spent.set(build_id, 0);
        if (!this.ledger.has(build_id)) this.ledger.set(build_id, []);
        if (!this.callTimestamps.has(build_id)) this.callTimestamps.set(build_id, []);
        if (!this.tokenTimestamps.has(build_id)) this.tokenTimestamps.set(build_id, []);
        log.info(`Budget registered`, { build_id, budget_usd: config.budget_usd });
    }

    authorize(build_id: string, estimated_cost_usd: number, estimated_tokens: number): void {
        const config = this.configs.get(build_id);
        if (!config) throw new Error(`BudgetAuthority: build ${build_id} not registered`);
        const currentSpend = this.spent.get(build_id) || 0;
        const projected = currentSpend + estimated_cost_usd;
        if (projected > config.budget_usd * 1.10) {
            log.error(`Budget exceeded`, { build_id, budget: config.budget_usd, spent: currentSpend, estimated: estimated_cost_usd });
            throw new BudgetExceededError(build_id, config.budget_usd, currentSpend, estimated_cost_usd);
        }
        const warnAt = config.warn_threshold ?? 0.8;
        if (projected > config.budget_usd * warnAt) {
            log.warn(`Budget warning`, { build_id, budget: config.budget_usd, spent: currentSpend, projected, threshold: warnAt });
        }
        // Rate limit: calls per minute
        if (config.max_calls_per_min && config.max_calls_per_min > 0) {
            const now = Date.now();
            const recent = (this.callTimestamps.get(build_id) || []).filter(t => now - t < 60_000);
            if (recent.length >= config.max_calls_per_min) {
                throw new RateLimitError(build_id, `${config.max_calls_per_min} calls/min`);
            }
        }
        // Rate limit: tokens per minute
        if (config.max_tokens_per_min && config.max_tokens_per_min > 0) {
            const now = Date.now();
            const recentTokens = (this.tokenTimestamps.get(build_id) || [])
                .filter(r => now - r.ts < 60_000)
                .reduce((sum, r) => sum + r.tokens, 0);
            if (recentTokens + estimated_tokens > config.max_tokens_per_min) {
                throw new RateLimitError(build_id, `${config.max_tokens_per_min} tokens/min`);
            }
        }
    }

    record(build_id: string, record: Omit<SpendRecord, 'build_id' | 'timestamp'>): void {
        const ts = new Date().toISOString();
        const full: SpendRecord = { build_id, timestamp: ts, ...record };
        const prev = this.spent.get(build_id) || 0;
        this.spent.set(build_id, prev + record.actual_cost_usd);
        const ledger = this.ledger.get(build_id) || [];
        ledger.push(full);
        this.ledger.set(build_id, ledger);
        const now = Date.now();
        const calls = this.callTimestamps.get(build_id) || [];
        calls.push(now);
        const cutoff = now - 120_000;
        this.callTimestamps.set(build_id, calls.filter(t => t > cutoff));
        const tokens = this.tokenTimestamps.get(build_id) || [];
        tokens.push({ ts: now, tokens: record.tokens_in + record.tokens_out });
        this.tokenTimestamps.set(build_id, tokens.filter(r => r.ts > cutoff));
        const drift = record.actual_cost_usd - record.estimated_cost_usd;
        if (Math.abs(drift) > 0.001) {
            log.debug(`Cost drift`, { build_id, model: record.model_id, estimated: record.estimated_cost_usd, actual: record.actual_cost_usd, drift });
        }
    }

    getSpend(build_id: string): number { return this.spent.get(build_id) || 0; }
    getLedger(build_id: string): SpendRecord[] { return [...(this.ledger.get(build_id) || [])]; }
    getRemaining(build_id: string): number {
        const config = this.configs.get(build_id);
        if (!config) return 0;
        return Math.max(0, config.budget_usd - (this.spent.get(build_id) || 0));
    }
    releaseBuild(build_id: string): SpendRecord[] {
        const ledger = this.getLedger(build_id);
        this.configs.delete(build_id);
        this.spent.delete(build_id);
        this.ledger.delete(build_id);
        this.callTimestamps.delete(build_id);
        this.tokenTimestamps.delete(build_id);
        log.info(`Budget released`, { build_id, total_records: ledger.length });
        return ledger;
    }
}

export const budgetAuthority = new BudgetAuthority();
```

### logger.ts (FULL — structured logging with correlation IDs)
```typescript
import * as fs from 'fs';
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
const LEVEL_ORDER: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };
const envLevel = (process.env.DIRECTOR_LOG_LEVEL || 'info').toLowerCase() as LogLevel;
const MIN_LEVEL: number = LEVEL_ORDER[envLevel] ?? 1;
const DEBUG_OVERRIDE = process.env.DIRECTOR_DEBUG === '1' || process.env.DIRECTOR_DEBUG === 'true';
const EFFECTIVE_MIN = DEBUG_OVERRIDE ? 0 : MIN_LEVEL;
const JSON_MODE = process.env.DIRECTOR_LOG_JSON === '1';
const LOG_FILE = process.env.DIRECTOR_LOG_FILE || '';

let _correlationId = '', _buildId = '', _stage = '', _target = '';

export function setCorrelation(opts: { correlationId?: string; buildId?: string; stage?: string; target?: string }): void {
    if (opts.correlationId !== undefined) _correlationId = opts.correlationId;
    if (opts.buildId !== undefined) _buildId = opts.buildId;
    if (opts.stage !== undefined) _stage = opts.stage;
    if (opts.target !== undefined) _target = opts.target;
}
export function clearCorrelation(): void { _correlationId = ''; _buildId = ''; _stage = ''; _target = ''; }

function emit(level: LogLevel, component: string, message: string, data?: Record<string, unknown>): void {
    if (LEVEL_ORDER[level] < EFFECTIVE_MIN) return;
    const ts = new Date().toISOString();
    if (JSON_MODE) {
        const entry: Record<string, unknown> = { ts, level, component, msg: message };
        if (_correlationId) entry.cid = _correlationId;
        if (_buildId) entry.build_id = _buildId;
        if (_stage) entry.stage = _stage;
        if (_target) entry.target = _target;
        if (data) entry.data = data;
        writeOutput(level, JSON.stringify(entry));
    } else {
        const ctx = _buildId ? ` [${_buildId.slice(0, 8)}${_stage ? ':' + _stage : ''}${_target ? '/' + _target : ''}]` : '';
        const prefix = `[${ts}] [${level.toUpperCase().padEnd(5)}] [${component}]${ctx}`;
        writeOutput(level, data ? `${prefix} ${message} ${JSON.stringify(data)}` : `${prefix} ${message}`);
    }
}
function writeOutput(level: LogLevel, line: string): void {
    switch (level) {
        case 'error': case 'warn': process.stderr.write(line + '\n'); break;
        default: process.stdout.write(line + '\n'); break;
    }
    if (LOG_FILE) { try { fs.appendFileSync(LOG_FILE, line + '\n'); } catch { } }
}

export interface Logger {
    debug(msg: string, data?: Record<string, unknown>): void;
    info(msg: string, data?: Record<string, unknown>): void;
    warn(msg: string, data?: Record<string, unknown>): void;
    error(msg: string, data?: Record<string, unknown>): void;
    child(component: string): Logger;
}
export function createLogger(component: string): Logger {
    return {
        debug: (msg, data) => emit('debug', component, msg, data),
        info:  (msg, data) => emit('info',  component, msg, data),
        warn:  (msg, data) => emit('warn',  component, msg, data),
        error: (msg, data) => emit('error', component, msg, data),
        child: (sub) => createLogger(`${component}:${sub}`),
    };
}
```

### TOCTOU-Safe File Enrichment (from kernel_orchestrator.ts, lines 1720-1901)
```typescript
private tryEnrichInputsFromNeedMoreContext(message: string, existing: ArtifactRef[]): ArtifactRef[] {
    const out: ArtifactRef[] = [];
    if (!message) return out;
    const MAX_ENRICHMENT_ARTIFACTS = 20;
    const MAX_ENRICHMENT_TOTAL_BYTES = 5 * 1024 * 1024;
    let totalEnrichmentBytes = 0;
    const existingIds = new Set(existing.map((r) => String(r.artifact_id)));
    const existingSha = new Set(existing.map((r) => String(r.sha256)));

    // 1. Structured JSON Protocol
    try {
        const firstBrace = message.indexOf('{');
        const lastBrace = message.lastIndexOf('}');
        if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
            const parsed = JSON.parse(message.slice(firstBrace, lastBrace + 1));
            if (parsed.reply_type === 'NEED_MORE_CONTEXT' && Array.isArray(parsed.missing)) {
                for (const req of parsed.missing) {
                    if (req.type === 'file' && req.path) {
                        const repoRoot = path.resolve(process.cwd());
                        const fullPath = path.resolve(repoRoot, req.path);
                        if (!fullPath.startsWith(repoRoot + path.sep) && fullPath !== repoRoot) continue;

                        const ALLOWED_EXTS = new Set(['.ts', '.js', '.json', '.md', '.txt', '.yaml', '.yml', '.toml']);
                        const DENIED_NAMES = new Set([
                            '.env', '.env.local', '.env.production', '.env.development', '.env.staging', '.env.test',
                            'credentials.json', 'secrets.json', 'secrets.yaml', 'secrets.yml',
                            '.npmrc', '.netrc', '.gitcredentials',
                            'id_rsa', 'id_ed25519', 'id_ecdsa', 'authorized_keys', 'known_hosts',
                            '.htpasswd', '.pgpass', 'token.json', 'service-account.json',
                        ]);
                        const DENIED_DIRS = new Set(['.ssh', '.gnupg', '.aws', '.docker', '.kube', 'node_modules']);
                        const ext = path.extname(req.path).toLowerCase();
                        const basename = path.basename(req.path).toLowerCase();
                        const pathParts = req.path.split(/[\\/]/).map((s: string) => s.toLowerCase());
                        if (!ALLOWED_EXTS.has(ext) || DENIED_NAMES.has(basename) || basename.startsWith('.env')) continue;
                        if (pathParts.some((p: string) => DENIED_DIRS.has(p))) continue;

                        // TOCTOU-safe: open with O_NOFOLLOW + fstat on fd
                        let fd: number;
                        try {
                            fd = fs.openSync(fullPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
                        } catch (openErr: any) {
                            if (openErr.code === 'ELOOP' || openErr.code === 'ENOENT') continue;
                            continue;
                        }
                        try {
                            const stat = fs.fstatSync(fd);
                            if (!stat.isFile()) continue;
                            if (stat.size > 1024 * 1024) continue; // 1MB max per file
                            const realFullPath = fs.realpathSync(fullPath);
                            if (!realFullPath.startsWith(repoRoot + path.sep) && realFullPath !== repoRoot) continue;
                            if (out.length >= MAX_ENRICHMENT_ARTIFACTS) continue;
                            if (totalEnrichmentBytes + stat.size > MAX_ENRICHMENT_TOTAL_BYTES) continue;
                            const content = fs.readFileSync(fd);
                            totalEnrichmentBytes += content.length;
                            const stored = this.artifactStore.store(content);
                            if (!existingSha.has(stored.sha256)) {
                                out.push({ artifact_id: stored.sha256, sha256: stored.sha256, kind: 'config' });
                                existingSha.add(stored.sha256);
                            }
                        } finally {
                            try { fs.closeSync(fd); } catch {}
                        }
                    }
                }
            }
        }
    } catch (e) { /* fall through to regex */ }

    // 2. Legacy regex fallback for sha256/UUID references
    const shaMatches = message.match(/[a-fA-F0-9]{64}/g) || [];
    const uuidMatches = message.match(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}/g) || [];
    for (const id of uuidMatches) { /* resolve from artifact table */ }
    for (const sha of shaMatches) { /* resolve from artifact table */ }
    return out;
}
```

### Build Loop with BudgetAuthority Integration (kernel_orchestrator.ts, lines 1292-1541)
```typescript
// Register budget authority for this build
budgetAuthority.registerBuild(build.build_id, {
    budget_usd: params.budget_usd,
    max_calls_per_min: 30,
    max_tokens_per_min: 500_000,
});

// Set build correlation context for structured logging
const correlationId = crypto.randomUUID();
setCorrelation({ correlationId, buildId: build.build_id });

try {
    for (const entry of plan) {
        setCorrelation({ stage: entry.stage, target: entry.target });
        if (this.gracefulShutdown) {
            this.lifecycle.transitionState(this.lock, build.build_id, "CRASHED", "crash_detected");
            break;
        }
        // Checkpoint skip (idempotent resume)
        if (this.planner.hasSuccessfulCheckpoint(build.build_id, entry.stage, entry.target, entry.context_hash)) {
            log.info(`[${targetIndex}/${plan.length}] ${entry.stage}/${entry.target} - skipped (cached)`);
            continue;
        }
        // Budget precheck from average of completed targets
        const remaining = this.remainingBudget(build.build_id);
        const estimated_cost = completedTargets > 0 ? completedCost / completedTargets : remaining * 0.1;
        if (estimated_cost >= remaining * THRESHOLDS.BUDGET_PRECHECK_TOLERANCE) {
            const token = this.tokens.mint(build.build_id, 60);
            this.lifecycle.transitionState(this.lock, build.build_id, "BUDGET_PAUSE", "budget_precheck_block");
            return { ok: true, value: { build_id, final_state: "BUDGET_PAUSE", confirmation_token: token } };
        }
        // Execute with retry
        // ... MC2 interception for code_generation stage ...
        // ... Standard executor with NEED_MORE_CONTEXT enrichment ...
    }
} finally {
    budgetAuthority.releaseBuild(build.build_id);
    clearCorrelation();
}
```

### Event Outbox — Exactly-Once Flush (kernel_orchestrator.ts)
```typescript
flush(batchSize: number): number {
    const rows = withSqliteRetry(
        () => this.db.prepare(`SELECT event_id, payload_json FROM event_outbox ORDER BY created_at LIMIT ?`).all(batchSize) as any[],
        3
    );
    if (!rows.length) return 0;
    const ids = rows.map(r => String(r.event_id));
    const placeholders = ids.map(() => '?').join(',');
    withSqliteRetry(() => {
        this.db.prepare(`DELETE FROM event_outbox WHERE event_id IN (${placeholders})`).run(...ids);
    }, 3);
    return rows.length;
}
```

### JSON Parse Safety (transform_engine.ts)
```typescript
private parseJsonCompletion(rawCompletion: string, label: string): any {
    let cleaned = String(rawCompletion || '').trim();
    if (cleaned.startsWith('```')) {
        const lines = cleaned.split('\n');
        lines.shift();
        if (lines[lines.length - 1].trim() === '```') lines.pop();
        cleaned = lines.join('\n').trim();
    } else {
        const firstBrace = cleaned.indexOf('{');
        const lastBrace = cleaned.lastIndexOf('}');
        if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
            cleaned = cleaned.slice(firstBrace, lastBrace + 1);
        }
    }
    // Try clean parse first
    try { return JSON.parse(cleaned); } catch {
        // Fallback: strip JS comments
        const stripped = cleaned.replace(/\\"|"(?:\\"|[^"])*"|(\/\/.*|\/\*[\s\S]*?\*\/)/g, (m, g) => g ? "" : m);
        try { return JSON.parse(stripped); }
        catch (e: any) { throw new Error(`${label} parse failed: ${String(e?.message || e)}`); }
    }
}
```

### TypeScript Validation — Mandatory for Enterprise (transform_engine.ts)
```typescript
private typecheckMs2(files: Array<{ path: string; content: string }>, tier?: DirectorTier): { ok: boolean; diagnostics: string } {
    const ts = this.tryGetTypeScript();
    if (!ts) {
        if (tier === 'enterprise' || tier === 'production') {
            return { ok: false, diagnostics: 'TypeScript module not available — mandatory for enterprise/production tier.' };
        }
        return { ok: true, diagnostics: '' };
    }
    // ... transpileModule per file with strict: true ...
}
```

### Model Capability Routing (model_router.ts)
```typescript
function computeCanonicalPayload(req: ModelRequest): any {
    const payload: any = {
        model: req.model_id, messages: req.messages,
        temperature: safeTemperature(req.temperature),
        max_tokens: req.max_tokens || FROZEN.MAX_COMPLETION_TOKENS,
        stream: false,
    };
    const registry = ModelRegistry.getInstance();
    const modelInfo = registry.getModelInfo(req.model_id);
    if (modelInfo?.supportsJsonMode !== false) {
        payload.response_format = { type: 'json_object' };
    }
    return payload;
}
```

## Round 3 Scores (5-AI Panel — asked to be HARSH)
| AI | Security | Reliability | Code Quality | Architecture | Observability | Overall |
|----|----------|-------------|--------------|--------------|---------------|---------|
| ChatGPT | 6.8 | 7.1 | 7.3 | 7.9 | 7.6 | 7.3 |
| Grok | 8.0 | 7.0 | 8.0 | 8.0 | 8.0 | 8.0 |
| DeepSeek | 7.0 | 7.0 | 7.0 | 7.0 | 7.0 | 7.25 |
| Gemini | 8.4 | 8.7 | 9.2 | 8.8 | 8.5 | 8.7 |
| Kimi | 6.0 | 7.0 | 7.0 | 6.5 | 7.0 | 6.7 |
| **AVG** | **7.2** | **7.4** | **7.7** | **7.6** | **7.6** | **7.6** |

## Fixes Applied After Round 3

### P0: BudgetAuthority NOW wired into model_router (FIXED)
- `budgetAuthority.authorize()` called before every API call in ModelRouter.executeModelCall()
- `budgetAuthority.record()` called after every successful API call with actual cost
- BudgetExceededError returns BUDGET_PAUSE; RateLimitError returns TRANSFORM_RATE_LIMIT
- Non-registered builds gracefully skip enforcement (non-fatal)

### P1: Token truncation fixed (max_tokens:8192 → configurable)
- Added `MAX_OUTPUT_TOKENS` to config.ts: `CODE_GEN: 16384`, `SEMANTIC: 8192`, `MC2_LOOP: 8192`
- Wired into transform_engine.ts (2 call sites) and mc2_serial_engine.ts (1 call site)
- Code generation transforms (ms3→ms2) now get 16384 tokens, semantic transforms keep 8192
- Env-overridable: `DIRECTOR_MAX_TOKENS_CODE`, `DIRECTOR_MAX_TOKENS_SEMANTIC`, `DIRECTOR_MAX_TOKENS_MC2`
- **Verified**: NASA roboclaw_wrapper.py (553 LOC Python→TypeScript) now compiles at personal tier

### P2: MS2.5 schema `behaviors.outputs` type crash fixed
- Changed `outputs` schema from `{ type: 'object' }` to `{ oneOf: [{ type: 'string' }, { type: 'object' }] }`
- Matches existing pattern used by `errors` field on the same schema level
- **Verified**: Express UserController.ts now passes MS2.5 stage (was crashing on schema validation)

## Real-World Test Results (NASA JPL + Express boilerplate)
- NASA rover.py (417 LOC Python→TypeScript, toy): SUCCESS $0.004
- NASA roboclaw_wrapper.py (553 LOC Python→TypeScript, personal): SUCCESS $0.005
- Express env.ts (75 LOC TS round-trip, personal): SUCCESS $0.0018 (semantically identical output)
- Express UserController.ts (personal): SUCCESS $0.0018
- Tier gate correctly rejects 5/5 tests at experimental tier for real-world code missing error modes/secrets/config

## Known Remaining Limitations
1. **Transform timeout**: Promise.race can't interrupt sync code. Worker-thread preemption would fix.
2. **Windows PID liveness**: process.kill(pid, 0) may report false positives. Mitigated by heartbeat TTL.
3. **Metrics endpoint**: Currently logs-only, no Prometheus-style counters.
4. **Multi-file input limit**: 7+ files (3K+ LOC) in single directory exceeds model capacity for single-call processing.

## INSTRUCTIONS

**Score 1-10 on these 5 dimensions. Be HARSH — we want to find weaknesses, not flattery.**

1. **Security** (secrets, injection, traversal, access control, financial controls, adversarial LLM output)
2. **Reliability** (error handling, recovery, state management, concurrency, data integrity)
3. **Code Quality** (type safety, dead code, patterns, maintainability, consistency)
4. **Architecture** (separation of concerns, extensibility, testability, design patterns)
5. **Observability** (logging, tracing, metrics, debugging, audit trail)

**Focus areas**: LLM-generated code (adversarial input), financial controls, multi-model governance, artifact integrity, TOCTOU prevention.

**Format your response as**:
- Security: X/10 — [1-2 sentence justification]
- Reliability: X/10 — [1-2 sentence justification]
- Code Quality: X/10 — [1-2 sentence justification]
- Architecture: X/10 — [1-2 sentence justification]
- Observability: X/10 — [1-2 sentence justification]
- Overall: X/10
- Top 3 remaining weaknesses (if any)

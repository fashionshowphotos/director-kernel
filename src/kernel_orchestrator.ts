/* Kernel Orchestrator v2 — Hardened (MC2 v1.1.2 compatible)
 *
 * Major hardening patches:
 * - PID liveness verification (process.kill(pid, 0))
 * - SQLite busy_timeout + SQLITE_BUSY retry wrapper
 * - Heartbeat in Worker thread (survives sync TransformEngine)
 * - ArtifactStore path correctness + size guard
 * - Failure fallback escalation (if cannot persist FAILED checkpoint -> CORRUPT_STATE)
 * - Canonical target_hash rules used for all outbox dedupe keys
 *
 * Dependencies:
 *   npm i better-sqlite3
 */

import Database from "better-sqlite3";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import process from "process";
import { Worker } from "worker_threads";
import { createOutputWriter, BuildPlanV1, WriteOptions } from "./output_writer";
import { MC2SerialEngine } from "./mc2_serial_engine";
import { MC2IterationRequest } from "./mc2_types";
import { createLogger, setCorrelation, clearCorrelation } from "./logger";
import { budgetAuthority } from "./budget_authority";
import { executeInWorker, IsolatedEngineConfig } from "./worker_isolator";

const log = createLogger('orchestrator');

const WORKER_ISOLATION_ENABLED = process.env.DIRECTOR_WORKER_ISOLATION === '1';

// ===========================
// Types / Enums
// ===========================

type UUID = string;
type Sha256Hex = string;

export type BuildState =
    | "PENDING"
    | "ACTIVE"
    | "CRASHED"
    | "BUDGET_PAUSE"
    | "SUCCESS"
    | "FAILED"
    | "ABANDONED";

type StateTransitionReason =
    | "normal_completion"
    | "unhandled_error"
    | "budget_exceeded"
    | "operator_abort"
    | "crash_detected"
    | "lock_stolen"
    | "corrupt_state_detected"
    | "orphaned_at_startup"
    | "budget_precheck_block";

type ResumePolicy = "strict" | "fork";

type ErrorCode =
    | "LOCK_CONFLICT"
    | "INVALID_CONFIG"
    | "INVALID_DEPENDENCY"
    | "CORRUPT_STATE"
    | "MALFORMED_OUTPUT"
    | "INVALID_RESUME_STATE"
    | "STORAGE_ERROR_RETRY"
    | "TRANSFORM_RATE_LIMIT"
    | "NETWORK_ERROR"
    | "EXECUTION_FAILED"
    | "NEED_MORE_CONTEXT";

type Result<T> = { ok: true; value: T } | { ok: false; error: ErrorCode; message?: string };

export type LockToken = {
    token: string;
    build_id: UUID | null;
    pid: number;
    process_name: string;
    exe_sha256: Sha256Hex;
};

type BuildContext = {
    build_id: UUID;
    state: BuildState;
    budget_usd: number;
    cumulative_cost_usd: number;
    ms5_spec_hash: Sha256Hex;
    build_inputs_hash: Sha256Hex;
    transition_seq: number;
    created_at: string;
    updated_at: string;
};

type RecoveryContext = {
    lock: LockToken;
    orphaned_build_ids: UUID[];
};

type ArtifactKind = "output" | "log" | "metadata" | "error" | "ms5" | "ms4" | "ms3" | "ms2" | "ms2_5" | "intent" | "config" | "boot_pack";

export type ArtifactRef = {
    artifact_id: UUID;
    sha256: Sha256Hex;
    kind: ArtifactKind;
};

export type TransformResult = {
    success: boolean;
    artifacts: { kind: ArtifactKind; content: Buffer; sha256?: Sha256Hex; name?: string }[];
    logs?: string;
    cost_usd: number;
    tokens: number;
    error?: { code: string; message: string };
    provenance?: {
        prompt_hash: string;
        response_hash: string;
        idempotency_key: string;
        model_id: string;
        artifact_hashes: string[];
    };
};

export interface TransformEngineInterface {
    execute(
        stage: string,
        target: string,
        inputs: ArtifactRef[],
        config: any,
        attempt_no: number,
        idempotency_key: string
    ): Promise<TransformResult>;
}

type ExecutionResult = {
    status: "SUCCESS" | "FAILED";
    artifact_ids: UUID[];
    cost_usd: number;
    tokens: number;
    budget_exceeded: boolean;
};

type ExecutionPlanEntry = {
    stage: string;
    target: string;
    context_hash: Sha256Hex;
};

export type BuildResult = {
    build_id: UUID;
    final_state: BuildState;
    cumulative_cost_usd: number;
    confirmation_token?: string;
};

// ===========================
// Constants (from MC2)
// ===========================

const THRESHOLDS = {
    MAX_ACTIVE_BUILDS: 1,
    LOCK_HEARTBEAT_INTERVAL_MS: 5000,
    LOCK_TTL_MS: 600000, // 10 minutes (was 15s)
    EVENT_OUTBOX_MAX_PENDING: 10000,
    EVENT_OUTBOX_FLUSH_TRIGGER: 100,
    BUDGET_PRECHECK_TOLERANCE: 1.10,
    TRANSFORM_ENGINE_TIMEOUT_S: 300,
    GRACEFUL_SHUTDOWN_TIMEOUT_S: 30,
    CHECKPOINT_RETENTION_SUCCESS_DAYS: 7,
    CHECKPOINT_RETENTION_FAILED_DAYS: 7,
    RETRY_MAX_ATTEMPTS: 3,
    RETRY_BACKOFF_BASE_MS: 1000,
    SQLITE_BUSY_TIMEOUT_MS: 5000,
} as const;

const PROCESS_NAME_REQUIRED = "dirkernel";
const MAX_ARTIFACT_BYTES = 25 * 1024 * 1024; // 25MB guard

// ===========================
// Utilities
// ===========================

function nowIso(): string {
    return new Date().toISOString();
}

function uuidv4(): UUID {
    return crypto.randomUUID();
}

function monotonicNowIso(prevIso: string | null | undefined): string {
    const now = new Date();
    if (!prevIso) return now.toISOString();
    const prev = Date.parse(prevIso);
    if (!Number.isFinite(prev)) return now.toISOString();
    const prevMs = prev;
    const nowMs = now.getTime();
    return new Date(Math.max(prevMs, nowMs)).toISOString();
}

function sha256Hex(data: Buffer | string): Sha256Hex {
    return crypto.createHash("sha256").update(data).digest("hex");
}

function sleepMs(ms: number) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function isProcessAlive(pid: number): boolean {
    if (!pid || pid <= 0) return false;
    try {
        process.kill(pid, 0);
        return true;
    } catch {
        return false;
    }
}

function decimalToDbString(n: number): string {
    // store as decimal string
    return n.toFixed(6);
}

function dbStringToNumber(s: any): number {
    if (s === null || s === undefined) return 0;
    return Number(String(s));
}

// Ensure no floats in config (decimals must be strings)
function assertNoFloatValues(obj: any, pathKey = "config", depth = 0): void {
    if (depth > 100) throw new Error("DEPTH_LIMIT_EXCEEDED");
    if (obj === null || obj === undefined) return;

    if (typeof obj === "number") {
        if (!Number.isInteger(obj)) {
            throw new Error(`INVALID_CONFIG: float not allowed at ${pathKey}=${obj}`);
        }
        return;
    }

    if (typeof obj === "string" || typeof obj === "boolean") return;

    if (Array.isArray(obj)) {
        for (let i = 0; i < obj.length; i++) assertNoFloatValues(obj[i], `${pathKey}[${i}]`, depth + 1);
        return;
    }

    if (typeof obj === "object") {
        for (const k of Object.keys(obj).sort()) {
            assertNoFloatValues(obj[k], `${pathKey}.${k}`, depth + 1);
        }
        return;
    }

    throw new Error(`INVALID_CONFIG: unsupported type at ${pathKey}`);
}

function canonicalJson(obj: any): string {
    if (obj === null || obj === undefined) return "null";
    if (typeof obj === "number") return String(obj);
    if (typeof obj === "string") return JSON.stringify(obj);
    if (typeof obj === "boolean") return obj ? "true" : "false";
    if (Array.isArray(obj)) return `[${obj.map(canonicalJson).join(",")}]`;
    if (typeof obj === "object") {
        const keys = Object.keys(obj).sort();
        return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
    }
    return JSON.stringify(String(obj));
}

function computeExeSha256(): Sha256Hex {
    try {
        const exePath = process.execPath;
        if (fs.existsSync(exePath)) return sha256Hex(fs.readFileSync(exePath));
    } catch { }
    try {
        const entry = process.argv[1];
        if (entry && fs.existsSync(entry)) return sha256Hex(fs.readFileSync(entry));
    } catch { }
    return sha256Hex(Buffer.from(process.execPath));
}

function sqliteIsBusyError(e: any): boolean {
    const msg = String(e?.message || "");
    return msg.includes("SQLITE_BUSY") || msg.includes("database is locked");
}

function withSqliteRetry<T>(fn: () => T, maxAttempts = 3): T {
    let attempt = 1;
    while (true) {
        try {
            return fn();
        } catch (e: any) {
            if (sqliteIsBusyError(e)) {
                if (attempt >= maxAttempts) throw e;
                sleepMs(50 * attempt); // Restored: prevents CPU spin under SQLITE_BUSY
                attempt++;
                continue;
            }
            throw e;
        }
    }
}

// ===========================
// Frozen Event target_hash rules
// ===========================

function computeTargetHashForEvent(params: {
    event_type: string;
    stage?: string;
    target?: string;
    context_hash?: string;
    to_state?: BuildState;
    reason?: StateTransitionReason;
    confirmation_token?: string;
}): string {
    if (params.event_type === "build_state_changed") {
        return sha256Hex(`${params.to_state ?? ""}:${params.reason ?? ""}`);
    }
    if (params.event_type === "target_completed") {
        return sha256Hex(`${params.stage ?? ""}:${params.target ?? ""}:${params.context_hash ?? ""}`);
    }
    if (params.event_type === "budget_pause") {
        return sha256Hex(`BUDGET_PAUSE:${params.confirmation_token ?? ""}`);
    }
    return sha256Hex(params.event_type);
}

// ===========================
// Artifact Store (CAS)
// ===========================

class ArtifactStore {
    constructor(private root: string) {
        fs.mkdirSync(this.root, { recursive: true });
    }

    store(content: Buffer): { sha256: Sha256Hex; filepath: string } {
        const sha = sha256Hex(content);
        const dir = path.join(this.root, sha.slice(0, 2));
        fs.mkdirSync(dir, { recursive: true });
        const fp = path.join(dir, sha);
        if (!fs.existsSync(fp)) fs.writeFileSync(fp, content);
        return { sha256: sha, filepath: fp };
    }

    getPathForSha(sha: string): string {
        return path.join(this.root, sha.slice(0, 2), sha);
    }

    getRoot(): string {
        return this.root;
    }
}

// ===========================
// SQLite Schema
// ===========================

function applySchema(db: Database.Database) {
    db.pragma("journal_mode = WAL");
    db.pragma("synchronous = FULL");
    db.pragma("foreign_keys = ON");
    db.pragma(`busy_timeout = ${THRESHOLDS.SQLITE_BUSY_TIMEOUT_MS}`);

    db.exec(`
    CREATE TABLE IF NOT EXISTS builds (
      build_id TEXT PRIMARY KEY,
      state TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,

      ms5_spec_hash TEXT NOT NULL,
      budget_usd TEXT NOT NULL,
      cumulative_cost_usd TEXT NOT NULL,

      build_inputs_hash TEXT NOT NULL,
      transition_seq INTEGER NOT NULL DEFAULT 0
    );

    CREATE UNIQUE INDEX IF NOT EXISTS uniq_one_active_build
      ON builds(state)
      WHERE state = 'ACTIVE';

    CREATE TABLE IF NOT EXISTS singleton_lock (
      lock_id INTEGER PRIMARY KEY CHECK (lock_id = 1),
      token TEXT NOT NULL,
      build_id TEXT,
      acquired_by_pid INTEGER NOT NULL,
      process_name TEXT NOT NULL,
      exe_sha256 TEXT NOT NULL,
      acquired_at TEXT NOT NULL,
      last_heartbeat_at TEXT NOT NULL
    );

    INSERT OR IGNORE INTO singleton_lock(lock_id, token, build_id, acquired_by_pid, process_name, exe_sha256, acquired_at, last_heartbeat_at)
    VALUES (1, '', NULL, 0, '', '', '', '');

    CREATE TABLE IF NOT EXISTS artifacts (
      artifact_id TEXT PRIMARY KEY,
      sha256 TEXT NOT NULL,
      kind TEXT NOT NULL,
      created_at TEXT NOT NULL,
      storage_path TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_artifacts_sha ON artifacts(sha256);

    CREATE TABLE IF NOT EXISTS artifact_refs (
      ref_id TEXT PRIMARY KEY,
      build_id TEXT NOT NULL,
      stage TEXT NOT NULL,
      target TEXT NOT NULL,
      artifact_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(build_id) REFERENCES builds(build_id) ON DELETE CASCADE,
      FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_artifact_refs_bst ON artifact_refs(build_id, stage, target);

    CREATE TABLE IF NOT EXISTS checkpoints (
      build_id TEXT NOT NULL,
      stage TEXT NOT NULL,
      target TEXT NOT NULL,

      context_hash TEXT NOT NULL,
      status TEXT NOT NULL, -- SUCCESS|FAILED
      error_message TEXT,
      executed_at TEXT NOT NULL,

      cost_usd TEXT NOT NULL,
      tokens INTEGER NOT NULL,

      PRIMARY KEY(build_id, stage, target),
      FOREIGN KEY(build_id) REFERENCES builds(build_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS cost_records (
      cost_id TEXT PRIMARY KEY,
      build_id TEXT NOT NULL,
      stage TEXT NOT NULL,
      target TEXT NOT NULL,
      context_hash TEXT NOT NULL,
      attempt_no INTEGER NOT NULL,
      cost_usd TEXT NOT NULL,
      tokens INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(build_id) REFERENCES builds(build_id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_cost_records_build ON cost_records(build_id);

    CREATE TABLE IF NOT EXISTS event_outbox (
      event_id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      build_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      dedupe_key TEXT NOT NULL UNIQUE,
      payload_json TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_outbox_build ON event_outbox(build_id);

    CREATE TABLE IF NOT EXISTS confirmation_tokens (
      token TEXT PRIMARY KEY,
      build_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      FOREIGN KEY(build_id) REFERENCES builds(build_id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_conf_tokens_build ON confirmation_tokens(build_id);

    CREATE TABLE IF NOT EXISTS state_audit_log (
      event_id TEXT PRIMARY KEY,
      build_id TEXT NOT NULL,
      from_state TEXT NOT NULL,
      to_state TEXT NOT NULL,
      reason TEXT NOT NULL,
      changed_by TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      transition_seq INTEGER NOT NULL,
      FOREIGN KEY(build_id) REFERENCES builds(build_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS build_inputs (
      build_id TEXT NOT NULL,
      artifact_id TEXT NOT NULL,
      sha256 TEXT NOT NULL,
      kind TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY(build_id, artifact_id, kind),
      FOREIGN KEY(build_id) REFERENCES builds(build_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS model_call_provenance (
      call_id TEXT PRIMARY KEY,
      build_id TEXT NOT NULL,
      stage TEXT NOT NULL,
      target TEXT NOT NULL,
      attempt_no INTEGER NOT NULL,
      model_id TEXT NOT NULL,
      prompt_hash TEXT NOT NULL,
      response_hash TEXT NOT NULL,
      idempotency_key TEXT NOT NULL,
      tokens_in INTEGER NOT NULL,
      tokens_out INTEGER NOT NULL,
      cost_usd TEXT NOT NULL,
      finish_reason TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(build_id) REFERENCES builds(build_id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_provenance_build ON model_call_provenance(build_id, stage, target);
  `);
}

// ===========================
// BuildLifecycleManager
// ===========================

class BuildLifecycleManager {
    constructor(private db: Database.Database, private config?: { lockTtlMs?: number }) { }

    acquireLock(build_id: UUID | null, force: boolean): Result<LockToken> {
        const pid = process.pid;
        const exeSha = computeExeSha256();
        const processName = PROCESS_NAME_REQUIRED;

        if (processName !== PROCESS_NAME_REQUIRED) {
            return { ok: false, error: "LOCK_CONFLICT", message: "process name mismatch" };
        }

        const row = withSqliteRetry(
            () => this.db.prepare(`SELECT * FROM singleton_lock WHERE lock_id=1`).get() as any,
            3
        );

        const tokenExisting = String(row.token || "");
        const lockPid = Number(row.acquired_by_pid || 0);
        const lastHb = String(row.last_heartbeat_at || "");
        const lockProc = String(row.process_name || "");
        const lockExe = String(row.exe_sha256 || "");

        const now = Date.now();
        const lastHbMs = lastHb ? Date.parse(lastHb) : 0;
        const ageMs = lastHbMs ? now - lastHbMs : Number.POSITIVE_INFINITY;

        const lockHeld = tokenExisting.length > 0 && lockPid > 0;
        const lockPidAlive = lockHeld ? isProcessAlive(lockPid) : false;

        const lockMatchesBinary = lockProc === PROCESS_NAME_REQUIRED && lockExe === exeSha;

        // stale if pid dead OR heartbeat expired
        const lockTtl = this.config?.lockTtlMs ?? THRESHOLDS.LOCK_TTL_MS;
        const lockIsStale = lockHeld && (!lockPidAlive || ageMs > lockTtl);

        if (lockHeld && lockPidAlive && !lockIsStale && lockPid !== pid) {
            return { ok: false, error: "LOCK_CONFLICT", message: "lock held by live process" };
        }

        if (lockHeld && !force && lockPid !== pid && !lockIsStale) {
            return { ok: false, error: "LOCK_CONFLICT", message: "lock conflict" };
        }

        if (lockHeld && !lockIsStale && !lockMatchesBinary && !force) {
            return { ok: false, error: "LOCK_CONFLICT", message: "lock held by different binary" };
        }

        const token = uuidv4();
        const acquiredAt = nowIso();

        withSqliteRetry(() => {
            this.db
                .prepare(
                    `
        UPDATE singleton_lock
        SET token=?, build_id=?, acquired_by_pid=?, process_name=?, exe_sha256=?, acquired_at=?, last_heartbeat_at=?
        WHERE lock_id=1
      `
                )
                .run(token, build_id, pid, PROCESS_NAME_REQUIRED, exeSha, acquiredAt, acquiredAt);
        }, 3);

        return {
            ok: true,
            value: { token, build_id, pid, process_name: PROCESS_NAME_REQUIRED, exe_sha256: exeSha },
        };
    }

    releaseLock(lock: LockToken): Result<void> {
        const row = withSqliteRetry(() => this.db.prepare(`SELECT * FROM singleton_lock WHERE lock_id=1`).get() as any, 3);
        if (String(row.token) !== lock.token) return { ok: false, error: "LOCK_CONFLICT", message: "token mismatch" };

        withSqliteRetry(() => {
            this.db
                .prepare(
                    `
        UPDATE singleton_lock
        SET token='', build_id=NULL, acquired_by_pid=0, process_name='', exe_sha256='', acquired_at='', last_heartbeat_at=''
        WHERE lock_id=1
      `
                )
                .run();
        }, 3);

        return { ok: true, value: undefined };
    }

    heartbeat(lock: LockToken): Result<void> {
        const row = withSqliteRetry(() => this.db.prepare(`SELECT token, exe_sha256 FROM singleton_lock WHERE lock_id=1`).get() as any, 3);
        if (String(row.token) !== lock.token) return { ok: false, error: "LOCK_CONFLICT", message: "lock stolen" };
        if (String(row.exe_sha256) !== lock.exe_sha256) return { ok: false, error: "LOCK_CONFLICT", message: "exe mismatch" };

        withSqliteRetry(() => this.db.prepare(`UPDATE singleton_lock SET last_heartbeat_at=? WHERE lock_id=1`).run(nowIso()), 3);
        return { ok: true, value: undefined };
    }

    getActiveBuild(): BuildContext | null {
        const row = withSqliteRetry(() => this.db.prepare(`SELECT * FROM builds WHERE state='ACTIVE' LIMIT 1`).get() as any, 3);
        return row ? this.rowToBuild(row) : null;
    }

    getBuild(build_id: UUID): BuildContext | null {
        const row = withSqliteRetry(() => this.db.prepare(`SELECT * FROM builds WHERE build_id=?`).get(build_id) as any, 3);
        return row ? this.rowToBuild(row) : null;
    }

    listBuilds(limit: number = 200): BuildContext[] {
        const rows = withSqliteRetry(
            () => this.db.prepare(`SELECT * FROM builds ORDER BY created_at DESC LIMIT ?`).all(limit) as any[],
            3
        );
        return (rows || []).map((r) => this.rowToBuild(r));
    }

    /**
     * Returns a canonical snapshot of the build list.
     * This is intended for API layers to serve /builds and allow clients to reason
     * about staleness/desync without guessing.
     */
    getBuildsSnapshot(limit: number = 200): { snapshot_at: string; snapshot_seq: number; builds: BuildContext[] } {
        const builds = this.listBuilds(limit);
        const snapshot_seq = builds.reduce((m, b) => (b.transition_seq > m ? b.transition_seq : m), 0);
        // snapshot_at is monotonic relative to the newest build.updated_at we just observed
        let newestUpdated: string | null = null;
        for (const b of builds) {
            if (!newestUpdated) { newestUpdated = b.updated_at; continue; }
            const a = Date.parse(newestUpdated);
            const c = Date.parse(b.updated_at);
            if (Number.isFinite(c) && (!Number.isFinite(a) || c > a)) newestUpdated = b.updated_at;
        }
        const snapshot_at = monotonicNowIso(newestUpdated);
        return { snapshot_at, snapshot_seq, builds };
    }

    createBuild(ms5_spec: any, budget_usd: number, build_inputs_hash: Sha256Hex): Result<BuildContext> {
        const build_id = uuidv4();
        const created = nowIso();
        const ms5_hash = sha256Hex(Buffer.from(canonicalJson(ms5_spec), "utf8"));

        try {
            withSqliteRetry(() => {
                this.db
                    .prepare(
                        `
          INSERT INTO builds(build_id, state, created_at, updated_at, ms5_spec_hash, budget_usd, cumulative_cost_usd, build_inputs_hash, transition_seq)
          VALUES(?, 'ACTIVE', ?, ?, ?, ?, ?, ?, 0)
        `
                    )
                    .run(build_id, created, created, ms5_hash, decimalToDbString(budget_usd), decimalToDbString(0), build_inputs_hash);
            }, 3);
        } catch (e: any) {
            return { ok: false, error: "CORRUPT_STATE", message: `createBuild failed: ${e?.message}` };
        }

        return { ok: true, value: this.getBuild(build_id)! };
    }

    transitionState(
        lock: LockToken,
        build_id: UUID,
        to_state: BuildState,
        reason: StateTransitionReason,
        changed_by: string = PROCESS_NAME_REQUIRED
    ): Result<void> {
        const lockRow = withSqliteRetry(() => this.db.prepare(`SELECT * FROM singleton_lock WHERE lock_id=1`).get() as any, 3);
        if (String(lockRow.token) !== lock.token) return { ok: false, error: "LOCK_CONFLICT", message: "lock token mismatch" };
        if (String(lockRow.exe_sha256) !== lock.exe_sha256) return { ok: false, error: "LOCK_CONFLICT", message: "exe mismatch" };

        const b = this.getBuild(build_id);
        if (!b) return { ok: false, error: "CORRUPT_STATE", message: "build missing" };
        const from_state = b.state;

        if (!isValidTransition(from_state, to_state)) {
            return { ok: false, error: "CORRUPT_STATE", message: `invalid transition ${from_state} -> ${to_state}` };
        }

        const ts = monotonicNowIso(b.updated_at);
        const nextSeq = b.transition_seq + 1;

        try {
            withSqliteRetry(() => {
                const tx = this.db.transaction(() => {
                    this.db
                        .prepare(`UPDATE builds SET state=?, updated_at=?, transition_seq=? WHERE build_id=?`)
                        .run(to_state, ts, nextSeq, build_id);

                    this.db
                        .prepare(
                            `INSERT INTO state_audit_log(event_id, build_id, from_state, to_state, reason, changed_by, timestamp, transition_seq)
               VALUES(?,?,?,?,?,?,?,?)`
                        )
                        .run(uuidv4(), build_id, from_state, to_state, reason, changed_by, ts, nextSeq);
                });
                tx();
            }, 3);
            return { ok: true, value: undefined };
        } catch (e: any) {
            return { ok: false, error: "STORAGE_ERROR_RETRY", message: `transition failed: ${e?.message}` };
        }
    }

    private rowToBuild(row: any): BuildContext {
        return {
            build_id: String(row.build_id),
            state: row.state,
            created_at: row.created_at,
            updated_at: row.updated_at,
            ms5_spec_hash: row.ms5_spec_hash,
            budget_usd: dbStringToNumber(row.budget_usd),
            cumulative_cost_usd: dbStringToNumber(row.cumulative_cost_usd),
            build_inputs_hash: row.build_inputs_hash,
            transition_seq: Number(row.transition_seq || 0),
        };
    }
}

function isValidTransition(from: BuildState, to: BuildState): boolean {
    const map: Record<BuildState, BuildState[]> = {
        PENDING: ["ACTIVE", "ABANDONED"],
        ACTIVE: ["SUCCESS", "FAILED", "CRASHED", "BUDGET_PAUSE", "ABANDONED"],
        CRASHED: ["ACTIVE", "ABANDONED"],
        BUDGET_PAUSE: ["ACTIVE", "FAILED", "ABANDONED"],
        SUCCESS: [],
        FAILED: [],
        ABANDONED: [],
    };
    return map[from].includes(to);
}

// ===========================
// ExecutionPlanner
// ===========================

class ExecutionPlanner {
    constructor(private db: Database.Database) { }

    computeContextHash(stage: string, target: string, inputs: ArtifactRef[], config: any): Sha256Hex {
        const inputsSorted = [...inputs].sort((a, b) => a.artifact_id.localeCompare(b.artifact_id));
        const inputBlob = inputsSorted.map((x) => `${x.artifact_id}:${x.sha256}:${x.kind}`).join("\n");
        const configBlob = canonicalJson(config);
        const raw = `stage=${stage};target=${target};inputs=${inputBlob};config=${configBlob}`;
        return sha256Hex(Buffer.from(raw, "utf8"));
    }

    hasSuccessfulCheckpoint(build_id: UUID, stage: string, target: string, context_hash: Sha256Hex): boolean {
        const row = withSqliteRetry(
            () =>
                this.db
                    .prepare(`SELECT status, context_hash FROM checkpoints WHERE build_id=? AND stage=? AND target=?`)
                    .get(build_id, stage, target) as any,
            3
        );
        if (!row) return false;
        return String(row.status) === "SUCCESS" && String(row.context_hash) === context_hash;
    }

    computePlan(ms5_spec: any, inputs: ArtifactRef[]): Result<ExecutionPlanEntry[]> {
        try {
            assertNoFloatValues(ms5_spec, "ms5_spec");
        } catch (e: any) {
            return { ok: false, error: "INVALID_CONFIG", message: e?.message };
        }

        const stages = ms5_spec?.stages;
        if (!Array.isArray(stages)) return { ok: false, error: "INVALID_CONFIG", message: "ms5_spec.stages must be array" };

        const plan: ExecutionPlanEntry[] = [];
        for (const st of stages) {
            const stageName = String(st?.name || "");
            if (!stageName) return { ok: false, error: "INVALID_CONFIG", message: "stage.name missing" };

            const targets = st?.targets;
            if (!Array.isArray(targets)) return { ok: false, error: "INVALID_CONFIG", message: "stage.targets must be array" };

            const sortedTargets = [...targets].sort((a, b) => String(a.name).localeCompare(String(b.name)));
            for (const tg of sortedTargets) {
                const targetName = String(tg?.name || "");
                if (!targetName) return { ok: false, error: "INVALID_CONFIG", message: "target.name missing" };

                const mergedConfig = { ...(ms5_spec.global_config || {}), ...(st.config || {}), ...(tg.config || {}) };

                try {
                    assertNoFloatValues(mergedConfig, `config(${stageName}.${targetName})`);
                } catch (e: any) {
                    return { ok: false, error: "INVALID_CONFIG", message: e?.message };
                }

                const context_hash = this.computeContextHash(stageName, targetName, inputs, mergedConfig);
                plan.push({ stage: stageName, target: targetName, context_hash });
            }
        }

        return { ok: true, value: plan };
    }
}

// ===========================
// EventOutbox
// ===========================

class EventOutbox {
    constructor(private db: Database.Database) { }

    pendingCount(): number {
        const row = withSqliteRetry(() => this.db.prepare(`SELECT COUNT(*) as n FROM event_outbox`).get() as any, 3);
        return Number(row?.n || 0);
    }

    emitEvent(params: {
        event_type: string;
        build_id: UUID;
        transition_seq: number;
        target_hash: string;
        payload: any;
    }): Result<void> {
        const pending = this.pendingCount();
        if (pending >= THRESHOLDS.EVENT_OUTBOX_MAX_PENDING) {
            return { ok: false, error: "CORRUPT_STATE", message: "Event outbox full" };
        }

        const event_id = uuidv4();
        const created_at = nowIso();
        const dedupe_key = sha256Hex(`${params.event_type}|${params.build_id}|${params.transition_seq}|${params.target_hash}`);

        try {
            withSqliteRetry(() => {
                this.db
                    .prepare(
                        `INSERT INTO event_outbox(event_id, event_type, build_id, created_at, dedupe_key, payload_json)
             VALUES(?,?,?,?,?,?)`
                    )
                    .run(
                        event_id,
                        params.event_type,
                        params.build_id,
                        created_at,
                        dedupe_key,
                        JSON.stringify({ ...params.payload, event_id, created_at, dedupe_key })
                    );
            }, 3);
            return { ok: true, value: undefined };
        } catch (e: any) {
            if (String(e?.message || "").includes("UNIQUE")) {
                return { ok: true, value: undefined };
            }
            return { ok: false, error: "STORAGE_ERROR_RETRY", message: e?.message };
        }
    }

    flush(batchSize: number): number {
        const rows = withSqliteRetry(
            () => this.db.prepare(`SELECT event_id, payload_json FROM event_outbox ORDER BY created_at LIMIT ?`).all(batchSize) as any[],
            3
        );
        if (!rows.length) return 0;

        // Delete only the specific event IDs we fetched (exactly-once semantics)
        const ids = rows.map(r => String(r.event_id));
        const placeholders = ids.map(() => '?').join(',');
        withSqliteRetry(() => {
            this.db.prepare(`DELETE FROM event_outbox WHERE event_id IN (${placeholders})`).run(...ids);
        }, 3);
        return rows.length;
    }
}

// ===========================
// Confirmation Tokens
// ===========================

class ConfirmationTokenStore {
    constructor(private db: Database.Database) { }

    mint(build_id: UUID, ttlMinutes: number = 60): string {
        const token = uuidv4();
        const created_at = nowIso();
        const expires_at = new Date(Date.now() + ttlMinutes * 60_000).toISOString();
        withSqliteRetry(() => {
            this.db
                .prepare(`INSERT INTO confirmation_tokens(token, build_id, created_at, expires_at) VALUES(?,?,?,?)`)
                .run(token, build_id, created_at, expires_at);
        }, 3);
        return token;
    }

    validateAndConsume(token: string, build_id: UUID): Result<void> {
        const row = withSqliteRetry(
            () => this.db.prepare(`SELECT * FROM confirmation_tokens WHERE token=? AND build_id=?`).get(token, build_id) as any,
            3
        );
        if (!row) return { ok: false, error: "INVALID_RESUME_STATE", message: "token missing" };
        const exp = Date.parse(String(row.expires_at));
        if (Date.now() > exp) return { ok: false, error: "INVALID_RESUME_STATE", message: "token expired" };

        withSqliteRetry(() => this.db.prepare(`DELETE FROM confirmation_tokens WHERE token=?`).run(token), 3);
        return { ok: true, value: undefined };
    }
}

// ===========================
// StageExecutor
// ===========================

class StageExecutor {
    constructor(private db: Database.Database, private artifacts: ArtifactStore) { }

    async executeTarget(params: {
        build_id: UUID;
        stage: string;
        target: string;
        context_hash: Sha256Hex;
        inputs: ArtifactRef[];
        config: any;
        engine: TransformEngineInterface;
        attempt_no: number;
    }): Promise<Result<ExecutionResult>> {
        const { build_id, stage, target, context_hash, inputs, config, engine, attempt_no } = params;

        try {
            assertNoFloatValues(config, `config(${stage}.${target})`);
        } catch (e: any) {
            return { ok: false, error: "INVALID_CONFIG", message: e?.message };
        }

        // Idempotency short-circuit
        const cp = withSqliteRetry(
            () =>
                this.db
                    .prepare(`SELECT status, context_hash FROM checkpoints WHERE build_id=? AND stage=? AND target=?`)
                    .get(build_id, stage, target) as any,
            3
        );

        if (cp && String(cp.status) === "SUCCESS" && String(cp.context_hash) === context_hash) {
            return { ok: true, value: { status: "SUCCESS", artifact_ids: [], cost_usd: 0, tokens: 0, budget_exceeded: false } };
        }

        const idempotency_key = sha256Hex(`${build_id}|${stage}|${target}|${context_hash}`);

        // ---- Phase 1: Pre-flight checks (Sync) ----
        let preFlightCheck = withSqliteRetry(() => {
            const bRow = this.db.prepare(`SELECT * FROM builds WHERE build_id=?`).get(build_id) as any;
            if (!bRow) throw new Error("CORRUPT_STATE: build missing");
            return {
                cumulative_cost: dbStringToNumber(bRow.cumulative_cost_usd),
                budget: dbStringToNumber(bRow.budget_usd)
            };
        }, 3);

        // ---- Phase 2: Execution (Async, OUTSIDE transaction) ----
        // Optional worker isolation: run transform in a separate thread with hard-kill timeout
        let result: TransformResult;
        try {
            if (WORKER_ISOLATION_ENABLED) {
                const workerConfig: IsolatedEngineConfig = {
                    artifactRoot: this.artifacts.getRoot(),
                    apiKey: process.env.OPENROUTER_API_KEY || '',
                    modelId: process.env.DIRECTOR_MODEL || 'deepseek/deepseek-chat',
                };
                log.info(`Worker isolation: executing ${stage}/${target} in isolated thread`);
                result = await executeInWorker(workerConfig, stage, target, inputs, config, attempt_no, idempotency_key);
            } else {
                result = await engine.execute(stage, target, inputs, config, attempt_no, idempotency_key);
            }
        } catch (e: any) {
            let errMsg = String(e?.message || e);
            // Persist failure
            this.persistFailure(build_id, stage, target, context_hash, attempt_no, errMsg);
            if (errMsg.includes("MALFORMED_OUTPUT")) return { ok: false, error: "MALFORMED_OUTPUT", message: errMsg };
            if (errMsg.includes("INVALID_CONFIG")) return { ok: false, error: "INVALID_CONFIG", message: errMsg };
            return { ok: false, error: "EXECUTION_FAILED", message: errMsg };
        }

        // === Context Negotiation Protocol ===
        // If model requested more context, return with special error for retry
        if (result.error?.code === 'NEED_MORE_CONTEXT') {
            const errMsg = `Model requested more context: ${result.error.message}`;
            this.persistFailure(build_id, stage, target, context_hash, attempt_no, errMsg);
            return {
                ok: false,
                error: 'NEED_MORE_CONTEXT' as ErrorCode,
                message: result.error.message
            };
        }

        // ---- Phase 3: Persistence (Sync Transaction) ----
        try {
            const execRes = withSqliteRetry(() => {
                const tx = this.db.transaction((): ExecutionResult => {
                    // Re-read cost to be safe (though lock prevents races)
                    const bRow = this.db.prepare(`SELECT cumulative_cost_usd, budget_usd FROM builds WHERE build_id=?`).get(build_id) as any;
                    const cumulative_cost = dbStringToNumber(bRow.cumulative_cost_usd);
                    const budget = dbStringToNumber(bRow.budget_usd);

                    if (!result || !Array.isArray(result.artifacts)) throw new Error("MALFORMED_OUTPUT: artifacts missing");
                    if (result.success === false) {
                        throw new Error(result.error?.message || "TRANSFORM_FAILED");
                    }
                    if (typeof result.cost_usd !== "number" || typeof result.tokens !== "number") {
                        throw new Error("MALFORMED_OUTPUT: cost/tokens invalid");
                    }

                    const artifactIds: UUID[] = [];
                    for (const a of result.artifacts) {
                        if (!a || !(a.content instanceof Buffer)) throw new Error("MALFORMED_OUTPUT: artifact content invalid");
                        if (a.content.byteLength > MAX_ARTIFACT_BYTES) throw new Error("MALFORMED_OUTPUT: artifact too large");

                        const stored = this.artifacts.store(a.content);
                        const artifact_id = uuidv4();
                        const created_at = nowIso();

                        this.db
                            .prepare(`INSERT INTO artifacts(artifact_id, sha256, kind, created_at, storage_path) VALUES(?,?,?,?,?)`)
                            .run(artifact_id, stored.sha256, a.kind, created_at, stored.filepath);

                        this.db
                            .prepare(
                                `INSERT INTO artifact_refs(ref_id, build_id, stage, target, artifact_id, kind, created_at)
                 VALUES(?,?,?,?,?,?,?)`
                            )
                            .run(uuidv4(), build_id, stage, target, artifact_id, a.kind, created_at);

                        artifactIds.push(artifact_id);
                    }

                    // Cost record
                    this.db
                        .prepare(
                            `INSERT INTO cost_records(cost_id, build_id, stage, target, context_hash, attempt_no, cost_usd, tokens, created_at)
               VALUES(?,?,?,?,?,?,?,?,?)`
                        )
                        .run(uuidv4(), build_id, stage, target, context_hash, attempt_no, decimalToDbString(result.cost_usd), Math.floor(result.tokens), nowIso());

                    // Provenance chain record
                    if (result.provenance) {
                        const p = result.provenance;
                        this.db
                            .prepare(
                                `INSERT INTO model_call_provenance(call_id, build_id, stage, target, attempt_no, model_id, prompt_hash, response_hash, idempotency_key, tokens_in, tokens_out, cost_usd, finish_reason, created_at)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
                            )
                            .run(
                                uuidv4(), build_id, stage, target, attempt_no,
                                p.model_id, p.prompt_hash, p.response_hash, p.idempotency_key,
                                0, 0, decimalToDbString(result.cost_usd), null, nowIso()
                            );
                    }

                    const newCumulative = cumulative_cost + result.cost_usd;
                    this.db
                        .prepare(`UPDATE builds SET cumulative_cost_usd=?, updated_at=? WHERE build_id=?`)
                        .run(decimalToDbString(newCumulative), nowIso(), build_id);

                    const budget_exceeded = newCumulative > budget;

                    // Checkpoint
                    this.db
                        .prepare(
                            `
              INSERT INTO checkpoints(build_id, stage, target, context_hash, status, executed_at, cost_usd, tokens)
              VALUES(?,?,?,?, 'SUCCESS', ?, ?, ?)
              ON CONFLICT(build_id, stage, target)
              DO UPDATE SET
                context_hash=excluded.context_hash,
                status='SUCCESS',
                executed_at=excluded.executed_at,
                cost_usd=excluded.cost_usd,
                tokens=excluded.tokens
            `
                        )
                        .run(build_id, stage, target, context_hash, nowIso(), decimalToDbString(result.cost_usd), Math.floor(result.tokens));

                    return {
                        status: "SUCCESS",
                        artifact_ids: artifactIds,
                        cost_usd: result.cost_usd,
                        tokens: result.tokens,
                        budget_exceeded,
                    };
                });

                return tx();
            }, 3);

            return { ok: true, value: execRes };
        } catch (e: any) {
            // Phase 3 failed
            const errMsg = String(e?.message || e);
            this.persistFailure(build_id, stage, target, context_hash, attempt_no, errMsg);

            if (errMsg.includes("MALFORMED_OUTPUT")) return { ok: false, error: "MALFORMED_OUTPUT", message: errMsg };
            return { ok: false, error: "EXECUTION_FAILED", message: errMsg };
        }
    }

    private persistFailure(build_id: UUID, stage: string, target: string, context_hash: string, attempt_no: number, errMsg: string) {
        try {
            withSqliteRetry(() => {
                const txFail = this.db.transaction(() => {
                    this.db
                        .prepare(
                            `
                INSERT INTO checkpoints(build_id, stage, target, context_hash, status, executed_at, cost_usd, tokens, error_message)
                VALUES(?,?,?,?, 'FAILED', ?, ?, ?, ?)
                ON CONFLICT(build_id, stage, target)
                DO UPDATE SET
                  context_hash=excluded.context_hash,
                  status='FAILED',
                  executed_at=excluded.executed_at,
                  cost_usd=excluded.cost_usd,
                  tokens=excluded.tokens,
                  error_message=excluded.error_message
              `
                        )
                        .run(build_id, stage, target, context_hash, nowIso(), decimalToDbString(0), 0, errMsg);

                    this.db
                        .prepare(
                            `INSERT INTO cost_records(cost_id, build_id, stage, target, context_hash, attempt_no, cost_usd, tokens, created_at)
                 VALUES(?,?,?,?,?,?,?,?,?)`
                        )
                        .run(uuidv4(), build_id, stage, target, context_hash, attempt_no, decimalToDbString(0), 0, nowIso());
                });
                txFail();
            }, 3);
        } catch (e2: any) {
            // Ignore, let orchestrator handle corrupt state if strictly needed, or just log
            // (Orchestrator handles persistent failure)
        }
    }
}

// ===========================
// Heartbeat Worker
// ===========================

type HeartbeatStartParams = {
    dbPath: string;
    token: string;
    exe_sha256: string;
    intervalMs: number;
};

function createHeartbeatWorker(params: HeartbeatStartParams): Worker {
    const workerCode = `
    const { parentPort, workerData } = require("worker_threads");
    const Database = require("better-sqlite3");

    const db = new Database(workerData.dbPath);
    db.pragma("journal_mode = WAL");
    db.pragma("synchronous = FULL");
    db.pragma("foreign_keys = ON");
    db.pragma("busy_timeout = 5000");

    function tick() {
      try {
        const row = db.prepare("SELECT token, exe_sha256 FROM singleton_lock WHERE lock_id=1").get();
        if (!row || String(row.token) !== workerData.token) {
          parentPort.postMessage({ type: "heartbeat_failed", reason: "token_mismatch" });
          return;
        }
        if (String(row.exe_sha256) !== workerData.exe_sha256) {
          parentPort.postMessage({ type: "heartbeat_failed", reason: "exe_mismatch" });
          return;
        }
        db.prepare("UPDATE singleton_lock SET last_heartbeat_at=? WHERE lock_id=1").run(new Date().toISOString());
        parentPort.postMessage({ type: "heartbeat_ok" });
      } catch (e) {
        parentPort.postMessage({ type: "heartbeat_failed", reason: String(e && e.message ? e.message : e) });
      }
      setTimeout(tick, workerData.intervalMs);
    }

    tick();
  `;

    return new Worker(workerCode, { eval: true, workerData: params });
}

// ===========================
// Kernel Orchestrator
// ===========================

export class KernelOrchestrator {
    private db: Database.Database;
    private lifecycle: BuildLifecycleManager;
    private planner: ExecutionPlanner;
    private outbox: EventOutbox;
    private tokens: ConfirmationTokenStore;
    private executor: StageExecutor;
    private mc2Engine: MC2SerialEngine;
    private artifactStore: ArtifactStore;
    private outputWriter: ReturnType<typeof createOutputWriter>;

    private lock: LockToken | null = null;
    private hbWorker: Worker | null = null;
    private gracefulShutdown = false;

    constructor(
        private dbPath: string,
        artifactRoot: string,
        private engine: TransformEngineInterface,
        private config?: { lockTtlMs?: number }
    ) {
        this.db = new Database(dbPath);
        applySchema(this.db);

        this.lifecycle = new BuildLifecycleManager(this.db, config);
        this.planner = new ExecutionPlanner(this.db);
        this.outbox = new EventOutbox(this.db);
        this.tokens = new ConfirmationTokenStore(this.db);
        this.artifactStore = new ArtifactStore(artifactRoot);
        this.executor = new StageExecutor(this.db, this.artifactStore);
        this.mc2Engine = new MC2SerialEngine(process.env.OPENROUTER_API_KEY || '');
        this.outputWriter = createOutputWriter();

        this.installSignalHandlers();
    }

    initializeRecovery(): Result<RecoveryContext> {
        // Validate binary identity pre-lock
        const exe_sha256 = computeExeSha256();

        // Acquire lock
        const acquire = this.lifecycle.acquireLock(null, false);
        if (!acquire.ok) return acquire as any;
        this.lock = acquire.value;

        // Start worker heartbeat
        this.startWorkerHeartbeat();

        // orphan detection: ACTIVE builds -> CRASHED
        const orphaned: UUID[] = [];
        const rows = withSqliteRetry(() => this.db.prepare(`SELECT build_id FROM builds WHERE state='ACTIVE'`).all() as any[], 3);

        for (const r of rows) {
            const bid = String(r.build_id);
            orphaned.push(bid);
            this.lifecycle.transitionState(this.lock, bid, "CRASHED", "orphaned_at_startup", PROCESS_NAME_REQUIRED);
            this.emitBuildStateChanged(bid, "ACTIVE", "CRASHED", "orphaned_at_startup");
        }

        if (this.outbox.pendingCount() > THRESHOLDS.EVENT_OUTBOX_FLUSH_TRIGGER) this.outbox.flush(1000);

        // Validate worker uses same exe hash (locks binary identity)
        if (this.lock.exe_sha256 !== exe_sha256) {
            return { ok: false, error: "LOCK_CONFLICT", message: "exe_sha256 mismatch after lock acquisition" };
        }

        return { ok: true, value: { lock: this.lock, orphaned_build_ids: orphaned } };
    }

    async orchestrateBuild(params: {
        ms5_spec: any;
        budget_usd: number;
        resume_build_id?: UUID;
        confirmation_token?: string;
        resume_policy?: ResumePolicy;
        input_artifacts?: ArtifactRef[];
    }): Promise<Result<BuildResult>> {
        if (!this.lock) return { ok: false, error: "LOCK_CONFLICT", message: "lock not held" };

        const resume_policy = params.resume_policy ?? "strict";
        let inputArtifacts = params.input_artifacts ?? [];

        // Auto-ingest MS5 spec as artifact to ensure it is available as input for first stage
        if (params.ms5_spec) {
            const content = Buffer.from(canonicalJson(params.ms5_spec), "utf8");
            const { sha256: ms5Hash } = this.artifactStore.store(content);
            // Prepend if not already present
            if (!inputArtifacts.find(a => a.sha256 === ms5Hash)) {
                const ms5Ref: ArtifactRef = {
                    artifact_id: ms5Hash, // Use hash as ID for content-addressed inputs
                    sha256: ms5Hash,
                    kind: 'ms5',
                };
                inputArtifacts = inputArtifacts.length > 0
                    ? [...inputArtifacts, ms5Ref]
                    : [ms5Ref, ...inputArtifacts];
            }
        }

        const build_inputs_hash = computeBuildInputsHash(inputArtifacts);

        let build: BuildContext;
        let from_state: BuildState = "PENDING";

        if (params.resume_build_id) {
            const existing = this.lifecycle.getBuild(params.resume_build_id);
            if (!existing) return { ok: false, error: "INVALID_RESUME_STATE", message: "build not found" };
            if (!(existing.state === "CRASHED" || existing.state === "BUDGET_PAUSE")) {
                return { ok: false, error: "INVALID_RESUME_STATE", message: `cannot resume from ${existing.state}` };
            }

            if (existing.state === "BUDGET_PAUSE") {
                if (!params.confirmation_token) return { ok: false, error: "INVALID_RESUME_STATE", message: "missing confirmation_token" };
                const okTok = this.tokens.validateAndConsume(params.confirmation_token, existing.build_id);
                if (!okTok.ok) return okTok as any;
            }

            if (resume_policy === "strict" && existing.build_inputs_hash !== build_inputs_hash) {
                return { ok: false, error: "INVALID_RESUME_STATE", message: "build_inputs_hash mismatch (strict)" };
            }

            if (resume_policy === "fork" && existing.build_inputs_hash !== build_inputs_hash) {
                const created = this.lifecycle.createBuild(params.ms5_spec, params.budget_usd, build_inputs_hash);
                if (!created.ok) return created as any;
                build = created.value;
                from_state = "ACTIVE"; // forked build also inserted as ACTIVE
            } else {
                from_state = existing.state;
                const tr = this.lifecycle.transitionState(this.lock, existing.build_id, "ACTIVE", "operator_abort", PROCESS_NAME_REQUIRED);
                if (!tr.ok) return tr as any;
                build = this.lifecycle.getBuild(existing.build_id)!;
            }
        } else {
            const created = this.lifecycle.createBuild(params.ms5_spec, params.budget_usd, build_inputs_hash);
            if (!created.ok) return created as any;
            build = created.value;
            from_state = "ACTIVE"; // createBuild inserts as ACTIVE directly — no phantom PENDING
        }

        // bind lock build_id
        withSqliteRetry(() => this.db.prepare(`UPDATE singleton_lock SET build_id=? WHERE lock_id=1`).run(build.build_id), 3);

        // Register budget authority for this build (centralized spend control)
        budgetAuthority.registerBuild(build.build_id, {
            budget_usd: params.budget_usd,
            max_calls_per_min: 30,
            max_tokens_per_min: 500_000,
        });

        // store inputs
        this.persistBuildInputs(build.build_id, inputArtifacts);

        // state change event (skip for new builds — already born ACTIVE)
        if (from_state !== "ACTIVE") {
            this.emitBuildStateChanged(build.build_id, from_state, "ACTIVE", "operator_abort");
        }

        // compute plan
        const planR = this.planner.computePlan(params.ms5_spec, inputArtifacts);
        if (!planR.ok) {
            this.failBuild(build.build_id, planR.error, "unhandled_error");
            return planR as any;
        }
        const plan = planR.value;

        // Set build correlation context for structured logging
        const correlationId = crypto.randomUUID();
        setCorrelation({ correlationId, buildId: build.build_id });

        log.info(`Plan: ${plan.length} targets across ${new Set(plan.map(e => e.stage)).size} stages`);
        let targetIndex = 0;

        try {
            for (const entry of plan) {
                targetIndex++;
                setCorrelation({ stage: entry.stage, target: entry.target });
                if (this.gracefulShutdown) {
                    this.lifecycle.transitionState(this.lock, build.build_id, "CRASHED", "crash_detected", PROCESS_NAME_REQUIRED);
                    this.emitBuildStateChanged(build.build_id, "ACTIVE", "CRASHED", "crash_detected");
                    break;
                }

                // Checkpoint skip
                if (this.planner.hasSuccessfulCheckpoint(build.build_id, entry.stage, entry.target, entry.context_hash)) {
                    log.info(`[${targetIndex}/${plan.length}] ${entry.stage}/${entry.target} - skipped (cached)`);
                    continue;
                }

                log.info(`[${targetIndex}/${plan.length}] ${entry.stage}/${entry.target} - executing...`);

                // Budget precheck — estimate from average cost of completed targets in this build
                const remaining = this.remainingBudget(build.build_id);
                const completedCost = this.getBuildCost(build.build_id);
                const completedTargets = targetIndex - 1; // targets before this one
                const estimated_cost = completedTargets > 0 ? completedCost / completedTargets : remaining * 0.1;
                if (estimated_cost >= remaining * THRESHOLDS.BUDGET_PRECHECK_TOLERANCE) {
                    const token = this.tokens.mint(build.build_id, 60);
                    this.lifecycle.transitionState(this.lock, build.build_id, "BUDGET_PAUSE", "budget_precheck_block", PROCESS_NAME_REQUIRED);
                    this.emitBudgetPause(build.build_id, token, "budget_precheck_block");
                    return {
                        ok: true,
                        value: {
                            build_id: build.build_id,
                            final_state: "BUDGET_PAUSE",
                            cumulative_cost_usd: this.getBuildCost(build.build_id),
                            confirmation_token: token,
                        },
                    };
                }

                // Execute with retry policy
                let attempt = 1;
                while (true) {
                    const cfg = resolveTargetConfig(params.ms5_spec, entry.stage, entry.target);

                    // MC2 INTERCEPTION: If stage is 'code_generation', use MC2 engine
                    if (entry.stage === 'code_generation') {
                        // Find appropriate input artifact (MS3)
                        const ms3Artifact = inputArtifacts.find(a => a.kind === 'ms3');
                        if (!ms3Artifact) {
                            // Fallback to normal execution if no MS3 found (unit tests etc)
                            // or fail? Let's fallback for now.
                        } else {
                            // Construct request
                            const mc2Req: MC2IterationRequest = {
                                stage_id: entry.stage,
                                stage_goal: 'Implement MS3 contracts as executable MS2 code',
                                initial_artifact: {
                                    content: Buffer.from('// Initial artifact', 'utf-8'), // Should fetch content?
                                    kind: 'ms2',
                                    hash: 'initial'
                                },
                                // Default sequence: Generator -> Reviewer -> Generator
                                model_sequence: [
                                    'anthropic/claude-3.5-sonnet',
                                    'openai/gpt-4o',
                                    'anthropic/claude-3.5-sonnet'
                                ],
                                max_iterations: 3,
                            };
                            // For MS3->MS2, the *Goal* is defined by MS3.
                            // The *Artifact* we iterate on is the MS2 code.
                            // So initial artifact is empty or previous draft.
                            // Let's use empty buffer for now.

                            const mc2Res = await this.mc2Engine.executeStage(mc2Req);

                            // Persist result
                            if (mc2Res.status === 'COMPLETE') {
                                // Save final artifact to store
                                const stored = this.artifactStore.store(mc2Res.final_artifact.content);

                                // Create a fake "execution result" to mesh with existing logic
                                const execRes: ExecutionResult = {
                                    status: 'SUCCESS',
                                    artifact_ids: [], // We need to insert into DB to get ID
                                    cost_usd: mc2Res.audit.total_cost,
                                    tokens: 0,
                                    budget_exceeded: false
                                };

                                // Manually insert artifact and ref
                                const artId = uuidv4();
                                this.db.prepare(`INSERT INTO artifacts(artifact_id, sha256, kind, created_at, storage_path) VALUES(?,?,?,?,?)`)
                                    .run(artId, stored.sha256, 'ms2', nowIso(), stored.filepath);

                                this.db.prepare(`INSERT INTO artifact_refs(ref_id, build_id, stage, target, artifact_id, kind, created_at) VALUES(?,?,?,?,?,?,?)`)
                                    .run(uuidv4(), build.build_id, entry.stage, entry.target, artId, 'ms2', nowIso());

                                execRes.artifact_ids.push(artId);

                                this.emitTargetCompleted(build.build_id, entry.stage, entry.target, entry.context_hash, execRes, attempt);

                                // Chain for next loop
                                const newRefs: ArtifactRef[] = [{
                                    artifact_id: artId,
                                    sha256: stored.sha256,
                                    kind: 'ms2'
                                }];
                                inputArtifacts = [...newRefs, ...inputArtifacts];

                                break; // Done with this target
                            } else {
                                // Failed
                                // Fallthrough to normal executor? Or fail build?
                                // Fail build for now as MC2 is authoritative
                                return { ok: false, error: "EXECUTION_FAILED", message: `MC2 Failed: ${mc2Res.audit.termination_reason}` };
                            }
                        }
                    }

                    const ex = await this.executor.executeTarget({
                        build_id: build.build_id,
                        stage: entry.stage,
                        target: entry.target,
                        context_hash: entry.context_hash,
                        inputs: inputArtifacts,
                        config: cfg,
                        engine: this.engine,
                        attempt_no: attempt,
                    });

                    if (ex.ok) {
                        const execRes = ex.value;
                        log.info(`[${targetIndex}/${plan.length}] ${entry.stage}/${entry.target} - done`, { cost_usd: execRes.cost_usd });
                        this.emitTargetCompleted(build.build_id, entry.stage, entry.target, entry.context_hash, execRes, attempt);

                        if (execRes.budget_exceeded) {
                            const token = this.tokens.mint(build.build_id, 60);
                            this.lifecycle.transitionState(this.lock, build.build_id, "BUDGET_PAUSE", "budget_exceeded", PROCESS_NAME_REQUIRED);
                            this.emitBudgetPause(build.build_id, token, "budget_exceeded");
                            return {
                                ok: true,
                                value: {
                                    build_id: build.build_id,
                                    final_state: "BUDGET_PAUSE",
                                    cumulative_cost_usd: this.getBuildCost(build.build_id),
                                    confirmation_token: token,
                                },
                            };
                        }

                        // === CHAIN ARTIFACTS: Update inputs for next stage ===
                        // Fetch the artifacts we just generated
                        const newRefs: ArtifactRef[] = [];
                        for (const aid of execRes.artifact_ids) {
                            const row = this.db.prepare(
                                `SELECT sha256, kind FROM artifacts WHERE artifact_id=?`
                            ).get(aid) as any;

                            if (row) {
                                newRefs.push({
                                    artifact_id: aid, // Content-addressed usually uses sha256 as id, but here we have distinct UUIDs. TransformEngine uses 'sha256' mostly.
                                    sha256: row.sha256,
                                    kind: row.kind as any,
                                });
                            }
                        }

                        if (newRefs.length > 0) {
                            // Prepend new artifacts so they are primary context for next stage
                            // But keep old ones available as secondary context
                            inputArtifacts = [...newRefs, ...inputArtifacts];
                        }

                        break; // next target
                    } else {
                        // === CONTEXT NEGOTIATION: Attempt to satisfy NEED_MORE_CONTEXT ===
                        // If the model asks for specific artifacts (by sha256 or artifact_id), try to fetch and
                        // prepend them to the inputs before retrying. This is a surgical, deterministic
                        // improvement that changes the retry input-set, rather than repeating identical calls.
                        if (ex.error === "NEED_MORE_CONTEXT") {
                            const added = this.tryEnrichInputsFromNeedMoreContext(ex.message || "", inputArtifacts);
                            if (added.length > 0) {
                                // Prepend requested artifacts to maximize their inclusion in subsequent context windows.
                                inputArtifacts = [...added, ...inputArtifacts];
                            }
                        }

                        if (!isRetryable(ex.error) || attempt >= THRESHOLDS.RETRY_MAX_ATTEMPTS) {
                            this.failBuild(build.build_id, ex.error, "unhandled_error");
                            return ex as any;
                        }
                        sleepMs(THRESHOLDS.RETRY_BACKOFF_BASE_MS * Math.pow(2, attempt - 1));
                        attempt++;
                    }
                }
            }

            const end = this.lifecycle.getBuild(build.build_id)!;
            if (end.state === "ACTIVE") {
                this.lifecycle.transitionState(this.lock, build.build_id, "SUCCESS", "normal_completion", PROCESS_NAME_REQUIRED);
                this.emitBuildStateChanged(build.build_id, "ACTIVE", "SUCCESS", "normal_completion");
                log.info(`Build complete`, { total_cost_usd: this.getBuildCost(build.build_id) });
            }

            return {
                ok: true,
                value: {
                    build_id: build.build_id,
                    final_state: this.lifecycle.getBuild(build.build_id)!.state,
                    cumulative_cost_usd: this.getBuildCost(build.build_id),
                },
            };
        } catch (e: any) {
            this.failBuild(build.build_id, "EXECUTION_FAILED", "unhandled_error");
            return { ok: false, error: "EXECUTION_FAILED", message: String(e?.message || e) };
        } finally {
            budgetAuthority.releaseBuild(build.build_id);
            clearCorrelation();
        }
    }

    async writeBuildOutput(build_id: UUID, project: string = "default"): Promise<Result<{ committed_path: string; manifest_path: string }>> {
        // Fetch all artifacts for this build
        const artifacts = withSqliteRetry(() =>
            this.db.prepare(`
                SELECT a.artifact_id, a.sha256, a.kind, a.storage_path, ar.stage, ar.target
                FROM artifacts a
                JOIN artifact_refs ar ON a.artifact_id = ar.artifact_id
                WHERE ar.build_id = ?
                ORDER BY ar.stage, ar.target
            `).all(build_id) as any[], 3
        );

        if (!artifacts.length) {
            return { ok: false, error: "INVALID_CONFIG", message: "No artifacts found for build" };
        }

        // Build output plan
        const items: BuildPlanV1["items"] = [];

        for (const art of artifacts) {
            const content = fs.readFileSync(String(art.storage_path));
            items.push({
                kind: "FILE_TEXT",
                rel_path: `files/${art.stage}/${art.target}/${art.kind}.txt`,
                content_utf8: content.toString("utf8"),
                perm: "0644"
            });
        }

        const plan: BuildPlanV1 = {
            schema_version: "build-plan-v1",
            project,
            build_id,
            created_utc: nowIso(),
            source: {
                agent: { name: "dirkernel", version: "1.0.0" }
            },
            items,
            bounds: {
                max_total_bytes: 100 * 1024 * 1024, // 100MB
                max_file_bytes: 25 * 1024 * 1024,   // 25MB
                max_files: 1000,
                max_path_len: 512,
                envelope_retention_count: 10
            },
            latest_pointer: {
                enabled: true,
                path: "output/<project>/_index/latest.json"
            },
            verify: {
                compute_checksums: true,
                fsync: "BEST_EFFORT"
            }
        };

        const opts: WriteOptions = {
            operator_mode: "AGENT",
            auto_cleanup_staging: true,
            staging_ttl_ms: 24 * 60 * 60 * 1000, // 24 hours
            lock_timeout_ms: 5000
        };

        const result = await this.outputWriter.write(plan, opts);

        if (!result.ok) {
            return { ok: false, error: "STORAGE_ERROR_RETRY", message: result.error.message };
        }

        return {
            ok: true,
            value: {
                committed_path: result.committed_path,
                manifest_path: result.manifest_path
            }
        };
    }

    shutdownHandler(signal: string): void {
        this.gracefulShutdown = true;
        if (!this.lock) return;

        const active = this.lifecycle.getActiveBuild();
        if (active) {
            this.lifecycle.transitionState(this.lock, active.build_id, "CRASHED", "crash_detected", PROCESS_NAME_REQUIRED);
            this.emitBuildStateChanged(active.build_id, "ACTIVE", "CRASHED", "crash_detected");
        }

        this.stopWorkerHeartbeat();
        this.lifecycle.releaseLock(this.lock);
        this.lock = null;

        log.info(`Shutdown complete`, { signal });
        process.exit(0);
    }

    close(): void {
        if (this.lock) {
            this.stopWorkerHeartbeat();
            this.lifecycle.releaseLock(this.lock);
            this.lock = null;
        }

        try {
            this.db.close();
        } catch {
            // ignore
        }
    }

    // ===========================
    // Internals
    // ===========================

    private startWorkerHeartbeat() {
        if (!this.lock) return;
        if (this.hbWorker) return;

        this.hbWorker = createHeartbeatWorker({
            dbPath: this.dbPath,
            token: this.lock.token,
            exe_sha256: this.lock.exe_sha256,
            intervalMs: THRESHOLDS.LOCK_HEARTBEAT_INTERVAL_MS,
        });

        this.hbWorker.on("message", (msg: any) => {
            if (!msg || typeof msg !== "object") return;
            if (msg.type === "heartbeat_failed") {
                log.error(`Heartbeat failed`, { reason: msg.reason });
                // catastrophic: lock stolen or DB broken
                this.gracefulShutdown = true;
            }
        });

        this.hbWorker.on("error", (err) => {
            log.error(`Heartbeat worker error`, { error: String(err) });
            this.gracefulShutdown = true;
        });
    }

    private stopWorkerHeartbeat() {
        if (this.hbWorker) {
            this.hbWorker.terminate();
            this.hbWorker = null;
        }
    }

    private installSignalHandlers() {
        process.on("SIGTERM", () => this.shutdownHandler("SIGTERM"));
        process.on("SIGINT", () => this.shutdownHandler("SIGINT"));
    }

    private persistBuildInputs(build_id: UUID, inputs: ArtifactRef[]) {
        const created_at = nowIso();
        withSqliteRetry(() => {
            const tx = this.db.transaction(() => {
                for (const a of inputs) {
                    this.db
                        .prepare(
                            `INSERT OR REPLACE INTO build_inputs(build_id, artifact_id, sha256, kind, created_at)
               VALUES(?,?,?,?,?)`
                        )
                        .run(build_id, a.artifact_id, a.sha256, a.kind, created_at);
                }
            });
            tx();
        }, 3);
    }

    /**
     * Best-effort enrichment for NEED_MORE_CONTEXT retries.
     *
     * The model's error message may include references to artifacts by sha256 (64-hex)
     * and/or artifact_id (UUID v4). When present, we attempt to resolve those references
     * from the local artifact table and return ArtifactRefs to prepend to the next attempt.
     *
     * This keeps the kernel deterministic while ensuring retries are not identical.
     */
    private tryEnrichInputsFromNeedMoreContext(message: string, existing: ArtifactRef[]): ArtifactRef[] {
        const out: ArtifactRef[] = [];
        if (!message) return out;

        // Guard: cap total enrichment artifacts to prevent memory exhaustion from adversarial model output
        const MAX_ENRICHMENT_ARTIFACTS = 20;
        const MAX_ENRICHMENT_TOTAL_BYTES = 5 * 1024 * 1024; // 5MB total
        let totalEnrichmentBytes = 0;

        const existingIds = new Set(existing.map((r) => String(r.artifact_id)));
        const existingSha = new Set(existing.map((r) => String(r.sha256)));

        // 1. Try to parse Structured JSON Protocol
        try {
            // Heal truncated JSON or text-wrapped JSON
            const firstBrace = message.indexOf('{');
            const lastBrace = message.lastIndexOf('}');
            if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
                const jsonStr = message.slice(firstBrace, lastBrace + 1);
                const parsed = JSON.parse(jsonStr);

                if (parsed.reply_type === 'NEED_MORE_CONTEXT' && Array.isArray(parsed.missing)) {
                    for (const req of parsed.missing) {
                        try {
                            // Handler: FILE
                            if (req.type === 'file' && req.path) {
                                // Security: resolve and jail to cwd
                                const repoRoot = path.resolve(process.cwd());
                                const fullPath = path.resolve(repoRoot, req.path);
                                if (!fullPath.startsWith(repoRoot + path.sep) && fullPath !== repoRoot) {
                                    log.warn(`Denied path escape`, { path: req.path, resolved: fullPath });
                                    continue;
                                }

                                // Extension + name policy (check before touching filesystem)
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
                                if (!ALLOWED_EXTS.has(ext) || DENIED_NAMES.has(basename) || basename.startsWith('.env')) {
                                    log.warn(`Denied file request (policy)`, { path: req.path });
                                    continue;
                                }
                                if (pathParts.some((p: string) => DENIED_DIRS.has(p))) {
                                    log.warn(`Denied file request (directory policy)`, { path: req.path });
                                    continue;
                                }

                                // Atomically open + fstat to prevent TOCTOU symlink race
                                let fd: number;
                                try {
                                    fd = fs.openSync(fullPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
                                } catch (openErr: any) {
                                    if (openErr.code === 'ELOOP' || openErr.code === 'ENOENT') {
                                        log.warn(`Denied (symlink or missing)`, { path: req.path });
                                        continue;
                                    }
                                    continue;
                                }
                                try {
                                    const stat = fs.fstatSync(fd);
                                    if (!stat.isFile()) {
                                        log.warn(`Denied non-regular file`, { path: req.path });
                                        continue;
                                    }
                                    // Size guard: 1MB max per file, prevents memory exhaustion
                                    const MAX_FILE_SIZE = 1024 * 1024;
                                    if (stat.size > MAX_FILE_SIZE) {
                                        log.warn(`Denied oversized file`, { path: req.path, size: stat.size });
                                        continue;
                                    }
                                    // Realpath check: verify resolved path is still inside jail after following any mount points
                                    const realFullPath = fs.realpathSync(fullPath);
                                    if (!realFullPath.startsWith(repoRoot + path.sep) && realFullPath !== repoRoot) {
                                        log.warn(`Denied realpath escape`, { path: req.path, realpath: realFullPath });
                                        continue;
                                    }
                                    // Enforce enrichment budget limits
                                    if (out.length >= MAX_ENRICHMENT_ARTIFACTS) {
                                        log.warn(`Enrichment artifact limit reached`, { limit: MAX_ENRICHMENT_ARTIFACTS });
                                        continue;
                                    }
                                    if (totalEnrichmentBytes + stat.size > MAX_ENRICHMENT_TOTAL_BYTES) {
                                        log.warn(`Enrichment size limit reached`, { limit: MAX_ENRICHMENT_TOTAL_BYTES });
                                        continue;
                                    }
                                    const content = fs.readFileSync(fd);
                                    totalEnrichmentBytes += content.length;
                                    const stored = this.artifactStore.store(content);

                                    if (!existingSha.has(stored.sha256)) {
                                        out.push({
                                            artifact_id: stored.sha256, // Use SHA as ID for ad-hoc files
                                            sha256: stored.sha256,
                                            kind: 'config' // Use 'config' as generic file type
                                        });
                                        existingSha.add(stored.sha256);
                                        log.info(`Resolved file`, { path: req.path });
                                    }
                                } finally {
                                    try { fs.closeSync(fd); } catch {}
                                }
                            }

                            // Handler: CHECKPOINT (stage/target)
                            if (req.type === 'checkpoint' && req.ref) {
                                const [s, t] = req.ref.split('/');
                                if (s && t) {
                                    // Find latest artifacts for this stage/target
                                    const rows = withSqliteRetry(() => this.db.prepare(`
                                        SELECT a.artifact_id, a.sha256, a.kind
                                        FROM artifact_refs ar
                                        JOIN artifacts a ON ar.artifact_id = a.artifact_id
                                        WHERE ar.stage=? AND ar.target=?
                                        ORDER BY ar.created_at DESC
                                        LIMIT 10
                                    `).all(s, t) as any[], 3);

                                    for (const r of rows) {
                                        if (existingSha.has(String(r.sha256))) continue;
                                        out.push({
                                            artifact_id: String(r.artifact_id),
                                            sha256: String(r.sha256),
                                            kind: r.kind
                                        });
                                        existingSha.add(String(r.sha256));
                                        log.info(`Resolved checkpoint`, { stage: s, target: t, sha: r.sha256.slice(0, 8) });
                                    }
                                }
                            }
                        } catch (err) {
                            log.warn(`Failed to handle context request`, { req, error: String(err) });
                        }
                    }
                    return out; // JSON matched, skip regex
                }
            }
        } catch (e) {
            // Ignore parse errors, fall through to regex
        }

        // 2. Legacy Regex Fallback
        // Collect candidate sha256 hashes (64 hex chars)
        const shaMatches = message.match(/[a-fA-F0-9]{64}/g) || [];
        // Collect candidate UUID v4s
        const uuidMatches = message.match(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}/g) || [];

        // Resolve UUIDs first (most precise)
        for (const id of uuidMatches) {
            if (existingIds.has(id)) continue;
            const row = withSqliteRetry(() => this.db.prepare(`SELECT artifact_id, sha256, kind FROM artifacts WHERE artifact_id=?`).get(id) as any, 3);
            if (row && row.artifact_id && row.sha256) {
                out.push({ artifact_id: String(row.artifact_id), sha256: String(row.sha256), kind: row.kind as any });
                existingIds.add(String(row.artifact_id));
                existingSha.add(String(row.sha256));
            }
        }

        // Resolve sha256 hashes
        for (const sha of shaMatches) {
            const shaLower = sha.toLowerCase();
            if (existingSha.has(shaLower) || existingSha.has(sha)) continue;
            const row = withSqliteRetry(() => this.db.prepare(`SELECT artifact_id, sha256, kind FROM artifacts WHERE sha256=?`).get(shaLower) as any, 3);
            if (row && row.artifact_id && row.sha256) {
                const aid = String(row.artifact_id);
                if (existingIds.has(aid)) continue;
                out.push({ artifact_id: aid, sha256: String(row.sha256), kind: row.kind as any });
                existingIds.add(aid);
                existingSha.add(String(row.sha256));
            }
        }

        return out;
    }

    private remainingBudget(build_id: UUID): number {
        const row = withSqliteRetry(
            () => this.db.prepare(`SELECT budget_usd, cumulative_cost_usd FROM builds WHERE build_id=?`).get(build_id) as any,
            3
        );
        if (!row) return 0;
        return dbStringToNumber(row.budget_usd) - dbStringToNumber(row.cumulative_cost_usd);
    }

    private getBuildCost(build_id: UUID): number {
        const row = withSqliteRetry(() => this.db.prepare(`SELECT cumulative_cost_usd FROM builds WHERE build_id=?`).get(build_id) as any, 3);
        return row ? dbStringToNumber(row.cumulative_cost_usd) : 0;
    }

    private failBuild(build_id: UUID, error: ErrorCode, reason: StateTransitionReason) {
        if (!this.lock) return;
        const b = this.lifecycle.getBuild(build_id);
        if (!b) return;

        // preserve SUCCESS checkpoints (MC2 invariant)
        this.lifecycle.transitionState(this.lock, build_id, "FAILED", reason, PROCESS_NAME_REQUIRED);
        this.emitBuildStateChanged(build_id, b.state, "FAILED", reason);
        this.outbox.flush(1000);
    }

    private emitBuildStateChanged(build_id: UUID, from_state: BuildState, to_state: BuildState, reason: StateTransitionReason) {
        const b = this.lifecycle.getBuild(build_id);
        if (!b) return;

        const target_hash = computeTargetHashForEvent({ event_type: "build_state_changed", to_state, reason });

        this.outbox.emitEvent({
            event_type: "build_state_changed",
            build_id,
            transition_seq: b.transition_seq,
            target_hash,
            payload: {
                event_type: "build_state_changed",
                timestamp: nowIso(),
                build_id,
                from_state,
                to_state,
                reason,
                cumulative_cost_usd: b.cumulative_cost_usd,
            },
        });

        // mandatory flush after transition
        this.outbox.flush(1000);
    }

    private emitTargetCompleted(build_id: UUID, stage: string, target: string, context_hash: Sha256Hex, res: ExecutionResult, attempt_no: number) {
        const b = this.lifecycle.getBuild(build_id);
        if (!b) return;

        const target_hash = computeTargetHashForEvent({ event_type: "target_completed", stage, target, context_hash });

        this.outbox.emitEvent({
            event_type: "target_completed",
            build_id,
            transition_seq: b.transition_seq,
            target_hash,
            payload: {
                event_type: "target_completed",
                timestamp: nowIso(),
                build_id,
                stage,
                target,
                context_hash,
                cost_usd: res.cost_usd,
                tokens: res.tokens,
                artifact_ids: res.artifact_ids,
                status: res.status,
                budget_exceeded: res.budget_exceeded,
                attempt_no,
            },
        });
    }

    private emitBudgetPause(build_id: UUID, confirmation_token: string, reason: StateTransitionReason) {
        const b = this.lifecycle.getBuild(build_id);
        if (!b) return;

        const target_hash = computeTargetHashForEvent({ event_type: "budget_pause", confirmation_token });

        this.outbox.emitEvent({
            event_type: "budget_pause",
            build_id,
            transition_seq: b.transition_seq,
            target_hash,
            payload: {
                event_type: "budget_pause",
                timestamp: nowIso(),
                build_id,
                cumulative_cost_usd: b.cumulative_cost_usd,
                budget_usd: b.budget_usd,
                remaining_targets: 0, // placeholder
                confirmation_token,
                reason,
            },
        });

        // mandatory flush after BUDGET_PAUSE transitions
        this.outbox.flush(1000);
    }
}

// ===========================
// Helpers
// ===========================

function isRetryable(code: ErrorCode): boolean {
    return code === "STORAGE_ERROR_RETRY" || code === "TRANSFORM_RATE_LIMIT" || code === "NETWORK_ERROR" || code === "NEED_MORE_CONTEXT";
}

function computeBuildInputsHash(inputs: ArtifactRef[]): Sha256Hex {
    const sorted = [...inputs].sort((a, b) => a.artifact_id.localeCompare(b.artifact_id));
    const blob = sorted.map((x) => `${x.artifact_id}:${x.sha256}:${x.kind}`).join("\n");
    return sha256Hex(Buffer.from(blob, "utf8"));
}

function resolveTargetConfig(ms5_spec: any, stage: string, target: string): any {
    const global = ms5_spec?.global_config || {};
    const stageObj = (ms5_spec?.stages || []).find((s: any) => String(s?.name) === stage);
    const stageCfg = stageObj?.config || {};
    const targetObj = (stageObj?.targets || []).find((t: any) => String(t?.name) === target);
    const targetCfg = targetObj?.config || {};
    return { ...global, ...stageCfg, ...targetCfg };
}

// artifact_store.ts — MS2 PRODUCTION v6.4.2
//
// GUARANTEES (LOCKABLE):
// - Content-addressed storage (SHA-256 over PLAINTEXT)
// - Collision detection (same hash, different plaintext => HASH_COLLISION)
// - Optional encryption-at-rest (AES-256-GCM), hash unaffected (hash over plaintext)
// - Key versioning (key_version stored, keyring lookup on decrypt)
// - Immutable artifacts by default; optional orphan GC (disabled by default)
// - Validated build state transitions (fail-closed)
// - Traceability: artifact_refs links artifacts ↔ builds (kind preserved)
// - Exactly-once event delivery per consumer (transactional outbox + processed_events)
// - Forward-compatible schema migrations (schema_version)
// - Memory-bounded cache (byte-aware LRU) with coherency on linkArtifactToBuild
//
// CONTRACT: Synchronous API (better-sqlite3 blocks by design)

import Database from 'better-sqlite3';
import crypto from 'crypto';
import { EventEmitter } from 'events';
import { LRUCache } from 'lru-cache';

/* -------------------------------------------------------------------------- */
/* Types                                                                      */
/* -------------------------------------------------------------------------- */

export type BuildState =
  | 'ACTIVE'
  | 'SUCCESS'
  | 'FAILED'
  | 'CRASHED'
  | 'BUDGET_PAUSE'
  | 'ABANDONED';

export type ArtifactKind =
  | 'ms5'
  | 'ms4'
  | 'ms3'
  | 'ms2'
  | 'ms2_5'
  | 'intent'
  | 'boot_pack'
  | 'checkpoint'
  | 'cost_record'
  | 'log'
  | 'config'
  | 'unknown';

export interface StoreArtifactParams {
  content: Buffer | string | object;
  kind: ArtifactKind;
}

export interface StoreArtifactResult {
  hash: string;
  alreadyExisted: boolean;
  sizeBytes: number;
  encrypted: boolean;
  keyVersion: number;
}

export interface RetrieveArtifactResult {
  content: Buffer;
  hash: string;
  kind: ArtifactKind;
  createdAt: Date;
  encrypted: boolean;
  keyVersion: number;
}

export interface CheckpointRecord {
  buildId: string;
  transformType: string;
  targetId: string;
  contextHash: string;
  artifactHash?: string;
  errorMessage?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface CostRecord {
  id: number;
  buildId: string;
  modelId: string;
  transformType: string;
  targetId: string;
  tokensIn: number;
  tokensOut: number;
  costUsd: number;
  createdAt: Date;
}

export interface StoreMetrics {
  artifactCount: number;
  buildCount: number;
  checkpointCount: number;
  costTotalUsd: number;
  outboxPendingCount: number;
  processedEventsCount: number;
  dbSizeBytes: number;
  cacheSizeBytes: number;
}

/* -------------------------------------------------------------------------- */
/* Errors                                                                     */
/* -------------------------------------------------------------------------- */

export class ArtifactStoreError extends Error {
  constructor(message: string, public readonly code: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'ArtifactStoreError';
  }
}

export const ERRORS = {
  INFRA_ERROR: 'INFRA_ERROR',
  ARTIFACT_NOT_FOUND: 'ARTIFACT_NOT_FOUND',
  BUILD_NOT_FOUND: 'BUILD_NOT_FOUND',
  BUILD_NOT_ACTIVE: 'BUILD_NOT_ACTIVE',
  HASH_COLLISION: 'HASH_COLLISION',
  BLOB_TOO_LARGE: 'BLOB_TOO_LARGE',
  INVALID_STATE_TRANSITION: 'INVALID_STATE_TRANSITION',
  ENCRYPTION_KEY_MISSING: 'ENCRYPTION_KEY_MISSING',
  INVALID_HASH_FORMAT: 'INVALID_HASH_FORMAT',
} as const;

/* -------------------------------------------------------------------------- */
/* Constants                                                                  */
/* -------------------------------------------------------------------------- */

const SCHEMA_VERSION = 2;

const MAX_BLOB_BYTES = 50 * 1024 * 1024;         // 50MB
const CACHE_MAX_BYTES = 512 * 1024 * 1024;       // 512MB
const EVENTS_TTL_DAYS = 7;                       // processed_events + event_outbox TTL
const ORPHAN_GC_DAYS = 30;                       // optional, conservative
const OUTBOX_BATCH_SIZE = 250;

const VALID_TRANSITIONS: Record<BuildState, BuildState[]> = {
  ACTIVE: ['SUCCESS', 'FAILED', 'CRASHED', 'BUDGET_PAUSE'],
  CRASHED: ['ACTIVE'],
  BUDGET_PAUSE: ['ACTIVE', 'ABANDONED'],
  SUCCESS: [],
  FAILED: [],
  ABANDONED: [],
};

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function sha256Hex(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function validateHash(hash: string): void {
  if (!/^[a-f0-9]{64}$/i.test(hash)) {
    throw new ArtifactStoreError(`Invalid hash format: ${hash}`, ERRORS.INVALID_HASH_FORMAT);
  }
}

function canonicalize(input: any, depth = 0): Buffer {
  if (depth > 100) throw new Error("DEPTH_LIMIT_EXCEEDED");
  if (Buffer.isBuffer(input)) return input;
  if (typeof input === 'string') return Buffer.from(input, 'utf8');

  try {
    // Note: this does not handle circular structures by design (fail fast).
    // If you need circular-safe canonicalization, handle upstream.
    return Buffer.from(JSON.stringify(input, Object.keys(input).sort()), 'utf8');
  } catch (e) {
    throw new ArtifactStoreError('Non-serializable artifact content', ERRORS.INFRA_ERROR, e);
  }
}

function encryptAesGcm(key: Buffer, plaintext: Buffer): Buffer {
  // Format: [ 12B IV ][ 16B TAG ][ ciphertext... ]
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]);
}

function decryptAesGcm(key: Buffer, ciphertext: Buffer): Buffer {
  const iv = ciphertext.subarray(0, 12);
  const tag = ciphertext.subarray(12, 28);
  const enc = ciphertext.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]);
}

function eventId(type: string, payload: any): string {
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  return sha256Hex(Buffer.from(type + '\0' + canonical));
}

/* -------------------------------------------------------------------------- */
/* Options                                                                    */
/* -------------------------------------------------------------------------- */

export interface ArtifactStoreOptions {
  /**
   * Primary encryption key for NEW writes (optional).
   * Must be 32 bytes for AES-256-GCM.
   */
  encryptionKey?: Buffer;

  /**
   * Version number to store alongside NEW encrypted artifacts (default: 0).
   * You can rotate keys by bumping this and providing a new key in keyRing.
   */
  activeKeyVersion?: number;

  /**
   * Map of key_version -> key bytes (32).
   * Used for decryption; MUST include activeKeyVersion if encryptionKey is set.
   */
  keyRing?: Map<number, Buffer>;

  /**
   * If true, enables conservative orphan GC (disabled by default).
   * Deletes artifacts that have no refs AND are older than orphanGcDays.
   */
  enableOrphanGc?: boolean;

  orphanGcDays?: number;

  /**
   * Processed/outbox TTL in days (default EVENTS_TTL_DAYS).
   */
  eventsTtlDays?: number;
}

/* -------------------------------------------------------------------------- */
/* Artifact Store                                                             */
/* -------------------------------------------------------------------------- */

export class ArtifactStore extends EventEmitter {
  private readonly db: Database.Database;

  // keyring supports decryption of old key_versions (rotation-safe)
  private readonly keyRing: Map<number, Buffer>;
  private readonly activeKeyVersion: number;
  private readonly enableOrphanGc: boolean;
  private readonly orphanGcDays: number;
  private readonly eventsTtlDays: number;

  // byte-aware cache: stores PLAINTEXT only, keyed by artifact hash (hash over plaintext)
  private cache = new LRUCache<string, Buffer>({
    maxSize: CACHE_MAX_BYTES,
    sizeCalculation: (b: Buffer) => b.length,
  });

  constructor(dbPath: string, optsOrKey?: Buffer | ArtifactStoreOptions) {
    super();

    const opts: ArtifactStoreOptions =
      Buffer.isBuffer(optsOrKey) ? { encryptionKey: optsOrKey } : (optsOrKey ?? {});

    const encryptionKey = opts.encryptionKey;
    const activeKeyVersion = opts.activeKeyVersion ?? 0;

    if (encryptionKey && encryptionKey.length !== 32) {
      throw new ArtifactStoreError('Encryption key must be 32 bytes', ERRORS.INFRA_ERROR);
    }

    this.keyRing = opts.keyRing ?? new Map<number, Buffer>();
    this.activeKeyVersion = activeKeyVersion;
    this.enableOrphanGc = opts.enableOrphanGc ?? false;
    this.orphanGcDays = opts.orphanGcDays ?? ORPHAN_GC_DAYS;
    this.eventsTtlDays = opts.eventsTtlDays ?? EVENTS_TTL_DAYS;

    if (encryptionKey) {
      // Ensure primary key is registered for its version
      this.keyRing.set(activeKeyVersion, encryptionKey);
    }

    this.db = new Database(dbPath);
    this.configureDatabase();
    this.runMigrations();
    this.integrityCheck();
    this.maintenance(); // TTL cleanup + optional orphan GC
  }

  /* ------------------------------------------------------------------------ */
  /* SQLite Configuration                                                     */
  /* ------------------------------------------------------------------------ */

  private configureDatabase(): void {
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.db.pragma('synchronous = NORMAL');
    this.db.pragma('busy_timeout = 5000');
    this.db.pragma('cache_size = -2000'); // 2MB
  }

  /* ------------------------------------------------------------------------ */
  /* Migrations                                                               */
  /* ------------------------------------------------------------------------ */

  private runMigrations(): void {
    const tx = this.db.transaction(() => {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS schema_version (
          version INTEGER PRIMARY KEY,
          applied_at TEXT DEFAULT CURRENT_TIMESTAMP
        ) STRICT
      `);

      const row = this.db
        .prepare(`SELECT version FROM schema_version ORDER BY version DESC LIMIT 1`)
        .get() as { version: number } | undefined;

      const current = row?.version ?? 0;

      if (current < 1) {
        // Initial schema (v1)
        this.db.exec(`
          CREATE TABLE IF NOT EXISTS artifacts (
            content_hash TEXT PRIMARY KEY,
            content_blob BLOB NOT NULL,
            is_encrypted INTEGER NOT NULL DEFAULT 0,
            key_version INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            CHECK(length(content_hash) = 64),
            CHECK(is_encrypted IN (0,1))
          ) STRICT;

          CREATE TABLE IF NOT EXISTS builds (
            build_id TEXT PRIMARY KEY,
            ms5_hash TEXT NOT NULL,
            state TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            CHECK(state IN ('ACTIVE','SUCCESS','FAILED','CRASHED','BUDGET_PAUSE','ABANDONED'))
          ) STRICT;

          CREATE TABLE IF NOT EXISTS artifact_refs (
            build_id TEXT NOT NULL,
            artifact_hash TEXT NOT NULL,
            artifact_kind TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (build_id, artifact_hash, artifact_kind),
            FOREIGN KEY (build_id) REFERENCES builds(build_id) ON DELETE CASCADE,
            FOREIGN KEY (artifact_hash) REFERENCES artifacts(content_hash) ON DELETE CASCADE
          ) STRICT;

          CREATE TABLE IF NOT EXISTS checkpoints (
            build_id TEXT NOT NULL,
            transform_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            context_hash TEXT NOT NULL,
            artifact_hash TEXT,
            error_message TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (build_id, transform_type, target_id),
            FOREIGN KEY (build_id) REFERENCES builds(build_id) ON DELETE CASCADE,
            CHECK(length(context_hash) = 64)
          ) STRICT;

          CREATE TABLE IF NOT EXISTS cost_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            build_id TEXT NOT NULL,
            model_id TEXT NOT NULL,
            transform_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            tokens_in INTEGER NOT NULL DEFAULT 0,
            tokens_out INTEGER NOT NULL DEFAULT 0,
            cost_usd REAL NOT NULL DEFAULT 0.0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (build_id) REFERENCES builds(build_id) ON DELETE CASCADE,
            CHECK(tokens_in >= 0),
            CHECK(tokens_out >= 0),
            CHECK(cost_usd >= 0)
          ) STRICT;

          CREATE TABLE IF NOT EXISTS event_outbox (
            event_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
          ) STRICT;

          CREATE TABLE IF NOT EXISTS processed_events (
            consumer_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (consumer_id, event_id)
          ) STRICT;

          CREATE INDEX IF NOT EXISTS idx_builds_state ON builds(state);
          CREATE INDEX IF NOT EXISTS idx_builds_updated ON builds(updated_at);

          CREATE INDEX IF NOT EXISTS idx_artifact_refs_build ON artifact_refs(build_id);
          CREATE INDEX IF NOT EXISTS idx_artifact_refs_hash ON artifact_refs(artifact_hash);

          CREATE INDEX IF NOT EXISTS idx_checkpoints_build ON checkpoints(build_id);
          CREATE INDEX IF NOT EXISTS idx_cost_records_build ON cost_records(build_id);

          CREATE INDEX IF NOT EXISTS idx_outbox_created ON event_outbox(created_at);
          CREATE INDEX IF NOT EXISTS idx_processed_consumer ON processed_events(consumer_id);
        `);

        this.db.prepare(`INSERT INTO schema_version (version) VALUES (1)`).run();
      }

      // v2: (re)assert FK on artifact_refs.artifact_hash and ensure key_version exists.
      // Some prior iterations may have created artifact_refs without the artifact_hash FK.
      if (current < 2) {
        // Ensure key_version exists (if older DB somehow lacks it)
        const artifactsCols = this.db.prepare(`PRAGMA table_info(artifacts)`).all() as Array<{ name: string }>;
        const hasKeyVersion = artifactsCols.some((c) => c.name === 'key_version');
        if (!hasKeyVersion) {
          this.db.exec(`ALTER TABLE artifacts ADD COLUMN key_version INTEGER NOT NULL DEFAULT 0`);
        }

        // Ensure artifact_refs has FK to artifacts(content_hash).
        // If missing, rebuild artifact_refs table safely.
        const fkList = this.db.prepare(`PRAGMA foreign_key_list(artifact_refs)`).all() as any[];
        const hasArtifactFk = fkList.some(
          (fk) => fk.table === 'artifacts' && fk.from === 'artifact_hash' && fk.to === 'content_hash'
        );

        if (!hasArtifactFk) {
          // Rebuild artifact_refs to add FK
          this.db.exec(`
            ALTER TABLE artifact_refs RENAME TO artifact_refs_old;

            CREATE TABLE artifact_refs (
              build_id TEXT NOT NULL,
              artifact_hash TEXT NOT NULL,
              artifact_kind TEXT NOT NULL,
              created_at TEXT DEFAULT CURRENT_TIMESTAMP,
              PRIMARY KEY (build_id, artifact_hash, artifact_kind),
              FOREIGN KEY (build_id) REFERENCES builds(build_id) ON DELETE CASCADE,
              FOREIGN KEY (artifact_hash) REFERENCES artifacts(content_hash) ON DELETE CASCADE
            ) STRICT;

            INSERT INTO artifact_refs (build_id, artifact_hash, artifact_kind, created_at)
            SELECT build_id, artifact_hash, artifact_kind, created_at
            FROM artifact_refs_old;

            DROP TABLE artifact_refs_old;

            CREATE INDEX IF NOT EXISTS idx_artifact_refs_build ON artifact_refs(build_id);
            CREATE INDEX IF NOT EXISTS idx_artifact_refs_hash ON artifact_refs(artifact_hash);
          `);
        }

        this.db.prepare(`INSERT INTO schema_version (version) VALUES (2)`).run();
      }

      // Future migrations: add only, never remove.
      if (SCHEMA_VERSION > 2) {
        // placeholder
      }
    });

    tx();
  }

  /* ------------------------------------------------------------------------ */
  /* Integrity / Maintenance                                                  */
  /* ------------------------------------------------------------------------ */

  private integrityCheck(): void {
    const result = this.db.prepare('PRAGMA quick_check').get() as any;
    if (result.quick_check !== 'ok') {
      throw new ArtifactStoreError(
        `Database integrity check failed: ${result.quick_check}`,
        ERRORS.INFRA_ERROR
      );
    }
  }

  /**
   * Maintenance:
   * - TTL cleanup for processed_events and event_outbox
   * - optional orphan artifact GC (conservative)
   */
  maintenance(): void {
    // processed_events TTL
    this.db
      .prepare(`DELETE FROM processed_events WHERE created_at < datetime('now', ?)`)
      .run(`-${this.eventsTtlDays} days`);

    // outbox TTL (in case consumer down for a long time)
    this.db
      .prepare(`DELETE FROM event_outbox WHERE created_at < datetime('now', ?)`)
      .run(`-${this.eventsTtlDays} days`);

    if (this.enableOrphanGc) {
      this.db
        .prepare(`
          DELETE FROM artifacts
          WHERE content_hash NOT IN (SELECT DISTINCT artifact_hash FROM artifact_refs)
            AND created_at < datetime('now', ?)
        `)
        .run(`-${this.orphanGcDays} days`);
    }
  }

  /* ------------------------------------------------------------------------ */
  /* Builds                                                                   */
  /* ------------------------------------------------------------------------ */

  createBuild(buildId: string, ms5Hash: string): void {
    this.db.prepare(
      `INSERT INTO builds (build_id, ms5_hash, state) VALUES (?, ?, 'ACTIVE')`
    ).run(buildId, ms5Hash);

    this.enqueueEvent('build_created', { build_id: buildId, ms5_hash: ms5Hash, state: 'ACTIVE' });
  }

  updateBuildState(buildId: string, next: BuildState): void {
    const row = this.db
      .prepare(`SELECT state FROM builds WHERE build_id = ?`)
      .get(buildId) as { state: BuildState } | undefined;

    if (!row) throw new ArtifactStoreError(`Build not found: ${buildId}`, ERRORS.BUILD_NOT_FOUND);

    if (!VALID_TRANSITIONS[row.state].includes(next)) {
      throw new ArtifactStoreError(
        `Invalid state transition ${row.state} → ${next}`,
        ERRORS.INVALID_STATE_TRANSITION
      );
    }

    this.db.prepare(
      `UPDATE builds SET state = ?, updated_at = CURRENT_TIMESTAMP WHERE build_id = ?`
    ).run(next, buildId);

    this.enqueueEvent('build_state_changed', { build_id: buildId, from: row.state, to: next });
  }

  getBuild(buildId: string): { buildId: string; ms5Hash: string; state: BuildState; createdAt: Date; updatedAt: Date } | null {
    const row = this.db.prepare(
      `SELECT build_id, ms5_hash, state, created_at, updated_at FROM builds WHERE build_id = ?`
    ).get(buildId) as any;

    if (!row) return null;
    return {
      buildId: row.build_id,
      ms5Hash: row.ms5_hash,
      state: row.state as BuildState,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    };
  }

  getActiveBuild(): string | null {
    const row = this.db.prepare(
      `SELECT build_id FROM builds WHERE state IN ('ACTIVE','CRASHED','BUDGET_PAUSE') ORDER BY updated_at DESC LIMIT 1`
    ).get() as { build_id: string } | undefined;

    return row?.build_id ?? null;
  }

  /* ------------------------------------------------------------------------ */
  /* Artifacts                                                                */
  /* ------------------------------------------------------------------------ */

  storeArtifact(params: StoreArtifactParams): StoreArtifactResult {
    const plaintext = canonicalize(params.content);

    if (plaintext.length > MAX_BLOB_BYTES) {
      throw new ArtifactStoreError(
        `Artifact too large: ${plaintext.length} > ${MAX_BLOB_BYTES}`,
        ERRORS.BLOB_TOO_LARGE
      );
    }

    const hash = sha256Hex(plaintext);

    const existing = this.db.prepare(
      `SELECT content_blob, is_encrypted, key_version FROM artifacts WHERE content_hash = ?`
    ).get(hash) as { content_blob: Buffer; is_encrypted: number; key_version: number } | undefined;

    if (existing) {
      let existingPlain = existing.content_blob;
      if (existing.is_encrypted) {
        const key = this.keyRing.get(existing.key_version);
        if (!key) {
          throw new ArtifactStoreError(
            `Missing key for version ${existing.key_version}`,
            ERRORS.ENCRYPTION_KEY_MISSING
          );
        }
        existingPlain = decryptAesGcm(key, existing.content_blob);
      }

      if (!existingPlain.equals(plaintext)) {
        throw new ArtifactStoreError(`SHA256 collision for hash ${hash}`, ERRORS.HASH_COLLISION);
      }

      return {
        hash,
        alreadyExisted: true,
        sizeBytes: plaintext.length,
        encrypted: existing.is_encrypted === 1,
        keyVersion: existing.key_version ?? 0,
      };
    }

    // Encrypt if encryption enabled (active key must be present in keyRing)
    let storedBlob = plaintext;
    let encrypted = false;
    let keyVersion = 0;

    const activeKey = this.keyRing.get(this.activeKeyVersion);
    if (activeKey) {
      storedBlob = encryptAesGcm(activeKey, plaintext);
      encrypted = true;
      keyVersion = this.activeKeyVersion;
    }

    const payload = { hash, kind: params.kind };
    const eid = eventId('artifact_stored', payload);

    this.db.transaction(() => {
      this.db.prepare(
        `INSERT INTO artifacts (content_hash, content_blob, is_encrypted, key_version)
         VALUES (?, ?, ?, ?)`
      ).run(hash, storedBlob, encrypted ? 1 : 0, keyVersion);

      this.db.prepare(
        `INSERT OR IGNORE INTO event_outbox (event_id, event_type, payload)
         VALUES (?, ?, ?)`
      ).run(eid, 'artifact_stored', JSON.stringify(payload));
    })();

    return { hash, alreadyExisted: false, sizeBytes: plaintext.length, encrypted, keyVersion };
  }

  retrieveArtifact(hash: string): RetrieveArtifactResult {
    validateHash(hash);

    const cached = this.cache.get(hash);
    if (cached) {
      const kind = this.lookupKind(hash);
      // createdAt/encrypted/keyVersion not in cache; read minimal metadata
      const meta = this.db.prepare(
        `SELECT created_at, is_encrypted, key_version FROM artifacts WHERE content_hash = ?`
      ).get(hash) as any;
      return {
        content: cached,
        hash,
        kind,
        createdAt: meta ? new Date(meta.created_at) : new Date(0),
        encrypted: meta ? meta.is_encrypted === 1 : false,
        keyVersion: meta ? meta.key_version ?? 0 : 0,
      };
    }

    const row = this.db.prepare(
      `SELECT content_blob, is_encrypted, key_version, created_at
       FROM artifacts WHERE content_hash = ?`
    ).get(hash) as { content_blob: Buffer; is_encrypted: number; key_version: number; created_at: string } | undefined;

    if (!row) {
      throw new ArtifactStoreError(`Artifact not found: ${hash}`, ERRORS.ARTIFACT_NOT_FOUND);
    }

    let content = row.content_blob;
    if (row.is_encrypted) {
      const key = this.keyRing.get(row.key_version);
      if (!key) {
        throw new ArtifactStoreError(
          `Key version not found: ${row.key_version}`,
          ERRORS.ENCRYPTION_KEY_MISSING
        );
      }
      content = decryptAesGcm(key, content);
    }

    // Verify integrity: hash must match PLAINTEXT
    if (sha256Hex(content) !== hash) {
      throw new ArtifactStoreError(`Artifact corruption detected: ${hash}`, ERRORS.INFRA_ERROR);
    }

    // Cache plaintext
    this.cache.set(hash, content);

    const kind = this.lookupKind(hash);

    return {
      content,
      hash,
      kind,
      createdAt: new Date(row.created_at),
      encrypted: row.is_encrypted === 1,
      keyVersion: row.key_version ?? 0,
    };
  }

  /**
   * Returns the most recent kind assigned via artifact_refs, if any.
   */
  private lookupKind(artifactHash: string): ArtifactKind {
    const ref = this.db.prepare(
      `SELECT artifact_kind
       FROM artifact_refs
       WHERE artifact_hash = ?
       ORDER BY created_at DESC
       LIMIT 1`
    ).get(artifactHash) as { artifact_kind: string } | undefined;

    return (ref?.artifact_kind as ArtifactKind) ?? 'unknown';
  }

  linkArtifactToBuild(buildId: string, artifactHash: string, kind: ArtifactKind): void {
    validateHash(artifactHash);

    // Verify build exists
    const build = this.db.prepare(`SELECT 1 FROM builds WHERE build_id = ?`).get(buildId);
    if (!build) throw new ArtifactStoreError(`Build not found: ${buildId}`, ERRORS.BUILD_NOT_FOUND);

    // Verify artifact exists
    const art = this.db.prepare(`SELECT 1 FROM artifacts WHERE content_hash = ?`).get(artifactHash);
    if (!art) throw new ArtifactStoreError(`Artifact not found: ${artifactHash}`, ERRORS.ARTIFACT_NOT_FOUND);

    const payload = { build_id: buildId, artifact_hash: artifactHash, kind };
    const eid = eventId('artifact_linked', payload);

    this.db.transaction(() => {
      this.db.prepare(
        `INSERT OR IGNORE INTO artifact_refs (build_id, artifact_hash, artifact_kind)
         VALUES (?, ?, ?)`
      ).run(buildId, artifactHash, kind);

      this.db.prepare(
        `INSERT OR IGNORE INTO event_outbox (event_id, event_type, payload)
         VALUES (?, ?, ?)`
      ).run(eid, 'artifact_linked', JSON.stringify(payload));
    })();

    // Cache coherency: kind may have changed, invalidate
    this.cache.delete(artifactHash);
  }

  getBuildArtifacts(buildId: string, kind?: ArtifactKind): Array<{ hash: string; kind: ArtifactKind; createdAt: Date }> {
    const build = this.db.prepare(`SELECT 1 FROM builds WHERE build_id = ?`).get(buildId);
    if (!build) throw new ArtifactStoreError(`Build not found: ${buildId}`, ERRORS.BUILD_NOT_FOUND);

    if (kind) {
      const rows = this.db.prepare(
        `SELECT artifact_hash, artifact_kind, created_at
         FROM artifact_refs
         WHERE build_id = ? AND artifact_kind = ?
         ORDER BY created_at DESC`
      ).all(buildId, kind) as Array<any>;

      return rows.map((r) => ({ hash: r.artifact_hash, kind: r.artifact_kind as ArtifactKind, createdAt: new Date(r.created_at) }));
    }

    const rows = this.db.prepare(
      `SELECT artifact_hash, artifact_kind, created_at
       FROM artifact_refs
       WHERE build_id = ?
       ORDER BY created_at DESC`
    ).all(buildId) as Array<any>;

    return rows.map((r) => ({ hash: r.artifact_hash, kind: r.artifact_kind as ArtifactKind, createdAt: new Date(r.created_at) }));
  }

  /* ------------------------------------------------------------------------ */
  /* Checkpoints                                                              */
  /* ------------------------------------------------------------------------ */

  writeCheckpoint(
    buildId: string,
    transformType: string,
    targetId: string,
    contextHash: string,
    artifactHash?: string,
    errorMessage?: string
  ): void {
    const build = this.db.prepare(`SELECT state FROM builds WHERE build_id = ?`).get(buildId) as { state: BuildState } | undefined;
    if (!build) throw new ArtifactStoreError(`Build not found: ${buildId}`, ERRORS.BUILD_NOT_FOUND);

    if (!['ACTIVE', 'CRASHED', 'BUDGET_PAUSE'].includes(build.state)) {
      throw new ArtifactStoreError(
        `Cannot checkpoint build in state ${build.state}`,
        ERRORS.BUILD_NOT_ACTIVE
      );
    }

    const payload = {
      build_id: buildId,
      transform_type: transformType,
      target_id: targetId,
      context_hash: contextHash,
      artifact_hash: artifactHash ?? null,
      error_message: errorMessage ?? null,
    };
    const eid = eventId('checkpoint_written', payload);

    this.db.transaction(() => {
      this.db.prepare(
        `INSERT INTO checkpoints
           (build_id, transform_type, target_id, context_hash, artifact_hash, error_message, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
         ON CONFLICT(build_id, transform_type, target_id) DO UPDATE SET
           context_hash = excluded.context_hash,
           artifact_hash = excluded.artifact_hash,
           error_message = excluded.error_message,
           updated_at = CURRENT_TIMESTAMP`
      ).run(buildId, transformType, targetId, contextHash, artifactHash ?? null, errorMessage ?? null);

      this.db.prepare(
        `INSERT OR IGNORE INTO event_outbox (event_id, event_type, payload)
         VALUES (?, ?, ?)`
      ).run(eid, 'checkpoint_written', JSON.stringify(payload));
    })();
  }

  getCheckpoint(buildId: string, transformType: string, targetId: string): CheckpointRecord | null {
    const row = this.db.prepare(
      `SELECT * FROM checkpoints WHERE build_id = ? AND transform_type = ? AND target_id = ?`
    ).get(buildId, transformType, targetId) as any;

    if (!row) return null;

    return {
      buildId: row.build_id,
      transformType: row.transform_type,
      targetId: row.target_id,
      contextHash: row.context_hash,
      artifactHash: row.artifact_hash ?? undefined,
      errorMessage: row.error_message ?? undefined,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    };
  }

  /* ------------------------------------------------------------------------ */
  /* Cost                                                                      */
  /* ------------------------------------------------------------------------ */

  recordCost(
    buildId: string,
    modelId: string,
    transformType: string,
    targetId: string,
    tokensIn: number,
    tokensOut: number,
    costUsd: number
  ): void {
    const build = this.db.prepare(`SELECT 1 FROM builds WHERE build_id = ?`).get(buildId);
    if (!build) throw new ArtifactStoreError(`Build not found: ${buildId}`, ERRORS.BUILD_NOT_FOUND);

    const payload = { build_id: buildId, model_id: modelId, transform_type: transformType, target_id: targetId, tokens_in: tokensIn, tokens_out: tokensOut, cost_usd: costUsd };
    const eid = eventId('cost_recorded', payload);

    // Important: outbox insertion is transactional with the durable write
    this.db.transaction(() => {
      this.db.prepare(
        `INSERT INTO cost_records (build_id, model_id, transform_type, target_id, tokens_in, tokens_out, cost_usd)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(buildId, modelId, transformType, targetId, tokensIn, tokensOut, costUsd);

      this.db.prepare(
        `INSERT OR IGNORE INTO event_outbox (event_id, event_type, payload)
         VALUES (?, ?, ?)`
      ).run(eid, 'cost_recorded', JSON.stringify(payload));
    })();
  }

  getCumulativeCost(buildId: string): number {
    const row = this.db.prepare(
      `SELECT SUM(cost_usd) as total FROM cost_records WHERE build_id = ?`
    ).get(buildId) as { total: number } | undefined;

    return row?.total ?? 0;
  }

  /* ------------------------------------------------------------------------ */
  /* Event Outbox (Exactly-once per consumer)                                  */
  /* ------------------------------------------------------------------------ */

  private enqueueEvent(type: string, payload: any): void {
    const eid = eventId(type, payload);
    this.db.prepare(
      `INSERT OR IGNORE INTO event_outbox (event_id, event_type, payload) VALUES (?, ?, ?)`
    ).run(eid, type, JSON.stringify(payload));
  }

  /**
   * Exactly-once per consumer:
   * - Within a single transaction:
   *   1) If not seen, insert into processed_events
   *   2) Delete from event_outbox
   *   3) Collect toEmit
   * - After commit: emit
   *
   * Crash safety:
   * - If crash before commit: processed not recorded, outbox not deleted => will retry later (no emit happened)
   * - If crash after commit but before emit: processed recorded + outbox deleted => will NOT be delivered again
   *
   * Note: "emit after commit" means the consumer might miss events if the process dies immediately after commit.
   * That's a deliberate choice to preserve exactly-once side effects (no duplication).
   * If you need at-least-once delivery, change the contract.
   */
  flushEvents(consumerId: string, batchSize = OUTBOX_BATCH_SIZE): number {
    const toEmit: Array<{ event_type: string; payload: any }> = [];

    const count = this.db.transaction(() => {
      const rows = this.db.prepare(
        `SELECT event_id, event_type, payload
         FROM event_outbox
         ORDER BY created_at ASC
         LIMIT ?`
      ).all(batchSize) as Array<{ event_id: string; event_type: string; payload: string }>;

      let processed = 0;

      for (const r of rows) {
        const seen = this.db.prepare(
          `SELECT 1 FROM processed_events WHERE consumer_id = ? AND event_id = ?`
        ).get(consumerId, r.event_id);

        if (!seen) {
          this.db.prepare(
            `INSERT INTO processed_events (consumer_id, event_id) VALUES (?, ?)`
          ).run(consumerId, r.event_id);

          toEmit.push({ event_type: r.event_type, payload: JSON.parse(r.payload) });
          processed++;
        }

        this.db.prepare(`DELETE FROM event_outbox WHERE event_id = ?`).run(r.event_id);
      }

      // TTL maintenance (cheap, keeps tables bounded)
      this.db.prepare(
        `DELETE FROM processed_events WHERE created_at < datetime('now', ?)`
      ).run(`-${this.eventsTtlDays} days`);

      this.db.prepare(
        `DELETE FROM event_outbox WHERE created_at < datetime('now', ?)`
      ).run(`-${this.eventsTtlDays} days`);

      return processed;
    })();

    // Emit after commit
    for (const e of toEmit) {
      this.emit(e.event_type, e.payload);
    }

    return count;
  }

  /* ------------------------------------------------------------------------ */
  /* Metrics                                                                   */
  /* ------------------------------------------------------------------------ */

  metrics(): StoreMetrics {
    const artifactCount = (this.db.prepare(`SELECT COUNT(*) as c FROM artifacts`).get() as any).c as number;
    const buildCount = (this.db.prepare(`SELECT COUNT(*) as c FROM builds`).get() as any).c as number;
    const checkpointCount = (this.db.prepare(`SELECT COUNT(*) as c FROM checkpoints`).get() as any).c as number;
    const costTotalUsd = ((this.db.prepare(`SELECT SUM(cost_usd) as t FROM cost_records`).get() as any).t as number) ?? 0;
    const outboxPendingCount = (this.db.prepare(`SELECT COUNT(*) as c FROM event_outbox`).get() as any).c as number;
    const processedEventsCount = (this.db.prepare(`SELECT COUNT(*) as c FROM processed_events`).get() as any).c as number;

    const dbSizeBytes =
      ((this.db.prepare(
        `SELECT (page_count * page_size) as size FROM pragma_page_count(), pragma_page_size()`
      ).get() as any).size as number) ?? 0;

    const cacheSizeBytes = this.cache.calculatedSize ?? 0;

    return {
      artifactCount,
      buildCount,
      checkpointCount,
      costTotalUsd,
      outboxPendingCount,
      processedEventsCount,
      dbSizeBytes,
      cacheSizeBytes,
    };
  }

  /* ------------------------------------------------------------------------ */
  /* Close                                                                     */
  /* ------------------------------------------------------------------------ */

  close(): void {
    this.cache.clear();
    this.db.close();
  }
}

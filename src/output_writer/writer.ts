// src/output_writer/writer.ts

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

import {
    BuildManifestV1,
    BuildPlanV1,
    OutputWriter,
    OutputWriterError,
    PatchBundleV1,
    WriteOptions,
    WriteResult,
} from "./types";

import { stableStringify } from "./stable_stringify";
import { validatePlanOrThrow } from "./validate";
import { atomicWriteFileSync, atomicWriteJsonSync } from "./atomic_write";
import { acquireBuildLock, releaseBuildLock } from "./lock";
import { applyUnifiedDiffFile } from "./patch_apply";

function nowIso(opts: WriteOptions): string {
    return opts.now_utc_iso || new Date().toISOString();
}

function toPermNumber(p: "0644" | "0755"): number {
    return p === "0755" ? 0o755 : 0o644;
}

function classifyIOError(e: any): { code: "DISK_FULL" | "IO_ERROR"; errno?: string } {
    const errno = e?.code as string | undefined;
    if (errno === "ENOSPC") return { code: "DISK_FULL", errno };
    return { code: "IO_ERROR", errno };
}

function makeErr(
    code: OutputWriterError["code"],
    message: string,
    details?: Record<string, any>,
    recovery_actions?: OutputWriterError["recovery_actions"]
): { ok: false; error: OutputWriterError } {
    return {
        ok: false,
        error: { code, message, details, recovery_actions },
    };
}

function ensureDir(p: string, mode: number, dirs_set: Set<string>, rootBase: string): void {
    fs.mkdirSync(p, { recursive: true, mode });
    // recursive mkdirSync applies mode=0755 to all intermediate directories

    // add dirs to set relative to build root
    // We want paths like "files" or "files/subdir"
    const rel = path.relative(rootBase, p).split(path.sep).join("/");
    if (rel && rel !== ".") {
        dirs_set.add(rel);
    }
}

function lstatRejectSymlink(p: string): void {
    if (!fs.existsSync(p)) return;
    const st = fs.lstatSync(p);
    if (st.isSymbolicLink()) {
        const err: any = new Error("SYMLINK_REJECTED");
        err.code = "SYMLINK_REJECTED";
        err.details = { path: p };
        throw err;
    }
}

function validateNoSymlinkParents(filePath: string, stopDir: string): void {
    const parts = filePath.split(path.sep);
    let cur = parts[0] === "" ? path.sep : parts[0];

    // build up path component by component
    // stop when reaching stopDir
    for (let i = 1; i < parts.length; i++) {
        cur = path.join(cur, parts[i]);
        if (cur === stopDir) break;

        if (fs.existsSync(cur)) {
            const st = fs.lstatSync(cur);
            if (st.isSymbolicLink()) {
                const err: any = new Error("SYMLINK_REJECTED");
                err.code = "SYMLINK_REJECTED";
                err.details = { path: cur };
                throw err;
            }
        }
    }
}

export class OutputWriterImpl implements OutputWriter {
    async write(plan: BuildPlanV1, opts: WriteOptions): Promise<WriteResult | { ok: false; error: OutputWriterError }> {
        const warnings: string[] = [];

        // defaults
        const autoCleanup =
            opts.auto_cleanup_staging ?? (opts.operator_mode === "AGENT" ? true : false);
        const ttlMs = opts.staging_ttl_ms ?? 24 * 60 * 60 * 1000;
        const lockTimeoutMs = opts.lock_timeout_ms ?? 5000;

        // Phase 1: validation + plan_hash
        try {
            validatePlanOrThrow(plan);
        } catch (e: any) {
            const err = e as OutputWriterError;
            return { ok: false, error: err };
        }

        let planHash: string;
        try {
            const s = stableStringify(plan);
            planHash = "sha256:" + crypto.createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");
        } catch (e: any) {
            return makeErr("VERIFY_FAILED", "Failed to stableStringify plan", { raw_error: e.message });
        }

        const projectRoot = path.resolve("output", plan.project);
        const indexRoot = path.join(projectRoot, "_index");
        const stagingParent = path.join(indexRoot, "staging");
        const locksRoot = path.join(indexRoot, "locks");

        const stagingRoot = path.join(stagingParent, plan.build_id);
        const committedRoot = path.join(projectRoot, plan.build_id);

        const filesRoot = path.join(stagingRoot, "files");
        const manifestDir = path.join(stagingRoot, "manifest");

        const latestPath = path.join(indexRoot, "latest.json");
        const buildsJsonlPath = path.join(indexRoot, "builds.jsonl");

        // Phase 0: staging cleanup (TTL)
        if (autoCleanup) {
            try {
                fs.mkdirSync(stagingParent, { recursive: true, mode: 0o755 });
                const entries = fs.readdirSync(stagingParent, { withFileTypes: true });
                for (const ent of entries) {
                    if (!ent.isDirectory()) continue;
                    const full = path.join(stagingParent, ent.name);
                    try {
                        const st = fs.statSync(full);
                        const age = Date.now() - st.mtimeMs;
                        if (age > ttlMs) {
                            // SECURITY FIX: Try to acquire lock before deleting
                            // If lock is held, the build is active - skip deletion
                            const cleanupLockPath = path.join(locksRoot, `${ent.name}.lock`);
                            let cleanupLock: any = null;
                            try {
                                cleanupLock = await acquireBuildLock({
                                    lockPath: cleanupLockPath,
                                    timeoutMs: 100, // Quick check only
                                    warnings,
                                    identityJson: { pid: process.pid, action: "cleanup" },
                                    staleTtlMs: opts.lock_stale_ttl_ms ?? 600000,
                                });
                                // Lock acquired - safe to delete
                                fs.rmSync(full, { recursive: true, force: true });
                                releaseBuildLock(cleanupLock);
                            } catch (e: any) {
                                if (e?.code === "LOCK_HELD") {
                                    // Build is active - skip deletion
                                    warnings.push(`STAGING_CLEANUP_SKIP(ACTIVE) ${full}`);
                                } else {
                                    warnings.push(`STAGING_CLEANUP_WARN(${e?.code || "UNKNOWN"}) ${full}`);
                                }
                            }
                        }
                    } catch (e: any) {
                        const code = e?.code;
                        if (code === "ENOSPC" || code === "EACCES") {
                            warnings.push(`STAGING_CLEANUP_WARN(${code}) ${full}`);
                        }
                    }
                }
            } catch (e: any) {
                warnings.push(`STAGING_CLEANUP_WARN(${e?.code || "UNKNOWN"}) ${stagingParent}`);
            }
        }

        // Acquire lock
        fs.mkdirSync(locksRoot, { recursive: true, mode: 0o755 });
        const lockPath = path.join(locksRoot, `${plan.build_id}.lock`);

        let lockHandle: any = null;
        try {
            lockHandle = await acquireBuildLock({
                lockPath,
                timeoutMs: lockTimeoutMs,
                warnings,
                identityJson: {
                    pid: process.pid,
                    boot_id: process.env.PANDORA_BOOT_ID || "unknown",
                    started_utc: nowIso(opts),
                },
                staleTtlMs: opts.lock_stale_ttl_ms ?? 600000,
            });
        } catch (e: any) {
            return makeErr(
                "LOCK_HELD",
                "Lock held by another writer",
                { lock_path: lockPath, timeout_ms: lockTimeoutMs },
                [
                    { action: "RETRY_WITH_BACKOFF", command: "sleep 3 && retry", risk: "none" },
                    { action: "INSPECT_LOCK", command: `cat ${lockPath}`, risk: "low" },
                ]
            );
        }

        try {
            // Prevent overwrite
            if (fs.existsSync(committedRoot)) {
                return makeErr("IO_ERROR", "Committed build already exists", {
                    committed_root: committedRoot,
                });
            }
            if (fs.existsSync(stagingRoot)) {
                // preserve but error (staging collision)
                return makeErr("IO_ERROR", "Staging build already exists", { staging_root: stagingRoot });
            }

            fs.mkdirSync(projectRoot, { recursive: true, mode: 0o755 });
            fs.mkdirSync(indexRoot, { recursive: true, mode: 0o755 });

            // Phase 2: materialize in staging
            const dirs_set = new Set<string>();
            const files_index: BuildManifestV1["files_index"] = [];
            const deletes_index: BuildManifestV1["deletes_index"] = [];

            // Create base dirs
            ensureDir(stagingRoot, 0o755, dirs_set, stagingRoot);
            ensureDir(filesRoot, 0o755, dirs_set, stagingRoot);
            ensureDir(manifestDir, 0o755, dirs_set, stagingRoot);

            // Track optional bundle
            let patchBundle: PatchBundleV1 | null = null;

            // Process items
            for (const it of plan.items) {
                switch (it.kind) {
                    case "DELETE": {
                        deletes_index.push({ rel_path: it.rel_path });
                        break;
                    }

                    case "FILE_TEXT":
                    case "FILE_BYTES_B64": {
                        const rel_path = it.rel_path; // starts with files/
                        const relUnderBuild = rel_path.replace(/^files\//, "");
                        const outPath = path.join(filesRoot, relUnderBuild);

                        // reject symlink parents (P1 hardening)
                        validateNoSymlinkParents(outPath, stagingRoot);

                        const parent = path.dirname(outPath);
                        ensureDir(parent, 0o755, dirs_set, stagingRoot);

                        // decode content
                        let buf: Buffer;
                        if (it.kind === "FILE_TEXT") buf = Buffer.from(it.content_utf8, "utf8");
                        else buf = Buffer.from(it.content_b64, "base64");

                        // CRITICAL: Runtime bounds enforcement (MS2 v1.0.2 requirement)
                        // validatePlanOrThrow checks estimated sizes, but we must verify actual decoded bytes
                        if (buf.length > plan.bounds.max_file_bytes) {
                            return makeErr("BOUNDS_EXCEEDED", "Decoded file exceeds max_file_bytes", {
                                rel_path: it.rel_path,
                                actual_bytes: buf.length,
                                max_file_bytes: plan.bounds.max_file_bytes,
                            });
                        }

                        const permNum = toPermNumber(it.perm);

                        try {
                            atomicWriteFileSync({
                                filePath: outPath,
                                content: buf,
                                mode: permNum,
                                fsyncMode: plan.verify.fsync,
                                warnings, // REQUIRED PATCH: always pass warnings
                            });
                        } catch (e: any) {
                            const cls = classifyIOError(e);
                            if (cls.code === "DISK_FULL") {
                                return makeErr(
                                    "DISK_FULL",
                                    "Disk full during materialization",
                                    { errno: cls.errno, path: outPath },
                                    [
                                        {
                                            action: "FREE_DISK_SPACE",
                                            command: `df -h && rm -rf ${stagingParent}/*`,
                                            risk: "low",
                                        },
                                    ]
                                );
                            }
                            return makeErr("IO_ERROR", "IO error during materialization", {
                                errno: cls.errno,
                                path: outPath,
                                raw_error: e.message,
                            });
                        }

                        // lstat verify not symlink
                        lstatRejectSymlink(outPath);

                        files_index.push({
                            rel_path: relUnderBuild.split(path.sep).join("/"),
                            perm: it.perm,
                            bytes: buf.length,
                            kind: it.kind,
                        });

                        break;
                    }

                    case "PATCH_BUNDLE": {
                        patchBundle = it.bundle;

                        // REQUIRED PATCH: deterministic order
                        patchBundle.patches.sort((a, b) => a.patch_id.localeCompare(b.patch_id));

                        // ensure statuses present (already validated), then write initial
                        const pbPath = path.join(stagingRoot, "patch_bundle.json");
                        atomicWriteJsonSync({
                            filePath: pbPath,
                            data: patchBundle,
                            mode: 0o644,
                            fsyncMode: plan.verify.fsync,
                            warnings, // REQUIRED PATCH: always pass warnings
                        });
                        break;
                    }
                }
            }

            // Phase 3: apply patches with stop-on-fail + single atomic write
            if (patchBundle) {
                const pbPath = path.join(stagingRoot, "patch_bundle.json");

                // MS2 INVARIANT: Apply patches sequentially, stop on first failure
                // Later patches must remain PENDING if earlier patch fails
                for (let idx = 0; idx < patchBundle.patches.length; idx++) {
                    const p = patchBundle.patches[idx];

                    if (p.status === "APPLIED") continue;

                    // Unsupported format check
                    if (p.format !== "UNIFIED_DIFF") {
                        p.status = "FAILED";
                        p.failed_utc = nowIso(opts);
                        p.failure_reason = "Unsupported patch format";

                        // Write bundle once with failure status
                        atomicWriteJsonSync({
                            filePath: pbPath,
                            data: patchBundle,
                            mode: 0o644,
                            fsyncMode: plan.verify.fsync,
                            warnings,
                        });

                        return makeErr("PATCH_APPLY_FAILED", "Unsupported patch format", {
                            patch_id: p.patch_id,
                            failed_at_index: idx + 1,
                        });
                    }

                    const targetRel = p.target_rel_path.replace(/^files\//, "");
                    const targetAbs = path.join(filesRoot, targetRel);

                    const r = applyUnifiedDiffFile({
                        targetPath: targetAbs,
                        diffUtf8: p.diff_utf8,
                    });

                    if (!r.ok) {
                        // STOP ON FAIL: Mark this patch failed, leave rest PENDING
                        p.status = "FAILED";
                        p.failed_utc = nowIso(opts);
                        p.failure_reason = r.error || "Patch apply failed";

                        // Write bundle once with failure status
                        atomicWriteJsonSync({
                            filePath: pbPath,
                            data: patchBundle,
                            mode: 0o644,
                            fsyncMode: plan.verify.fsync,
                            warnings,
                        });

                        return makeErr(
                            "PATCH_APPLY_FAILED",
                            "Patch apply failed",
                            {
                                patch_id: p.patch_id,
                                failed_at_index: idx + 1,
                                target_rel_path: p.target_rel_path,
                                reason: p.failure_reason,
                                staging_dir: stagingRoot,
                            },
                            [
                                {
                                    action: "INSPECT_STAGING",
                                    command: `ls -la ${stagingRoot}`,
                                    risk: "low",
                                },
                            ]
                        );
                    }

                    // Success - mark applied
                    p.status = "APPLIED";
                    p.applied_utc = nowIso(opts);
                }

                // All patches succeeded - write bundle once
                atomicWriteJsonSync({
                    filePath: pbPath,
                    data: patchBundle,
                    mode: 0o644,
                    fsyncMode: plan.verify.fsync,
                    warnings,
                });
            }

            // Phase 4: verify checksums
            if (plan.verify.compute_checksums) {
                for (const f of files_index) {
                    const abs = path.join(filesRoot, f.rel_path);
                    lstatRejectSymlink(abs);
                    if (!fs.existsSync(abs)) {
                        return makeErr("VERIFY_FAILED", "File missing during verify", {
                            rel_path: f.rel_path,
                        });
                    }
                    const b = fs.readFileSync(abs);
                    const sha = crypto.createHash("sha256").update(b).digest("hex");
                    f.sha256 = "sha256:" + sha;
                }

                // optional checksums.json (recommended)
                const checksumsPath = path.join(manifestDir, "checksums.json");
                const checksums: any = {};
                for (const f of files_index) checksums[f.rel_path] = f.sha256;
                atomicWriteJsonSync({
                    filePath: checksumsPath,
                    data: { schema_version: "checksums-v1", files: checksums },
                    mode: 0o644,
                    fsyncMode: plan.verify.fsync,
                    warnings,
                });
            }

            // dirs_index build (P0-2)
            const dirs_index: BuildManifestV1["dirs_index"] = Array.from(dirs_set)
                .sort()
                .map((p) => ({ path: p, perm: "0755" }));

            // manifest
            const patchSummary =
                patchBundle != null
                    ? {
                        present: true,
                        patch_count: patchBundle.patches.length,
                        applied_count: patchBundle.patches.filter((p) => p.status === "APPLIED").length,
                        failed_count: patchBundle.patches.filter((p) => p.status === "FAILED").length,
                    }
                    : undefined;

            const totalBytes = files_index.reduce((s, x) => s + x.bytes, 0);

            const manifest: BuildManifestV1 = {
                schema_version: "build-manifest-v1",
                project: plan.project,
                build_id: plan.build_id,
                created_utc: plan.created_utc,
                committed_utc: undefined,
                plan_hash: planHash,
                output_root: committedRoot,
                files_root: path.join(committedRoot, "files"),
                dirs_index,
                files_index,
                deletes_index,
                patch_bundle: patchSummary,
                pointers: { latest_json_written: false },
                stats: {
                    total_bytes: totalBytes,
                    file_count: files_index.length,
                    dir_count: dirs_index.length,
                },
            };

            const manifestPathStaging = path.join(manifestDir, "build_manifest.json");
            atomicWriteJsonSync({
                filePath: manifestPathStaging,
                data: manifest,
                mode: 0o644,
                fsyncMode: plan.verify.fsync,
                warnings,
            });

            // Phase 6 pointer protocol
            if (plan.latest_pointer.enabled) {
                try {
                    atomicWriteJsonSync({
                        filePath: latestPath,
                        data: {
                            build_id: plan.build_id,
                            committed: false,
                            staging_dir: stagingRoot,
                            updated_utc: nowIso(opts),
                        },
                        mode: 0o644,
                        fsyncMode: plan.verify.fsync,
                        warnings,
                    });
                } catch (e: any) {
                    return makeErr(
                        "POINTER_UPDATE_FAILED",
                        "Failed to write latest.json pre-commit pointer",
                        { latest_path: latestPath, raw_error: e.message },
                        [
                            {
                                action: "CHECK_PERMISSIONS",
                                command: `ls -la ${latestPath}`,
                                risk: "low",
                            },
                        ]
                    );
                }
                manifest.pointers.latest_json_written = true;
            }

            // Commit rename
            try {
                fs.renameSync(stagingRoot, committedRoot);
            } catch (e: any) {
                return makeErr("COMMIT_RENAME_FAILED", "Failed to rename staging -> committed", {
                    staging_root: stagingRoot,
                    committed_root: committedRoot,
                    errno: e?.code,
                    raw_error: e.message,
                });
            }

            // post-commit pointer finalize
            let latestFinalized = false;
            if (plan.latest_pointer.enabled) {
                try {
                    atomicWriteJsonSync({
                        filePath: latestPath,
                        data: {
                            build_id: plan.build_id,
                            committed: true,
                            committed_dir: committedRoot,
                            updated_utc: nowIso(opts),
                        },
                        mode: 0o644,
                        fsyncMode: plan.verify.fsync,
                        warnings,
                    });
                    latestFinalized = true;
                } catch {
                    warnings.push("LATEST_POINTER_NOT_FINALIZED");
                }
            }

            // Update manifest committed_utc: best effort (write inside committed tree)
            try {
                manifest.committed_utc = nowIso(opts);
                manifest.pointers.latest_json_committed_flag = latestFinalized;
                const committedManifestPath = path.join(committedRoot, "manifest", "build_manifest.json");
                atomicWriteJsonSync({
                    filePath: committedManifestPath,
                    data: manifest,
                    mode: 0o644,
                    fsyncMode: plan.verify.fsync,
                    warnings,
                });
            } catch (e: any) {
                warnings.push(`MANIFEST_POSTCOMMIT_WARN(${e?.code || "UNKNOWN"})`);
            }

            // Phase 7: append builds.jsonl (best effort)
            try {
                fs.mkdirSync(indexRoot, { recursive: true, mode: 0o755 });
                const line = JSON.stringify({
                    build_id: plan.build_id,
                    committed_utc: manifest.committed_utc,
                    plan_hash: planHash,
                });
                fs.appendFileSync(buildsJsonlPath, line + "\n", "utf8");
            } catch (e: any) {
                warnings.push(`BUILDS_JSONL_WARN(${e?.code || "UNKNOWN"})`);
            }

            const committedManifestPath = path.join(committedRoot, "manifest", "build_manifest.json");

            const result: WriteResult = {
                ok: true,
                project: plan.project,
                build_id: plan.build_id,
                committed_path: committedRoot,
                manifest_path: committedManifestPath,
                warnings,
            };

            return result;
        } catch (e: any) {
            if (e?.code === "SYMLINK_REJECTED") {
                return makeErr("SYMLINK_REJECTED", "Symlink rejected", e.details || { path: "unknown" });
            }
            return makeErr("INTERNAL", "Unhandled writer exception", {
                raw_error: e?.message || String(e),
            });
        } finally {
            if (lockHandle) releaseBuildLock(lockHandle);
        }
    }
}

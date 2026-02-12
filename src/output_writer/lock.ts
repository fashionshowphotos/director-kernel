// src/output_writer/lock.ts

import * as fs from "fs";
import * as path from "path";

export interface LockHandle {
    fd: number;
    lockPath: string;
}

function sleep(ms: number) {
    return new Promise((r) => setTimeout(r, ms));
}

function backoff(attempt: number): number {
    // 50,100,200,400,800,... capped at 1000
    const v = 50 * Math.pow(2, attempt);
    return Math.min(v, 1000);
}

export async function acquireBuildLock(params: {
    lockPath: string;
    timeoutMs: number;
    warnings: string[];
    identityJson: any;
    staleTtlMs?: number;
}): Promise<LockHandle> {
    const { lockPath, timeoutMs, warnings, identityJson } = params;

    fs.mkdirSync(path.dirname(lockPath), { recursive: true, mode: 0o755 });

    const started = Date.now();
    let attempt = 0;
    const STALE_LOCK_MS = params.staleTtlMs ?? 600000; // 10 minutes default

    while (true) {
        try {
            // SECURITY FIX: Use 'wx' flag for exclusive creation (O_CREAT | O_EXCL)
            // This ensures atomic lock acquisition - only one process succeeds
            const fd = fs.openSync(lockPath, "wx");

            // write identity for debugging and stale detection
            const lockData = {
                ...identityJson,
                pid: process.pid,
                started_utc: new Date().toISOString(),
                started_ms: Date.now(),
            };
            fs.writeSync(fd, JSON.stringify(lockData, null, 2));

            return { fd, lockPath };
        } catch (e: any) {
            // EEXIST means lock file exists - check if stale
            if (e?.code === "EEXIST") {
                try {
                    // Read lock file to check staleness
                    const lockContent = fs.readFileSync(lockPath, "utf8");
                    const lockData = JSON.parse(lockContent);
                    const lockAge = Date.now() - (lockData.started_ms || 0);
                    const lockPid = lockData.pid;

                    // Check if lock is stale (PID dead OR age > threshold)
                    let isStale = false;

                    // Check 1: PID liveness
                    if (lockPid && typeof lockPid === "number") {
                        try {
                            // process.kill(pid, 0) throws if PID doesn't exist
                            process.kill(lockPid, 0);
                            // PID exists - not stale based on PID
                        } catch {
                            // PID doesn't exist - stale
                            isStale = true;
                            warnings.push(`STALE_LOCK(PID_DEAD) ${lockPath} pid=${lockPid}`);
                        }
                    }

                    // Check 2: Age-based staleness
                    if (!isStale && lockAge > STALE_LOCK_MS) {
                        isStale = true;
                        warnings.push(`STALE_LOCK(AGE) ${lockPath} age=${lockAge}ms`);
                    }

                    // Delete stale lock and retry
                    if (isStale) {
                        fs.unlinkSync(lockPath);
                        continue; // Retry immediately
                    }
                } catch (readErr: any) {
                    // Can't read lock file - might be corrupt or just deleted
                    // Try to delete and retry
                    try {
                        fs.unlinkSync(lockPath);
                        continue;
                    } catch {
                        // Someone else deleted it, retry
                    }
                }
            } else {
                // Unexpected error - propagate
                throw e;
            }

            const elapsed = Date.now() - started;
            if (elapsed >= timeoutMs) {
                const err: any = new Error("LOCK_HELD");
                err.code = "LOCK_HELD";
                throw err;
            }

            const wait = backoff(attempt++);
            warnings.push(`LOCK_RETRY after ${wait}ms on ${lockPath}`);
            await sleep(wait);
        }
    }
}

export function releaseBuildLock(handle: LockHandle): void {
    try {
        fs.closeSync(handle.fd);
    } catch { }
    // Delete lock file to release the lock (exclusive creation requires cleanup)
    try {
        fs.unlinkSync(handle.lockPath);
    } catch { }
}

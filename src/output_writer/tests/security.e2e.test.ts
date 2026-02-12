import { describe, test, beforeEach, afterEach } from "node:test";
import assert from "node:assert";
import fs from "fs";
import path from "path";
import os from "os";

import { OutputWriterImpl } from "../writer.js";
import type { BuildPlanV1, WriteOptions } from "../types.js";
import { acquireBuildLock, releaseBuildLock } from "../lock.js";

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

describe("output_writer v1.0.2 — Security & Resilience (E2E)", () => {
    let tmpRoot: string;

    const project = "security-test-project";
    const buildId = "test-build-123";

    beforeEach(() => {
        tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "output-writer-test-"));
    });

    afterEach(() => {
        try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch { }
    });

    function makeMinimalPlan(): BuildPlanV1 {
        return {
            schema_version: "build-plan-v1",
            project,
            build_id: buildId,
            created_utc: new Date().toISOString(),
            source: {},
            items: [
                { kind: "FILE_TEXT", rel_path: "files/hello.txt", content_utf8: "Hello world", perm: "0644" },
            ],
            bounds: {
                max_total_bytes: 1024 * 1024,
                max_file_bytes: 1024 * 1024,
                max_files: 100,
                max_path_len: 1024,
                envelope_retention_count: 5,
            },
            latest_pointer: { enabled: true, path: "output/<project>/_index/latest.json" },
            verify: { compute_checksums: false, fsync: "BEST_EFFORT" },
        };
    }

    // ======================================================================
    // TEST 1 — Exclusive Lock Atomicity (in-process test)
    // ======================================================================
    test("enforces exclusive lock - second acquire fails with LOCK_HELD", { timeout: 10_000 }, async () => {
        const lockPath = path.join(tmpRoot, "test.lock");

        // First lock succeeds
        const lock1 = await acquireBuildLock({
            lockPath,
            timeoutMs: 1000,
            warnings: [],
            identityJson: { name: "lock1" },
        });

        assert.ok(lock1, "First lock should succeed");
        assert.ok(fs.existsSync(lockPath), "Lock file should exist");

        // Second lock fails
        let lock2Failed = false;
        try {
            await acquireBuildLock({
                lockPath,
                timeoutMs: 500,
                warnings: [],
                identityJson: { name: "lock2" },
            });
        } catch (e: any) {
            lock2Failed = e.code === "LOCK_HELD";
        }

        assert.strictEqual(lock2Failed, true, "Second lock should fail with LOCK_HELD");

        // Release first lock
        releaseBuildLock(lock1);

        // Wait for cleanup
        await sleep(100);

        // Now third lock succeeds
        const lock3 = await acquireBuildLock({
            lockPath,
            timeoutMs: 1000,
            warnings: [],
            identityJson: { name: "lock3" },
        });

        assert.ok(lock3, "Third lock should succeed after release");
        releaseBuildLock(lock3);
    });

    // ======================================================================
    // TEST 2 — TTL Cleanup + Lock-Before-Delete
    // ======================================================================
    test("TTL cleanup skips staging dirs with held locks", { timeout: 15_000 }, async () => {
        const writer = new OutputWriterImpl();
        const plan = makeMinimalPlan();
        const opts: WriteOptions = {
            operator_mode: "AGENT",
            staging_ttl_ms: 1000,
            auto_cleanup_staging: true
        };

        const stagingParent = path.join(tmpRoot, "output", project, "_index", "staging");
        const locksRoot = path.join(tmpRoot, "output", project, "_index", "locks");

        const oldStaging = path.join(stagingParent, "old-build");
        const activeStaging = path.join(stagingParent, buildId);

        fs.mkdirSync(oldStaging, { recursive: true });
        fs.mkdirSync(activeStaging, { recursive: true });
        fs.mkdirSync(locksRoot, { recursive: true });

        // Make old one old
        const oldTime = Date.now() - 5000;
        fs.utimesSync(oldStaging, oldTime / 1000, oldTime / 1000);

        // Hold real lock on active build
        const activeLockPath = path.join(locksRoot, `${buildId}.lock`);
        const activeLock = await acquireBuildLock({
            lockPath: activeLockPath,
            timeoutMs: 1000,
            warnings: [],
            identityJson: { pid: process.pid, action: "test_hold" },
        });

        // Change to tmpRoot for writer
        const originalCwd = process.cwd();
        process.chdir(tmpRoot);

        try {
            // Run writer → triggers cleanup
            await writer.write(plan, opts);

            assert.strictEqual(fs.existsSync(oldStaging), false, "Old staging dir should be deleted");
            assert.strictEqual(fs.existsSync(activeStaging), true, "Active staging dir should be preserved (lock held)");

            // Release lock
            releaseBuildLock(activeLock);
            await sleep(200);

            // Make active staging old
            const activeOldTime = Date.now() - 5000;
            fs.utimesSync(activeStaging, activeOldTime / 1000, activeOldTime / 1000);

            // Run cleanup again with different build
            const plan2 = makeMinimalPlan();
            plan2.build_id = "another-build";
            await writer.write(plan2, opts);

            assert.strictEqual(fs.existsSync(activeStaging), false, "Active staging dir should be deleted after lock release");
        } finally {
            process.chdir(originalCwd);
        }
    });

    // ======================================================================
    // TEST 3 — Basic Write Success
    // ======================================================================
    test("successfully writes a basic build", { timeout: 10_000 }, async () => {
        const writer = new OutputWriterImpl();
        const plan = makeMinimalPlan();
        const opts: WriteOptions = { operator_mode: "AGENT" };

        const originalCwd = process.cwd();
        process.chdir(tmpRoot);

        try {
            const result = await writer.write(plan, opts);

            assert.strictEqual(result.ok, true, "Write should succeed");
            if (result.ok) {
                assert.strictEqual(result.project, project);
                assert.strictEqual(result.build_id, buildId);
                assert.ok(fs.existsSync(result.committed_path), "Committed path should exist");
                assert.ok(fs.existsSync(result.manifest_path), "Manifest should exist");
            }
        } finally {
            process.chdir(originalCwd);
        }
    });
});

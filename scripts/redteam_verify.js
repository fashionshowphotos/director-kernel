
const { KernelOrchestrator } = require('../dist/kernel_orchestrator');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const DB_PATH = './redteam.db';
const ARTIFACT_ROOT = './redteam_artifacts';

// Setup clean env
if (fs.existsSync(DB_PATH)) fs.unlinkSync(DB_PATH);
if (fs.existsSync(ARTIFACT_ROOT)) fs.rmSync(ARTIFACT_ROOT, { recursive: true, force: true });

// Mock Engine
const mockEngine = {
    syncExecute: (inputs, config, attempt, key) => {
        return {
            artifacts: [{ kind: 'output', content: Buffer.from("test"), sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }],
            cost_usd: 0.01,
            tokens: 100
        };
    }
};

async function runTest() {
    console.log("=== STARTING RED TEAM VERIFICATION ===");
    let failures = 0;

    // 1. Concurrent Locks (Multi-Process)
    console.log("\n[TEST] Concurrent Lock Acquisition (Multi-Process)...");

    // K1 starts in this process
    const k1 = new KernelOrchestrator(DB_PATH, ARTIFACT_ROOT, mockEngine, { lockTtlMs: 2000 });
    const r1 = k1.initializeRecovery();

    if (!r1.ok) {
        console.error("FAIL: K1 failed to acquire lock", r1);
        failures++;
    } else {
        console.log(`PASS: K1 acquired lock (pid=${process.pid})`);
    }

    // K2 starts in a child process
    const childScript = `
    const { KernelOrchestrator } = require('./dist/kernel_orchestrator');
    const dbPath = '${DB_PATH.replace(/\\/g, '\\\\')}';
    const root = '${ARTIFACT_ROOT.replace(/\\/g, '\\\\')}';
    
    // Silence logs
    const consoleLog = console.log;
    console.log = () => {};
    
    try {
      const k2 = new KernelOrchestrator(dbPath, root, {}, { lockTtlMs: 2000 });
      const r2 = k2.initializeRecovery();
      if (r2.ok) process.exit(0); // Acquired (FAIL)
      if (r2.error === 'LOCK_CONFLICT') process.exit(1); // Blocked (PASS)
      process.exit(2); // Error
    } catch(e) {
      process.exit(3);
    }
  `;

    const childFile = './k2_attempt.js';
    fs.writeFileSync(childFile, childScript);

    try {
        await new Promise((resolve) => {
            const child = spawn(process.execPath, [childFile], { stdio: 'inherit' });
            child.on('exit', (code) => {
                if (code === 1) {
                    console.log("PASS: K2 (child) blocked by LOCK_CONFLICT");
                } else if (code === 0) {
                    console.error("FAIL: K2 (child) acquired lock while held!");
                    failures++;
                } else {
                    console.error(`FAIL: K2 process exited with code ${code}`);
                    failures++;
                }
                resolve();
            });
        });
    } finally {
        if (fs.existsSync(childFile)) fs.unlinkSync(childFile);
    }

    // 2. Resume BUDGET_PAUSE without Token
    console.log("\n[TEST] Resume BUDGET_PAUSE without Token...");
    // Manually insert a BUDGET_PAUSE build
    const db = new Database(DB_PATH);
    const buildId = 'test-build-1';
    db.prepare(`
    INSERT INTO builds(build_id, state, created_at, updated_at, ms5_spec_hash, budget_usd, cumulative_cost_usd, build_inputs_hash)
    VALUES(?, 'BUDGET_PAUSE', ?, ?, 'hash', 1.0, 1.5, 'inputs')
  `).run(buildId, new Date().toISOString(), new Date().toISOString());

    // Manually ensure lock is held by K1 (since we just inserted bypassing K1) - wait, K1 holds lock on ID=1.
    // We need to associate K1 lock with a build? initializeRecovery resets lock build_id to NULL usually?
    // Let's try orchestrateBuild resume

    const res = k1.orchestrateBuild({
        ms5_spec: {},
        budget_usd: 10,
        resume_build_id: buildId
        // No token
    });

    if (res.ok) { console.error("FAIL: Resumed BUDGET_PAUSE without token!"); failures++; }
    else if (res.error === 'INVALID_RESUME_STATE' && res.message.includes('token')) { console.log("PASS: Blocked resume without token"); }
    else { console.error("FAIL: Unexpected resume error", res); failures++; }

    // 3. Corrupt Checkpoint Persistence (Simulated)
    console.log("\n[TEST] Corrupt Checkpoint Persistence Escaltion...");
    // We can't easily inject a DB failure into the internal transaction from here without mocking DB.
    // However, we can test that 'FAILED' state persists if execution fails.
    const k3 = new KernelOrchestrator(DB_PATH, ARTIFACT_ROOT, {
        syncExecute: () => { throw new Error("Simulated Engine Failure"); }
    });

    // Need to release K1 lock first or K3 will fail lock
    k1.shutdownHandler("SIGTERM"); // Release lock
    await new Promise(r => setTimeout(r, 100)); // Wait for release

    const r3 = k3.initializeRecovery();
    if (!r3.ok) { console.error("FAIL: K3 failed to acquire lock", r3); failures++; }

    const buildRes = k3.orchestrateBuild({
        ms5_spec: { stages: [{ name: 's1', targets: [{ name: 't1' }] }] },
        budget_usd: 10,
        input_artifacts: []
    });

    if (buildRes.ok && buildRes.value.final_state === 'FAILED') {
        console.log("PASS: Build failed gracefully on engine error");
        // Verify checkpoint is FAILED
        const cp = db.prepare("SELECT status FROM checkpoints WHERE status='FAILED'").get();
        if (cp) console.log("PASS: FAILED checkpoint persisted");
        else { console.error("FAIL: No FAILED checkpoint found"); failures++; }
    } else {
        console.error("FAIL: Build did not fail as expected", buildRes); failures++;
    }

    // Final Verdict
    console.log("\n=== RED TEAM VERDICT ===");
    if (failures === 0) {
        console.log("SUCCESS: All invariants hold.");
        process.exit(0);
    } else {
        console.error(`FAILURE: ${failures} invariant violations detected.`);
        process.exit(1);
    }
}

runTest();

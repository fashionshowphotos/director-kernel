/**
 * Worker Isolator — Hard process isolation for transform execution.
 *
 * Wraps TransformEngineInterface.execute() in a worker_thread with hard-kill timeout.
 * If the transform hangs (sync CPU-bound work, infinite loops), the worker is terminated.
 *
 * Follows the same eval'd worker pattern as the heartbeat worker in kernel_orchestrator.ts.
 */

import { Worker } from 'worker_threads';
import * as path from 'path';
import { createLogger } from './logger';
import { TIMEOUTS } from './config';

const log = createLogger('worker-isolator');

// The orchestrator's TransformResult type (re-declared to avoid circular imports)
type ArtifactKind = "output" | "log" | "metadata" | "error" | "ms5" | "ms4" | "ms3" | "ms2" | "ms2_5" | "intent" | "config" | "boot_pack";

interface TransformResult {
    success: boolean;
    artifacts: { kind: ArtifactKind; content: Buffer; sha256?: string; name?: string }[];
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
}

interface ArtifactRef {
    artifact_id: string;
    sha256: string;
    kind: ArtifactKind;
}

export interface IsolatedEngineConfig {
    artifactRoot: string;
    apiKey: string;
    modelId: string;
    timeoutMs?: number;
}

/**
 * Runs a transform engine call inside a worker thread with hard-kill semantics.
 * If the worker exceeds the timeout, it is terminated via worker.terminate().
 */
export async function executeInWorker(
    config: IsolatedEngineConfig,
    stage: string,
    target: string,
    inputs: ArtifactRef[],
    transformConfig: any,
    attempt_no: number,
    idempotency_key: string
): Promise<TransformResult> {
    const timeoutMs = config.timeoutMs ?? TIMEOUTS.WORKER_TIMEOUT_MS;
    const distDir = path.resolve(__dirname);

    // Serialize inputs for transfer
    const serializedInputs = inputs.map(i => ({
        artifact_id: i.artifact_id,
        sha256: i.sha256,
        kind: i.kind,
    }));

    return new Promise<TransformResult>((resolve, reject) => {
        const workerCode = `
            const { parentPort, workerData } = require("worker_threads");
            const path = require("path");

            async function run() {
                try {
                    // Require compiled modules from dist
                    const distDir = workerData.distDir;
                    const { TransformEngine } = require(path.join(distDir, "transform_engine"));
                    const { ModelRouter } = require(path.join(distDir, "model_router"));
                    const fs = require("fs");

                    // Create engine components
                    const modelRouter = new ModelRouter({ apiKey: workerData.apiKey });
                    const engine = new TransformEngine({
                        modelRouter,
                        ms5Invariants: "{}",
                    });

                    // Load artifact content from disk
                    const loadedInputs = workerData.inputs.map(ref => {
                        const p = path.join(workerData.artifactRoot, ref.sha256.slice(0, 2), ref.sha256);
                        if (!fs.existsSync(p)) throw new Error("Artifact missing on disk: " + ref.sha256);
                        return {
                            content: fs.readFileSync(p),
                            kind: ref.kind,
                            hash: ref.sha256
                        };
                    });

                    // Derive transform type from config or inputs
                    const config = workerData.transformConfig || {};
                    const explicit = config.transformType || config.transform_type;
                    let transformType = explicit;
                    if (!transformType) {
                        const kinds = loadedInputs.map(x => String(x.kind || "").toLowerCase());
                        if (kinds.some(k => k.includes("intent"))) transformType = "intent_to_ms5";
                        else if (kinds.some(k => k.includes("ms2_5") || k.includes("ms2.5"))) transformType = "ms2_5_to_ms3";
                        else if (kinds.some(k => k.includes("ms3"))) transformType = "ms3_to_ms2";
                        else if (kinds.some(k => k.includes("ms4"))) transformType = "ms4_to_ms3";
                        else if (kinds.some(k => k.includes("ms5"))) transformType = "ms5_to_ms4";
                        else transformType = "ms5_to_ms4";
                    }

                    // Build policy
                    const { buildPolicyForTier, parseDirectorTier } = require(path.join(distDir, "transform_engine"));
                    const configTier = config.tier || (config.global_config && config.global_config.tier);
                    const parsedTier = parseDirectorTier(configTier) || parseDirectorTier(process.env.DIRECTOR_TIER) || "experimental";
                    const policy = buildPolicyForTier(parsedTier);

                    const req = {
                        transformType,
                        targetId: workerData.target,
                        inputs: loadedInputs,
                        validationMode: "fast",
                        tokenBudget: 100000,
                        attemptNo: workerData.attempt_no,
                        modelId: workerData.modelId,
                        idempotencyKey: workerData.idempotency_key,
                        policy
                    };

                    const res = await engine.execute(req);

                    // Serialize result (Buffer → base64 for transfer)
                    const serialized = {
                        success: res.success,
                        artifacts: res.artifacts.map(a => ({
                            kind: a.kind,
                            content_base64: a.content.toString("base64"),
                        })),
                        logs: Array.isArray(res.logs) ? res.logs.join("\\n") : (res.logs || ""),
                        cost_usd: res.costUsd,
                        tokens: res.tokenUsage ? res.tokenUsage.totalTokens : 0,
                        error: res.error ? { code: res.error.code, message: res.error.message } : undefined,
                        provenance: res.provenance || undefined,
                    };

                    parentPort.postMessage({ type: "result", data: serialized });
                } catch (err) {
                    parentPort.postMessage({ type: "error", message: String(err && err.message ? err.message : err) });
                }
            }

            run();
        `;

        const worker = new Worker(workerCode, {
            eval: true,
            workerData: {
                distDir,
                artifactRoot: config.artifactRoot,
                apiKey: config.apiKey,
                modelId: config.modelId,
                inputs: serializedInputs,
                transformConfig,
                stage,
                target,
                attempt_no,
                idempotency_key,
            },
        });

        let settled = false;

        const timer = setTimeout(() => {
            if (!settled) {
                settled = true;
                log.error(`Worker timeout after ${timeoutMs}ms`, { stage, target });
                worker.terminate().then(() => {
                    reject(new Error(`EXECUTION_TIMEOUT: Worker killed after ${timeoutMs}ms for ${stage}/${target}`));
                });
            }
        }, timeoutMs);

        worker.on('message', (msg: any) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);

            if (msg.type === 'result') {
                // Deserialize: base64 → Buffer
                const data = msg.data;
                const result: TransformResult = {
                    success: data.success,
                    artifacts: data.artifacts.map((a: any) => ({
                        kind: a.kind,
                        content: Buffer.from(a.content_base64, 'base64'),
                    })),
                    logs: data.logs,
                    cost_usd: data.cost_usd,
                    tokens: data.tokens,
                    error: data.error,
                    provenance: data.provenance,
                };
                resolve(result);
            } else if (msg.type === 'error') {
                reject(new Error(msg.message));
            }
        });

        worker.on('error', (err: Error) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            reject(new Error(`WORKER_CRASHED: ${err.message}`));
        });

        worker.on('exit', (code: number) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (code !== 0) {
                reject(new Error(`WORKER_CRASHED: Worker exited with code ${code}`));
            }
        });
    });
}

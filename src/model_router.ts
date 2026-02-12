// model_router.ts - MC2-LITE Production Implementation
/* eslint-disable @typescript-eslint/no-explicit-any */

import crypto from "crypto";
import { createLogger } from "./logger";
import { ModelRegistry } from "./model_registry";
import { budgetAuthority, BudgetExceededError, RateLimitError } from "./budget_authority";

const log = createLogger('model-router');

// Note: This implementation expects EventBus and ConcurrencyLimiter to be provided
// For standalone usage, mock implementations can be used

// ============================================================================
// Types
// ============================================================================

export type ModelRole = "system" | "user" | "assistant";

export interface ModelMessage {
    role: ModelRole;
    content: string;
}

export interface ModelRequest {
    model_id: string;
    messages: ModelMessage[];
    max_tokens?: number;
    temperature?: number;
    top_p?: number;
    seed?: number;
    stop?: string[];
    timeout_ms?: number;
}

export interface CallContext {
    build_id?: string | null;
    transform_type?: string | null;
    target_id?: string | null;
}

export interface ModelResponse {
    ok: true;
    completion: string;
    finish_reason: string | null;
    tokenUsage: {
        promptTokens: number;
        completionTokens: number;
        totalTokens: number;
    };
    costUsd: number | null;
    provider: {
        requestId: string | null;
        modelId: string;
        latencyMs: number;
    };
    meta: {
        idempotencyKey: string;
        estimatedCostUsd: number;
        attemptNo: number;
        promptHash: string;
        responseHash: string;
    };
}

export type ModelRouterErrorCode =
    | "INVALID_CONFIG"
    | "BUDGET_PAUSE"
    | "CIRCUIT_OPEN"
    | "TRANSFORM_RATE_LIMIT"
    | "NETWORK_ERROR"
    | "MODEL_ERROR"
    | "INFRA_ERROR";

export interface ModelRouterError {
    ok: false;
    errorCode: ModelRouterErrorCode;
    message: string;
    retryable: boolean;
    attemptsUsed: number;
    httpStatus: number | null;
    providerBodySnippet: string | null;
    meta?: {
        idempotencyKey?: string;
        modelId?: string;
        buildId?: string | null;
        transformType?: string | null;
        targetId?: string | null;
    };
}

export interface ModelRouterConfig {
    apiKey: string;
    debug?: boolean;
}

// ============================================================================
// Frozen constants (MC2-LITE)
// ============================================================================

const FROZEN = {
    // OpenRouter API endpoint
    ENDPOINT: "https://openrouter.ai/api/v1/chat/completions",

    // Use standard OpenAI-compatible API (not Web AI)
    USE_WEB_AI: false,

    MODEL_CALL_TIMEOUT_MS: 300_000, // Increase for browser automation (5 min)
    MAX_RETRY_ATTEMPTS: 3,
    RETRY_BACKOFF_MS: [2000, 5000, 10000] as const,

    MAX_PROMPT_CHARS: 1_000_000, // Large context for Web AI
    MAX_RESPONSE_CHARS: 1_000_000,
    MAX_COMPLETION_TOKENS: 32000,
    MAX_COST_PER_REQUEST_USD: 50.0, // Higher limits for local/web AI
    MAX_COST_PER_BUILD_ID_USD: 500.0,

    MODEL_ALLOWLIST: [
        "anthropic/claude-3.5-haiku",
        "anthropic/claude-3-haiku",
        "openai/gpt-4o-mini",
        "meta-llama/llama-3.1-70b-instruct",
        "deepseek/deepseek-chat",
        "deepseek", // Add generic shortcuts
        "kimi",
        "gemini",
        "claude",
        "chatgpt",
        "anthropic/claude-3.5-sonnet",
        "openai/gpt-4o"
    ] as const,

    MODEL_PRICING_USD_PER_MILLION: {
        "anthropic/claude-3.5-haiku": { prompt: 0.25, completion: 1.25 },
        "anthropic/claude-3-haiku": { prompt: 0.25, completion: 1.25 },
        "openai/gpt-4o-mini": { prompt: 0.15, completion: 0.6 },
        "deepseek/deepseek-chat": { prompt: 0.14, completion: 0.28 },
        "meta-llama/llama-3.1-70b-instruct": { prompt: 0.59, completion: 0.59 },
        "anthropic/claude-3.5-sonnet": { prompt: 3.00, completion: 15.00 },
        "openai/gpt-4o": { prompt: 5.00, completion: 15.00 },
    } as Record<string, { prompt: number; completion: number }>,

    FALLBACK_PRICING_USD_PER_MILLION: { prompt: 0.0, completion: 0.0 }, // Free for Web AI

    CIRCUIT_BREAKER: {
        MAX_FAILURES: 10,
        WINDOW_MS: 60_000,
        COOLDOWN_MS: 10_000,
    },

    SANITIZE: {
        ERROR_SNIPPET_MAX_CHARS: 500,
        STRIP_PATTERNS: [
            // Standard sensitive patterns
            /\b\d{1,3}(?:\.\d{1,3}){3}\b/g,
            /[a-fA-F0-9]{32,}/g,
            /sk-[A-Za-z0-9]{10,}/g,
            /Authorization:\s*Bearer\s+[A-Za-z0-9._-]+/gi,
        ],
    },

    MAX_CONCURRENT_CALLS: 1, // Serial execution is safer for browser automation
} as const;

type AllowedModel = (typeof FROZEN.MODEL_ALLOWLIST)[number];

// ============================================================================
// Circuit Breaker
// ============================================================================

class CircuitBreaker {
    private failures: number[] = [];
    private openUntilMs = 0;

    isOpen(nowMs: number): boolean {
        return nowMs < this.openUntilMs;
    }

    recordFailure(nowMs: number): void {
        this.failures.push(nowMs);
        const cutoff = nowMs - FROZEN.CIRCUIT_BREAKER.WINDOW_MS;
        this.failures = this.failures.filter((t) => t >= cutoff);

        if (this.failures.length >= FROZEN.CIRCUIT_BREAKER.MAX_FAILURES) {
            this.openUntilMs = nowMs + FROZEN.CIRCUIT_BREAKER.COOLDOWN_MS;
        }
    }

    recordSuccess(): void {
        this.failures = [];
    }
}

// ============================================================================
// Concurrency Limiter (simple semaphore)
// ============================================================================

class ConcurrencyLimiter {
    private activeCount = 0;
    private queue: Array<() => void> = [];

    constructor(private maxSlots: number) { }

    async acquireSlot(): Promise<void> {
        if (this.activeCount < this.maxSlots) {
            this.activeCount++;
            return;
        }

        return new Promise<void>((resolve) => {
            this.queue.push(resolve);
        });
    }

    releaseSlot(): void {
        const next = this.queue.shift();
        if (next) {
            next();
        } else {
            this.activeCount--;
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

function formatDuration(ms: number): string {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${(ms / 60000).toFixed(1)}m`;
}

function clampInt(n: any): number {
    const x = Number(n);
    if (!Number.isFinite(x)) return 0;
    return Math.max(0, Math.floor(x));
}

function sha256Hex(s: string): string {
    return crypto.createHash("sha256").update(s).digest("hex");
}

function sanitizeErrorSnippet(input: string): string {
    let out = input || "";
    for (const re of FROZEN.SANITIZE.STRIP_PATTERNS) {
        out = out.replace(re, "[REDACTED]");
    }
    if (out.length > FROZEN.SANITIZE.ERROR_SNIPPET_MAX_CHARS) {
        out = out.slice(0, FROZEN.SANITIZE.ERROR_SNIPPET_MAX_CHARS);
    }
    out = out.replace(/[^\x20-\x7E]+/g, " ");
    return out;
}

function estimateTokensFromMessages(messages: ModelMessage[]): number {
    const text = JSON.stringify(messages);
    const chars = text.length;
    const words = text.split(/\s+/).length;
    // Conservative: ~3.3 chars/token for code/JSON, with word-count floor
    return Math.max(Math.ceil(chars / 3.3), Math.ceil(words * 1.3));
}

function safeTemperature(x: any): number {
    if (x === undefined || x === null) return 0.7;
    const n = Number(x);
    if (!Number.isFinite(n)) return 0.7;
    return Math.max(0, Math.min(2.0, n));
}

function validateMessages(messages: any): { ok: true } | { ok: false; err: string } {
    if (!Array.isArray(messages) || messages.length === 0) {
        return { ok: false, err: "messages must be a non-empty array" };
    }
    for (const m of messages) {
        if (!m || typeof m !== "object") return { ok: false, err: "message must be object" };
        if (m.role !== "system" && m.role !== "user" && m.role !== "assistant") {
            return { ok: false, err: "message.role must be system|user|assistant" };
        }
        if (typeof m.content !== "string" || m.content.trim().length === 0) {
            return { ok: false, err: "message.content must be non-empty string" };
        }
    }
    return { ok: true };
}

function getPricingForModel(model_id: string): { prompt: number; completion: number } {
    return (
        FROZEN.MODEL_PRICING_USD_PER_MILLION[model_id] ?? FROZEN.FALLBACK_PRICING_USD_PER_MILLION
    );
}

function estimateCostUsd(model_id: string, prompt_tokens_est: number, max_tokens: number): number {
    const pricing = getPricingForModel(model_id);
    const promptCost = (prompt_tokens_est / 1_000_000) * pricing.prompt;
    const completionCost = (max_tokens / 1_000_000) * pricing.completion;
    return promptCost + completionCost;
}

function computeCanonicalPayload(req: ModelRequest): any {
    // FIX: Use || instead of ?? for max_tokens to handle 0 case
    const payload: any = {
        model: req.model_id,
        messages: req.messages,
        temperature: safeTemperature(req.temperature),
        max_tokens: req.max_tokens || FROZEN.MAX_COMPLETION_TOKENS,
        stream: false,
    };

    // Only add response_format: json_object for models that support it
    // For others, JSON output is enforced via prompt instructions
    const registry = ModelRegistry.getInstance();
    const modelInfo = registry.getModelInfo(req.model_id);
    if (modelInfo?.supportsJsonMode !== false) {
        payload.response_format = { type: 'json_object' };
    }

    if (req.top_p !== undefined) payload.top_p = Number(req.top_p);
    if (req.seed !== undefined) payload.seed = req.seed;
    if (req.stop !== undefined) payload.stop = req.stop;

    return payload;
}

function canonicalizeLite(payload: any): string {
    const stable = (obj: any): any => {
        if (obj === null || obj === undefined) return obj;
        if (Array.isArray(obj)) return obj.map(stable);
        if (typeof obj === "object") {
            const keys = Object.keys(obj).sort();
            const out: any = {};
            for (const k of keys) out[k] = stable(obj[k]);
            return out;
        }
        return obj;
    };
    return JSON.stringify(stable(payload));
}

// ============================================================================
// ModelRouter
// ============================================================================

export class ModelRouter {
    private breaker = new CircuitBreaker();
    private buildBudgets = new Map<string, number>();
    private limiter: ConcurrencyLimiter;
    private apiKey: string;
    private debug: boolean;

    constructor(config: ModelRouterConfig) {
        const key = config.apiKey || process.env.OPENROUTER_API_KEY || '';
        if (!key) {
            log.warn("No API key configured. Set OPENROUTER_API_KEY environment variable.");
        }
        this.apiKey = key;
        this.debug = config.debug ?? false;
        this.limiter = new ConcurrencyLimiter(FROZEN.MAX_CONCURRENT_CALLS);
    }

    async executeModelCall(
        req: ModelRequest,
        ctx?: CallContext
    ): Promise<ModelResponse | ModelRouterError> {
        // Validate model allowlist
        // Optional escape hatch for local experimentation (kept off by default).
        const bypass = String(process.env.DIRECTOR_MODEL_ALLOWLIST_BYPASS || "").trim() === "1";
        if (!bypass && !FROZEN.MODEL_ALLOWLIST.includes(req.model_id as AllowedModel)) {
            return this.err(
                "INVALID_CONFIG",
                `Model not allowed: ${req.model_id}`,
                false,
                1,
                null,
                null,
                req.model_id,
                ctx
            );
        }

        // Validate messages
        const vm = validateMessages(req.messages);
        if (!vm.ok) {
            return this.err("INVALID_CONFIG", vm.err, false, 1, null, null, req.model_id, ctx);
        }

        const canonicalPayload = computeCanonicalPayload(req);
        const canonicalStr = canonicalizeLite(canonicalPayload);

        const promptChars = canonicalStr.length;
        if (promptChars > FROZEN.MAX_PROMPT_CHARS) {
            return this.err(
                "INVALID_CONFIG",
                `Prompt too large: ${promptChars} chars > ${FROZEN.MAX_PROMPT_CHARS}`,
                false,
                1,
                null,
                null,
                req.model_id,
                ctx
            );
        }

        const idempotencyKey = sha256Hex(canonicalStr);

        // Cost preflight
        const max_tokens = canonicalPayload.max_tokens;
        const prompt_tokens_est = estimateTokensFromMessages(req.messages);
        const estimatedCost = estimateCostUsd(req.model_id, prompt_tokens_est, max_tokens);

        if (estimatedCost > FROZEN.MAX_COST_PER_REQUEST_USD) {
            return this.err(
                "BUDGET_PAUSE",
                `Request estimated cost $${estimatedCost.toFixed(3)} exceeds $${FROZEN.MAX_COST_PER_REQUEST_USD.toFixed(2)} cap`,
                false,
                1,
                null,
                null,
                req.model_id,
                ctx,
                idempotencyKey
            );
        }

        // Per-build budget check
        if (ctx?.build_id) {
            const buildId = String(ctx.build_id);
            const spent = this.buildBudgets.get(buildId) ?? 0;

            if (spent + estimatedCost > FROZEN.MAX_COST_PER_BUILD_ID_USD) {
                return this.err(
                    "BUDGET_PAUSE",
                    `Build ${buildId} estimated spend would exceed $${FROZEN.MAX_COST_PER_BUILD_ID_USD.toFixed(2)} cap`,
                    false,
                    1,
                    null,
                    null,
                    req.model_id,
                    ctx,
                    idempotencyKey
                );
            }
        }

        // BudgetAuthority pre-flight: authorize spend before any API call
        if (ctx?.build_id) {
            try {
                budgetAuthority.authorize(String(ctx.build_id), estimatedCost, prompt_tokens_est + max_tokens);
            } catch (e: any) {
                if (e instanceof BudgetExceededError) {
                    return this.err("BUDGET_PAUSE", e.message, false, 1, null, null, req.model_id, ctx, idempotencyKey);
                }
                if (e instanceof RateLimitError) {
                    return this.err("TRANSFORM_RATE_LIMIT", e.message, true, 1, null, null, req.model_id, ctx, idempotencyKey);
                }
                // Build not registered — log warning but allow in non-strict mode
                // In strict mode, BudgetAuthority.authorize() throws BudgetExceededError (caught above)
                if (String(e?.message || '').includes('not registered')) {
                    log.warn(`Budget enforcement skipped: build not registered`, { build_id: ctx.build_id, model: req.model_id });
                } else {
                    throw e;
                }
            }
        }

        // Circuit breaker check
        const now = Date.now();
        if (this.breaker.isOpen(now)) {
            return this.err(
                "CIRCUIT_OPEN",
                "Circuit breaker open (too many recent failures)",
                false,
                1,
                null,
                null,
                req.model_id,
                ctx,
                idempotencyKey
            );
        }

        // Acquire concurrency slot
        await this.limiter.acquireSlot();

        try {
            for (let attempt = 1; attempt <= FROZEN.MAX_RETRY_ATTEMPTS; attempt++) {
                if (attempt > 1) {
                    const backoff = FROZEN.RETRY_BACKOFF_MS[attempt - 2] ?? 4000;
                    await new Promise((r) => setTimeout(r, backoff));
                }

                if (this.debug) {
                    log.debug(`API call`, { attempt, max_attempts: FROZEN.MAX_RETRY_ATTEMPTS, model: req.model_id, build_id: ctx?.build_id, transform: ctx?.transform_type, est_cost: estimatedCost, prompt_chars: promptChars });
                }

                const res = await this.tryOnce(canonicalPayload, req, attempt, ctx, idempotencyKey, estimatedCost);

                if (res.ok) {
                    this.breaker.recordSuccess();

                    if (ctx?.build_id && res.costUsd !== null) {
                        const buildId = String(ctx.build_id);
                        const spent = this.buildBudgets.get(buildId) ?? 0;
                        this.buildBudgets.set(buildId, spent + res.costUsd);

                        // Record actual spend in BudgetAuthority (centralized ledger)
                        try {
                            budgetAuthority.record(buildId, {
                                stage: ctx.transform_type || 'unknown',
                                target: ctx.target_id || 'unknown',
                                model_id: req.model_id,
                                estimated_cost_usd: estimatedCost,
                                actual_cost_usd: res.costUsd,
                                tokens_in: res.tokenUsage.promptTokens,
                                tokens_out: res.tokenUsage.completionTokens,
                            });
                        } catch (recordErr: any) {
                            log.warn(`Budget record failed`, { build_id: buildId, error: String(recordErr?.message || recordErr) });
                        }
                    }

                    if (this.debug) {
                        log.debug(`API success`, { latency_ms: res.provider.latencyMs, cost: res.costUsd, tokens: res.tokenUsage.totalTokens, finish: res.finish_reason });
                    }

                    return res;
                }

                if (res.retryable && attempt < FROZEN.MAX_RETRY_ATTEMPTS) {
                    continue;
                }

                if (
                    res.errorCode === "NETWORK_ERROR" ||
                    res.errorCode === "TRANSFORM_RATE_LIMIT" ||
                    res.errorCode === "INFRA_ERROR"
                ) {
                    this.breaker.recordFailure(Date.now());
                }

                return res;
            }

            return this.err(
                "INFRA_ERROR",
                "Unreachable retry loop end",
                true,
                FROZEN.MAX_RETRY_ATTEMPTS,
                null,
                null,
                req.model_id,
                ctx,
                idempotencyKey
            );
        } finally {
            this.limiter.releaseSlot();
        }
    }

    private async tryOnce(
        canonicalPayload: any,
        req: ModelRequest,
        attempt: number,
        ctx: CallContext | undefined,
        idempotencyKey: string,
        estimatedCost: number
    ): Promise<ModelResponse | ModelRouterError> {
        const timeoutMs = Math.min(
            req.timeout_ms ?? FROZEN.MODEL_CALL_TIMEOUT_MS,
            FROZEN.MODEL_CALL_TIMEOUT_MS
        );

        const ac = new AbortController();
        const tid = setTimeout(() => ac.abort(), timeoutMs);

        const started = Date.now();

        try {
            // === OPENROUTER API LOGIC ===
            const resp = await fetch(FROZEN.ENDPOINT, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${this.apiKey}`,
                    "HTTP-Referer": "https://director-kernel.local",
                    "X-Title": "Director Kernel"
                },
                body: JSON.stringify(canonicalPayload),
                signal: ac.signal,
            });

            const latencyMs = Date.now() - started;
            const bodyText = await resp.text();

            if (!resp.ok) {
                const snippet = sanitizeErrorSnippet(bodyText);
                const httpStatus = resp.status;
                const retryable = httpStatus >= 500 || httpStatus === 429;

                return this.err(
                    httpStatus === 429 ? "TRANSFORM_RATE_LIMIT" : "INFRA_ERROR",
                    `OpenRouter Error ${httpStatus}`,
                    retryable,
                    attempt,
                    httpStatus,
                    snippet,
                    req.model_id,
                    ctx,
                    idempotencyKey
                );
            }

            let data: any;
            try {
                data = JSON.parse(bodyText);
            } catch {
                const snippet = sanitizeErrorSnippet(bodyText);
                return this.err(
                    "MODEL_ERROR",
                    "provider_response_not_json",
                    false,
                    attempt,
                    200,
                    snippet,
                    req.model_id,
                    ctx,
                    idempotencyKey
                );
            }

            // Extract completion from OpenAI-compatible response
            const choice = data.choices?.[0];
            const completion = choice?.message?.content || "";
            const finish_reason = choice?.finish_reason || "stop";

            // Extract token usage
            const usage = data.usage || {};
            const tokenUsage = {
                promptTokens: clampInt(usage.prompt_tokens),
                completionTokens: clampInt(usage.completion_tokens),
                totalTokens: clampInt(usage.total_tokens || (usage.prompt_tokens + usage.completion_tokens))
            };

            // Compute cost
            const pricing = getPricingForModel(req.model_id);
            const costUsd = (tokenUsage.promptTokens / 1_000_000) * pricing.prompt +
                (tokenUsage.completionTokens / 1_000_000) * pricing.completion;

            // Provenance hashes
            const promptHash = sha256Hex(JSON.stringify(canonicalPayload.messages));
            const responseHash = sha256Hex(completion);

            return {
                ok: true,
                completion,
                finish_reason,
                tokenUsage,
                costUsd,
                provider: {
                    requestId: data.id || `openrouter-${Date.now()}`,
                    modelId: data.model || req.model_id,
                    latencyMs: latencyMs,
                },
                meta: {
                    idempotencyKey,
                    estimatedCostUsd: estimatedCost,
                    attemptNo: attempt,
                    promptHash,
                    responseHash,
                },
            };
        } catch (e: any) {
            const isTimeout = e?.name === "AbortError";
            const msg = isTimeout
                ? `timeout after ${timeoutMs}ms`
                : `network_error: ${String(e?.message || e)}`;
            return this.err("NETWORK_ERROR", msg, true, attempt, null, null, req.model_id, ctx, idempotencyKey);
        } finally {
            clearTimeout(tid);
        }
    }

    private err(
        errorCode: ModelRouterErrorCode,
        message: string,
        retryable: boolean,
        attemptsUsed: number,
        httpStatus: number | null,
        providerBodySnippet: string | null,
        modelId: string,
        ctx?: CallContext,
        idempotencyKey?: string
    ): ModelRouterError {
        const safeMsg = sanitizeErrorSnippet(String(message ?? "error"));

        return {
            ok: false,
            errorCode,
            message: safeMsg,
            retryable,
            attemptsUsed,
            httpStatus,
            providerBodySnippet: providerBodySnippet ? sanitizeErrorSnippet(providerBodySnippet) : null,
            meta: {
                idempotencyKey,
                modelId,
                buildId: ctx?.build_id ?? null,
                transformType: ctx?.transform_type ?? null,
                targetId: ctx?.target_id ?? null,
            },
        };
    }
}

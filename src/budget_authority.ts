/**
 * BudgetAuthority — Centralized financial control for all model calls.
 *
 * INVARIANT: No model call reaches OpenRouter without passing through BudgetAuthority.
 * This is the single choke point for spend control, rate limiting, and cost auditing.
 *
 * Features:
 * - Hard budget ceiling per build (fail-closed)
 * - Pre-flight cost estimation before each call
 * - Actual cost recording after each call
 * - Rate limiting (calls/min, tokens/min per build)
 * - Spend ledger with full audit trail
 * - Reconciliation: estimated vs actual
 */

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
    /** Hard ceiling for this build in USD */
    budget_usd: number;
    /** Max calls per minute per build (0 = unlimited) */
    max_calls_per_min?: number;
    /** Max tokens per minute per build (0 = unlimited) */
    max_tokens_per_min?: number;
    /** Warn at this fraction of budget (default 0.8) */
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
    private spent = new Map<string, number>();          // build_id -> cumulative USD
    private ledger = new Map<string, SpendRecord[]>();  // build_id -> records
    private callTimestamps = new Map<string, number[]>(); // build_id -> recent call times
    private tokenTimestamps = new Map<string, Array<{ ts: number; tokens: number }>>(); // build_id -> recent token counts
    private configs = new Map<string, BudgetConfig>();  // build_id -> config
    private strictMode = false;

    /** Enable strict mode: unregistered builds cause hard failure instead of silent skip. */
    setStrictMode(enabled: boolean): void {
        this.strictMode = enabled;
        log.info(`Strict mode ${enabled ? 'enabled' : 'disabled'}`);
    }

    /** Check if a build is registered. */
    isRegistered(build_id: string): boolean {
        return this.configs.has(build_id);
    }

    /** Register a build's budget before any calls. */
    registerBuild(build_id: string, config: BudgetConfig): void {
        this.configs.set(build_id, config);
        if (!this.spent.has(build_id)) this.spent.set(build_id, 0);
        if (!this.ledger.has(build_id)) this.ledger.set(build_id, []);
        if (!this.callTimestamps.has(build_id)) this.callTimestamps.set(build_id, []);
        if (!this.tokenTimestamps.has(build_id)) this.tokenTimestamps.set(build_id, []);
        log.info(`Budget registered`, { build_id, budget_usd: config.budget_usd });
    }

    /**
     * Pre-flight check: can we afford this call?
     * Throws BudgetExceededError if estimated cost would exceed ceiling.
     * Throws RateLimitError if rate limits exceeded.
     */
    authorize(build_id: string, estimated_cost_usd: number, estimated_tokens: number): void {
        const config = this.configs.get(build_id);
        if (!config) {
            if (this.strictMode) {
                log.error(`Strict mode: unregistered build blocked`, { build_id });
                throw new BudgetExceededError(build_id, 0, 0, estimated_cost_usd);
            }
            throw new Error(`BudgetAuthority: build ${build_id} not registered`);
        }

        const currentSpend = this.spent.get(build_id) || 0;
        const projected = currentSpend + estimated_cost_usd;

        // Hard ceiling check (fail-closed: block if would exceed 110% of budget)
        if (projected > config.budget_usd * 1.10) {
            log.error(`Budget exceeded`, { build_id, budget: config.budget_usd, spent: currentSpend, estimated: estimated_cost_usd });
            throw new BudgetExceededError(build_id, config.budget_usd, currentSpend, estimated_cost_usd);
        }

        // Warning threshold
        const warnAt = config.warn_threshold ?? 0.8;
        if (projected > config.budget_usd * warnAt) {
            log.warn(`Budget warning`, { build_id, budget: config.budget_usd, spent: currentSpend, projected, threshold: warnAt });
        }

        // Rate limit: calls per minute
        if (config.max_calls_per_min && config.max_calls_per_min > 0) {
            const now = Date.now();
            const window = 60_000;
            const recent = (this.callTimestamps.get(build_id) || []).filter(t => now - t < window);
            if (recent.length >= config.max_calls_per_min) {
                log.warn(`Call rate limit hit`, { build_id, limit: config.max_calls_per_min });
                throw new RateLimitError(build_id, `${config.max_calls_per_min} calls/min`);
            }
        }

        // Rate limit: tokens per minute
        if (config.max_tokens_per_min && config.max_tokens_per_min > 0) {
            const now = Date.now();
            const window = 60_000;
            const recentTokens = (this.tokenTimestamps.get(build_id) || [])
                .filter(r => now - r.ts < window)
                .reduce((sum, r) => sum + r.tokens, 0);
            if (recentTokens + estimated_tokens > config.max_tokens_per_min) {
                log.warn(`Token rate limit hit`, { build_id, limit: config.max_tokens_per_min, recent: recentTokens });
                throw new RateLimitError(build_id, `${config.max_tokens_per_min} tokens/min`);
            }
        }
    }

    /**
     * Record actual cost after a successful model call.
     */
    record(build_id: string, record: Omit<SpendRecord, 'build_id' | 'timestamp'>): void {
        const ts = new Date().toISOString();
        const full: SpendRecord = { build_id, timestamp: ts, ...record };

        // Update cumulative spend
        const prev = this.spent.get(build_id) || 0;
        this.spent.set(build_id, prev + record.actual_cost_usd);

        // Append to ledger
        const ledger = this.ledger.get(build_id) || [];
        ledger.push(full);
        this.ledger.set(build_id, ledger);

        // Track rate limiting timestamps
        const now = Date.now();
        const calls = this.callTimestamps.get(build_id) || [];
        calls.push(now);
        // Prune old entries (keep last 2 minutes)
        const cutoff = now - 120_000;
        this.callTimestamps.set(build_id, calls.filter(t => t > cutoff));

        const tokens = this.tokenTimestamps.get(build_id) || [];
        tokens.push({ ts: now, tokens: record.tokens_in + record.tokens_out });
        this.tokenTimestamps.set(build_id, tokens.filter(r => r.ts > cutoff));

        // Reconciliation logging
        const drift = record.actual_cost_usd - record.estimated_cost_usd;
        if (Math.abs(drift) > 0.001) {
            log.debug(`Cost drift`, { build_id, model: record.model_id, estimated: record.estimated_cost_usd, actual: record.actual_cost_usd, drift });
        }

        log.debug(`Spend recorded`, { build_id, model: record.model_id, cost: record.actual_cost_usd, cumulative: prev + record.actual_cost_usd });
    }

    /** Get cumulative spend for a build. */
    getSpend(build_id: string): number {
        return this.spent.get(build_id) || 0;
    }

    /** Get full spend ledger for a build (for audit/provenance). */
    getLedger(build_id: string): SpendRecord[] {
        return [...(this.ledger.get(build_id) || [])];
    }

    /** Get remaining budget for a build. */
    getRemaining(build_id: string): number {
        const config = this.configs.get(build_id);
        if (!config) return 0;
        return Math.max(0, config.budget_usd - (this.spent.get(build_id) || 0));
    }

    /** Cleanup after build finishes. */
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

/** Singleton instance — all model calls go through this. */
export const budgetAuthority = new BudgetAuthority();

/**
 * Shared Configuration Constants
 * 
 * Centralized configuration for the Director compiler.
 * Values can be overridden via environment variables.
 */

// Default model for all transforms
export const DEFAULT_MODEL_ID = process.env.DIRECTOR_MODEL || 'deepseek/deepseek-chat';

// Model pricing (USD per million tokens)
export const MODEL_PRICING: Record<string, { prompt: number; completion: number }> = {
    'anthropic/claude-3.5-haiku': { prompt: 0.25, completion: 1.25 },
    'anthropic/claude-3-haiku': { prompt: 0.25, completion: 1.25 },
    'anthropic/claude-3.5-sonnet': { prompt: 3.00, completion: 15.00 },
    'openai/gpt-4o-mini': { prompt: 0.15, completion: 0.6 },
    'openai/gpt-4o': { prompt: 5.00, completion: 15.00 },
    'deepseek/deepseek-chat': { prompt: 0.14, completion: 0.28 },
    'meta-llama/llama-3.1-70b-instruct': { prompt: 0.59, completion: 0.59 },
};

// Fallback pricing when model not in registry
export const FALLBACK_PRICING = {
    prompt: parseFloat(process.env.DIRECTOR_COST_PROMPT_PER_M || '3.0'),
    completion: parseFloat(process.env.DIRECTOR_COST_COMPLETION_PER_M || '15.0'),
};

// Linkage contract validation
export const LINKAGE_CONTRACT_MAX_CHARS = 5000;

// Quality thresholds
export const QUALITY_THRESHOLDS = {
    MIN_MS2_OUTPUT_BYTES: 500,
    MAX_DIAGNOSTICS_CHARS: 6000,
    MAX_DIAGNOSTICS_COUNT: 50,
    MAX_RESPONSIBILITY_CHARS: 120,
    MAX_RETRY_ATTEMPTS: 3,
};

// Max output tokens per model call
export const MAX_OUTPUT_TOKENS = {
    CODE_GEN: parseInt(process.env.DIRECTOR_MAX_TOKENS_CODE || '16384', 10),   // ms3→ms2 code generation
    SEMANTIC: parseInt(process.env.DIRECTOR_MAX_TOKENS_SEMANTIC || '8192', 10), // ms2→ms2.5, ms2.5→ms3
    MC2_LOOP: parseInt(process.env.DIRECTOR_MAX_TOKENS_MC2 || '8192', 10),     // MC2 governance iterations
};

// Timeouts (milliseconds)
export const TIMEOUTS = {
    TRANSFORM_MS: 300000,      // 5 minutes
    MODEL_CALL_MS: 120000,     // 2 minutes
    PATCH_LOOP_MS: 180000,     // 3 minutes for entire patch loop
    WORKER_TIMEOUT_MS: parseInt(process.env.DIRECTOR_WORKER_TIMEOUT || '300000', 10), // Worker hard-kill timeout
};

// Provenance chain
export const PROVENANCE_ENABLED = process.env.DIRECTOR_PROVENANCE !== '0';

// Truncation thresholds (ratios)
export const TRUNCATION = {
    WARN_THRESHOLD: 0.20,
    FAIL_THRESHOLD: 0.50,
};

// Max artifact sizes
export const MAX_SIZES = {
    DOWNSTREAM_BYTES: 25 * 1024 * 1024,  // 25MB
};

/**
 * Get pricing for a model, falling back to defaults if not found
 */
export function getModelPricing(modelId: string): { prompt: number; completion: number } {
    return MODEL_PRICING[modelId] || FALLBACK_PRICING;
}

/**
 * Estimate cost for a model call
 */
export function estimateModelCost(
    modelId: string,
    promptTokens: number,
    completionTokens: number
): number {
    const pricing = getModelPricing(modelId);
    return (
        (promptTokens / 1_000_000) * pricing.prompt +
        (completionTokens / 1_000_000) * pricing.completion
    );
}

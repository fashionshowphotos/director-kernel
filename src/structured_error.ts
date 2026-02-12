/**
 * Structured Error Schema for AI-First Recovery
 * 
 * Provides machine-readable errors with recovery options that can be
 * automatically evaluated and executed by the recovery orchestrator.
 */

/* -------------------------------------------------------------------------- */
/* Types                                                                      */
/* -------------------------------------------------------------------------- */

export type ErrorCode =
    // User errors (MS5/MS4 issues)
    | 'USER_ERROR'
    | 'INVALID_INTENT'
    | 'CONTRADICTORY_SPEC'

    // Model errors (LLM output issues)
    | 'MODEL_ERROR'
    | 'SCHEMA_MISMATCH'
    | 'VALIDATION_FAILED'
    | 'INCOMPLETE_OUTPUT'
    | 'LOW_CONFIDENCE'

    // Infrastructure errors
    | 'INFRA_ERROR'
    | 'DB_FAILURE'
    | 'NETWORK_ERROR'
    | 'FILESYSTEM_ERROR'

    // Budget/limits
    | 'BUDGET_PAUSE'
    | 'BUDGET_EXCEEDED'
    | 'RATE_LIMITED'

    // Recovery-specific
    | 'USER_ACTION_REQUIRED'
    | 'RECOVERY_EXHAUSTED'
    | 'MANUAL_INTERVENTION_NEEDED';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH';

export type RecoveryAction =
    // Retry strategies
    | 'retry_with_examples'
    | 'retry_with_expanded_context'
    | 'retry_with_different_model'
    | 'retry_with_lower_temperature'

    // Context adjustments
    | 'expand_context_window'
    | 'add_schema_examples'
    | 'add_validation_hints'

    // MS4 adjustments
    | 'regenerate_with_observed_dependencies'
    | 'auto_patch_ms4_dependencies'

    // Escalation
    | 'escalate_to_human'
    | 'enter_safe_mode'
    | 'abort_build';

export interface RecoveryOption {
    action: RecoveryAction;
    description: string;
    risk_level: RiskLevel;
    estimated_success_probability: number; // 0.0-1.0
    side_effects?: string[];
    command?: string; // Optional shell command
    env_vars?: Record<string, string>; // Optional environment overrides
}

export interface StructuredError {
    code: ErrorCode;
    message: string;
    severity: 'FATAL' | 'ERROR' | 'WARNING';
    context: Record<string, any>;
    recovery_options: RecoveryOption[];
    human_intervention_required: boolean;
    timestamp: string;
}

/* -------------------------------------------------------------------------- */
/* Error Builders                                                             */
/* -------------------------------------------------------------------------- */

export function createStructuredError(
    code: ErrorCode,
    message: string,
    context: Record<string, any> = {},
    recoveryOptions: RecoveryOption[] = []
): StructuredError {
    return {
        code,
        message,
        severity: getSeverity(code),
        context,
        recovery_options: recoveryOptions.sort(
            (a, b) => b.estimated_success_probability - a.estimated_success_probability
        ),
        human_intervention_required: recoveryOptions.length === 0 ||
            recoveryOptions.every(opt => opt.estimated_success_probability < 0.5),
        timestamp: new Date().toISOString()
    };
}

function getSeverity(code: ErrorCode): 'FATAL' | 'ERROR' | 'WARNING' {
    const fatalCodes: ErrorCode[] = [
        'INFRA_ERROR',
        'DB_FAILURE',
        'BUDGET_EXCEEDED'
    ];

    const warningCodes: ErrorCode[] = [
        'LOW_CONFIDENCE',
        'RATE_LIMITED'
    ];

    if (fatalCodes.includes(code)) return 'FATAL';
    if (warningCodes.includes(code)) return 'WARNING';
    return 'ERROR';
}

/* -------------------------------------------------------------------------- */
/* Common Recovery Options                                                    */
/* -------------------------------------------------------------------------- */

export const CommonRecoveryOptions = {
    retryWithExamples: (): RecoveryOption => ({
        action: 'retry_with_examples',
        description: 'Retry transform with schema examples in prompt',
        risk_level: 'LOW',
        estimated_success_probability: 0.85,
        side_effects: ['Increased token usage']
    }),

    retryWithExpandedContext: (): RecoveryOption => ({
        action: 'retry_with_expanded_context',
        description: 'Retry with larger context window (reduce truncation)',
        risk_level: 'LOW',
        estimated_success_probability: 0.75,
        side_effects: ['Higher cost', 'Slower execution']
    }),

    retryWithDifferentModel: (modelId: string): RecoveryOption => ({
        action: 'retry_with_different_model',
        description: `Retry with fallback model: ${modelId}`,
        risk_level: 'MEDIUM',
        estimated_success_probability: 0.65,
        side_effects: ['Different output style', 'Potentially higher cost'],
        env_vars: { FALLBACK_MODEL: modelId }
    }),

    autoPatchDependencies: (): RecoveryOption => ({
        action: 'auto_patch_ms4_dependencies',
        description: 'Automatically patch MS4 with observed dependencies',
        risk_level: 'MEDIUM',
        estimated_success_probability: 0.80,
        side_effects: ['MS4 modified', 'Requires validation']
    }),

    escalateToHuman: (reason: string): RecoveryOption => ({
        action: 'escalate_to_human',
        description: `Escalate to human: ${reason}`,
        risk_level: 'LOW',
        estimated_success_probability: 0.95,
        side_effects: ['Build paused', 'Requires manual intervention']
    }),

    abortBuild: (reason: string): RecoveryOption => ({
        action: 'abort_build',
        description: `Abort build: ${reason}`,
        risk_level: 'HIGH',
        estimated_success_probability: 1.0,
        side_effects: ['Build terminated', 'Partial artifacts may exist']
    })
};

/* -------------------------------------------------------------------------- */
/* Error Factory Methods                                                      */
/* -------------------------------------------------------------------------- */

export class ErrorFactory {
    static schemaValidationFailed(
        details: { expected: string; actual: string; errors: string[] }
    ): StructuredError {
        return createStructuredError(
            'SCHEMA_MISMATCH',
            'Model output failed schema validation',
            details,
            [
                CommonRecoveryOptions.retryWithExamples(),
                CommonRecoveryOptions.retryWithDifferentModel('anthropic/claude-3-opus'),
                CommonRecoveryOptions.escalateToHuman('Schema validation failed after retries')
            ]
        );
    }

    static lowConfidence(
        confidence: number,
        reason: string,
        context: Record<string, any>
    ): StructuredError {
        return createStructuredError(
            'LOW_CONFIDENCE',
            `AI output confidence too low: ${confidence.toFixed(2)} (${reason})`,
            { confidence, reason, ...context },
            [
                CommonRecoveryOptions.retryWithExpandedContext(),
                CommonRecoveryOptions.escalateToHuman(`Low confidence: ${reason}`)
            ]
        );
    }

    static dependencyMismatch(
        declared: string[],
        observed: string[]
    ): StructuredError {
        const missing = observed.filter(dep => !declared.includes(dep));
        const extra = declared.filter(dep => !observed.includes(dep));

        return createStructuredError(
            'MODEL_ERROR',
            'Dependency mismatch between MS4 and generated code',
            { declared, observed, missing, extra },
            [
                CommonRecoveryOptions.autoPatchDependencies(),
                CommonRecoveryOptions.escalateToHuman('Dependency mismatch requires review')
            ]
        );
    }

    static budgetExceeded(
        current: number,
        limit: number
    ): StructuredError {
        return createStructuredError(
            'BUDGET_EXCEEDED',
            `Budget exceeded: $${current.toFixed(2)} / $${limit.toFixed(2)}`,
            { current_usd: current, limit_usd: limit },
            [
                {
                    action: 'escalate_to_human',
                    description: 'Request budget increase or build pause',
                    risk_level: 'LOW',
                    estimated_success_probability: 1.0,
                    side_effects: ['Build paused until budget approved']
                }
            ]
        );
    }

    static contextTruncated(
        truncationRatio: number,
        tokensRequested: number,
        tokensSent: number
    ): StructuredError {
        return createStructuredError(
            'LOW_CONFIDENCE',
            `Context heavily truncated: ${(truncationRatio * 100).toFixed(1)}%`,
            { truncation_ratio: truncationRatio, tokens_requested: tokensRequested, tokens_sent: tokensSent },
            [
                CommonRecoveryOptions.retryWithExpandedContext(),
                {
                    action: 'retry_with_lower_temperature',
                    description: 'Retry with lower temperature for more focused output',
                    risk_level: 'LOW',
                    estimated_success_probability: 0.70,
                    side_effects: ['Less creative output']
                }
            ]
        );
    }
}

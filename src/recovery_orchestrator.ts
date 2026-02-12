/**
 * Recovery Orchestrator - AI-First Decision Engine
 * 
 * Evaluates failures and selects optimal recovery strategies based on
 * confidence scoring and risk assessment.
 */

import { StructuredError, RecoveryOption, RecoveryAction, CommonRecoveryOptions } from './structured_error';

/* -------------------------------------------------------------------------- */
/* Types                                                                      */
/* -------------------------------------------------------------------------- */

export type RecoveryDecision = 'RETRY' | 'ESCALATE' | 'ABORT';

export interface RecoveryEvaluation {
    decision: RecoveryDecision;
    confidence: number; // 0.0-1.0
    selected_option: RecoveryOption | null;
    reasoning: string;
    metadata: {
        options_evaluated: number;
        highest_success_probability: number;
        lowest_risk_level: string;
    };
}

export interface RecoveryContext {
    build_id: string;
    transform_type?: string;
    attempt_number: number;
    previous_errors?: StructuredError[];
    cost_remaining_usd?: number;
}

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

const CONFIDENCE_THRESHOLD_AUTO_PROCEED = 0.95;
const CONFIDENCE_THRESHOLD_ESCALATE = 0.5;
const MAX_RETRY_ATTEMPTS = 3;

/* -------------------------------------------------------------------------- */
/* Recovery Orchestrator                                                      */
/* -------------------------------------------------------------------------- */

export class RecoveryOrchestrator {
    private readonly confidenceThresholdAutoProceed: number;
    private readonly confidenceThresholdEscalate: number;
    private readonly maxRetryAttempts: number;

    constructor(config?: {
        confidenceThresholdAutoProceed?: number;
        confidenceThresholdEscalate?: number;
        maxRetryAttempts?: number;
    }) {
        this.confidenceThresholdAutoProceed = config?.confidenceThresholdAutoProceed ?? CONFIDENCE_THRESHOLD_AUTO_PROCEED;
        this.confidenceThresholdEscalate = config?.confidenceThresholdEscalate ?? CONFIDENCE_THRESHOLD_ESCALATE;
        this.maxRetryAttempts = config?.maxRetryAttempts ?? MAX_RETRY_ATTEMPTS;
    }

    /**
     * Evaluate a structured error and decide on recovery strategy
     */
    async evaluate(
        error: StructuredError,
        context: RecoveryContext
    ): Promise<RecoveryEvaluation> {
        // Check if we've exceeded retry attempts
        if (context.attempt_number >= this.maxRetryAttempts) {
            return {
                decision: 'ESCALATE',
                confidence: 1.0,
                selected_option: CommonRecoveryOptions.escalateToHuman('Retry limit exceeded'),
                reasoning: `Exceeded maximum retry attempts (${this.maxRetryAttempts})`,
                metadata: {
                    options_evaluated: 0,
                    highest_success_probability: 0,
                    lowest_risk_level: 'LOW'
                }
            };
        }

        // Check if error requires human intervention
        if (error.human_intervention_required) {
            return {
                decision: 'ESCALATE',
                confidence: 1.0,
                selected_option: CommonRecoveryOptions.escalateToHuman(error.message),
                reasoning: 'Error marked as requiring human intervention',
                metadata: {
                    options_evaluated: error.recovery_options.length,
                    highest_success_probability: 0,
                    lowest_risk_level: 'LOW'
                }
            };
        }

        // No recovery options available
        if (error.recovery_options.length === 0) {
            return {
                decision: 'ABORT',
                confidence: 1.0,
                selected_option: CommonRecoveryOptions.abortBuild('No recovery options available'),
                reasoning: 'No recovery strategies available for this error',
                metadata: {
                    options_evaluated: 0,
                    highest_success_probability: 0,
                    lowest_risk_level: 'HIGH'
                }
            };
        }

        // Evaluate recovery options
        const evaluatedOptions = this.evaluateOptions(error.recovery_options, context);
        const bestOption = evaluatedOptions[0]; // Already sorted by score

        // Calculate confidence in recovery
        const confidence = this.calculateRecoveryConfidence(bestOption, context);

        // Decide based on confidence
        if (confidence < this.confidenceThresholdEscalate) {
            return {
                decision: 'ESCALATE',
                confidence,
                selected_option: CommonRecoveryOptions.escalateToHuman(
                    `Low recovery confidence: ${confidence.toFixed(2)}`
                ),
                reasoning: `Recovery confidence ${confidence.toFixed(2)} below threshold ${this.confidenceThresholdEscalate}`,
                metadata: {
                    options_evaluated: evaluatedOptions.length,
                    highest_success_probability: bestOption.estimated_success_probability,
                    lowest_risk_level: this.getLowestRisk(evaluatedOptions)
                }
            };
        }

        // Check if recovery action is escalation or abort
        if (bestOption.action === 'escalate_to_human') {
            return {
                decision: 'ESCALATE',
                confidence,
                selected_option: bestOption,
                reasoning: 'Best option is to escalate to human',
                metadata: {
                    options_evaluated: evaluatedOptions.length,
                    highest_success_probability: bestOption.estimated_success_probability,
                    lowest_risk_level: this.getLowestRisk(evaluatedOptions)
                }
            };
        }

        if (bestOption.action === 'abort_build') {
            return {
                decision: 'ABORT',
                confidence,
                selected_option: bestOption,
                reasoning: 'Best option is to abort build',
                metadata: {
                    options_evaluated: evaluatedOptions.length,
                    highest_success_probability: bestOption.estimated_success_probability,
                    lowest_risk_level: this.getLowestRisk(evaluatedOptions)
                }
            };
        }

        // Attempt retry with selected recovery option
        return {
            decision: 'RETRY',
            confidence,
            selected_option: bestOption,
            reasoning: `Selected recovery: ${bestOption.action} (success prob: ${bestOption.estimated_success_probability.toFixed(2)})`,
            metadata: {
                options_evaluated: evaluatedOptions.length,
                highest_success_probability: bestOption.estimated_success_probability,
                lowest_risk_level: this.getLowestRisk(evaluatedOptions)
            }
        };
    }

    /**
     * Evaluate and score recovery options
     */
    private evaluateOptions(
        options: RecoveryOption[],
        context: RecoveryContext
    ): RecoveryOption[] {
        // Score each option based on success probability and risk
        const scored = options.map(option => ({
            option,
            score: this.scoreOption(option, context)
        }));

        // Sort by score descending
        scored.sort((a, b) => b.score - a.score);

        return scored.map(s => s.option);
    }

    /**
     * Score a recovery option (higher is better)
     */
    private scoreOption(option: RecoveryOption, context: RecoveryContext): number {
        let score = option.estimated_success_probability;

        // Penalize high-risk options
        const riskPenalty = {
            'LOW': 0,
            'MEDIUM': 0.1,
            'HIGH': 0.3
        };
        score -= riskPenalty[option.risk_level];

        // Penalize expensive options if budget is low
        if (context.cost_remaining_usd !== undefined && context.cost_remaining_usd < 1.0) {
            if (option.side_effects?.some(effect => effect.includes('cost') || effect.includes('token'))) {
                score -= 0.15;
            }
        }

        // Penalize options that have failed before
        if (context.previous_errors?.some(e =>
            e.recovery_options.some(ro => ro.action === option.action)
        )) {
            score -= 0.2;
        }

        return Math.max(0, Math.min(1, score));
    }

    /**
     * Calculate confidence in recovery success
     */
    private calculateRecoveryConfidence(
        option: RecoveryOption,
        context: RecoveryContext
    ): number {
        let confidence = option.estimated_success_probability;

        // Reduce confidence based on attempt number
        const attemptPenalty = (context.attempt_number - 1) * 0.1;
        confidence -= attemptPenalty;

        // Reduce confidence if previous errors exist
        if (context.previous_errors && context.previous_errors.length > 0) {
            confidence -= context.previous_errors.length * 0.05;
        }

        return Math.max(0, Math.min(1, confidence));
    }

    /**
     * Get lowest risk level from options
     */
    private getLowestRisk(options: RecoveryOption[]): string {
        if (options.some(o => o.risk_level === 'LOW')) return 'LOW';
        if (options.some(o => o.risk_level === 'MEDIUM')) return 'MEDIUM';
        return 'HIGH';
    }
}

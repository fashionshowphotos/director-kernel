/**
 * AI Logger - JSONL Audit Trail
 * 
 * Provides machine-parsable logging for all AI decisions, recoveries,
 * and transformations. Logs are written in JSONL format for easy analysis.
 */

import * as fs from 'fs';
import * as path from 'path';
import { StructuredError, RecoveryOption } from './structured_error';
import { RecoveryEvaluation } from './recovery_orchestrator';

/* -------------------------------------------------------------------------- */
/* Types                                                                      */
/* -------------------------------------------------------------------------- */

export type LogEventType =
    // Build lifecycle
    | 'build_started'
    | 'build_completed'
    | 'build_failed'
    | 'build_escalated'

    // Transform events
    | 'transform_started'
    | 'transform_completed'
    | 'transform_failed'
    | 'transform_retrying'

    // Validation events
    | 'validation_started'
    | 'validation_passed'
    | 'validation_failed'

    // Recovery events
    | 'recovery_evaluating'
    | 'recovery_selected'
    | 'recovery_executing'
    | 'recovery_succeeded'
    | 'recovery_failed'

    // Confidence events
    | 'confidence_scored'
    | 'confidence_low'
    | 'escalation_triggered'

    // Cost tracking
    | 'token_usage'
    | 'cost_updated';

export interface LogEvent {
    timestamp: string;
    event_type: LogEventType;
    build_id?: string;
    transform_type?: string;
    attempt_number?: number;
    data: Record<string, any>;
}

/* -------------------------------------------------------------------------- */
/* AI Logger                                                                  */
/* -------------------------------------------------------------------------- */

export class AILogger {
    private readonly logPath: string;
    private stream: fs.WriteStream | null = null;

    constructor(logPath: string = 'logs/ai_decisions.jsonl') {
        this.logPath = logPath;
        this.ensureLogDirectory();
    }

    private ensureLogDirectory(): void {
        const dir = path.dirname(this.logPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    }

    /**
     * Initialize log stream (call once at start)
     */
    initialize(): void {
        if (this.stream) {
            return; // Already initialized
        }

        this.stream = fs.createWriteStream(this.logPath, {
            flags: 'a', // Append mode
            encoding: 'utf8'
        });

        this.log('build_started', {
            kernel_version: require('../../package.json').version,
            node_version: process.version,
            platform: process.platform
        });
    }

    /**
     * Close log stream (call on shutdown)
     */
    close(): void {
        if (this.stream) {
            this.stream.end();
            this.stream = null;
        }
    }

    /**
     * Write a log event
     */
    log(
        eventType: LogEventType,
        data: Record<string, any>,
        metadata?: {
            build_id?: string;
            transform_type?: string;
            attempt_number?: number;
        }
    ): void {
        const event: LogEvent = {
            timestamp: new Date().toISOString(),
            event_type: eventType,
            build_id: metadata?.build_id,
            transform_type: metadata?.transform_type,
            attempt_number: metadata?.attempt_number,
            data
        };

        const line = JSON.stringify(event) + '\n';

        if (this.stream) {
            this.stream.write(line);
        } else {
            // Fallback to sync write if stream not initialized
            fs.appendFileSync(this.logPath, line, 'utf8');
        }
    }

    /* ---------------------------------------------------------------------- */
    /* Convenience Methods                                                    */
    /* ---------------------------------------------------------------------- */

    logTransformStarted(
        buildId: string,
        transformType: string,
        attemptNumber: number
    ): void {
        this.log('transform_started', {}, {
            build_id: buildId,
            transform_type: transformType,
            attempt_number: attemptNumber
        });
    }

    logTransformCompleted(
        buildId: string,
        transformType: string,
        result: {
            success: boolean;
            confidence?: number;
            cost_usd: number;
            tokens: number;
            duration_ms: number;
        }
    ): void {
        this.log('transform_completed', result, {
            build_id: buildId,
            transform_type: transformType
        });
    }

    logTransformFailed(
        buildId: string,
        transformType: string,
        error: StructuredError,
        attemptNumber: number
    ): void {
        this.log('transform_failed', {
            error_code: error.code,
            error_message: error.message,
            severity: error.severity,
            recovery_options_count: error.recovery_options.length,
            human_intervention_required: error.human_intervention_required
        }, {
            build_id: buildId,
            transform_type: transformType,
            attempt_number: attemptNumber
        });
    }

    logRecoveryEvaluation(
        buildId: string,
        transformType: string,
        error: StructuredError,
        evaluation: RecoveryEvaluation
    ): void {
        this.log('recovery_evaluating', {
            error_code: error.code,
            decision: evaluation.decision,
            confidence: evaluation.confidence,
            selected_action: evaluation.selected_option?.action,
            reasoning: evaluation.reasoning,
            options_evaluated: evaluation.metadata.options_evaluated
        }, {
            build_id: buildId,
            transform_type: transformType
        });
    }

    logRecoveryExecuting(
        buildId: string,
        transformType: string,
        option: RecoveryOption
    ): void {
        this.log('recovery_executing', {
            action: option.action,
            description: option.description,
            risk_level: option.risk_level,
            estimated_success: option.estimated_success_probability
        }, {
            build_id: buildId,
            transform_type: transformType
        });
    }

    logConfidenceScore(
        buildId: string,
        transformType: string,
        confidence: {
            overall: number;
            schema_valid?: number;
            semantic_coherence?: number;
            completeness?: number;
        }
    ): void {
        this.log('confidence_scored', confidence, {
            build_id: buildId,
            transform_type: transformType
        });
    }

    logEscalation(
        buildId: string,
        transformType: string,
        reason: string,
        confidence: number
    ): void {
        this.log('escalation_triggered', {
            reason,
            confidence,
            timestamp: new Date().toISOString()
        }, {
            build_id: buildId,
            transform_type: transformType
        });
    }

    logTokenUsage(
        buildId: string,
        transformType: string,
        usage: {
            prompt_tokens: number;
            completion_tokens: number;
            total_tokens: number;
            cost_usd: number;
            model_id: string;
        }
    ): void {
        this.log('token_usage', usage, {
            build_id: buildId,
            transform_type: transformType
        });
    }
}

/* -------------------------------------------------------------------------- */
/* Singleton Instance                                                         */
/* -------------------------------------------------------------------------- */

let globalLogger: AILogger | null = null;

export function getAILogger(logPath?: string): AILogger {
    if (!globalLogger) {
        globalLogger = new AILogger(logPath);
        globalLogger.initialize();

        // Ensure stream is closed on exit
        process.on('exit', () => {
            if (globalLogger) {
                globalLogger.close();
            }
        });
    }
    return globalLogger;
}

/**
 * Context Slicer - Bounded context generation for model calls
 * Implements MS3 contract: context_slicer
 */

import * as crypto from 'crypto';

export interface ContextSlicerConfig {
    tokenBudget: number;
    truncationWarnThreshold?: number; // percentage
    truncationFailThreshold?: number; // percentage
}

export interface ContextArtifact {
    id: string;
    content: string;
    priority: number; // 1-10, higher = more important
    estimatedTokens: number;
    // Rich metadata for excluded artifact manifests
    kind?: string;
    summary?: string;
    exports?: string[];
}

export interface ContextSliceResult {
    contextPayload: string;
    tokensRequested: number;
    tokensSent: number;
    truncationRatio: number;
    contextHash: string;
    includedArtifacts: string[];
    excludedArtifacts: string[];
}

export class ContextSlicerError extends Error {
    constructor(message: string, public readonly code: string) {
        super(message);
        this.name = 'ContextSlicerError';
    }
}

export class ContextSlicer {
    private readonly warnThreshold: number;
    private readonly failThreshold: number;

    constructor(private config: ContextSlicerConfig) {
        this.warnThreshold = config.truncationWarnThreshold ?? 20;
        this.failThreshold = config.truncationFailThreshold ?? 50;
    }

    sliceContext(
        invariants: string,
        artifacts: ContextArtifact[],
        targetId: string
    ): ContextSliceResult {
        const invariantsTokens = this.estimateTokens(invariants);
        const budgetForArtifacts = this.config.tokenBudget - invariantsTokens;

        if (budgetForArtifacts <= 0) {
            throw new ContextSlicerError(
                'Token budget too small to include invariants',
                'BUDGET_TOO_SMALL'
            );
        }

        // Sort artifacts by priority (descending)
        const sortedArtifacts = [...artifacts].sort((a, b) => b.priority - a.priority);

        let totalTokens = invariantsTokens;
        const included: ContextArtifact[] = [];
        const excluded: ContextArtifact[] = [];

        // Greedy selection by priority
        for (const artifact of sortedArtifacts) {
            if (totalTokens + artifact.estimatedTokens <= this.config.tokenBudget) {
                included.push(artifact);
                totalTokens += artifact.estimatedTokens;
            } else {
                excluded.push(artifact);
            }
        }

        // Calculate truncation metrics
        const tokensRequested = artifacts.reduce((sum, a) => sum + a.estimatedTokens, 0) + invariantsTokens;
        const tokensSent = totalTokens;
        const truncationRatio = 1 - (tokensSent / tokensRequested);
        const truncationPercent = truncationRatio * 100;

        // Check thresholds
        if (truncationPercent >= this.failThreshold) {
            throw new ContextSlicerError(
                `Excessive truncation: ${truncationPercent.toFixed(1)}% ≥ ${this.failThreshold}% threshold`,
                'EXCESSIVE_TRUNCATION'
            );
        }

        // Build context payload
        const sections = [
            '# MS5 Invariants',
            invariants,
            '',
            '# Included Artifacts',
            ...included.map((a) => `## Artifact: ${a.id}\n${a.content}`),
        ];

        if (excluded.length > 0) {
            sections.push(
                '',
                '# Excluded Artifacts Manifest (token budget exceeded)',
                '> These artifacts were excluded. If you need them, respond with:',
                '> { "reply_type": "NEED_MORE_CONTEXT", "missing": [{"artifact_id": "...", "reason": "..."}] }',
                '',
                ...excluded.map((a) => this.buildExcludedManifestLine(a))
            );
        }

        const contextPayload = sections.join('\n');
        const contextHash = crypto.createHash('sha256').update(contextPayload).digest('hex');

        return {
            contextPayload,
            tokensRequested,
            tokensSent,
            truncationRatio,
            contextHash,
            includedArtifacts: included.map((a) => a.id),
            excludedArtifacts: excluded.map((a) => a.id),
        };
    }

    /**
     * Token estimation using weighted heuristic.
     * Code/JSON averages ~3.3 chars/token; whitespace-heavy text ~4.
     * Uses word count as secondary signal for better accuracy.
     */
    estimateTokens(text: string): number {
        if (!text) return 0;
        const wordCount = text.split(/\s+/).length;
        const charEstimate = Math.ceil(text.length / 3.3);
        // Blend: ~1.3 tokens per word for code, ~0.75 tokens per word for prose
        const wordEstimate = Math.ceil(wordCount * 1.3);
        // Use the higher of the two estimates (conservative for budget safety)
        return Math.max(charEstimate, wordEstimate);
    }

    /**
     * Build a rich manifest line for an excluded artifact.
     * Includes preview, kind, exports to help model request what it needs.
     */
    private buildExcludedManifestLine(a: ContextArtifact): string {
        const preview = (a.content ?? '')
            .replace(/\s+/g, ' ')
            .slice(0, 240);
        const exportsStr = a.exports?.length ? ` exports=[${a.exports.slice(0, 5).join(', ')}]` : '';
        const summaryStr = a.summary ? ` summary="${a.summary.slice(0, 80)}"` : '';
        return `- ${a.id} kind=${a.kind ?? 'unknown'} est=${a.estimatedTokens}${exportsStr}${summaryStr} preview="${preview}..."`;
    }
}

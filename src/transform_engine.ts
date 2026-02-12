/**
 * Transform Engine - Pure Compute (v2.0.0 - Clean Architecture)
 * 
 * OWNERSHIP MODEL (Threat Model A):
 * - TransformEngine: Pure compute (LLM orchestration + validation + artifact generation)
 * - StageExecutor: Durability (SQLite, checkpoints, artifact linking, cost persistence)
 * 
 * DOES:
 * - Execute MS-layer transforms (MS5→MS4→MS3→MS2)
 * - Schema validation
 * - Context slicing with truncation safety
 * - Cost estimation
 * - Return artifacts as Buffer + metadata
 * 
 * DOES NOT:
 * - Touch SQLite
 * - Write checkpoints
 * - Link artifacts to builds
 * - Persist cost records
 * - Emit durable events
 * 
 * CRITICAL INVARIANTS:
 * - Stateless and deterministic
 * - No external side effects
 * - Schema validation mandatory
 * - Truncation safety (>50% = fail)
 * - MS5 invariants always included
 */

import { debugLog, debugLogStart, debugLogEnd, debugLogStep } from './debug_logger';
import { getSystemPrompt, getPatchPrompt } from './prompts';
import { ArtifactKind } from './artifact_store';
import { ModelRouter, ModelResponse } from './model_router';
import { ContextSlicer, ContextArtifact } from './context_slicer';
import { SchemaValidator } from './schema_validator';
import { tracer } from './codegen_tracer';
import { MAX_OUTPUT_TOKENS, PROVENANCE_ENABLED } from './config';
import * as crypto from 'crypto';

type TypeScriptModule = typeof import('typescript');

/* -------------------------------------------------------------------------- */
/* Types                                                                      */
/* -------------------------------------------------------------------------- */

export type TransformType = 'ms5_to_ms4' | 'ms4_to_ms3' | 'ms3_to_ms2' | 'ms2_to_ms2_5' | 'ms2_5_to_ms3' | 'intent_to_ms5';
export type ValidationMode = 'fast' | 'spec_pass';

export type DirectorTier = 'toy' | 'personal' | 'experimental' | 'production' | 'enterprise';

// Quality Level: Semantic declaration of convergence requirements
// This replaces arbitrary iteration limits with convergence predicates
export type QualityLevel = 'experimental' | 'solo' | 'frontier' | 'production' | 'enterprise';

export type SecurityLevel = 'none' | 'basic' | 'hardened' | 'audited';

// Convergence state for each layer
export interface LayerConvergence {
    mc5: { converged: boolean; unknowns: string[]; };
    mc4: { converged: boolean; missingInvariants: string[]; };
    mc3: { converged: boolean; violations: string[]; warnings: string[]; };
    mc2: { converged: boolean; unresolvedDeps: string[]; };
    code: { converged: boolean; gatesPassed: boolean; testsPresent: boolean; };
}

// Stop conditions
export type StopCondition = 
    | { type: 'CONVERGED'; layer: string; }
    | { type: 'REFUSAL'; reason: string; missing: string[]; }
    | { type: 'CIRCUIT_BREAKER'; trigger: 'cost' | 'time'; value: number; };

// Quality-based build policy (replaces iteration-based)
export interface BuildPolicy {
    tier: DirectorTier;
    qualityLevel: QualityLevel;
    securityLevel: SecurityLevel;
    // Convergence requirements (not iteration limits)
    requireFullConvergence: boolean;
    allowPartialSpecs: boolean;
    allowUnresolvedAmbiguity: boolean;
    allowWarnings: boolean;
    // Circuit breakers (safety, not correctness)
    maxCostUsd?: number;
    maxWallclockSeconds?: number;
    // Legacy fields for backward compatibility
    maxIterations: number;
    completenessTarget: string;
    requireRunnableTests: boolean;
    requireSecurityHardening: boolean;
    enableSlowChecks: boolean;
    gateMissingTypes: boolean;
    gateMissingErrorHandling: boolean;
}

export function parseDirectorTier(raw: any): DirectorTier | null {
    const v = String(raw || '').trim().toLowerCase();
    if (v === 'toy' || v === 'personal' || v === 'experimental' || v === 'production' || v === 'enterprise') return v;
    return null;
}

// Map DirectorTier to QualityLevel
export function tierToQualityLevel(tier: DirectorTier): QualityLevel {
    switch (tier) {
        case 'toy': return 'experimental';
        case 'personal': return 'solo';
        case 'experimental': return 'frontier';
        case 'production': return 'production';
        case 'enterprise': return 'enterprise';
    }
}

export function buildPolicyForTier(tier: DirectorTier): BuildPolicy {
    const qualityLevel = tierToQualityLevel(tier);
    
    switch (tier) {
        case 'toy':
            return {
                tier,
                qualityLevel,
                securityLevel: 'none',
                // Convergence: partial specs allowed, ambiguity tolerated
                requireFullConvergence: false,
                allowPartialSpecs: true,
                allowUnresolvedAmbiguity: true,
                allowWarnings: true,
                // Circuit breakers
                maxCostUsd: 1.0,
                maxWallclockSeconds: 300,
                // Legacy
                maxIterations: 1,
                completenessTarget: '0.60',
                requireRunnableTests: false,
                requireSecurityHardening: false,
                enableSlowChecks: false,
                gateMissingTypes: false,
                gateMissingErrorHandling: false,
            };
        case 'personal':
            return {
                tier,
                qualityLevel,
                securityLevel: 'none',
                // Convergence: reasonable defaults allowed, warnings OK
                requireFullConvergence: false,
                allowPartialSpecs: true,
                allowUnresolvedAmbiguity: true,
                allowWarnings: true,
                // Circuit breakers
                maxCostUsd: 2.0,
                maxWallclockSeconds: 600,
                // Legacy
                maxIterations: 2,
                completenessTarget: '0.75',
                requireRunnableTests: false,
                requireSecurityHardening: false,
                enableSlowChecks: false,
                gateMissingTypes: false,
                gateMissingErrorHandling: false,
            };
        case 'experimental':
            return {
                tier,
                qualityLevel,
                securityLevel: 'basic',
                // Convergence: aggressive completion, some assumptions allowed
                requireFullConvergence: false,
                allowPartialSpecs: false,
                allowUnresolvedAmbiguity: true,
                allowWarnings: true,
                // Circuit breakers
                maxCostUsd: 5.0,
                maxWallclockSeconds: 1200,
                // Legacy
                maxIterations: 6,
                completenessTarget: '0.90',
                requireRunnableTests: false,
                requireSecurityHardening: false,
                enableSlowChecks: false,
                gateMissingTypes: true,
                gateMissingErrorHandling: true,
            };
        case 'production':
            return {
                tier,
                qualityLevel,
                securityLevel: 'basic',
                // Convergence: all core contracts must converge
                requireFullConvergence: true,
                allowPartialSpecs: false,
                allowUnresolvedAmbiguity: false,
                allowWarnings: true,
                // Circuit breakers
                maxCostUsd: 10.0,
                maxWallclockSeconds: 3600,
                // Legacy
                maxIterations: 10,
                completenessTarget: '0.97',
                requireRunnableTests: true,
                requireSecurityHardening: false,
                enableSlowChecks: true,
                gateMissingTypes: true,
                gateMissingErrorHandling: true,
            };
        case 'enterprise':
            return {
                tier,
                qualityLevel,
                securityLevel: 'hardened',
                // Convergence: full semantic convergence required or refuse
                requireFullConvergence: true,
                allowPartialSpecs: false,
                allowUnresolvedAmbiguity: false,
                allowWarnings: false,
                // Circuit breakers
                maxCostUsd: 50.0,
                maxWallclockSeconds: 7200,
                // Legacy
                maxIterations: 14,
                completenessTarget: '0.99',
                requireRunnableTests: true,
                requireSecurityHardening: true,
                enableSlowChecks: true,
                gateMissingTypes: true,
                gateMissingErrorHandling: true,
            };
    }
}

// Convergence checker for each layer
export function checkLayerConvergence(
    layer: 'mc5' | 'mc4' | 'mc3' | 'mc2' | 'code',
    artifact: any,
    policy: BuildPolicy
): { converged: boolean; issues: string[] } {
    const issues: string[] = [];
    
    switch (layer) {
        case 'mc5': {
            // MC5 converged when: no unresolved "unknown intent" markers, no NEED_MORE_CONTEXT
            const unknowns = artifact?.unknowns || artifact?.unresolved || [];
            if (unknowns.length > 0 && !policy.allowUnresolvedAmbiguity) {
                issues.push(...unknowns.map((u: string) => `Unresolved intent: ${u}`));
            }
            if (artifact?.need_more_context && policy.qualityLevel === 'enterprise') {
                issues.push('MC5 requires more context (enterprise refuses)');
            }
            return { converged: issues.length === 0, issues };
        }
        case 'mc4': {
            // MC4 converged when: all required invariants present, no forbidden moves unresolved
            const missingInvariants = artifact?.missing_invariants || [];
            const unresolvedForbidden = artifact?.unresolved_forbidden || [];
            if (missingInvariants.length > 0 && policy.requireFullConvergence) {
                issues.push(...missingInvariants.map((i: string) => `Missing invariant: ${i}`));
            }
            if (unresolvedForbidden.length > 0) {
                issues.push(...unresolvedForbidden.map((f: string) => `Unresolved forbidden: ${f}`));
            }
            if (policy.qualityLevel === 'enterprise' && !artifact?.explicit_governance) {
                issues.push('MC4 must have explicit governance (no implied rules)');
            }
            return { converged: issues.length === 0, issues };
        }
        case 'mc3': {
            // MC3 converged when: tier contracts pass, no must_hold violations
            const violations = artifact?.violations || [];
            const warnings = artifact?.warnings || [];
            const mustHoldViolations = violations.filter((v: any) => v.severity === 'error');
            if (mustHoldViolations.length > 0) {
                issues.push(...mustHoldViolations.map((v: any) => `Must-hold violation: ${v.invariant}`));
            }
            if (warnings.length > 0 && !policy.allowWarnings) {
                issues.push(...warnings.map((w: any) => `Warning not allowed: ${w.invariant || w}`));
            }
            return { converged: issues.length === 0, issues };
        }
        case 'mc2': {
            // MC2 converged when: linkage contract passes, no unresolved dependencies
            const unresolvedDeps = artifact?.unresolved_dependencies || [];
            const linkageValid = artifact?.linkage_valid !== false;
            if (!linkageValid) {
                issues.push('Linkage contract validation failed');
            }
            if (unresolvedDeps.length > 0 && policy.requireFullConvergence) {
                issues.push(...unresolvedDeps.map((d: string) => `Unresolved dependency: ${d}`));
            }
            return { converged: issues.length === 0, issues };
        }
        case 'code': {
            // Code converged when: Gate C passes, tests present (if required)
            const gatesPassed = artifact?.gates_passed !== false;
            const testsPresent = artifact?.tests_present || false;
            const unsafeConstructs = artifact?.unsafe_constructs || [];
            if (!gatesPassed) {
                issues.push('Code safety gates failed');
            }
            if (policy.requireRunnableTests && !testsPresent) {
                issues.push('Tests required but not present');
            }
            if (unsafeConstructs.length > 0 && policy.securityLevel !== 'none') {
                issues.push(...unsafeConstructs.map((u: string) => `Unsafe construct: ${u}`));
            }
            return { converged: issues.length === 0, issues };
        }
    }
}

// Determine stop condition
export function determineStopCondition(
    convergence: LayerConvergence,
    policy: BuildPolicy,
    currentCostUsd: number,
    elapsedSeconds: number
): StopCondition | null {
    // Check circuit breakers first (safety, not correctness)
    if (policy.maxCostUsd && currentCostUsd >= policy.maxCostUsd) {
        return { type: 'CIRCUIT_BREAKER', trigger: 'cost', value: currentCostUsd };
    }
    if (policy.maxWallclockSeconds && elapsedSeconds >= policy.maxWallclockSeconds) {
        return { type: 'CIRCUIT_BREAKER', trigger: 'time', value: elapsedSeconds };
    }
    
    // Check convergence (correctness)
    const allConverged = 
        convergence.mc5.converged &&
        convergence.mc4.converged &&
        convergence.mc3.converged &&
        convergence.mc2.converged &&
        convergence.code.converged;
    
    if (allConverged) {
        return { type: 'CONVERGED', layer: 'all' };
    }
    
    // Check for refusal conditions (enterprise)
    if (policy.qualityLevel === 'enterprise') {
        const missing: string[] = [];
        if (!convergence.mc5.converged) missing.push(...convergence.mc5.unknowns);
        if (!convergence.mc4.converged) missing.push(...convergence.mc4.missingInvariants);
        if (!convergence.mc3.converged) missing.push(...convergence.mc3.violations);
        if (!convergence.mc2.converged) missing.push(...convergence.mc2.unresolvedDeps);
        
        if (missing.length > 0) {
            return { type: 'REFUSAL', reason: 'Cannot converge without additional information', missing };
        }
    }
    
    return null; // Continue iterating
}

export interface TierContractViolation {
    invariant: string;
    severity: 'error' | 'warning' | 'info';
    tier: DirectorTier;
}

export interface TierContractResult {
    passed: boolean;
    violations: TierContractViolation[];
}

export interface TransformEngineConfig {
    modelRouter: ModelRouter;
    ms5Invariants: string;
}

export interface TransformArtifactInput {
    content: Buffer;
    kind: ArtifactKind;
    hash: string;
    priority?: number;
}

export interface TransformRequest {
    transformType: TransformType;
    targetId: string;
    inputs: TransformArtifactInput[];
    validationMode: ValidationMode;
    tokenBudget: number;
    attemptNo: number;
    modelId: string;
    idempotencyKey: string; // For StageExecutor to use
    policy?: BuildPolicy;
}

export interface TransformArtifactOutput {
    content: Buffer;
    kind: ArtifactKind;
}

export interface TransformResult {
    success: boolean;
    artifacts: TransformArtifactOutput[];
    costUsd: number;
    tokenUsage: {
        promptTokens: number;
        completionTokens: number;
        totalTokens: number;
    };
    truncation: {
        tokensRequested: number;
        tokensSent: number;
        truncationRatio: number;
        contextHash: string;
    };
    timing: {
        durationMs: number;
        modelCallMs: number;
        validationMs: number;
    };
    logs: string[];
    error?: {
        code: 'MODEL_ERROR' | 'USER_ACTION_REQUIRED' | 'INFRA_ERROR' | 'NEED_MORE_CONTEXT';
        message: string;
    };
    provenance?: {
        prompt_hash: string;
        response_hash: string;
        idempotency_key: string;
        model_id: string;
        artifact_hashes: string[];
    };
}

interface SchemaRegistryEntry {
    schemaId: string;
    schema: any;
}

/* -------------------------------------------------------------------------- */
/* Transform Engine (Pure Compute)                                           */
/* -------------------------------------------------------------------------- */

export class TransformEngine {
    private modelRouter: ModelRouter;
    private schemaValidator: SchemaValidator;
    private ms5Invariants: string;
    private schemaRegistry: Map<string, SchemaRegistryEntry> = new Map();

    // Timeouts per MC3 spec
    private readonly TRANSFORM_TIMEOUT_MS = 300000; // 300s
    private readonly MODEL_CALL_TIMEOUT_MS = 120000; // 120s

    // Truncation thresholds
    private readonly TRUNCATION_WARN_THRESHOLD = 0.20;
    private readonly TRUNCATION_FAIL_THRESHOLD = 0.50;

    // Max downstream size: 25MB
    private readonly MAX_DOWNSTREAM_BYTES = 25 * 1024 * 1024;

    // Quality validation thresholds
    private readonly MIN_MS2_OUTPUT_BYTES = 500;
    private readonly MAX_DIAGNOSTICS_CHARS = 6000;
    private readonly MAX_DIAGNOSTICS_COUNT = 50;
    private readonly MAX_RESPONSIBILITY_CHARS = 120;
    private readonly MAX_RETRY_ATTEMPTS = 3;

    constructor(config: TransformEngineConfig) {
        this.modelRouter = config.modelRouter;
        this.schemaValidator = new SchemaValidator();
        this.ms5Invariants = config.ms5Invariants;

        this.initializeSchemaRegistry();
    }

    private resolvePolicy(request: TransformRequest): BuildPolicy {
        const fromEnv = parseDirectorTier(process.env.DIRECTOR_TIER);
        const fromReq = request?.policy?.tier;
        const tier: DirectorTier = fromReq || fromEnv || 'experimental';
        const base = buildPolicyForTier(tier);
        const merged: BuildPolicy = { ...base, ...(request.policy || {}), tier };
        const max = Number(merged.maxIterations);
        const bounded = Number.isFinite(max) ? Math.max(1, Math.min(14, Math.floor(max))) : base.maxIterations;
        merged.maxIterations = bounded;
        merged.completenessTarget = String(merged.completenessTarget ?? base.completenessTarget);
        merged.requireRunnableTests = Boolean(merged.requireRunnableTests);
        merged.requireSecurityHardening = Boolean(merged.requireSecurityHardening);
        merged.enableSlowChecks = Boolean(merged.enableSlowChecks);
        merged.gateMissingTypes = Boolean(merged.gateMissingTypes);
        merged.gateMissingErrorHandling = Boolean(merged.gateMissingErrorHandling);
        return merged;
    }

    private initializeSchemaRegistry(): void {
        // MS5→MS4: Orientation (MC4)
        this.schemaRegistry.set('ms5_to_ms4:fast', {
            schemaId: 'ms4_orientation_v1',
            schema: {
                type: "object",
                required: ["mc_family"],
                properties: {
                    mc_family: {
                        type: "object",
                        required: ["levels"],
                        properties: {
                            levels: {
                                type: "array",
                                minItems: 1,
                                items: {
                                    type: "object",
                                    required: ["level", "name", "required_fields", "example"],
                                    properties: {
                                        level: { const: "MC4" },
                                        name: { type: "string" },
                                        required_fields: { type: "object" },
                                        example: { type: "object" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        // MS4→MS3: Contract specifications
        this.schemaRegistry.set('ms4_to_ms3:fast', {
            schemaId: 'ms3_contracts_v1',
            schema: {
                type: "object",
                required: ["mc_family"],
                properties: {
                    mc_family: {
                        type: "object",
                        required: ["levels"],
                        properties: {
                            levels: {
                                type: "array",
                                items: {
                                    type: "object",
                                    required: ["level", "example"],
                                    properties: {
                                        level: { const: "MC3" },
                                        example: { type: "object" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        // MS3→MS2: Code generation
        this.schemaRegistry.set('ms3_to_ms2:fast', {
            schemaId: 'ms2_code_v1',
            schema: {
                type: 'object',
                properties: {
                    files: {
                        type: 'array',
                        items: {
                            type: 'object',
                            required: ['path', 'content'],
                            properties: {
                                path: { type: 'string' },
                                content: { type: 'string' },
                                language: { type: 'string' },
                            },
                        },
                    },
                    patch: {
                        type: 'array',
                        items: {
                            type: 'object',
                            required: ['op', 'path'],
                            properties: {
                                op: { type: 'string', enum: ['add', 'replace', 'delete'] },
                                path: { type: 'string' },
                                content: { type: 'string' },
                            },
                        },
                    },
                },
                anyOf: [{ required: ['files'] }, { required: ['patch'] }],
            },
        });

        // MC2.5: Objection Ledger (Red Team RT-002)
        this.schemaRegistry.set('objection_ledger_v1', {
            schemaId: 'objection_ledger_v1',
            schema: {
                type: 'object',
                required: ['id', 'type', 'description', 'status'],
                properties: {
                    id: { type: 'string' },
                    type: { type: 'string', enum: ['logic', 'security', 'style', 'incomplete'] },
                    description: { type: 'string' }, // minLength handled by validator logic if needed, or simple string here
                    status: { type: 'string', enum: ['open', 'resolved'] },
                    resolution_context: { type: 'string' }
                }
            }
        });

        // MC2.5: Completion Declaration (Red Team RT-002)
        this.schemaRegistry.set('completion_declaration_v1', {
            schemaId: 'completion_declaration_v1',
            schema: {
                type: 'object',
                required: ['status', 'justification'],
                properties: {
                    status: { type: 'string', enum: ['stage_complete', 'stage_incomplete'] },
                    justification: { type: 'string' },
                    objections: {
                        type: 'array',
                        items: {
                            type: 'object',
                            required: ['id', 'type', 'description', 'status'],
                            properties: {
                                id: { type: 'string' },
                                type: { type: 'string', enum: ['logic', 'security', 'style', 'incomplete'] },
                                description: { type: 'string' },
                                status: { type: 'string', enum: ['open', 'resolved'] },
                                resolution_context: { type: 'string' }
                            }
                        }
                    }
                }
            }
        });

        // Intent→MS5: Thin Intent Expansion
        this.schemaRegistry.set('intent_to_ms5:fast', {
            schemaId: 'ms5_spec_v1',
            schema: {
                type: "object",
                required: ["problem", "goal"],
                properties: {
                    problem: { type: "string" },
                    goal: { type: "string" },
                    product_definition: {
                        type: "object",
                        properties: {
                            name: { type: "string" },
                            description: { type: "string" },
                            target_users: { type: "array", items: { type: "string" } }
                        }
                    },
                    functional_requirements: { type: "array", items: { type: "string" } },
                    non_functional_requirements: { type: "array", items: { type: "string" } },
                    constraints: { type: "array", items: { type: "string" } },
                    threat_model: {
                        type: "object",
                        properties: {
                            assets: { type: "array", items: { type: "string" } },
                            threats: { type: "array", items: { type: "string" } },
                            mitigations: { type: "array", items: { type: "string" } }
                        }
                    },
                    performance_envelope: {
                        type: "object",
                        properties: {
                            latency_targets: { type: "object" },
                            throughput_targets: { type: "object" },
                            resource_limits: { type: "object" }
                        }
                    },
                    persistence_model: {
                        type: "object",
                        properties: {
                            data_types: { type: "array", items: { type: "string" } },
                            storage_requirements: { type: "array", items: { type: "string" } },
                            consistency_requirements: { type: "array", items: { type: "string" } }
                        }
                    },
                    stages: {
                        type: "array",
                        items: {
                            type: "object",
                            required: ["stage"],
                            properties: {
                                stage: { type: "string" },
                                targets: { type: "array", items: { type: "object" } }
                            }
                        }
                    },
                    global_config: { type: "object" }
                }
            }
        });

        // MS2.5→MS3: Clean-Room Elevation (Semantics to Contracts)
        this.schemaRegistry.set('ms2_5_to_ms3:fast', {
            schemaId: 'ms3_contracts_v1',
            schema: {
                type: "object",
                required: ["mc_family"],
                properties: {
                    mc_family: {
                        type: "object",
                        required: ["levels"],
                        properties: {
                            levels: {
                                type: "array",
                                items: {
                                    type: "object",
                                    required: ["level", "example"],
                                    properties: {
                                        level: { const: "MC3" },
                                        example: { type: "object" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        // MS2→MS2.5: Semantic Compression (Code Analysis)
        this.schemaRegistry.set('ms2_to_ms2_5:fast', {
            schemaId: 'ms2_5_v1',
            schema: {
                type: 'object',
                required: ['schema_version', 'source', 'modules'],
                properties: {
                    schema_version: { type: 'string', enum: ['ms2_5_v1'] },
                    source: {
                        type: 'object',
                        required: ['language', 'analysis_scope', 'inputs'],
                        properties: {
                            language: { type: 'string' },
                            repo_id: { type: 'string' },
                            commit: { type: 'string' },
                            analysis_scope: { type: 'string', enum: ['repo', 'module', 'file'] },
                            inputs: {
                                type: 'array',
                                items: {
                                    type: 'object',
                                    required: ['path'],
                                    properties: {
                                        path: { type: 'string' },
                                        sha256: { type: 'string' }
                                    }
                                }
                            }
                        }
                    },
                    modules: {
                        type: 'array',
                        items: {
                            type: 'object',
                            required: ['id', 'name', 'files', 'responsibilities'],
                            properties: {
                                id: { type: 'string' },
                                name: { type: 'string' },
                                files: { type: 'array', items: { type: 'string' } },
                                responsibilities: { type: 'array', items: { type: 'string' } },
                                public_surface: {
                                    type: 'object',
                                    properties: {
                                        exports: {
                                            type: 'array',
                                            items: {
                                                type: 'object',
                                                required: ['name', 'kind'],
                                                properties: {
                                                    name: { type: 'string' },
                                                    kind: { type: 'string', enum: ['class', 'function', 'type', 'interface', 'const', 'enum', 'struct', 'method', 'trait', 'module', 'variable'] }
                                                }
                                            }
                                        }
                                    }
                                },
                                data_models: {
                                    type: 'array',
                                    items: {
                                        type: 'object',
                                        required: ['name', 'fields'],
                                        properties: {
                                            name: { type: 'string' },
                                            fields: {
                                                type: 'array',
                                                items: {
                                                    type: 'object',
                                                    required: ['name', 'type'],
                                                    properties: {
                                                        name: { type: 'string' },
                                                        type: { type: 'string' },
                                                        required: { type: 'boolean' }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                invariants: {
                                    type: 'array',
                                    items: {
                                        type: 'object',
                                        required: ['id', 'statement'],
                                        properties: {
                                            id: { type: 'string' },
                                            statement: { type: 'string' }
                                        }
                                    }
                                },
                                behaviors: {
                                    type: 'array',
                                    items: {
                                        type: 'object',
                                        required: ['name', 'summary'],
                                        properties: {
                                            name: { type: 'string' },
                                            summary: { type: 'string' },
                                            inputs: { type: 'array', items: { type: 'object' } },
                                            outputs: { type: 'array', items: { oneOf: [{ type: 'string' }, { type: 'object' }] } },
                                            side_effects: { type: 'array', items: { type: 'string' } },
                                            errors: { type: 'array', items: { oneOf: [{ type: 'string' }, { type: 'object' }] } }
                                        }
                                    }
                                },
                                dependencies: {
                                    type: 'object',
                                    properties: {
                                        internal: { type: 'array', items: { type: 'string' } },
                                        external: { type: 'array', items: { type: 'string' } }
                                    }
                                },
                                error_taxonomy: {
                                    type: 'array',
                                    items: {
                                        type: 'object',
                                        required: ['code', 'meaning'],
                                        properties: {
                                            code: { type: 'string' },
                                            meaning: { type: 'string' }
                                        }
                                    }
                                },
                                tests: {
                                    type: 'object',
                                    properties: {
                                        present: { type: 'boolean' },
                                        paths: { type: 'array', items: { type: 'string' } }
                                    }
                                }
                            }
                        }
                    },
                    crosscutting: {
                        type: 'object',
                        properties: {
                            global_invariants: { type: 'array', items: { type: 'string' } },
                            shared_error_taxonomy: {
                                type: 'array',
                                items: {
                                    type: 'object',
                                    required: ['code', 'meaning'],
                                    properties: {
                                        code: { type: 'string' },
                                        meaning: { type: 'string' }
                                    }
                                }
                            },
                            architecture_notes: { type: 'array', items: { type: 'string' } }
                        }
                    }
                }
            }
        });

        // Register all schemas
        for (const entry of this.schemaRegistry.values()) {
            this.schemaValidator.registerSchema(entry.schemaId, entry.schema);
        }
    }

    /**
     * Execute transform (pure compute, no persistence)
     * StageExecutor handles idempotency, checkpoints, and persistence
     */
    async execute(request: TransformRequest): Promise<TransformResult> {
        const startTime = Date.now();
        const logs: string[] = [];

        const policy = this.resolvePolicy(request);
        logs.push(`Build policy: tier=${policy.tier}, maxIterations=${policy.maxIterations}, completenessTarget=${policy.completenessTarget}`);

        // Enforce transform timeout with cleanup
        let timeoutId: NodeJS.Timeout | null = null;
        const timeoutPromise = new Promise<never>((_, reject) => {
            timeoutId = setTimeout(
                () => reject(new Error('Transform timeout')),
                this.TRANSFORM_TIMEOUT_MS
            );
        });

        try {
            const result = await Promise.race([
                this.executeInternal(request, startTime, logs),
                timeoutPromise,
            ]);
            if (result.success === false) return result;
            return result;
        } catch (e: any) {
            if (e.success === false) return e; // Already a TransformResult
            logs.push(`ERROR: ${e.message}`);
            return {
                success: false,
                artifacts: [],
                costUsd: 0,
                tokenUsage: { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
                truncation: { tokensRequested: 0, tokensSent: 0, truncationRatio: 0, contextHash: '' },
                timing: { durationMs: Date.now() - startTime, modelCallMs: 0, validationMs: 0 },
                logs,
                error: {
                    code: e.message === 'Transform timeout' ? 'INFRA_ERROR' : 'MODEL_ERROR',
                    message: e.message,
                },
            };
        } finally {
            if (timeoutId) clearTimeout(timeoutId);
        }
    }

    private async executeInternal(
        request: TransformRequest,
        startTime: number,
        logs: string[]
    ): Promise<TransformResult> {
        const policy = this.resolvePolicy(request);
        debugLogStart(request.transformType, request.targetId);
        logs.push(`Starting transform: ${request.transformType} -> ${request.targetId}`);

        const globalInstruction = `Global instruction: Produce production-quality results (correctness, maintainability, and tests). Keep security hardening minimal: do not introduce advanced/complex security frameworks, compliance scaffolding, or heavy hardening passes unless explicitly required by the contract/spec. Prefer simple, standard best practices only (validate inputs, safe defaults, avoid obvious vulnerabilities).`;

        const expectedUpstreamKind = request.transformType === 'ms5_to_ms4'
            ? 'ms5'
            : request.transformType === 'ms4_to_ms3'
                ? 'ms4'
                : request.transformType === 'ms2_to_ms2_5'
                    ? 'ms2'
                    : request.transformType === 'ms2_5_to_ms3'
                        ? 'ms2_5'
                        : request.transformType === 'intent_to_ms5'
                            ? 'intent'
                            : 'ms3';
        const orderedInputs = (() => {
            const idx = request.inputs.findIndex((i) => String(i.kind) === expectedUpstreamKind);
            if (idx <= 0) return request.inputs;
            const copy = [...request.inputs];
            const [picked] = copy.splice(idx, 1);
            return [picked, ...copy];
        })();
        const orderedRequest: TransformRequest = { ...request, inputs: orderedInputs };

        // Step 0: Resolve schema
        debugLogStep('0', 'Schema');
        const schemaKey = `${request.transformType}:${request.validationMode}`;
        const schemaEntry = this.schemaRegistry.get(schemaKey);
        if (!schemaEntry) {
            throw new Error(`No schema registered for ${schemaKey}`);
        }

        // Step 1: Get upstream content (primary input)
        if (orderedRequest.inputs.length === 0) {
            throw new Error('No upstream artifacts provided');
        }
        const upstreamContent = orderedRequest.inputs[0].content;

        // Step 2: Slice context with truncation safety
        const contextSlice = this.sliceContext(orderedRequest, upstreamContent, logs);

        // Step 3: Check truncation threshold (>50% = fail)
        if (contextSlice.truncationRatio > this.TRUNCATION_FAIL_THRESHOLD) {
            logs.push(
                `TRUNCATION FAIL: ${(contextSlice.truncationRatio * 100).toFixed(1)}% > ${(this.TRUNCATION_FAIL_THRESHOLD * 100).toFixed(1)}%`
            );
            return {
                success: false,
                artifacts: [],
                costUsd: 0,
                tokenUsage: { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
                truncation: {
                    tokensRequested: contextSlice.tokensRequested,
                    tokensSent: contextSlice.tokensSent,
                    truncationRatio: contextSlice.truncationRatio,
                    contextHash: contextSlice.contextHash,
                },
                timing: { durationMs: Date.now() - startTime, modelCallMs: 0, validationMs: 0 },
                logs,
                error: {
                    code: 'USER_ACTION_REQUIRED',
                    message: `Excessive truncation: ${(contextSlice.truncationRatio * 100).toFixed(1)}%`,
                },
            };
        }

        if (contextSlice.truncationRatio > this.TRUNCATION_WARN_THRESHOLD) {
            logs.push(
                `TRUNCATION WARNING: ${(contextSlice.truncationRatio * 100).toFixed(1)}%`
            );
        }



        // Step 4: Call model with retry logic (ModelRouter already has timeout)
        debugLogStep('4', 'Model Call');
        const modelStartTime = Date.now();
        let modelResponse: ModelResponse | undefined;
        let cumulativeCostUsd = 0;
        let cumulativePromptTokens = 0;
        let cumulativeCompletionTokens = 0;
        let patchCompletionsForTrace: string[] = [];

        for (let attempt = 1; attempt <= this.MAX_RETRY_ATTEMPTS; attempt++) {
            try {
                debugLogStep(`4.${attempt}`, 'Preparing call');
                logs.push(`Model call attempt ${attempt}/${this.MAX_RETRY_ATTEMPTS}`);

                // Select System Prompt using prompts module
                const targetLang = request.transformType === 'ms3_to_ms2' 
                    ? (this.extractTargetLanguage(contextSlice.contextPayload) || 'typescript')
                    : undefined;
                const langInstructions = targetLang ? this.getLanguageInstructions(targetLang) : undefined;
                
                const systemPrompt = getSystemPrompt(request.transformType, globalInstruction, {
                    targetLanguage: targetLang,
                    langInstructions
                });

                // Convert context to messages format
                const messages = [
                    { role: 'system' as const, content: systemPrompt },
                    {
                        role: 'user' as const,
                        content: contextSlice.contextPayload,
                    }
                ];

                debugLogStep(`4.${attempt}`, 'Sending request to router');
                const maxTokens = request.transformType === 'ms3_to_ms2'
                    ? MAX_OUTPUT_TOKENS.CODE_GEN
                    : MAX_OUTPUT_TOKENS.SEMANTIC;
                const result = await this.modelRouter.executeModelCall({
                    model_id: request.modelId,
                    messages,
                    temperature: 0.2, // Lower temperature for more deterministic/strict output
                    max_tokens: maxTokens,
                });
                debugLogStep(`4.${attempt}`, `Received response. OK=${result.ok}`);

                // Check if call succeeded (union type: ModelResponse | ModelRouterError)
                if (!result.ok) {
                    throw new Error(result.message || 'Model call failed');
                }

                modelResponse = result;
                cumulativeCostUsd += modelResponse.costUsd ?? this.estimateCost(modelResponse.tokenUsage);
                cumulativePromptTokens += modelResponse.tokenUsage.promptTokens;
                cumulativeCompletionTokens += modelResponse.tokenUsage.completionTokens;
                logs.push(`Model call succeeded: ${modelResponse.tokenUsage.totalTokens} tokens`);
                break;
            } catch (e: any) {
                debugLogStep(`4.${attempt}`, `FAILED: ${e.message}`);
                logs.push(`Model call attempt ${attempt} failed: ${e.message}`);
                if (attempt === this.MAX_RETRY_ATTEMPTS) {
                    throw new Error(`Model call failed after ${this.MAX_RETRY_ATTEMPTS} attempts: ${e.message}`);
                }
                // Exponential backoff: 1s, 2s, 4s...
                const backoffMs = 1000 * Math.pow(2, attempt - 1);
                logs.push(`Waiting ${backoffMs}ms before retry...`);
                await new Promise(resolve => setTimeout(resolve, backoffMs));
            }
        }



        if (!modelResponse) {
            throw new Error('Model call failed: no response obtained');
        }

        const modelCallMs = Date.now() - modelStartTime;




        // Step 5: Parse and validate
        debugLogStep('5', 'Parse');
        const validationStartTime = Date.now();
        let downstreamPayload: any;

        try {
            const rawCompletion = modelResponse.completion;

            logs.push(`Raw completion length: ${rawCompletion.length} `);
            logs.push(`Raw completion snippet: ${rawCompletion.slice(0, 200)}...`);
            debugLog(`REPLY: ${rawCompletion.slice(0, 500)}`);

            // Use consolidated JSON parsing
            downstreamPayload = this.parseJsonCompletion(rawCompletion, 'Model response');
            logs.push('JSON parse successful');

            // If MS2 returned a patch directly, apply it to the most recent MS2 input (if present)
            if (request.transformType === 'ms3_to_ms2' && !Array.isArray(downstreamPayload?.files) && Array.isArray(downstreamPayload?.patch)) {
                const baseMs2 = request.inputs.find((i) => String(i.kind) === 'ms2');
                let baseFiles: Array<{ path: string; content: string }> = [];

                if (baseMs2) {
                    try {
                        const baseParsed = JSON.parse(baseMs2.content.toString('utf8')) as any;
                        if (Array.isArray(baseParsed?.files)) {
                            baseFiles = baseParsed.files;
                        }
                    } catch {
                        logs.push('Warning: failed to parse base MS2 artifact as JSON, using empty base');
                    }
                }

                const mergedFiles = this.applyMs2Patch(baseFiles, downstreamPayload.patch);
                downstreamPayload = { files: mergedFiles };
                logs.push('Applied patch output to base MS2 files');
            }

            // Resilient auto-wrapping for MS2
            if (request.transformType === 'ms3_to_ms2') {
                if (Array.isArray(downstreamPayload)) {
                    downstreamPayload = { files: downstreamPayload };
                    logs.push('Auto-wrapped naked MS2 array');
                }

                // STUB DETECTION / VALIDATION
                if (downstreamPayload.files && Array.isArray(downstreamPayload.files)) {
                    // Check if files are substantial
                    const totalBytes = downstreamPayload.files.reduce((acc: number, f: any) => acc + (f.content?.length || 0), 0);
                    if (totalBytes < this.MIN_MS2_OUTPUT_BYTES && downstreamPayload.files.length > 0) {
                        throw new Error(`MS2 Generation Validation Failed: Output is too small (${totalBytes} bytes). Likely a stub. Rejecting.`);
                    }

                    // Check for common stub patterns
                    for (const f of downstreamPayload.files) {
                        if (f.content && (f.content.includes("// implementation goes here") || f.content.includes("/* implementation */"))) {
                            throw new Error(`MS2 Generation Validation Failed: Found explicit stub in ${f.path}. Rejecting.`);
                        }
                    }

                    // QUALITY VALIDATION (warnings logged, not failures)
                    const qualityIssues: string[] = [];
                    const files = downstreamPayload.files as Array<{ path: string; content: string }>;
                    
                    // Check for @types in package.json
                    const pkgJson = files.find(f => f.path === 'package.json' || f.path.endsWith('/package.json'));
                    if (pkgJson) {
                        if (pkgJson.content.includes('"express"') && !pkgJson.content.includes('@types/express')) {
                            qualityIssues.push('Missing @types/express');
                        }
                        if (pkgJson.content.includes('"uuid"') && !pkgJson.content.includes('@types/uuid')) {
                            qualityIssues.push('Missing @types/uuid');
                        }
                    }
                    
                    // Check for in-memory database
                    for (const f of files) {
                        if (typeof f.content === 'string' && (f.content.includes("':memory:'") || f.content.includes('":memory:"'))) {
                            qualityIssues.push(`In-memory DB in ${f.path} (data won't persist)`);
                        }
                    }
                    
                    // Check for missing error handling in route handlers
                    for (const f of files) {
                        if (f.path.endsWith('.ts') && f.content.includes('app.') && f.content.includes('async')) {
                            if (!f.content.includes('try {') && !f.content.includes('try{')) {
                                qualityIssues.push(`No try/catch in ${f.path}`);
                            }
                        }
                    }
                    
                    if (qualityIssues.length > 0) {
                        logs.push(`Quality warnings: ${qualityIssues.join(', ')}`);
                    }
                    
                    // Run tracer analysis
                    let workingFiles = files.map((f) => ({ path: f.path, content: f.content }));
                    const maxPatchRounds = Math.max(1, policy.maxIterations);
                    for (let patchRound = 0; patchRound < maxPatchRounds; patchRound++) {
                        const qualityChecks = tracer.analyzeOutput(workingFiles);
                        const stubFiles = this.detectStubFiles(workingFiles);
                        const compileCheck = this.typecheckMs2(workingFiles, policy.tier);

                        const hardIssues: string[] = [];
                        if (qualityChecks.stub_detected || stubFiles.length > 0) hardIssues.push('stubs_detected');
                        if (policy.gateMissingTypes && qualityChecks.missing_types.length > 0) hardIssues.push(`missing_types:${qualityChecks.missing_types.join(',')}`);
                        if (policy.gateMissingErrorHandling && qualityChecks.missing_error_handling.length > 0) hardIssues.push(`missing_error_handling:${qualityChecks.missing_error_handling.join(',')}`);
                        if (!compileCheck.ok) hardIssues.push('ts_compile_errors');

                        if (hardIssues.length === 0) {
                            break;
                        }

                        logs.push(`Quality gates failed (round ${patchRound + 1}/${maxPatchRounds}): ${hardIssues.join(' | ')}`);

                        const diagBlock = compileCheck.ok ? '' : `\n\nTypeScript diagnostics (ERRORS):\n${compileCheck.diagnostics}\n`;
                        const stubBlock = stubFiles.length === 0 ? '' : `\n\nStub markers detected in files (MUST fully fix by replacing these files):\n${stubFiles.map((p) => `- ${p}`).join('\n')}\n`;

                        const patchSystemPrompt = `You are a Senior Developer editing an existing codebase. You MUST return ONLY valid JSON.${diagBlock}${stubBlock}

Input: Current MS2 codebase as { "files": [...] } plus upstream contract context.
Output: JSON object with a 'patch' key containing an array of patch operations.
Structure: { "patch": [ { "op": "add|replace|delete", "path": "...", "content": "..." } ] }

Rules:
1. Minimize change: only modify files necessary to fix the stated issues.
2. Do NOT re-emit the entire codebase as 'files'. Use patch ops.
3. For op=delete, omit content.
4. For op=add/replace, include full file content.
5. Remove ALL stub markers (e.g. // TODO, // implementation, Not implemented).
6. ONLY RETURN JSON. No other text.

${globalInstruction}`;

                        const ms2Draft = Buffer.from(JSON.stringify({ files: workingFiles }), 'utf8');
                        const patchInputs: TransformArtifactInput[] = [
                            { content: ms2Draft, kind: 'ms2', hash: `ms2_draft_${patchRound}` },
                            ...orderedRequest.inputs,
                        ];

                        const patchRequest: TransformRequest = {
                            ...orderedRequest,
                            inputs: patchInputs,
                            idempotencyKey: `${request.idempotencyKey}:patch:${patchRound}`,
                        };

                        const patchContextSlice = this.sliceContext(patchRequest, ms2Draft, logs);
                        const patchMessages = [
                            { role: 'system' as const, content: patchSystemPrompt },
                            { role: 'user' as const, content: patchContextSlice.contextPayload },
                        ];

                        const patchResult = await this.modelRouter.executeModelCall({
                            model_id: request.modelId,
                            messages: patchMessages,
                            temperature: 0.2,
                            max_tokens: MAX_OUTPUT_TOKENS.CODE_GEN,
                        });

                        if (!patchResult.ok) {
                            throw new Error(patchResult.message || 'Patch model call failed');
                        }

                        patchCompletionsForTrace.push(patchResult.completion);

                        cumulativeCostUsd += patchResult.costUsd ?? this.estimateCost(patchResult.tokenUsage);
                        cumulativePromptTokens += patchResult.tokenUsage.promptTokens;
                        cumulativeCompletionTokens += patchResult.tokenUsage.completionTokens;

                        const patchPayload = this.parseJsonCompletion(patchResult.completion, 'Patch');
                        let mergedFiles: Array<{ path: string; content: string }>;
                        if (Array.isArray(patchPayload?.files)) {
                            mergedFiles = patchPayload.files;
                        } else if (Array.isArray(patchPayload?.patch)) {
                            mergedFiles = this.applyMs2Patch(workingFiles, patchPayload.patch);
                        } else {
                            throw new Error('Patch output invalid: expected patch or files');
                        }

                        workingFiles = mergedFiles;
                        if (patchRound === (maxPatchRounds - 1)) {
                            const finalChecks = tracer.analyzeOutput(workingFiles);
                            const finalStubFiles = this.detectStubFiles(workingFiles);
                            const finalCompile = this.typecheckMs2(workingFiles, policy.tier);
                            const remaining: string[] = [];
                            if (finalChecks.stub_detected || finalStubFiles.length > 0) remaining.push('stubs_detected');
                            if (policy.gateMissingTypes && finalChecks.missing_types.length > 0) remaining.push(`missing_types:${finalChecks.missing_types.join(',')}`);
                            if (policy.gateMissingErrorHandling && finalChecks.missing_error_handling.length > 0) remaining.push(`missing_error_handling:${finalChecks.missing_error_handling.join(',')}`);
                            if (!finalCompile.ok) remaining.push('ts_compile_errors');
                            if (remaining.length > 0) {
                                const suffix = finalCompile.ok ? '' : `\nTypeScript diagnostics (ERRORS):\n${finalCompile.diagnostics}`;
                                const stubSuffix = finalStubFiles.length === 0 ? '' : `\nStub files: ${finalStubFiles.join(', ')}`;
                                throw new Error(`MS2 patch did not satisfy quality gates: ${remaining.join(' | ')}` + suffix + stubSuffix);
                            }
                        }
                    }

                    downstreamPayload = { files: workingFiles };
                }
            }
        } catch (e: any) {
            logs.push(`JSON parse failed: ${e.message}`);
            logs.push(`Raw response (first 500 chars): ${((modelResponse as any)?.completion || '').slice(0, 500)}`);
            return {
                success: false,
                artifacts: [],
                costUsd: (modelResponse as any)?.costUsd || 0,
                tokenUsage: (modelResponse as any)?.tokenUsage || { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
                truncation: {
                    tokensRequested: contextSlice.tokensRequested,
                    tokensSent: contextSlice.tokensSent,
                    truncationRatio: contextSlice.truncationRatio,
                    contextHash: contextSlice.contextHash,
                },
                timing: { durationMs: Date.now() - startTime, modelCallMs: 0, validationMs: 0 },
                logs,
                error: {
                    code: 'MODEL_ERROR',
                    message: `JSON parse failed: ${e.message}`,
                },
            };
        }

        // === Context Negotiation Protocol ===
        // Detect if model is requesting more context instead of producing output
        if (downstreamPayload?.reply_type === 'NEED_MORE_CONTEXT') {
            logs.push('Model requested more context');
            logs.push(`Missing artifacts: ${JSON.stringify(downstreamPayload.missing)}`);
            return {
                success: false,
                artifacts: [],
                costUsd: modelResponse.costUsd ?? 0,
                tokenUsage: modelResponse.tokenUsage,
                truncation: {
                    tokensRequested: contextSlice.tokensRequested,
                    tokensSent: contextSlice.tokensSent,
                    truncationRatio: contextSlice.truncationRatio,
                    contextHash: contextSlice.contextHash,
                },
                timing: { durationMs: Date.now() - startTime, modelCallMs: modelCallMs, validationMs: 0 },
                logs,
                error: {
                    code: 'NEED_MORE_CONTEXT',
                    message: JSON.stringify(downstreamPayload),
                },
            };
        }

        const validationResult = this.schemaValidator.validate(
            downstreamPayload,
            schemaEntry.schemaId
        );

        if (!validationResult.valid) {
            const errors = validationResult.errors.map((e) => `${e.path}: ${e.message}`).join('; ');
            throw new Error(`Schema validation failed: ${errors}`);
        }

        logs.push('Schema validation passed');
        const validationMs = Date.now() - validationStartTime;


        // Step 6: Generate artifact output
        const downstreamContent = Buffer.from(JSON.stringify(downstreamPayload), 'utf-8');

        if (downstreamContent.length > this.MAX_DOWNSTREAM_BYTES) {
            throw new Error(
                `Downstream too large: ${downstreamContent.length} > ${this.MAX_DOWNSTREAM_BYTES}`
            );
        }

        const artifactKind = this.getArtifactKind(request.transformType);
        const costUsd = cumulativeCostUsd > 0 ? cumulativeCostUsd : (modelResponse.costUsd ?? this.estimateCost(modelResponse.tokenUsage));

        logs.push(`Transform complete: ${downstreamContent.length} bytes, $${costUsd.toFixed(4)}`);

        try {
            if (request.transformType === 'ms3_to_ms2') {
                const parsed = JSON.parse(downstreamContent.toString('utf8')) as any;
                const files = Array.isArray(parsed?.files) ? parsed.files : null;
                tracer.completeTrace(
                    tracer.startTrace({
                        transform_type: request.transformType,
                        target_id: request.targetId,
                        model_id: request.modelId,
                        tier: policy.tier,
                        policy,
                        inputs: request.inputs.map(i => ({ kind: String(i.kind), hash: i.hash, content: i.content })),
                        system_prompt: 'ms3_to_ms2',
                        user_prompt: contextSlice.contextPayload,
                    }),
                    (modelResponse?.completion || '') + (patchCompletionsForTrace.length ? `\n---PATCHES---\n${patchCompletionsForTrace.join('\n---PATCH---\n')}` : ''),
                    files,
                    Date.now() - startTime,
                    (cumulativePromptTokens + cumulativeCompletionTokens) || (modelResponse?.tokenUsage.totalTokens || 0),
                    costUsd,
                    true,
                    undefined,
                    PROVENANCE_ENABLED ? {
                        prompt_hash: modelResponse?.meta?.promptHash,
                        response_hash: modelResponse?.meta?.responseHash,
                        artifact_hashes: [crypto.createHash('sha256').update(downstreamContent).digest('hex')],
                    } : undefined
                );
            }
        } catch {
        }

        debugLogStep('5.9', `Artifact Size ${downstreamContent.length}. Kind ${artifactKind}`);

        debugLogEnd(request.transformType, true, costUsd);

        // Provenance chain
        const provenanceData = PROVENANCE_ENABLED && modelResponse?.meta ? {
            prompt_hash: modelResponse.meta.promptHash,
            response_hash: modelResponse.meta.responseHash,
            idempotency_key: modelResponse.meta.idempotencyKey,
            model_id: request.modelId,
            artifact_hashes: [crypto.createHash('sha256').update(downstreamContent).digest('hex')],
        } : undefined;

        // Return pure result (no persistence)
        return {
            success: true,
            artifacts: [
                {
                    content: downstreamContent,
                    kind: artifactKind,
                },
            ],
            costUsd,
            tokenUsage: {
                promptTokens: cumulativePromptTokens > 0 ? cumulativePromptTokens : modelResponse.tokenUsage.promptTokens,
                completionTokens: cumulativeCompletionTokens > 0 ? cumulativeCompletionTokens : modelResponse.tokenUsage.completionTokens,
                totalTokens: (cumulativePromptTokens + cumulativeCompletionTokens) > 0
                    ? (cumulativePromptTokens + cumulativeCompletionTokens)
                    : modelResponse.tokenUsage.totalTokens,
            },
            truncation: {
                tokensRequested: contextSlice.tokensRequested,
                tokensSent: contextSlice.tokensSent,
                truncationRatio: contextSlice.truncationRatio,
                contextHash: contextSlice.contextHash,
            },
            timing: {
                durationMs: Date.now() - startTime,
                modelCallMs,
                validationMs,
            },
            logs,
            provenance: provenanceData,
        };
    }

    /**
     * Check convergence for a transform result
     * Returns convergence status and any issues found
     */
    checkConvergence(
        transformType: TransformType,
        artifact: any,
        policy: BuildPolicy
    ): { converged: boolean; issues: string[]; layer: string } {
        const layerMap: Record<TransformType, 'mc5' | 'mc4' | 'mc3' | 'mc2' | 'code'> = {
            'intent_to_ms5': 'mc5',
            'ms5_to_ms4': 'mc4',
            'ms4_to_ms3': 'mc3',
            'ms3_to_ms2': 'code',
            'ms2_to_ms2_5': 'mc2',
            'ms2_5_to_ms3': 'mc3',
        };
        
        const layer = layerMap[transformType];
        const result = checkLayerConvergence(layer, artifact, policy);
        
        return {
            converged: result.converged,
            issues: result.issues,
            layer
        };
    }

    private applyMs2Patch(
        baseFiles: Array<{ path: string; content: string }>,
        patchOps: Array<{ op: 'add' | 'replace' | 'delete'; path: string; content?: string }>
    ): Array<{ path: string; content: string }> {
        const map = new Map<string, string>();
        for (const f of baseFiles) map.set(String(f.path), String(f.content ?? ''));

        const baseIndex = baseFiles.map((f) => String(f.path));

        for (const op of patchOps) {
            let p = String((op as any)?.path ?? '');
            const kind = String((op as any)?.op ?? '');
            if (!p) continue;

            const m = p.match(/^\/files\/(\d+)\/content$/);
            if (m) {
                const idx = Number(m[1]);
                if (Number.isFinite(idx) && idx >= 0 && idx < baseIndex.length) {
                    p = baseIndex[idx];
                }
            }

            if (kind === 'delete') {
                map.delete(p);
                continue;
            }
            const c = String((op as any)?.content ?? '');
            map.set(p, c);
        }

        return Array.from(map.entries())
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([path, content]) => ({ path, content }));
    }

    private detectStubFiles(files: Array<{ path: string; content: string }>): string[] {
        const patterns = ['// TODO', '// implementation', 'throw new Error("Not implemented")'];
        const out: string[] = [];
        for (const f of files) {
            const c = String((f as any)?.content ?? '');
            if (!c) continue;
            if (patterns.some((p) => c.includes(p))) out.push(String(f.path));
        }
        return Array.from(new Set(out)).sort((a, b) => a.localeCompare(b));
    }

    private parseJsonCompletion(rawCompletion: string, label: string): any {
        let cleaned = String(rawCompletion || '').trim();

        if (cleaned.startsWith('```')) {
            const lines = cleaned.split('\n');
            lines.shift();
            if (lines[lines.length - 1].trim() === '```') lines.pop();
            cleaned = lines.join('\n').trim();
        } else {
            const firstBrace = cleaned.indexOf('{');
            const lastBrace = cleaned.lastIndexOf('}');
            if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
                cleaned = cleaned.slice(firstBrace, lastBrace + 1);
            }
        }

        // Try parsing without comment removal first (safest)
        try {
            return JSON.parse(cleaned);
        } catch {
            // Fallback: strip JS-style comments, then retry
            // This regex preserves string contents while removing // and /* */ comments
            const stripped = cleaned.replace(/\\"|"(?:\\"|[^"])*"|(\/\/.*|\/\*[\s\S]*?\*\/)/g, (m, g) => g ? "" : m);
            try {
                return JSON.parse(stripped);
            } catch (e: any) {
                throw new Error(`${label} parse failed: ${String(e?.message || e)}`);
            }
        }
    }

    private typecheckMs2(
        files: Array<{ path: string; content: string }>,
        tier?: DirectorTier
    ): { ok: boolean; diagnostics: string } {
        const ts = this.tryGetTypeScript();
        if (!ts) {
            // Enterprise/production tier: TypeScript validation is mandatory
            if (tier === 'enterprise' || tier === 'production') {
                return { ok: false, diagnostics: 'TypeScript module not available — mandatory for enterprise/production tier. Install typescript as a dependency.' };
            }
            return { ok: true, diagnostics: '' };
        }

        const diagnostics: any[] = [];
        const compilerOptions: any = {
            strict: true,
            target: ts.ScriptTarget.ES2020,
            module: ts.ModuleKind.CommonJS,
            esModuleInterop: true,
            skipLibCheck: true,
            noResolve: true,
        };

        for (const f of files) {
            const p = String(f.path || '');
            if (!p.endsWith('.ts') || p.endsWith('.d.ts')) continue;

            const res = ts.transpileModule(String(f.content ?? ''), {
                compilerOptions,
                fileName: p,
                reportDiagnostics: true,
            });

            if (Array.isArray((res as any).diagnostics) && (res as any).diagnostics.length > 0) {
                diagnostics.push(...(res as any).diagnostics);
            }
        }

        const errs = diagnostics.filter((d: any) => d && d.category === ts.DiagnosticCategory.Error);
        if (errs.length === 0) return { ok: true, diagnostics: '' };

        return {
            ok: false,
            diagnostics: this.formatTypeScriptDiagnostics(ts, errs).slice(0, 6000),
        };
    }

    private tryGetTypeScript(): TypeScriptModule | null {
        try {
            // eslint-disable-next-line @typescript-eslint/no-var-requires
            return require('typescript') as TypeScriptModule;
        } catch {
            return null;
        }
    }

    private formatTypeScriptDiagnostics(ts: TypeScriptModule, diags: any[]): string {
        const lines: string[] = [];
        for (const d of diags.slice(0, 50)) {
            const msg = ts.flattenDiagnosticMessageText(d.messageText, '\n');
            const code = d.code ? `TS${d.code}` : 'TS';

            if (d.file && typeof d.start === 'number') {
                const pos = d.file.getLineAndCharacterOfPosition(d.start);
                const fileName = String(d.file.fileName || '');
                lines.push(`${fileName}:${pos.line + 1}:${pos.character + 1} ${code}: ${msg}`);
            } else {
                lines.push(`${code}: ${msg}`);
            }
        }
        return lines.join('\n');
    }

    private sliceContext(
        request: TransformRequest,
        upstreamContent: Buffer,
        logs: string[]
    ): {
        contextPayload: string;
        tokensRequested: number;
        tokensSent: number;
        truncationRatio: number;
        contextHash: string;
    } {
        const slicer = new ContextSlicer({
            tokenBudget: request.tokenBudget,
            truncationWarnThreshold: this.TRUNCATION_WARN_THRESHOLD * 100,
            truncationFailThreshold: this.TRUNCATION_FAIL_THRESHOLD * 100,
        });

        // Include ALL inputs (not just first) with descending priority
        const artifacts: ContextArtifact[] = request.inputs.map((inp, idx) => {
            const contentStr = inp.content.toString('utf-8');
            const priority = Math.max(1, 10 - idx);
            return {
                id: `input_${idx}:${inp.kind}`,
                content: contentStr,
                priority,
                estimatedTokens: slicer.estimateTokens(contentStr),
                kind: inp.kind,
            };
        });

        // Keep stable alias for primary upstream
        if (artifacts.length > 0) {
            artifacts[0].id = 'upstream';
            artifacts[0].priority = 10;
        }

        // MS5 invariants always included
        const result = slicer.sliceContext(this.ms5Invariants, artifacts, request.targetId);

        logs.push(
            `Context sliced: ${result.tokensSent}/${result.tokensRequested} tokens (${(result.truncationRatio * 100).toFixed(1)}% truncation)`
        );

        return result;
    }

    private getArtifactKind(transformType: TransformType): ArtifactKind {
        switch (transformType) {
            case 'ms5_to_ms4':
                return 'ms4';
            case 'ms4_to_ms3':
                return 'ms3';
            case 'ms3_to_ms2':
                return 'ms2';
            case 'ms2_to_ms2_5':
                return 'ms2_5';
            case 'ms2_5_to_ms3':
                return 'ms3';
            case 'intent_to_ms5':
                return 'ms5';
        }
    }

    private estimateCost(usage: { promptTokens: number; completionTokens: number }): number {
        // Cost estimation - configurable via env vars, defaults to DeepSeek pricing
        const costPerMillionPrompt = parseFloat(process.env.DIRECTOR_COST_PROMPT_PER_M || '3.0');
        const costPerMillionCompletion = parseFloat(process.env.DIRECTOR_COST_COMPLETION_PER_M || '15.0');

        return (
            (usage.promptTokens / 1000000) * costPerMillionPrompt +
            (usage.completionTokens / 1000000) * costPerMillionCompletion
        );
    }

    private extractTargetLanguage(contextPayload: string): string | null {
        const patterns = [
            /target_language["']?\s*[:=]\s*["']?(\w+)/i,
            /--to\s+(\w+)/i,
            /Target:\s*(\w+)/i,
            /language["']?\s*[:=]\s*["']?(\w+)/i,
        ];
        for (const pattern of patterns) {
            const match = contextPayload.match(pattern);
            if (match) {
                const lang = match[1].toLowerCase();
                if (['rust', 'go', 'python', 'typescript', 'javascript', 'java', 'csharp', 'c#', 'cpp', 'c++'].includes(lang)) {
                    return lang === 'c#' ? 'csharp' : lang === 'c++' ? 'cpp' : lang;
                }
            }
        }
        return null;
    }

    private getLanguageInstructions(lang: string): string {
        const instructions: Record<string, string> = {
            typescript: `GOAL: Production-ready Node.js/TypeScript implementation.
                    - Include 'package.json' with dependencies AND @types packages.
                    - Include 'tsconfig.json' with "strict": true.
                    - Use async/await for asynchronous operations.
                    - File extensions: .ts`,
            rust: `GOAL: Production-ready Rust implementation.
                    - Include 'Cargo.toml' with dependencies.
                    - Use Result<T, E> for error handling.
                    - Use proper ownership and borrowing.
                    - Implement traits where appropriate.
                    - File extensions: .rs
                    - Main file: src/lib.rs or src/main.rs`,
            go: `GOAL: Production-ready Go implementation.
                    - Include 'go.mod' with module name.
                    - Use error returns (not panic) for error handling.
                    - Use interfaces for abstraction.
                    - Follow Go naming conventions (exported = capitalized).
                    - File extensions: .go`,
            python: `GOAL: Production-ready Python implementation.
                    - Include 'requirements.txt' or 'pyproject.toml'.
                    - Use type hints throughout.
                    - Use dataclasses or Pydantic for data models.
                    - Use try/except for error handling.
                    - File extensions: .py`,
            java: `GOAL: Production-ready Java implementation.
                    - Include 'pom.xml' or 'build.gradle'.
                    - Use proper package structure.
                    - Use exceptions for error handling.
                    - File extensions: .java`,
            csharp: `GOAL: Production-ready C# implementation.
                    - Include '.csproj' file.
                    - Use async/await for asynchronous operations.
                    - Use exceptions for error handling.
                    - File extensions: .cs`,
        };
        return instructions[lang] || instructions.typescript;
    }

    /**
     * Validate MS3 contract against tier-specific requirements
     * 
     * @param ms3 - The MS3 artifact containing DOES, DENIES, and METHODS
     * @param tier - The DirectorTier to validate against (toy, personal, experimental, production, enterprise)
     * @returns TierContractResult with violations array (severity: 'error' | 'warning')
     */
    validateTierContract(ms3: { DOES?: string[]; DENIES?: string[]; METHODS?: string[] }, tier: DirectorTier): TierContractResult {
        const violations: TierContractViolation[] = [];
        const does = ms3.DOES || [];
        const denies = ms3.DENIES || [];
        const methods = ms3.METHODS || [];

        const checks: Record<string, (d: string[], n: string[], m: string[]) => boolean> = {
            'All public interfaces have type signatures': (_, __, m) =>
                m.length > 0 && m.every(sig => sig.includes(':') || sig.includes('interface') || sig.includes('type')),
            'Error modes enumerated for core behaviors': (d, _, m) =>
                m.some(sig => sig.toLowerCase().includes('error')) || d.some(s => s.toLowerCase().includes('error')),
            'No hardcoded secrets': (_, n, __) =>
                n.some(s => s.toLowerCase().includes('secret') || s.toLowerCase().includes('credential') || s.toLowerCase().includes('hardcod')),
            'Config sources explicit (env, file, or defaults)': (d, _, m) =>
                d.some(s => s.toLowerCase().includes('config') || s.toLowerCase().includes('environment')) ||
                m.some(s => s.toLowerCase().includes('config')),
            'Tests present for core logic': (d, _, __) =>
                d.some(s => s.toLowerCase().includes('test')),
            'Deterministic startup (no race conditions)': (d, n, __) =>
                d.some(s => s.toLowerCase().includes('startup') || s.toLowerCase().includes('initialize')) ||
                n.some(s => s.toLowerCase().includes('race')),
            'Graceful shutdown handling': (d, _, m) =>
                d.some(s => s.toLowerCase().includes('shutdown') || s.toLowerCase().includes('cleanup') || s.toLowerCase().includes('close')) ||
                m.some(s => s.toLowerCase().includes('close') || s.toLowerCase().includes('shutdown')),
            'Input validation on all public interfaces': (d, n, __) =>
                d.some(s => s.toLowerCase().includes('validat')) || n.some(s => s.toLowerCase().includes('invalid')),
            'Logging for errors and key operations': (d, _, __) =>
                d.some(s => s.toLowerCase().includes('log')),
            'Threat model documented': (_, n, __) =>
                n.filter(s => s.toLowerCase().includes('must not') &&
                    (s.toLowerCase().includes('attack') || s.toLowerCase().includes('inject') ||
                     s.toLowerCase().includes('unauthorized') || s.toLowerCase().includes('bypass'))).length >= 2,
            'Audit trail for security-relevant operations': (d, _, __) =>
                d.some(s => s.toLowerCase().includes('audit') || s.toLowerCase().includes('trace')),
            'Dependency versions pinned': (d, n, __) =>
                d.some(s => s.toLowerCase().includes('pin') || s.toLowerCase().includes('version')) ||
                n.some(s => s.toLowerCase().includes('floating')),
            'Defense-in-depth (multiple validation layers)': (d, n, __) =>
                (d.filter(s => s.toLowerCase().includes('validat')).length >= 2) ||
                (n.filter(s => s.toLowerCase().includes('must not')).length >= 3),
            'Explicit failure modes for all external dependencies': (d, _, m) =>
                d.some(s => s.toLowerCase().includes('failure') || s.toLowerCase().includes('fallback')) ||
                m.some(s => s.toLowerCase().includes('error') && s.toLowerCase().includes('external')),
            'Rate limiting or resource bounds on public interfaces': (d, n, __) =>
                d.some(s => s.toLowerCase().includes('rate') || s.toLowerCase().includes('limit') || s.toLowerCase().includes('bound')) ||
                n.some(s => s.toLowerCase().includes('unbounded')),
        };

        const tierRequirements: Record<DirectorTier, { must: string[]; should: string[] }> = {
            toy: { must: [], should: [] },
            personal: {
                must: ['Basic error handling present'],
                should: ['Config sources explicit (env, file, or defaults)']
            },
            experimental: {
                must: [
                    'All public interfaces have type signatures',
                    'Error modes enumerated for core behaviors',
                    'Config sources explicit (env, file, or defaults)',
                    'No hardcoded secrets'
                ],
                should: ['Tests present for core logic', 'Logging for errors and key operations', 'Input validation on all public interfaces']
            },
            production: {
                must: [
                    'All public interfaces have type signatures',
                    'Error modes enumerated for core behaviors',
                    'Config sources explicit (env, file, or defaults)',
                    'No hardcoded secrets',
                    'Tests present for core logic',
                    'Deterministic startup (no race conditions)',
                    'Graceful shutdown handling',
                    'Input validation on all public interfaces',
                    'Logging for errors and key operations'
                ],
                should: ['Dependency versions pinned']
            },
            enterprise: {
                must: [
                    'All public interfaces have type signatures',
                    'Error modes enumerated for core behaviors',
                    'Config sources explicit (env, file, or defaults)',
                    'No hardcoded secrets',
                    'Tests present for core logic',
                    'Deterministic startup (no race conditions)',
                    'Graceful shutdown handling',
                    'Input validation on all public interfaces',
                    'Logging for errors and key operations',
                    'Threat model documented',
                    'Audit trail for security-relevant operations',
                    'Dependency versions pinned',
                    'Defense-in-depth (multiple validation layers)',
                    'Explicit failure modes for all external dependencies',
                    'Rate limiting or resource bounds on public interfaces'
                ],
                should: []
            }
        };

        const reqs = tierRequirements[tier];

        for (const inv of reqs.must) {
            const checkFn = checks[inv];
            if (checkFn && !checkFn(does, denies, methods)) {
                violations.push({ invariant: inv, severity: 'error', tier });
            }
        }

        for (const inv of reqs.should) {
            const checkFn = checks[inv];
            if (checkFn && !checkFn(does, denies, methods)) {
                violations.push({ invariant: inv, severity: 'warning', tier });
            }
        }

        return {
            passed: violations.filter(v => v.severity === 'error').length === 0,
            violations
        };
    }
}

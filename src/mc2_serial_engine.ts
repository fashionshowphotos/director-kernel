import * as crypto from 'crypto';
import { ModelRouter, ModelResponse } from './model_router';
import { SchemaValidator } from './schema_validator';
import { ModelRegistry } from './model_registry';
import { createLogger } from './logger';
import { MAX_OUTPUT_TOKENS } from './config';
import {
    MC2IterationRequest,
    StageStatus,
    MC2Artifact,
    MC2AuditRecord,
    Objection,
    MC2IterationResponse,
    ModelStatus
} from './mc2_types';

const log = createLogger('mc2');

export class MC2SerialEngine {
    private modelRouter: ModelRouter;
    private schemaValidator: SchemaValidator;
    private modelRegistry: ModelRegistry;

    constructor(apiKey: string) {
        this.modelRouter = new ModelRouter({ apiKey });
        this.schemaValidator = new SchemaValidator();
        this.modelRegistry = ModelRegistry.getInstance();
    }

    /**
     * MC2-I1, MC2-I2, MC2-I4: Serial iteration with kernel authority
     */
    async executeStage(request: MC2IterationRequest): Promise<{
        status: StageStatus;
        final_artifact: MC2Artifact;
        audit: MC2AuditRecord;
    }> {
        const audit: MC2AuditRecord = {
            stage_id: request.stage_id,
            models_used: [],
            iterations: 0,
            stage_status: 'FAILED', // Assume fail until proven complete
            termination_reason: 'max_iterations_reached',
            final_objections: [],
            total_cost: 0
        };

        let currentArtifact = request.initial_artifact;
        let openObjections: Objection[] = [];
        let iterationIndex = 0;

        // MC2 Gate 3: Track all objections (open + resolved) for history
        const objectionHistory: { objection: Objection; resolved: boolean }[] = [];

        // MC2 Loop: Serial execution, one model at a time
        while (iterationIndex < request.max_iterations) {
            const activeModelId = request.model_sequence[iterationIndex % request.model_sequence.length];
            audit.models_used.push(activeModelId);

            log.info(`Iteration ${iterationIndex + 1}/${request.max_iterations}`, { model: activeModelId });

            const response = await this.callModelIteration(
                activeModelId,
                currentArtifact,
                openObjections,
                request.stage_goal,
                iterationIndex,
                request.stage_id,
                request.governance_bundle,
                objectionHistory
            );

            audit.iterations++;
            // MC2: cost is observational only
            // MC2.5+ may enforce limits
            audit.total_cost += response.cost_usd;

            // MC2-I3: Handle model refusal
            // MC2 Refinement: REFUSE = "skip this model, try next", only fail on max_iterations
            if (response.status === 'REFUSE') {
                audit.termination_reason = `model_refused:${activeModelId}`; // Log refusal
                log.warn(`Model refused`, { model: activeModelId, reason: response.reasoning });
                iterationIndex++;
                continue;
            }

            // Update artifact
            currentArtifact = response.artifact;

            // MC2 Refinement: Enforce Schema Validation in Kernel
            try {
                const jsonContent = JSON.parse(currentArtifact.content.toString('utf-8'));
                const schemaResult = this.schemaValidator.validate(
                    jsonContent,
                    currentArtifact.kind
                );

                if (!schemaResult.valid) {
                    const errorMsg = schemaResult.errors.map(e => `${e.path}: ${e.message}`).join(', ');
                    response.new_objections.push({
                        id: `schema:kernel:${iterationIndex}`,
                        category: 'SCHEMA',
                        severity: 'CRITICAL',
                        message: `Kernel Schema Validation Failed: ${errorMsg}`,
                        raised_by_model: 'kernel',
                        iteration_index: iterationIndex
                    });
                }

                // MC2 Gate 2: AST Validation for MS2 Code Artifacts
                if (currentArtifact.kind === 'ms2' && jsonContent.files) {
                    for (const file of jsonContent.files) {
                        if (file.path?.endsWith('.ts') || file.path?.endsWith('.tsx')) {
                            const syntaxErrors = this.validateTypescriptSyntax(file.content, file.path);
                            if (syntaxErrors.length > 0) {
                                response.new_objections.push({
                                    id: this.computeHash(Buffer.from(`syntax:${file.path}:${iterationIndex}`)),
                                    category: 'SCHEMA', // Syntax is pre-semantic, so treated as schema
                                    severity: 'CRITICAL',
                                    message: `Syntax Error in ${file.path}: ${syntaxErrors.join('; ')}`,
                                    raised_by_model: 'kernel',
                                    iteration_index: iterationIndex
                                });
                            }
                        }
                    }
                }
            } catch (e) {
                // If not JSON, cannot validate against JSON schema, or might be invalid JSON
                // If kind is expected to be JSON, this is a SCHEMA error
                if (['ms2', 'ms3', 'ms4', 'ms5'].includes(currentArtifact.kind)) {
                    response.new_objections.push({
                        id: `schema:kernel:parse:${iterationIndex}`,
                        category: 'SCHEMA',
                        severity: 'CRITICAL',
                        message: `Invalid JSON artifact: ${(e as Error).message}`,
                        raised_by_model: 'kernel',
                        iteration_index: iterationIndex
                    });
                }
            }

            // MC2-I4: Merge and resolve objections
            openObjections = this.updateObjections(
                openObjections,
                response.new_objections,
                response.resolved_objections,
                activeModelId,
                iterationIndex
            );

            // MC2 Gate 3: Update objection history (add new, mark resolved)
            for (const newObj of response.new_objections) {
                if (!objectionHistory.some(h => h.objection.id === newObj.id)) {
                    objectionHistory.push({ objection: newObj, resolved: false });
                }
            }
            for (const historyEntry of objectionHistory) {
                if (response.resolved_objections.includes(historyEntry.objection.id)) {
                    historyEntry.resolved = true;
                }
            }

            // MC2-Completeness Rule: Success when COMPLETE + no objections
            if (response.status === 'COMPLETE' && openObjections.length === 0) {
                audit.stage_status = 'COMPLETE';
                audit.termination_reason = 'success';
                break;
            }

            iterationIndex++;
        }

        // Capture final state
        audit.final_objections = openObjections; // Only open ones remain
        // audit.iterations is already correct from loop increment

        return {
            status: audit.stage_status,
            final_artifact: currentArtifact,
            audit
        };
    }

    /**
     * MC2: Single model call per iteration
     */
    private async callModelIteration(
        modelId: string,
        artifact: MC2Artifact,
        objections: Objection[],
        stageGoal: string,
        iterationIndex: number,
        stageId: string,
        governanceBundle?: any,
        objectionHistory?: { objection: Objection; resolved: boolean }[]
    ): Promise<MC2IterationResponse> {
        const modelInfo = this.modelRegistry.getModelInfo(modelId);
        if (!modelInfo) {
            log.warn(`Model not found in registry, using defaults`, { model: modelId });
        }

        // Baton Construction
        const baton = {
            stage_id: stageId,
            artifact_sha_before: artifact.hash,
            artifact_sha_after: 'PENDING', // Model must calculate/match this
            objection_ids_open_before: objections.map(o => o.id).sort(),
            objection_ids_open_after: [],
            iteration_index: iterationIndex,
            model_id: modelId,
            mc_bundle_sha: governanceBundle?.bundle_sha
        };

        const prompt = this.buildIterationPrompt(artifact, objections, stageGoal, modelId, iterationIndex, baton, governanceBundle, objectionHistory);

        const result = await this.modelRouter.executeModelCall({
            model_id: modelId,
            messages: [
                { role: 'system', content: prompt },
                { role: 'user', content: `Iteration ${iterationIndex + 1}: Continue stage execution.` }
            ],
            temperature: 0.3,
            max_tokens: MAX_OUTPUT_TOKENS.MC2_LOOP
        });

        if (!result.ok || ('errorCode' in result)) {
            const err = result as any;
            const msg = err.message || 'Unknown error';
            return {
                status: 'REFUSE',
                artifact,
                new_objections: [],
                resolved_objections: [],
                baton,
                reasoning: `Model call failed: ${msg}`,
                cost_usd: 0,
                tokens_used: 0
            };
        }

        return this.parseIterationResponse(result.completion, modelId, iterationIndex, baton);
    }

    /**
     * MC2: Build prompt with current state
     */
    private buildIterationPrompt(
        artifact: MC2Artifact,
        objections: Objection[],
        stageGoal: string,
        modelId: string,
        iterationIndex: number,
        baton: any,
        governanceBundle?: any,
        objectionHistory?: { objection: Objection; resolved: boolean }[]
    ): string {
        const objectionStr = objections.length > 0
            ? `Current Objections:\n${objections.map(o => `- [${o.category}] ${o.message} (ID: ${o.id})`).join('\n')}`
            : 'No objections currently.';

        // MC2 Gate 3: Objection History (prevents regression)
        const historyStr = objectionHistory && objectionHistory.length > 0
            ? `OBJECTION HISTORY (All objections raised this stage):\n${objectionHistory.map(h => {
                const status = h.resolved ? '[RESOLVED]' : '[OPEN]';
                return `- ${status} ${h.objection.category}: ${h.objection.message} (Iteration ${h.objection.iteration_index})`;
            }).join('\n')}`
            : '';

        const artifactContent = artifact.content.toString('utf-8');

        const governanceStr = governanceBundle ? `
GOVERNANCE BUNDLE (MUST FOLLOW):
MC_BUNDLE_SHA: ${governanceBundle.bundle_sha}

MC4_CONSTITUTION:
${JSON.stringify(governanceBundle.mc4, null, 2)}

MC3_INDEX:
${JSON.stringify(governanceBundle.mc3_index, null, 2)}

MC3_PACKETS:
${JSON.stringify(governanceBundle.packets, null, 2)}
` : 'No governance bundle provided.';

        return `You are a software engineer working on: ${stageGoal}

Current Artifact (${artifact.kind}):
\`\`\`
${artifactContent}
\`\`\`

${objectionStr}

${historyStr}

${governanceStr}

SECURITY BATON (MUST ROUND TRIP):
${JSON.stringify(baton)}

Your task:
1. Review the artifact and objections.
2. Produce an improved artifact that solves the goal and addresses objections.
3. Declare status: COMPLETE, INCOMPLETE, or REFUSE.
4. Optionally raise new objections or resolve existing ones by ID.
5. RETURN THE BATON EXACTLY AS IS, but update 'artifact_sha_after' to match your NEW artifact hash.

Output JSON ONLY:
{
  "status": "COMPLETE" | "INCOMPLETE" | "REFUSE",
  "baton": { ...same object, but update artifact_sha_after ... },
  "artifact": { "content": "...", "kind": "...", "hash": "..." },
  "new_objections": [ { "category": "LOGIC"|"SECURITY"|"STYLE"|"SCHEMA", "severity": "CRITICAL"|"HIGH"|"MEDIUM", "message": "..." } ],
  "resolved_objections": ["id1", "id2"],
  "reasoning": "explanation"
}

Rules:
- REFUSE only if you cannot make progress.
- COMPLETE only if artifact is correct AND no objections remain.
- Objection IDs will be generated by kernel based on hash(category+message).
`;
    }

    private parseIterationResponse(
        raw: string,
        modelId: string,
        iterationIndex: number,
        expectedBaton: any
    ): MC2IterationResponse {
        try {
            let cleaned = raw.trim();
            if (cleaned.startsWith('```')) {
                cleaned = cleaned.replace(/^```[a-z]*\n/, '').replace(/\n```$/, '');
            }
            const parsed = JSON.parse(cleaned);

            // Normalize status
            const status = ['COMPLETE', 'INCOMPLETE', 'REFUSE'].includes(parsed.status)
                ? parsed.status as ModelStatus
                : 'INCOMPLETE';

            const contentStr = parsed.artifact?.content || '';
            const contentBuf = Buffer.from(contentStr, 'utf-8');
            const artifactHash = this.computeHash(contentBuf);

            // Stable Objection IDs
            const new_objections = (parsed.new_objections || []).map((o: any) => {
                const stableId = this.computeHash(Buffer.from(`${o.category}:${o.message}`));
                return {
                    id: stableId,
                    category: o.category,
                    severity: o.severity,
                    message: o.message,
                    raised_by_model: modelId,
                    iteration_index: iterationIndex
                };
            });

            // Baton Integrity Check
            const receivedBaton = parsed.baton || {};
            const batonErrors: string[] = [];

            if (receivedBaton.stage_id !== expectedBaton.stage_id) batonErrors.push('stage_id mismatch');
            if (receivedBaton.artifact_sha_before !== expectedBaton.artifact_sha_before) batonErrors.push('artifact_sha_before mismatch');
            if (receivedBaton.iteration_index !== expectedBaton.iteration_index) batonErrors.push('iteration_index mismatch');
            if (receivedBaton.model_id !== expectedBaton.model_id) batonErrors.push('model_id mismatch');
            if (receivedBaton.mc_bundle_sha !== expectedBaton.mc_bundle_sha) batonErrors.push('mc_bundle_sha mismatch');

            // Check artifact integrity if declared
            if (contentStr.length > 0 && receivedBaton.artifact_sha_after !== artifactHash) {
                batonErrors.push(`artifact_sha_after mismatch (expected ${artifactHash}, got ${receivedBaton.artifact_sha_after})`);
            }

            if (batonErrors.length > 0) {
                new_objections.push({
                    id: this.computeHash(Buffer.from(`security:baton:${iterationIndex}`)),
                    category: 'SECURITY',
                    severity: 'CRITICAL',
                    message: `Baton Integrity Failed: ${batonErrors.join(', ')}`,
                    raised_by_model: 'kernel',
                    iteration_index: iterationIndex
                });
            }

            return {
                status,
                artifact: {
                    content: contentBuf,
                    kind: parsed.artifact?.kind || 'unknown',
                    hash: artifactHash
                },
                new_objections,
                resolved_objections: parsed.resolved_objections || [],
                baton: receivedBaton,
                reasoning: parsed.reasoning || '',
                cost_usd: this.estimateCost(modelId, contentStr),
                tokens_used: 0
            };
        } catch (e) {
            log.error(`Failed to parse model response`, { error: String(e) });
            return {
                status: 'REFUSE',
                artifact: { content: Buffer.from(''), kind: 'error', hash: '' },
                new_objections: [],
                resolved_objections: [],
                baton: expectedBaton,
                reasoning: `Parse error: ${String(e)}`,
                cost_usd: 0,
                tokens_used: 0
            };
        }
    }

    /**
     * MC2-I4: Objection persistence and update logic
     */
    private updateObjections(
        current: Objection[],
        newOnes: Objection[],
        resolvedIds: string[],
        modelId: string,
        iterationIndex: number
    ): Objection[] {
        // Remove resolved objections
        const updated = current.filter(o => !resolvedIds.includes(o.id));

        // Add new objections (dedupe by ID)
        for (const obj of newOnes) {
            if (!updated.some(o => o.id === obj.id)) {
                updated.push(obj);
            }
        }

        return updated;
    }

    private computeHash(content: Buffer): string {
        return crypto.createHash('sha256').update(content).digest('hex');
    }

    private estimateCost(modelId: string, content: string): number {
        const model = this.modelRegistry.getModelInfo(modelId);
        if (!model) return 0;

        const tokens = Math.ceil(content.length / 4);
        return (tokens / 1000000) * model.pricing.prompt; // Pricing is per million
    }

    /**
     * MC2 Gate 2: Lightweight AST validation for TypeScript files.
     * Returns an array of syntax error messages. Empty = valid.
     */
    private validateTypescriptSyntax(content: string, fileName: string): string[] {
        try {
            // Dynamic import to avoid hard dependency
            const ts = require('typescript');
            const sourceFile = ts.createSourceFile(
                fileName,
                content,
                ts.ScriptTarget.Latest,
                true // setParentNodes
            );

            // Check for parse diagnostics
            const errors: string[] = [];
            if (sourceFile.parseDiagnostics && sourceFile.parseDiagnostics.length > 0) {
                for (const diag of sourceFile.parseDiagnostics) {
                    const msg = ts.flattenDiagnosticMessageText(diag.messageText, '\n');
                    errors.push(`L${diag.start !== undefined ? Math.floor(diag.start / 80) + 1 : '?'}: ${msg}`);
                }
            }
            return errors;
        } catch (e) {
            // If typescript is not available, log warning and skip AST check
            log.warn(`TypeScript AST validation skipped (ts not available)`, { error: (e as Error).message });
            return [];
        }
    }
}

export type ModelStatus = 'COMPLETE' | 'INCOMPLETE' | 'REFUSE';
export type StageStatus = 'COMPLETE' | 'FAILED';

export interface Baton {
    stage_id: string;
    artifact_sha_before: string;
    artifact_sha_after: string; // Model must verify this specific transition
    objection_ids_open_before: string[];
    objection_ids_open_after: string[];
    iteration_index: number;
    model_id: string;
    mc_bundle_sha?: string; // Governance: version binding
}

export interface Objection {
    id: string; // stable identifier: hash(category+message)
    category: 'SCHEMA' | 'STUB' | 'LOGIC' | 'SECURITY' | 'GOVERNANCE' | 'CONTRACT';
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    message: string;
    raised_by_model: string;
    iteration_index: number;
}

export interface MC2Artifact {
    content: Buffer;
    kind: string; // 'ms2', 'ms3', etc.
    hash: string;
}

export interface GovernanceBundle {
    mc4: any;
    mc3_index: any;
    packets: any[];
    bundle_sha: string;
}

export interface MC2IterationRequest {
    stage_id: string;
    stage_goal: string;
    initial_artifact: MC2Artifact;
    model_sequence: string[]; // MC2: human-selected order
    max_iterations: number;
    governance_bundle?: GovernanceBundle;
}

export interface MC2IterationResponse {
    status: ModelStatus;
    artifact: MC2Artifact;
    new_objections: Objection[];
    resolved_objections: string[]; // Objection IDs to remove
    baton: Baton; // REQUIRED: Round-trip integrity
    reasoning: string;
    cost_usd: number;
    tokens_used: number;
}

export interface MC2AuditRecord {
    stage_id: string;
    models_used: string[];
    iterations: number;
    stage_status: StageStatus;
    termination_reason: string;
    final_objections: Objection[];
    total_cost: number;
}

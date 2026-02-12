// src/output_writer/types.ts

export type OperatorMode = "AGENT" | "HUMAN";

export type OutputItem =
    | {
        kind: "FILE_TEXT";
        rel_path: string;
        content_utf8: string;
        perm: "0644" | "0755";
    }
    | {
        kind: "FILE_BYTES_B64";
        rel_path: string;
        content_b64: string;
        perm: "0644" | "0755";
    }
    | { kind: "DELETE"; rel_path: string }
    | {
        kind: "PATCH_BUNDLE";
        rel_path: "patch_bundle.json";
        bundle: PatchBundleV1;
    };

export type PatchStatus = "PENDING" | "APPLIED" | "FAILED";

export interface PatchItemV1 {
    patch_id: string; // stable identifier
    desc: string;
    format: "UNIFIED_DIFF";
    target_rel_path: string; // within files/
    diff_utf8: string;
    status: PatchStatus; // REQUIRED
    applied_utc?: string | null;
    failed_utc?: string | null;
    failure_reason?: string | null;
}

export interface PatchBundleV1 {
    schema_version: "patch-bundle-v1";
    build_id: string;
    patches: PatchItemV1[];
}

export interface BuildPlanV1 {
    schema_version: "build-plan-v1";
    project: string;
    build_id: string;
    created_utc: string;
    source: {
        ms4_hash?: string;
        ms3_hash?: string;
        ms2_hash?: string;
        agent?: { name: string; version?: string };
    };
    items: OutputItem[];
    bounds: {
        max_total_bytes: number;
        max_file_bytes: number;
        max_files: number;
        max_path_len: number;
        envelope_retention_count: number;
    };
    latest_pointer: {
        enabled: boolean;
        path: "output/<project>/_index/latest.json";
    };
    verify: {
        compute_checksums: boolean;
        fsync: "BEST_EFFORT" | "REQUIRED";
    };
}

export interface BuildManifestV1 {
    schema_version: "build-manifest-v1";
    project: string;
    build_id: string;
    created_utc: string;
    committed_utc?: string;

    plan_hash: string;

    output_root: string;
    files_root: string;

    dirs_index: Array<{ path: string; perm: "0755" }>;
    files_index: Array<{
        rel_path: string; // relative to files_root
        perm: "0644" | "0755";
        bytes: number;
        sha256?: string;
        kind: "FILE_TEXT" | "FILE_BYTES_B64";
    }>;
    deletes_index: Array<{ rel_path: string }>;

    patch_bundle?: {
        present: boolean;
        patch_count: number;
        applied_count: number;
        failed_count: number;
    };

    pointers: {
        latest_json_written: boolean;
        latest_json_committed_flag?: boolean;
    };

    stats: {
        total_bytes: number;
        file_count: number;
        dir_count: number;
    };
}

export type OutputWriterErrorCode =
    | "INVALID_PROJECT"
    | "INVALID_BUILD_ID"
    | "INVALID_REL_PATH"
    | "PATH_TRAVERSAL"
    | "SYMLINK_REJECTED"
    | "BOUNDS_EXCEEDED"
    | "DISK_FULL"
    | "IO_ERROR"
    | "LOCK_HELD"
    | "PATCH_APPLY_FAILED"
    | "POINTER_UPDATE_FAILED"
    | "COMMIT_RENAME_FAILED"
    | "LATEST_POINTER_NOT_FINALIZED"
    | "VERIFY_FAILED"
    | "INTERNAL";

export interface RecoveryAction {
    action: string;
    command: string;
    risk: "none" | "low" | "medium" | "high";
}

export interface OutputWriterError {
    code: OutputWriterErrorCode;
    message: string;
    details?: Record<string, any>;
    recovery_actions?: RecoveryAction[];
}

export interface WriteResult {
    ok: true;
    project: string;
    build_id: string;
    committed_path: string;
    manifest_path: string;
    warnings: string[];
}

export interface WriteOptions {
    operator_mode: OperatorMode;
    now_utc_iso?: string;

    auto_cleanup_staging?: boolean;
    staging_ttl_ms?: number;

    lock_timeout_ms?: number;
    lock_stale_ttl_ms?: number; // 600,000 (10m)

    allow_symlinks?: false;
}

export interface OutputWriter {
    write(
        plan: BuildPlanV1,
        opts: WriteOptions
    ): Promise<WriteResult | { ok: false; error: OutputWriterError }>;
}

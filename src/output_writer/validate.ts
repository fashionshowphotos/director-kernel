// src/output_writer/validate.ts

import * as path from "path";
import { BuildPlanV1, OutputItem, OutputWriterError, OutputWriterErrorCode } from "./types";

const SAFE_SLUG_RE = /^[a-zA-Z0-9._-]{1,80}$/;

function fail(code: OutputWriterErrorCode, message: string, details?: any): never {
    const err: OutputWriterError = { code, message, details };
    throw err;
}

export function isPathTraversal(relPath: string): boolean {
    // reject absolute unix or windows drive
    if (path.isAbsolute(relPath)) return true;
    if (/^[a-zA-Z]:[\\/]/.test(relPath)) return true;

    const parts = relPath.split(/[\\/]+/);
    for (const p of parts) {
        if (p === "..") return true;
    }
    return false;
}

export function validateSlugOrThrow(kind: "project" | "build_id", v: string): void {
    if (!SAFE_SLUG_RE.test(v)) {
        fail(kind === "project" ? "INVALID_PROJECT" : "INVALID_BUILD_ID", `Invalid ${kind}`, {
            value: v,
            regex: SAFE_SLUG_RE.source,
        });
    }
    if (v === "." || v === "..") {
        fail(kind === "project" ? "INVALID_PROJECT" : "INVALID_BUILD_ID", `Invalid ${kind}`, {
            value: v,
        });
    }
}

export function validateRelPathOrThrow(
    plan: BuildPlanV1,
    rel_path: string,
    kind: "FILE" | "DELETE"
): void {
    if (typeof rel_path !== "string" || rel_path.length === 0) {
        fail("INVALID_REL_PATH", "rel_path must be non-empty string", { rel_path });
    }

    if (Buffer.from(rel_path, "utf8").length > plan.bounds.max_path_len) {
        fail("INVALID_REL_PATH", "rel_path exceeds max_path_len", {
            rel_path,
            max_path_len: plan.bounds.max_path_len,
        });
    }

    if (isPathTraversal(rel_path)) {
        fail("PATH_TRAVERSAL", "Path traversal detected in rel_path", { rel_path });
    }

    // reserved
    if (rel_path.startsWith("_index/") || rel_path.startsWith("_index\\")) {
        fail("INVALID_REL_PATH", "rel_path cannot target reserved _index/", { rel_path });
    }

    if (!rel_path.startsWith("files/")) {
        fail("INVALID_REL_PATH", `${kind} rel_path must start with files/`, { rel_path, kind });
    }
}

export function validatePlanOrThrow(plan: BuildPlanV1): void {
    if (!plan || plan.schema_version !== "build-plan-v1") {
        fail("INTERNAL", "Invalid plan schema_version", { schema_version: plan?.schema_version });
    }

    validateSlugOrThrow("project", plan.project);
    validateSlugOrThrow("build_id", plan.build_id);

    // bounds sanity
    if (!plan.bounds || plan.bounds.max_total_bytes <= 0) {
        fail("INTERNAL", "Invalid bounds", { bounds: plan.bounds });
    }

    // count FILE_* items
    const fileItems = plan.items.filter((x) => x.kind === "FILE_TEXT" || x.kind === "FILE_BYTES_B64");
    if (fileItems.length > plan.bounds.max_files) {
        fail("BOUNDS_EXCEEDED", "Too many files", {
            file_count: fileItems.length,
            max_files: plan.bounds.max_files,
        });
    }

    // validate items
    let totalBytesEst = 0;
    for (const it of plan.items) {
        switch (it.kind) {
            case "FILE_TEXT": {
                validateRelPathOrThrow(plan, it.rel_path, "FILE");
                const bytes = Buffer.from(it.content_utf8, "utf8").length;
                if (bytes > plan.bounds.max_file_bytes) {
                    fail("BOUNDS_EXCEEDED", "FILE_TEXT exceeds max_file_bytes", {
                        rel_path: it.rel_path,
                        bytes,
                        max_file_bytes: plan.bounds.max_file_bytes,
                    });
                }
                totalBytesEst += bytes;
                break;
            }

            case "FILE_BYTES_B64": {
                validateRelPathOrThrow(plan, it.rel_path, "FILE");
                let bytes = 0;
                try {
                    bytes = Buffer.from(it.content_b64, "base64").length;
                } catch {
                    fail("VERIFY_FAILED", "Invalid base64 content", { rel_path: it.rel_path });
                }
                if (bytes > plan.bounds.max_file_bytes) {
                    fail("BOUNDS_EXCEEDED", "FILE_BYTES_B64 exceeds max_file_bytes", {
                        rel_path: it.rel_path,
                        bytes,
                        max_file_bytes: plan.bounds.max_file_bytes,
                    });
                }
                totalBytesEst += bytes;
                break;
            }

            case "DELETE": {
                validateRelPathOrThrow(plan, it.rel_path, "DELETE");
                break;
            }

            case "PATCH_BUNDLE": {
                // TypeScript narrowing workaround
                const patchItem = it as Extract<OutputItem, { kind: "PATCH_BUNDLE" }>;

                // only file allowed is patch_bundle.json, and bundle must have status fields
                if (patchItem.rel_path !== "patch_bundle.json") {
                    fail("INVALID_REL_PATH", "PATCH_BUNDLE rel_path must be patch_bundle.json", {
                        rel_path: patchItem.rel_path,
                    });
                }
                if (!patchItem.bundle || patchItem.bundle.schema_version !== "patch-bundle-v1") {
                    fail("VERIFY_FAILED", "Invalid patch bundle schema_version", {
                        schema_version: patchItem.bundle?.schema_version,
                    });
                }
                for (const p of patchItem.bundle.patches) {
                    if (!p.status) {
                        fail("VERIFY_FAILED", "Patch missing status field", { patch_id: p.patch_id });
                    }
                    if (!p.target_rel_path.startsWith("files/")) {
                        fail("INVALID_REL_PATH", "Patch target_rel_path must start with files/", {
                            target_rel_path: p.target_rel_path,
                            patch_id: p.patch_id,
                        });
                    }
                    if (isPathTraversal(p.target_rel_path)) {
                        fail("PATH_TRAVERSAL", "Patch target_rel_path path traversal", {
                            patch_id: p.patch_id,
                            target_rel_path: p.target_rel_path,
                        });
                    }
                }
                break;
            }

            default: {
                // TypeScript exhaustiveness check
                const _exhaustive: never = it;
                fail("INTERNAL", "Unknown item kind", { item: _exhaustive });
            }
        }

        if (totalBytesEst > plan.bounds.max_total_bytes) {
            fail("BOUNDS_EXCEEDED", "Total bytes exceeds max_total_bytes", {
                total_bytes_est: totalBytesEst,
                max_total_bytes: plan.bounds.max_total_bytes,
            });
        }
    }
}

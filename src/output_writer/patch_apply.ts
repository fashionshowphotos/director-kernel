// src/output_writer/patch_apply.ts

import * as fs from "fs";

export interface PatchApplyResult {
    ok: boolean;
    error?: string;
}

// Minimal unified diff applier:
// - supports @@ hunks with line numbers
// - no fuzz matching
// - strict apply or fail
export function applyUnifiedDiffFile(params: {
    targetPath: string;
    diffUtf8: string;
}): PatchApplyResult {
    const { targetPath, diffUtf8 } = params;

    if (!fs.existsSync(targetPath)) {
        return { ok: false, error: `Target does not exist: ${targetPath}` };
    }

    const original = fs.readFileSync(targetPath, "utf8");
    const origLines = original.split("\n");

    const diffLines = diffUtf8.split("\n");

    // locate hunks
    const hunks: Array<{ header: string; lines: string[] }> = [];
    let i = 0;
    while (i < diffLines.length) {
        const line = diffLines[i];
        if (line.startsWith("@@")) {
            const header = line;
            i++;
            const lines: string[] = [];
            while (i < diffLines.length && !diffLines[i].startsWith("@@")) {
                // skip file headers ---/+++ (some patches include them before first hunk)
                if (diffLines[i].startsWith("---") || diffLines[i].startsWith("+++")) {
                    i++;
                    continue;
                }
                lines.push(diffLines[i]);
                i++;
            }
            hunks.push({ header, lines });
        } else {
            i++;
        }
    }

    if (hunks.length === 0) {
        return { ok: false, error: "No hunks found in diff" };
    }

    let working = origLines.slice();

    for (const hunk of hunks) {
        const m = hunk.header.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
        if (!m) return { ok: false, error: `Invalid hunk header: ${hunk.header}` };

        const oldStart = parseInt(m[1], 10) - 1; // 0-based
        let cursor = oldStart;

        const out: string[] = [];
        out.push(...working.slice(0, cursor));

        for (const dl of hunk.lines) {
            if (dl.startsWith(" ")) {
                const expected = dl.slice(1);
                const actual = working[cursor] ?? "";
                if (actual !== expected) {
                    return {
                        ok: false,
                        error: `Context mismatch at line ${cursor + 1}. expected="${expected}" actual="${actual}"`,
                    };
                }
                out.push(actual);
                cursor++;
            } else if (dl.startsWith("-")) {
                const expected = dl.slice(1);
                const actual = working[cursor] ?? "";
                if (actual !== expected) {
                    return {
                        ok: false,
                        error: `Delete mismatch at line ${cursor + 1}. expected="${expected}" actual="${actual}"`,
                    };
                }
                cursor++;
            } else if (dl.startsWith("+")) {
                out.push(dl.slice(1));
            } else if (dl === "\\ No newline at end of file") {
                // ignore
            } else {
                // unknown line kind
                return { ok: false, error: `Invalid diff line: ${dl}` };
            }
        }

        out.push(...working.slice(cursor));
        working = out;
    }

    fs.writeFileSync(targetPath, working.join("\n"), "utf8");
    return { ok: true };
}

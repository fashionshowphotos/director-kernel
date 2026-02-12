// src/output_writer/atomic_write.ts

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

type FsyncMode = "BEST_EFFORT" | "REQUIRED";

function isFatalBestEffort(code?: string): boolean {
    return code === "ENOSPC" || code === "EIO";
}

function isWarnBestEffort(code?: string): boolean {
    return code === "EPERM" || code === "EINVAL" || code === "EROFS";
}

// REQUIRED PATCH: warnings is REQUIRED (no optional)
export function atomicWriteFileSync(params: {
    filePath: string;
    content: Buffer | string;
    mode: number;
    fsyncMode: FsyncMode;
    warnings: string[];
}): void {
    const { filePath, content, mode, fsyncMode, warnings } = params;

    const tmp = `${filePath}.tmp.${crypto.randomBytes(4).toString("hex")}`;
    const dir = path.dirname(filePath);

    try {
        fs.mkdirSync(dir, { recursive: true, mode: 0o755 });

        // tmp always 0600 initially
        fs.writeFileSync(tmp, content, { mode: 0o600 });

        // fsync file (always attempt)
        try {
            const fd = fs.openSync(tmp, "r+");
            try {
                fs.fdatasyncSync(fd);
            } finally {
                fs.closeSync(fd);
            }
        } catch (e: any) {
            const code = e?.code as string | undefined;

            if (fsyncMode === "REQUIRED") {
                throw e;
            }

            // BEST_EFFORT rules
            if (isFatalBestEffort(code)) {
                throw e;
            }

            warnings.push(`FSYNC_WARN(${code || "UNKNOWN"}) on ${tmp}`);
        }

        fs.renameSync(tmp, filePath);
        // rename consumes tmp on POSIX — no extra cleanup needed

        fs.chmodSync(filePath, mode);

        // fsync directory (always attempt)
        try {
            const dirFd = fs.openSync(dir, "r");
            try {
                fs.fsyncSync(dirFd);
            } finally {
                fs.closeSync(dirFd);
            }
        } catch (e: any) {
            const code = e?.code as string | undefined;

            if (fsyncMode === "REQUIRED") throw e;
            if (isFatalBestEffort(code)) throw e;

            warnings.push(`FSYNC_WARN(${code || "UNKNOWN"}) on ${dir}`);
        }
    } catch (e) {
        // Temp cleanup best effort
        try {
            if (fs.existsSync(tmp)) fs.unlinkSync(tmp);
        } catch { }
        throw e;
    }
}

export function atomicWriteJsonSync(params: {
    filePath: string;
    data: any;
    mode: number;
    fsyncMode: FsyncMode;
    warnings: string[];
}): void {
    const json = JSON.stringify(params.data, null, 2);
    atomicWriteFileSync({
        filePath: params.filePath,
        content: json,
        mode: params.mode,
        fsyncMode: params.fsyncMode,
        warnings: params.warnings,
    });
}

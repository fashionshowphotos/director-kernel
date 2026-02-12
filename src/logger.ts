/**
 * Structured Logger — Enterprise logging for Director Kernel
 *
 * Features:
 * - Log levels: DEBUG, INFO, WARN, ERROR
 * - ISO timestamps on every entry
 * - Structured JSON output (JSONL) when DIRECTOR_LOG_JSON=1
 * - Optional file output via DIRECTOR_LOG_FILE
 * - Module context (component name) on every line
 * - Build correlation ID propagated through all log entries
 *
 * Environment:
 *   DIRECTOR_LOG_LEVEL  = debug|info|warn|error (default: info)
 *   DIRECTOR_LOG_JSON   = 1 (default: text)
 *   DIRECTOR_LOG_FILE   = path (optional, appends)
 *   DIRECTOR_DEBUG      = 1 (sets level to debug)
 */

import * as fs from 'fs';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };

const envLevel = (process.env.DIRECTOR_LOG_LEVEL || 'info').toLowerCase() as LogLevel;
const MIN_LEVEL: number = LEVEL_ORDER[envLevel] ?? 1;
const DEBUG_OVERRIDE = process.env.DIRECTOR_DEBUG === '1' || process.env.DIRECTOR_DEBUG === 'true';
const EFFECTIVE_MIN = DEBUG_OVERRIDE ? 0 : MIN_LEVEL;

const JSON_MODE = process.env.DIRECTOR_LOG_JSON === '1';
const LOG_FILE = process.env.DIRECTOR_LOG_FILE || '';

/* -------------------------------------------------------------------------- */
/* Build Correlation Context (thread-local style, singleton)                  */
/* -------------------------------------------------------------------------- */

let _correlationId: string = '';
let _buildId: string = '';
let _stage: string = '';
let _target: string = '';

/** Set the active build correlation context. Called by orchestrator at build start. */
export function setCorrelation(opts: { correlationId?: string; buildId?: string; stage?: string; target?: string }): void {
    if (opts.correlationId !== undefined) _correlationId = opts.correlationId;
    if (opts.buildId !== undefined) _buildId = opts.buildId;
    if (opts.stage !== undefined) _stage = opts.stage;
    if (opts.target !== undefined) _target = opts.target;
}

/** Clear correlation context. Called at build end. */
export function clearCorrelation(): void {
    _correlationId = '';
    _buildId = '';
    _stage = '';
    _target = '';
}

/* -------------------------------------------------------------------------- */
/* Core emit                                                                  */
/* -------------------------------------------------------------------------- */

function emit(level: LogLevel, component: string, message: string, data?: Record<string, unknown>): void {
    if (LEVEL_ORDER[level] < EFFECTIVE_MIN) return;

    const ts = new Date().toISOString();

    if (JSON_MODE) {
        const entry: Record<string, unknown> = { ts, level, component, msg: message };
        if (_correlationId) entry.cid = _correlationId;
        if (_buildId) entry.build_id = _buildId;
        if (_stage) entry.stage = _stage;
        if (_target) entry.target = _target;
        if (data) entry.data = data;
        const line = JSON.stringify(entry);
        writeOutput(level, line);
    } else {
        const ctx = _buildId ? ` [${_buildId.slice(0, 8)}${_stage ? ':' + _stage : ''}${_target ? '/' + _target : ''}]` : '';
        const prefix = `[${ts}] [${level.toUpperCase().padEnd(5)}] [${component}]${ctx}`;
        const line = data
            ? `${prefix} ${message} ${JSON.stringify(data)}`
            : `${prefix} ${message}`;
        writeOutput(level, line);
    }
}

function writeOutput(level: LogLevel, line: string): void {
    // Console output
    switch (level) {
        case 'error': process.stderr.write(line + '\n'); break;
        case 'warn':  process.stderr.write(line + '\n'); break;
        default:      process.stdout.write(line + '\n'); break;
    }

    // Optional file append
    if (LOG_FILE) {
        try { fs.appendFileSync(LOG_FILE, line + '\n'); } catch { /* ignore */ }
    }
}

/* -------------------------------------------------------------------------- */
/* Logger interface                                                           */
/* -------------------------------------------------------------------------- */

export interface Logger {
    debug(msg: string, data?: Record<string, unknown>): void;
    info(msg: string, data?: Record<string, unknown>): void;
    warn(msg: string, data?: Record<string, unknown>): void;
    error(msg: string, data?: Record<string, unknown>): void;
    child(component: string): Logger;
}

export function createLogger(component: string): Logger {
    return {
        debug: (msg, data) => emit('debug', component, msg, data),
        info:  (msg, data) => emit('info',  component, msg, data),
        warn:  (msg, data) => emit('warn',  component, msg, data),
        error: (msg, data) => emit('error', component, msg, data),
        child: (sub) => createLogger(`${component}:${sub}`),
    };
}

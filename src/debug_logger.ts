/**
 * Debug Logger - Conditional logging for transform engine
 * 
 * Enable with: DIRECTOR_DEBUG=1 or DIRECTOR_DEBUG=true
 */

import * as fs from 'fs';

const DEBUG_ENABLED = process.env.DIRECTOR_DEBUG === '1' || process.env.DIRECTOR_DEBUG === 'true';
const DEBUG_LOG_PATH = process.env.DIRECTOR_DEBUG_LOG || 'debug_transform.log';

export function debugLog(message: string): void {
    if (!DEBUG_ENABLED) return;
    
    try {
        const timestamp = new Date().toISOString();
        fs.appendFileSync(DEBUG_LOG_PATH, `[${timestamp}] ${message}\n`);
    } catch {
        // Silently ignore write failures
    }
}

export function debugLogStart(transformType: string, targetId: string): void {
    debugLog(`START ${transformType} -> ${targetId}`);
}

export function debugLogEnd(transformType: string, success: boolean, cost: number): void {
    debugLog(`END ${transformType} -> Success=${success}. Cost: ${cost}`);
}

export function debugLogStep(step: string, detail?: string): void {
    debugLog(`Step: ${step}${detail ? ` - ${detail}` : ''}`);
}

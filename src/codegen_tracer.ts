/**
 * Code Generation Tracer - Observability for watching how Director codes
 * 
 * Captures detailed traces of each transform to help analyze and improve code generation.
 */

import * as fs from 'fs';
import * as path from 'path';

export interface CodeGenTrace {
    trace_id: string;
    timestamp: string;
    transform_type: string;
    target_id: string;
    model_id: string;

    tier?: string;
    policy?: any;
    
    // Input context
    input_artifacts: Array<{
        kind: string;
        hash: string;
        size_bytes: number;
        snippet: string; // First 500 chars
    }>;
    
    // Prompt sent
    system_prompt: string;
    user_prompt_length: number;
    user_prompt_snippet: string; // First 1000 chars
    
    // Model response
    response_length: number;
    response_snippet: string; // First 1000 chars
    
    // Output analysis
    output_files?: Array<{
        path: string;
        size_bytes: number;
        has_error_handling: boolean;
        has_types: boolean;
        has_validation: boolean;
    }>;
    
    // Quality metrics
    quality_checks: {
        total_output_bytes: number;
        file_count: number;
        has_package_json: boolean;
        has_tsconfig: boolean;
        has_tests: boolean;
        stub_detected: boolean;
        missing_error_handling: string[];
        missing_types: string[];
    };
    
    // Provenance
    prompt_hash?: string;
    response_hash?: string;
    artifact_hashes?: string[];

    // Performance
    duration_ms: number;
    tokens_used: number;
    cost_usd: number;

    // Outcome
    success: boolean;
    error_message?: string;
}

export class CodeGenTracer {
    private traceDir: string;
    private enabled: boolean;
    
    constructor(traceDir?: string) {
        this.traceDir = traceDir || path.join(process.cwd(), '.director-traces');
        this.enabled = process.env.DIRECTOR_TRACE !== '0';
        
        if (this.enabled) {
            try {
                fs.mkdirSync(this.traceDir, { recursive: true });
            } catch (e) {
                // Ignore if can't create
            }
        }
    }
    
    startTrace(params: {
        transform_type: string;
        target_id: string;
        model_id: string;
        tier?: string;
        policy?: any;
        inputs: Array<{ kind: string; hash: string; content: Buffer }>;
        system_prompt: string;
        user_prompt: string;
    }): Partial<CodeGenTrace> {
        const trace_id = `trace-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        
        return {
            trace_id,
            timestamp: new Date().toISOString(),
            transform_type: params.transform_type,
            target_id: params.target_id,
            model_id: params.model_id,
            tier: params.tier,
            policy: params.policy,
            input_artifacts: params.inputs.map(i => ({
                kind: i.kind,
                hash: i.hash,
                size_bytes: i.content.length,
                snippet: i.content.toString('utf8').slice(0, 500),
            })),
            system_prompt: params.system_prompt,
            user_prompt_length: params.user_prompt.length,
            user_prompt_snippet: params.user_prompt.slice(0, 1000),
        };
    }
    
    analyzeOutput(files: Array<{ path: string; content: string }>): CodeGenTrace['quality_checks'] {
        const checks: CodeGenTrace['quality_checks'] = {
            total_output_bytes: 0,
            file_count: files.length,
            has_package_json: false,
            has_tsconfig: false,
            has_tests: false,
            stub_detected: false,
            missing_error_handling: [],
            missing_types: [],
        };
        
        for (const file of files) {
            checks.total_output_bytes += file.content.length;
            
            if (file.path === 'package.json' || file.path.endsWith('/package.json')) {
                checks.has_package_json = true;
                
                // Check for missing @types
                if (file.content.includes('"express"') && !file.content.includes('@types/express')) {
                    checks.missing_types.push('@types/express');
                }
                if (file.content.includes('"uuid"') && !file.content.includes('@types/uuid')) {
                    checks.missing_types.push('@types/uuid');
                }
            }
            
            if (file.path === 'tsconfig.json' || file.path.endsWith('/tsconfig.json')) {
                checks.has_tsconfig = true;
            }
            
            if (file.path.includes('.test.') || file.path.includes('.spec.') || file.path.includes('__tests__')) {
                checks.has_tests = true;
            }
            
            // Check for stubs
            if (file.content.includes('// TODO') || 
                file.content.includes('// implementation') ||
                file.content.includes('throw new Error("Not implemented")')) {
                checks.stub_detected = true;
            }
            
            // Check for error handling in .ts files
            if (file.path.endsWith('.ts') && !file.path.endsWith('.d.ts')) {
                const hasAsyncFunctions = file.content.includes('async ');
                const hasTryCatch = file.content.includes('try {') || file.content.includes('try{');
                const hasErrorHandling = file.content.includes('.catch(') || file.content.includes('catch (');

                const looksLikeExpressHandler = file.content.includes('app.') || file.content.includes('router.');
                if (looksLikeExpressHandler && hasAsyncFunctions && !hasTryCatch && !hasErrorHandling) {
                    checks.missing_error_handling.push(file.path);
                }
            }
        }
        
        return checks;
    }
    
    completeTrace(
        partial: Partial<CodeGenTrace>,
        response: string,
        files: Array<{ path: string; content: string }> | null,
        duration_ms: number,
        tokens_used: number,
        cost_usd: number,
        success: boolean,
        error_message?: string,
        provenance?: { prompt_hash?: string; response_hash?: string; artifact_hashes?: string[] }
    ): CodeGenTrace {
        const trace: CodeGenTrace = {
            ...partial as CodeGenTrace,
            response_length: response.length,
            response_snippet: response.slice(0, 1000),
            output_files: files?.map(f => ({
                path: f.path,
                size_bytes: f.content.length,
                has_error_handling: f.content.includes('try {') || f.content.includes('.catch('),
                has_types: f.path.endsWith('.ts') || f.content.includes(': string') || f.content.includes(': number'),
                has_validation: f.content.includes('if (') && (f.content.includes('throw') || f.content.includes('return')),
            })),
            quality_checks: files ? this.analyzeOutput(files) : {
                total_output_bytes: 0,
                file_count: 0,
                has_package_json: false,
                has_tsconfig: false,
                has_tests: false,
                stub_detected: false,
                missing_error_handling: [],
                missing_types: [],
            },
            prompt_hash: provenance?.prompt_hash,
            response_hash: provenance?.response_hash,
            artifact_hashes: provenance?.artifact_hashes,
            duration_ms,
            tokens_used,
            cost_usd,
            success,
            error_message,
        };

        this.saveTrace(trace);
        this.printTraceSummary(trace);
        
        return trace;
    }
    
    private saveTrace(trace: CodeGenTrace): void {
        if (!this.enabled) return;
        
        try {
            const filename = `${trace.trace_id}.json`;
            const filepath = path.join(this.traceDir, filename);
            fs.writeFileSync(filepath, JSON.stringify(trace, null, 2));
        } catch (e) {
            // Ignore save errors
        }
    }
    
    private printTraceSummary(trace: CodeGenTrace): void {
        const q = trace.quality_checks;
        
        console.log(`[Trace] ${trace.trace_id}`);
        console.log(`  Transform: ${trace.transform_type} | Target: ${trace.target_id}`);
        if (trace.tier) console.log(`  Tier: ${trace.tier}`);
        console.log(`  Model: ${trace.model_id} | Tokens: ${trace.tokens_used} | Cost: $${trace.cost_usd.toFixed(4)}`);
        console.log(`  Output: ${q.file_count} files, ${q.total_output_bytes} bytes`);
        
        // Quality warnings
        const warnings: string[] = [];
        if (q.stub_detected) warnings.push('STUBS_DETECTED');
        if (q.missing_error_handling.length > 0) warnings.push(`NO_ERROR_HANDLING(${q.missing_error_handling.length})`);
        if (q.missing_types.length > 0) warnings.push(`MISSING_TYPES(${q.missing_types.join(',')})`);
        if (!q.has_package_json && trace.transform_type === 'ms3_to_ms2') warnings.push('NO_PACKAGE_JSON');
        
        if (warnings.length > 0) {
            console.log(`  Warnings: ${warnings.join(' | ')}`);
        }
        
        if (!trace.success) {
            console.log(`  FAILED: ${trace.error_message}`);
        }
    }
    
    // Get recent traces for analysis
    getRecentTraces(limit: number = 10): CodeGenTrace[] {
        if (!this.enabled) return [];
        
        try {
            const files = fs.readdirSync(this.traceDir)
                .filter(f => f.endsWith('.json'))
                .sort()
                .reverse()
                .slice(0, limit);
            
            return files.map(f => {
                const content = fs.readFileSync(path.join(this.traceDir, f), 'utf8');
                return JSON.parse(content);
            });
        } catch (e) {
            return [];
        }
    }
}

// Singleton instance
export const tracer = new CodeGenTracer();

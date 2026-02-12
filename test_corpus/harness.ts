/**
 * Test Corpus Harness
 * 
 * Runs compiler tests and archives results for regression/evidence.
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

interface TestCase {
    id: string;
    name: string;
    category: 'large_legacy' | 'defunct_code' | 'security_auth' | 'framework_heavy' | 'directory_input';
    inputPath: string;
    flags: string[];
    expectedOutcome: 'SUCCESS' | 'REFUSED' | 'FAILED' | 'CIRCUIT_BREAKER';
    description: string;
}

interface TestResult {
    testId: string;
    timestamp: string;
    outcome: string;
    expectedOutcome: string;
    passed: boolean;
    durationMs: number;
    costUsd: number;
    artifacts: string[];
    error?: string;
}

const CORPUS_DIR = path.join(__dirname);
const INPUTS_DIR = path.join(CORPUS_DIR, 'inputs');
const RESULTS_DIR = path.join(CORPUS_DIR, 'results');
const ARCHIVE_DIR = path.join(CORPUS_DIR, 'archive');

// Test registry
const TEST_CASES: TestCase[] = [
    {
        id: '01_large_legacy',
        name: 'Large Legacy Single File',
        category: 'large_legacy',
        inputPath: 'inputs/01_large_legacy/legacy_monolith.ts',
        flags: ['--tier', 'experimental', '--mode', 'semantic_governed'],
        expectedOutcome: 'SUCCESS',
        description: '2500+ LOC legacy TypeScript file with mixed patterns'
    },
    {
        id: '02_defunct_code',
        name: 'Defunct Code with Broken Imports',
        category: 'defunct_code',
        inputPath: 'inputs/02_defunct_code/broken_service.ts',
        flags: ['--tier', 'experimental', '--mode', 'semantic_governed'],
        expectedOutcome: 'SUCCESS', // Should extract semantics despite broken imports
        description: 'Code with deprecated APIs and missing dependencies'
    },
    {
        id: '03_security_auth',
        name: 'Security-Sensitive Auth Module',
        category: 'security_auth',
        inputPath: 'inputs/03_security_auth/auth_handler.ts',
        flags: ['--tier', 'production', '--mode', 'semantic_governed'],
        expectedOutcome: 'SUCCESS',
        description: 'Authentication with hashing, JWT, session management'
    },
    {
        id: '04_framework_heavy',
        name: 'Framework-Heavy Express Service',
        category: 'framework_heavy',
        inputPath: 'inputs/04_framework_heavy/express_api.ts',
        flags: ['--tier', 'experimental', '--mode', 'semantic_governed'],
        expectedOutcome: 'SUCCESS',
        description: 'Express.js REST API with middleware chain'
    },
    {
        id: '05_directory_input',
        name: 'Whole Directory Input (Expected Refusal)',
        category: 'directory_input',
        inputPath: 'inputs/05_directory_input/',
        flags: ['--tier', 'enterprise', '--mode', 'semantic_governed'],
        expectedOutcome: 'REFUSED', // Should refuse with STUBS_DETECTED or NEED_MORE_CONTEXT
        description: 'Multi-file directory - tests composition boundary'
    }
];

async function runTest(test: TestCase): Promise<TestResult> {
    const startTime = Date.now();
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const resultDir = path.join(RESULTS_DIR, test.id);
    
    // Clean previous results
    if (fs.existsSync(resultDir)) {
        fs.rmSync(resultDir, { recursive: true });
    }
    fs.mkdirSync(resultDir, { recursive: true });
    
    // Write input record
    fs.writeFileSync(
        path.join(resultDir, 'INPUT.md'),
        `# Test Input: ${test.name}\n\n` +
        `**Category:** ${test.category}\n` +
        `**Input Path:** ${test.inputPath}\n` +
        `**Description:** ${test.description}\n\n` +
        `## Source\n\n` +
        '```\n' +
        (fs.existsSync(path.join(CORPUS_DIR, test.inputPath)) && fs.statSync(path.join(CORPUS_DIR, test.inputPath)).isFile()
            ? fs.readFileSync(path.join(CORPUS_DIR, test.inputPath), 'utf8').slice(0, 5000)
            : '[Directory input - multiple files]') +
        '\n```'
    );
    
    // Write flags
    fs.writeFileSync(
        path.join(resultDir, 'FLAGS.txt'),
        `dirkernel compile --from code --input ${test.inputPath} ${test.flags.join(' ')}`
    );
    
    let outcome = 'UNKNOWN';
    let error: string | undefined;
    let costUsd = 0;
    const artifacts: string[] = [];
    
    try {
        // Run compiler
        const cmd = `npx ts-node src/cli.ts compile --from code --input "${path.join(CORPUS_DIR, test.inputPath)}" ${test.flags.join(' ')}`;
        console.log(`Running: ${cmd}`);
        
        const output = execSync(cmd, {
            cwd: path.join(CORPUS_DIR, '..'),
            encoding: 'utf8',
            timeout: 300000, // 5 minute timeout
            stdio: ['pipe', 'pipe', 'pipe']
        });
        
        // Parse output for outcome
        if (output.includes('SEMANTIC GOVERNED PIPELINE COMPLETE') || output.includes('SUCCESS')) {
            outcome = 'SUCCESS';
        } else if (output.includes('REFUSED') || output.includes('NEED_MORE_CONTEXT') || output.includes('STUBS_DETECTED')) {
            outcome = 'REFUSED';
        } else if (output.includes('CIRCUIT_BREAKER')) {
            outcome = 'CIRCUIT_BREAKER';
        } else {
            outcome = 'FAILED';
        }
        
        // Copy artifacts
        const outputDir = path.join(CORPUS_DIR, '..', 'output');
        if (fs.existsSync(outputDir)) {
            const artifactsDir = path.join(resultDir, 'ARTIFACTS');
            fs.mkdirSync(artifactsDir, { recursive: true });
            
            for (const file of fs.readdirSync(outputDir)) {
                const src = path.join(outputDir, file);
                const dest = path.join(artifactsDir, file);
                if (fs.statSync(src).isFile()) {
                    fs.copyFileSync(src, dest);
                    artifacts.push(file);
                }
            }
            
            // Extract cost from audit log
            const auditPath = path.join(artifactsDir, 'AUDIT_LOG.json');
            if (fs.existsSync(auditPath)) {
                const audit = JSON.parse(fs.readFileSync(auditPath, 'utf8'));
                costUsd = audit.cost_usd || 0;
            }
        }
        
        fs.writeFileSync(path.join(resultDir, 'OUTPUT.log'), output);
        
    } catch (e: any) {
        error = e.message;
        outcome = 'FAILED';
        
        if (e.stderr) {
            fs.writeFileSync(path.join(resultDir, 'STDERR.log'), e.stderr);
        }
        if (e.stdout) {
            fs.writeFileSync(path.join(resultDir, 'STDOUT.log'), e.stdout);
            
            // Check for expected refusals in output
            if (e.stdout.includes('STUBS_DETECTED') || e.stdout.includes('NEED_MORE_CONTEXT')) {
                outcome = 'REFUSED';
            }
        }
    }
    
    const durationMs = Date.now() - startTime;
    const passed = outcome === test.expectedOutcome;
    
    // Write outcome
    fs.writeFileSync(
        path.join(resultDir, 'OUTCOME.txt'),
        `${outcome}\n\nExpected: ${test.expectedOutcome}\nPassed: ${passed}`
    );
    
    // Write explanation
    fs.writeFileSync(
        path.join(resultDir, 'EXPLANATION.md'),
        `# Test Result: ${test.name}\n\n` +
        `**Test ID:** ${test.id}\n` +
        `**Timestamp:** ${timestamp}\n` +
        `**Duration:** ${(durationMs / 1000).toFixed(1)}s\n` +
        `**Cost:** $${costUsd.toFixed(4)}\n\n` +
        `## Outcome\n\n` +
        `- **Actual:** ${outcome}\n` +
        `- **Expected:** ${test.expectedOutcome}\n` +
        `- **Passed:** ${passed ? '✅ YES' : '❌ NO'}\n\n` +
        `## Artifacts Produced\n\n` +
        artifacts.map(a => `- ${a}`).join('\n') + '\n\n' +
        (error ? `## Error\n\n\`\`\`\n${error}\n\`\`\`\n` : '') +
        `## Analysis\n\n` +
        (passed 
            ? `Test passed. Compiler behavior matched expectations.`
            : `Test failed. Expected ${test.expectedOutcome} but got ${outcome}.`)
    );
    
    return {
        testId: test.id,
        timestamp,
        outcome,
        expectedOutcome: test.expectedOutcome,
        passed,
        durationMs,
        costUsd,
        artifacts,
        error
    };
}

async function runAllTests(): Promise<void> {
    console.log('═══════════════════════════════════════════════════════════');
    console.log('           DIRECTOR COMPILER TEST CORPUS');
    console.log('═══════════════════════════════════════════════════════════\n');
    
    const results: TestResult[] = [];
    
    for (const test of TEST_CASES) {
        console.log(`\n[${test.id}] ${test.name}`);
        console.log(`  Category: ${test.category}`);
        console.log(`  Expected: ${test.expectedOutcome}`);
        
        // Check if input exists
        const inputPath = path.join(CORPUS_DIR, test.inputPath);
        if (!fs.existsSync(inputPath)) {
            console.log(`  ⚠️  SKIPPED - Input not found: ${test.inputPath}`);
            continue;
        }
        
        const result = await runTest(test);
        results.push(result);
        
        console.log(`  Outcome: ${result.outcome}`);
        console.log(`  Passed: ${result.passed ? '✅' : '❌'}`);
        console.log(`  Duration: ${(result.durationMs / 1000).toFixed(1)}s`);
        console.log(`  Cost: $${result.costUsd.toFixed(4)}`);
    }
    
    // Write summary
    const summary = {
        timestamp: new Date().toISOString(),
        totalTests: results.length,
        passed: results.filter(r => r.passed).length,
        failed: results.filter(r => !r.passed).length,
        totalCostUsd: results.reduce((sum, r) => sum + r.costUsd, 0),
        totalDurationMs: results.reduce((sum, r) => sum + r.durationMs, 0),
        results
    };
    
    fs.writeFileSync(
        path.join(RESULTS_DIR, 'SUMMARY.json'),
        JSON.stringify(summary, null, 2)
    );
    
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('                      SUMMARY');
    console.log('═══════════════════════════════════════════════════════════');
    console.log(`  Total: ${summary.totalTests}`);
    console.log(`  Passed: ${summary.passed}`);
    console.log(`  Failed: ${summary.failed}`);
    console.log(`  Cost: $${summary.totalCostUsd.toFixed(4)}`);
    console.log(`  Duration: ${(summary.totalDurationMs / 1000).toFixed(1)}s`);
    console.log('═══════════════════════════════════════════════════════════\n');
}

function archiveResults(): void {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const archivePath = path.join(ARCHIVE_DIR, timestamp);
    
    if (fs.existsSync(RESULTS_DIR)) {
        fs.cpSync(RESULTS_DIR, archivePath, { recursive: true });
        console.log(`Archived results to: ${archivePath}`);
    }
}

// CLI
const args = process.argv.slice(2);

if (args.includes('--all')) {
    runAllTests();
} else if (args.includes('--archive')) {
    archiveResults();
} else if (args.includes('--test')) {
    const testId = args[args.indexOf('--test') + 1];
    const test = TEST_CASES.find(t => t.id === testId);
    if (test) {
        runTest(test).then(result => {
            console.log(JSON.stringify(result, null, 2));
        });
    } else {
        console.error(`Test not found: ${testId}`);
        console.log('Available tests:', TEST_CASES.map(t => t.id).join(', '));
    }
} else {
    console.log('Usage:');
    console.log('  npx ts-node test_corpus/harness.ts --all       Run all tests');
    console.log('  npx ts-node test_corpus/harness.ts --test ID   Run single test');
    console.log('  npx ts-node test_corpus/harness.ts --archive   Archive current results');
    console.log('\nAvailable tests:');
    TEST_CASES.forEach(t => console.log(`  ${t.id}: ${t.name}`));
}

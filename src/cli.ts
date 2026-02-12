/**
 * CLI Entry Point for Director Kernel
 */

import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';
import Database from 'better-sqlite3';
import {
    KernelOrchestrator,
    TransformEngineInterface,
    TransformResult as KernelResult,
    ArtifactRef
} from './kernel_orchestrator';
import { TransformEngine, TransformResult as ComputeResult, buildPolicyForTier, parseDirectorTier } from './transform_engine';
import { ModelRouter } from './model_router';
import { DEFAULT_MODEL_ID, LINKAGE_CONTRACT_MAX_CHARS } from './config';
import { computeSemanticMass, checkSemanticConservation, SemanticMassReport, extractEnforcementRules, EnforcementRule } from './semantic_mass';

interface CliConfig {
    dbPath: string;
    artifactRoot: string;
    apiKey: string;
}

class DirectorKernelCLI {
    private config!: CliConfig;

    constructor() {
        // Config loaded on demand
    }

    private loadConfig(): CliConfig {
        const configPath = path.join(process.env.HOME || process.env.USERPROFILE || '', '.director', 'config.json');

        if (!fs.existsSync(configPath)) {
            console.error('Error: Configuration not found. Run `dirkernel init` first.');
            process.exit(1);
        }

        return JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    }

    async run(args: string[]): Promise<void> {
        const command = args[2] || 'help';

        if (command === 'init') {
            await this.runInit();
            return;
        } else if (command === 'help') {
            this.showHelp();
            return;
        }

        this.config = this.loadConfig();

        switch (command) {
            case 'build':
                await this.runBuild(args.slice(3));
                break;
            case 'compile':
                await this.runCompile(args.slice(3));
                break;
            case 'clear-lock':
                console.log('Forcing lock release...');
                const db = new Database(this.config.dbPath);
                db.prepare('UPDATE singleton_lock SET token=\'\', build_id=NULL, acquired_by_pid=0, process_name=\'\', exe_sha256=\'\', acquired_at=\'\', last_heartbeat_at=\'\' WHERE lock_id=1').run();
                db.prepare("UPDATE builds SET state='ABANDONED' WHERE state='ACTIVE'").run();
                console.log('Lock cleared and active builds reset.');
                process.exit(0);
                break;
            case 'status':
                await this.runStatus();
                break;
            default:
                this.showHelp();
        }
    }

    private async runInit(): Promise<void> {
        console.log('Initializing Director Kernel...');

        const homeDir = process.env.HOME || process.env.USERPROFILE;
        if (!homeDir) {
            console.error('Error: Unable to determine home directory (HOME or USERPROFILE not set)');
            process.exit(1);
        }

        const configDir = path.join(homeDir, '.director');
        const configPath = path.join(configDir, 'config.json');

        if (fs.existsSync(configPath)) {
            console.log('Configuration already exists at:', configPath);
            console.log('   To reinitialize, delete the existing config first.');
            process.exit(0);
        }

        try {
            if (!fs.existsSync(configDir)) {
                fs.mkdirSync(configDir, { recursive: true });
                console.log('Created config directory:', configDir);
            }

            const apiKey = process.env.OPENROUTER_API_KEY || '';
            if (!apiKey) {
                console.error('Error: OPENROUTER_API_KEY environment variable not set');
                if (process.platform === 'win32') {
                    console.error('   Please set it with: setx OPENROUTER_API_KEY "sk-or-..."');
                } else {
                    console.error('   Please set it with: export OPENROUTER_API_KEY=sk-or-...');
                }
                process.exit(1);
            }

            if (!apiKey.startsWith('sk-or-')) {
                console.warn('Warning: API key does not start with "sk-or-" (expected format for OpenRouter)');
            }

            const config: CliConfig = {
                dbPath: path.join(configDir, 'kernel.db'),
                artifactRoot: path.join(configDir, 'artifacts'),
                apiKey,
            };

            fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
            console.log('Created config file:', configPath);

            fs.mkdirSync(config.artifactRoot, { recursive: true });
            console.log('Created artifacts directory:', config.artifactRoot);

            console.log('\nDirector Kernel initialized successfully.');
            console.log(`   Config: ${configPath}`);
            console.log(`   Database: ${config.dbPath}`);
            console.log(`   Artifacts: ${config.artifactRoot}`);
            console.log('\nNext steps:');
            console.log('   1. Create an MS5 specification file (see examples/)');
            console.log('   2. Run: dirkernel build <your-spec.ms5.json>');
        } catch (error: any) {
            console.error('Initialization failed:', error.message);
            process.exit(1);
        }
    }

    private async runBuild(args: string[]): Promise<void> {
        const ms5Path = args[0];
        let budget = 0;
        const budgetIndex = args.indexOf('--budget');
        if (budgetIndex !== -1 && args[budgetIndex + 1]) {
            budget = parseFloat(args[budgetIndex + 1]);
        }

        const tierIndex = args.indexOf('--tier');
        const tierRaw = tierIndex !== -1 ? args[tierIndex + 1] : undefined;
        const tierFromArg = tierRaw ? parseDirectorTier(tierRaw) : null;
        if (tierIndex !== -1 && !tierRaw) {
            console.error('Error: --tier requires a value');
            process.exitCode = 1;
            return;
        }
        if (tierIndex !== -1 && tierRaw && !tierFromArg) {
            console.error(`Error: Invalid tier: ${tierRaw}`);
            console.error('Valid tiers: toy, personal, experimental, production, enterprise');
            process.exitCode = 1;
            return;
        }
        const tierFromEnv = parseDirectorTier(process.env.DIRECTOR_TIER);
        const tier = tierFromArg || tierFromEnv || 'experimental';
        process.env.DIRECTOR_TIER = tier;

        const inputMs4Index = args.indexOf('--input-ms4');
        const inputMs4Path = inputMs4Index !== -1 ? args[inputMs4Index + 1] : undefined;
        if (inputMs4Index !== -1 && !inputMs4Path) {
            console.error('Error: --input-ms4 requires a file path');
            process.exitCode = 1;
            return;
        }

        const inputMs3Index = args.indexOf('--input-ms3');
        const inputMs3Path = inputMs3Index !== -1 ? args[inputMs3Index + 1] : undefined;
        if (inputMs3Index !== -1 && !inputMs3Path) {
            console.error('Error: --input-ms3 requires a file path');
            process.exitCode = 1;
            return;
        }

        if (!ms5Path) {
            console.error('Error: MS5 specification file required');
            console.error('Usage: dirkernel build <ms5_file.json> [--budget <amount>] [--tier <tier>] [--input-ms4 <mc4.json>] [--input-ms3 <mc3.json>]');
            process.exitCode = 1;
            return;
        }

        if (!fs.existsSync(ms5Path)) {
            console.error(`Error: File not found: ${ms5Path}`);
            process.exitCode = 1;
            return;
        }

        const parsed = JSON.parse(fs.readFileSync(ms5Path, 'utf-8'));
        const ms5Spec = parsed?.ms5 ?? parsed;

        if (!ms5Spec || typeof ms5Spec !== 'object') {
            console.error('Error: Invalid MS5 spec (expected JSON object)');
            process.exitCode = 1;
            return;
        }

        if (!Array.isArray((ms5Spec as any).stages)) {
            const keys = Object.keys(ms5Spec as any);
            console.error('Error: Invalid MS5 spec: ms5_spec.stages must be an array');
            console.error(`Top-level keys: ${keys.join(', ')}`);
            console.error('Tip: If your file is shaped like { ms5: { ... } }, pass the same file; the CLI will unwrap it.');
            process.exitCode = 1;
            return;
        }

        const modelRouter = new ModelRouter({
            apiKey: this.config.apiKey,
            debug: false
        });

        const baseEngine = new TransformEngine({
            modelRouter,
            ms5Invariants: "{}"
        });

        const engineAdapter = new CliTransformAdapter(baseEngine, this.config.artifactRoot);

        const kernel = new KernelOrchestrator(
            this.config.dbPath,
            this.config.artifactRoot,
            engineAdapter
        );

        try {
            const init = kernel.initializeRecovery();
            if (!init.ok) {
                console.error('Kernel initialization failed:', init.error, init.message);
                process.exitCode = 1;
                return;
            }

            const { lock } = init.value;
            console.log(`Kernel locked (PID: ${lock.pid})`);

            console.log('Starting build orchestration...');

            const input_artifacts: ArtifactRef[] = [];
            if (inputMs4Path) {
                if (!fs.existsSync(inputMs4Path)) {
                    console.error(`Error: File not found: ${inputMs4Path}`);
                    process.exitCode = 1;
                    return;
                }
                const raw = fs.readFileSync(inputMs4Path);
                const { sha256 } = this.storeInputArtifact(raw);
                input_artifacts.push({ artifact_id: sha256, sha256, kind: 'ms4' });
            }

            if (inputMs3Path) {
                if (!fs.existsSync(inputMs3Path)) {
                    console.error(`Error: File not found: ${inputMs3Path}`);
                    process.exitCode = 1;
                    return;
                }
                const raw = fs.readFileSync(inputMs3Path);
                const { sha256 } = this.storeInputArtifact(raw);
                input_artifacts.push({ artifact_id: sha256, sha256, kind: 'ms3' });
            }

            const result = await kernel.orchestrateBuild({
                ms5_spec: ms5Spec,
                budget_usd: budget || 10.0,
                input_artifacts
            });

            if (!result.ok) {
                console.error('Build failed:', result.error, result.message);
                process.exitCode = 1;
                return;
            }

            const build = result.value;

            console.log(`Build ${build.build_id} ${build.final_state}`);
            console.log(`   Budget Used: $${parseFloat(String(build.cumulative_cost_usd || 0)).toFixed(2)}`);

            if (build.final_state === 'SUCCESS') {
                const rawName = String((ms5Spec as any).id || (ms5Spec as any).title || 'output');
                const projectName = rawName
                    .trim()
                    .replace(/[^a-zA-Z0-9._-]+/g, '_')
                    .slice(0, 80) || 'output';
                await this.exportBuildArtifacts(build.build_id, projectName);
            }
        } finally {
            kernel.close();
        }
    }

    private storeInputArtifact(content: Buffer): { sha256: string; path: string } {
        const sha256 = createHash('sha256').update(content).digest('hex');
        const dir = path.join(this.config.artifactRoot, sha256.slice(0, 2));
        const p = path.join(dir, sha256);
        fs.mkdirSync(dir, { recursive: true });
        if (!fs.existsSync(p)) {
            fs.writeFileSync(p, content);
        }
        return { sha256, path: p };
    }

    private async runCompile(args: string[]): Promise<void> {
        console.log('╔════════════════════════════════════════════════════════════╗');
        console.log('║              DIRECTOR COMPILER MODE                        ║');
        console.log('╚════════════════════════════════════════════════════════════╝\n');

        let fromSource: string | undefined;
        let toLanguage: string | undefined;
        let tier: string = 'experimental';
        let inputPath: string | undefined;
        let outputName: string | undefined;
        let diffMode = false;
        let explainMode = false;
        let lockArchitecture = false;
        let mode: 'default' | 'semantic_governed' = 'default';
        let mc3Path: string | undefined;
        let mc4Path: string | undefined;
        let mc5Path: string | undefined;
        let moduleName: string | undefined;
        let patchOnly = false;

        for (let i = 0; i < args.length; i++) {
            if (args[i] === '--from' && args[i + 1]) {
                fromSource = args[++i];
            } else if (args[i] === '--to' && args[i + 1]) {
                toLanguage = args[++i];
            } else if (args[i] === '--tier' && args[i + 1]) {
                tier = args[++i];
            } else if (args[i] === '--input' && args[i + 1]) {
                inputPath = args[++i];
            } else if (args[i] === '--output' && args[i + 1]) {
                outputName = args[++i];
            } else if (args[i] === '--diff') {
                diffMode = true;
            } else if (args[i] === '--explain') {
                explainMode = true;
            } else if (args[i] === '--lock-architecture') {
                lockArchitecture = true;
            } else if (args[i] === '--mode' && args[i + 1]) {
                const modeArg = args[++i];
                if (modeArg === 'semantic_governed') {
                    mode = 'semantic_governed';
                }
            } else if (args[i] === '--mc3' && args[i + 1]) {
                mc3Path = args[++i];
            } else if (args[i] === '--mc4' && args[i + 1]) {
                mc4Path = args[++i];
            } else if (args[i] === '--mc5' && args[i + 1]) {
                mc5Path = args[++i];
            } else if (args[i] === '--module' && args[i + 1]) {
                moduleName = args[++i];
            } else if (args[i] === '--patch-only') {
                patchOnly = true;
            }
        }

        if (!fromSource || !inputPath) {
            console.log('Usage: dirkernel compile --from <source> --to <target> --tier <tier> --input <path> [--output <name>]');
            console.log('');
            console.log('Options:');
            console.log('  --from <source>   Source type: code, intent');
            console.log('  --to <target>     Target language: typescript, rust, go, python (default: same as source)');
            console.log('  --tier <tier>     Quality tier: toy, personal, experimental, production, enterprise');
            console.log('  --input <path>    Path to input file or directory');
            console.log('  --output <name>   Output project name (default: derived from input)');
            console.log('  --diff            Emit semantic diff (MS2.5) and contract diff (MS3)');
            console.log('  --explain         Emit explanation of what changed and why');
            console.log('  --lock-architecture  Preserve MS3 contracts, only vary implementation');
            console.log('');
            console.log('Examples:');
            console.log('  # Modernize legacy code to production-tier TypeScript');
            console.log('  dirkernel compile --from code --to typescript --tier production --input ./legacy-app');
            console.log('');
            console.log('  # Port Python to Rust');
            console.log('  dirkernel compile --from code --to rust --tier production --input ./service.py');
            console.log('');
            console.log('  # Expand intent to full spec and code');
            console.log('  dirkernel compile --from intent --to typescript --tier experimental --input ./idea.txt');
            return;
        }

        const validTier = parseDirectorTier(tier);
        if (!validTier) {
            console.error(`Invalid tier: ${tier}. Must be one of: toy, personal, experimental, production, enterprise`);
            return;
        }

        console.log(`Source:    ${fromSource}`);
        console.log(`Target:    ${toLanguage || '(same language)'}`);
        console.log(`Tier:      ${validTier}`);
        console.log(`Input:     ${inputPath}`);
        if (mode === 'semantic_governed') console.log(`Mode:      SEMANTIC GOVERNED`);
        if (diffMode) console.log(`Diff:      enabled`);
        if (explainMode) console.log(`Explain:   enabled`);
        if (lockArchitecture) console.log(`Lock Arch: enabled`);
        if (patchOnly) console.log(`Patch:     enabled`);
        console.log('');

        if (!fs.existsSync(inputPath)) {
            console.error(`Input path not found: ${inputPath}`);
            return;
        }

        // Handle directory input: collect all source files
        let inputContent: string;
        const inputStat = fs.statSync(inputPath);
        if (inputStat.isDirectory()) {
            const sourceExtensions = ['.go', '.ts', '.js', '.py', '.java', '.rs', '.c', '.cpp', '.cs'];
            const collectFiles = (dir: string, files: string[] = []): string[] => {
                const entries = fs.readdirSync(dir, { withFileTypes: true });
                for (const entry of entries) {
                    const fullPath = path.join(dir, entry.name);
                    if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'vendor') {
                        collectFiles(fullPath, files);
                    } else if (entry.isFile() && sourceExtensions.some(ext => entry.name.endsWith(ext))) {
                        files.push(fullPath);
                    }
                }
                return files;
            };
            const sourceFiles = collectFiles(inputPath);
            if (sourceFiles.length === 0) {
                console.error(`No source files found in directory: ${inputPath}`);
                return;
            }
            console.log(`Directory mode: Found ${sourceFiles.length} source files\n`);
            // Concatenate all files with file markers
            inputContent = sourceFiles.map(f => {
                const relativePath = path.relative(inputPath, f);
                const content = fs.readFileSync(f, 'utf-8');
                return `// === FILE: ${relativePath} ===\n${content}`;
            }).join('\n\n');
        } else {
            inputContent = fs.readFileSync(inputPath, 'utf-8');
        }
        const projectName = outputName || path.basename(inputPath, path.extname(inputPath)).toUpperCase() + '-COMPILED';

        const compileOptions = { diffMode, explainMode, lockArchitecture, patchOnly };

        // Route to semantic_governed pipeline if mode is set
        if (mode === 'semantic_governed') {
            await this.runSemanticGovernedPipeline({
                mc5Path,
                mc4Path,
                mc3Path,
                moduleName,
                inputPath,
                inputContent,
                targetLanguage: toLanguage,
                tier: validTier,
                projectName,
                options: compileOptions
            });
            return;
        }

        if (fromSource === 'code') {
            await this.compileFromCode(inputContent, inputPath, toLanguage, validTier, projectName, compileOptions);
        } else if (fromSource === 'intent') {
            await this.compileFromIntent(inputContent, toLanguage, validTier, projectName, compileOptions);
        } else {
            console.error(`Unknown source type: ${fromSource}. Use 'code' or 'intent'.`);
        }
    }

    private async compileFromCode(
        code: string,
        sourcePath: string,
        targetLanguage: string | undefined,
        tier: 'toy' | 'personal' | 'experimental' | 'production' | 'enterprise',
        projectName: string,
        options: { diffMode: boolean; explainMode: boolean; lockArchitecture: boolean }
    ): Promise<void> {
        if (options.lockArchitecture) {
            console.log('Pipeline: Code → MS2.5 → [LOCKED MS3] → MS2 (target)\n');
            console.log('⚠️  Architecture locked: MS3 contracts will be preserved from first run.\n');
        } else {
            console.log('Pipeline: Code → MS2.5 → MS3 → MS2 (target)\n');
        }

        const stages = options.lockArchitecture
            ? [
                {
                    name: 'semantic_analysis',
                    targets: [{ name: 'ms2_5', config: { transform_type: 'ms2_to_ms2_5' } }],
                },
                {
                    name: 'implementation',
                    targets: [{ name: 'code', config: { transform_type: 'ms3_to_ms2', target_language: targetLanguage, lock_architecture: true } }],
                },
            ]
            : [
                {
                    name: 'semantic_analysis',
                    targets: [{ name: 'ms2_5', config: { transform_type: 'ms2_to_ms2_5' } }],
                },
                {
                    name: 'contract_elevation',
                    targets: [{ name: 'ms3', config: { transform_type: 'ms2_5_to_ms3' } }],
                },
                {
                    name: 'implementation',
                    targets: [{ name: 'code', config: { transform_type: 'ms3_to_ms2', target_language: targetLanguage } }],
                },
            ];

        const ms5Spec = {
            problem: `Modernize/port existing code from ${sourcePath}`,
            goal: `Generate ${targetLanguage || 'same language'} implementation at ${tier} tier`,
            product_definition: {
                name: projectName,
                description: `Compiled from ${sourcePath}`,
            },
            stages,
            global_config: {
                tier,
                default_model: DEFAULT_MODEL_ID,
                lock_architecture: options.lockArchitecture,
            },
        };

        const ms2Artifact = {
            files: [{ path: sourcePath, content: code }],
        };

        const ms2Stored = this.storeInputArtifact(Buffer.from(JSON.stringify(ms2Artifact, null, 2)));

        const modelRouter = new ModelRouter({
            apiKey: this.config.apiKey,
            debug: false
        });

        const baseEngine = new TransformEngine({
            modelRouter,
            ms5Invariants: '{}'
        });

        const engineAdapter = new CliTransformAdapter(baseEngine, this.config.artifactRoot);

        const kernel = new KernelOrchestrator(
            this.config.dbPath,
            this.config.artifactRoot,
            engineAdapter
        );

        try {
            const init = kernel.initializeRecovery();
            if (!init.ok) {
                console.error('Kernel initialization failed:', init.error, init.message);
                return;
            }

            const result = await kernel.orchestrateBuild({
                ms5_spec: ms5Spec,
                budget_usd: 5.0,
                input_artifacts: [{ artifact_id: ms2Stored.sha256, sha256: ms2Stored.sha256, kind: 'ms2' }]
            });

            if (!result.ok) {
                console.error('Compilation failed:', result.error, result.message);
                return;
            }

            const build = result.value;

            // FIX 1: Tier validation after MS3 generation
            const tierValidation = await this.validateTierFromBuild(build.build_id, tier, baseEngine);
            if (!tierValidation.ok) {
                console.error('\n❌ TIER VALIDATION FAILED');
                console.error(`   Tier: ${tier}`);
                console.error(`   Violations (${tierValidation.violations.length}):`);
                for (const v of tierValidation.violations) {
                    console.error(`     • [${v.severity}] ${v.requirement}: ${v.reason}`);
                }
                console.log(`\n   Cost: $${parseFloat(String(build.cumulative_cost_usd || 0)).toFixed(4)}`);
                return;
            }

            if (tierValidation.warnings.length > 0) {
                console.log('\n⚠️  TIER WARNINGS:');
                for (const w of tierValidation.warnings) {
                    console.log(`     • ${w.requirement}: ${w.reason}`);
                }
            }

            console.log(`\nCompilation ${build.final_state}`);
            console.log(`   Cost: $${parseFloat(String(build.cumulative_cost_usd || 0)).toFixed(4)}`);

            if (build.final_state === 'SUCCESS') {
                await this.exportBuildArtifacts(build.build_id, projectName);

                if (options.diffMode || options.explainMode) {
                    await this.emitCompilationReport(build.build_id, projectName, options);
                }
            }
        } finally {
            kernel.close();
        }
    }

    private async validateTierFromBuild(
        buildId: string,
        tier: 'toy' | 'personal' | 'experimental' | 'production' | 'enterprise',
        engine: TransformEngine
    ): Promise<{ ok: boolean; violations: Array<{ severity: string; requirement: string; reason: string }>; warnings: Array<{ requirement: string; reason: string }> }> {
        const db = new Database(this.config.dbPath, { readonly: true });
        const violations: Array<{ severity: string; requirement: string; reason: string }> = [];
        const warnings: Array<{ requirement: string; reason: string }> = [];

        try {
            const rows = db.prepare(`
                SELECT a.sha256, a.kind, a.storage_path
                FROM artifact_refs ar
                JOIN artifacts a ON ar.artifact_id = a.artifact_id
                WHERE ar.build_id = ? AND (a.kind = 'ms3' OR ar.target = 'ms3')
            `).all(buildId) as any[];

            for (const row of rows) {
                const artifactPath = row.storage_path
                    ? row.storage_path
                    : path.join(this.config.artifactRoot, row.sha256.slice(0, 2), row.sha256);

                if (fs.existsSync(artifactPath)) {
                    try {
                        const ms3Content = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
                        const levels = ms3Content.mc_family?.levels || [];
                        for (const level of levels) {
                            const example = level.example || {};
                            const result = engine.validateTierContract(example, tier);
                            
                            for (const v of result.violations) {
                                if (v.severity === 'error') {
                                    violations.push({ severity: 'MUST_HOLD', requirement: v.invariant, reason: `Missing for ${v.tier} tier` });
                                } else if (v.severity === 'warning') {
                                    warnings.push({ requirement: v.invariant, reason: `Recommended for ${v.tier} tier` });
                                }
                            }
                        }
                    } catch { }
                }
            }
        } finally {
            db.close();
        }

        return { ok: violations.length === 0, violations, warnings };
    }

    /**
     * SEMANTIC GOVERNED PIPELINE
     * 
     * Implements the MS2 spec for governed semantic coding:
     * - Stage 1: Intent Convergence (MC5) - External AI refines goals
     * - Stage 2: Constitutional Governance (MC4) - External AI amends invariants
     * - Stage 3: Contract Definition (MC3) - External AI modifies contracts
     * - Stage 4: Module Semantic Finalisation (MC2) - External AI defines executable semantics
     * - Stage 5: Implementation (CODE) - IDE AI writes code from MC2
     * 
     * Authority: MC5 > MC4 > MC3 > MC2 > Code
     * External AI never sees code. IDE AI never changes MC semantics.
     */
    private async runSemanticGovernedPipeline(params: {
        mc5Path?: string;
        mc4Path?: string;
        mc3Path?: string;
        moduleName?: string;
        inputPath: string;
        inputContent: string;
        targetLanguage?: string;
        tier: 'toy' | 'personal' | 'experimental' | 'production' | 'enterprise';
        projectName: string;
        options: { diffMode: boolean; explainMode: boolean; lockArchitecture: boolean; patchOnly: boolean };
    }): Promise<void> {
        console.log('╔════════════════════════════════════════════════════════════╗');
        console.log('║          SEMANTIC GOVERNED PIPELINE                        ║');
        console.log('╚════════════════════════════════════════════════════════════╝\n');
        console.log('Authority: MC5 > MC4 > MC3 > MC2 > Code');
        console.log('External AI: semantic artifacts only');
        console.log('IDE AI: code author (local, trusted)\n');

        const { mc5Path, mc4Path, mc3Path, moduleName, inputPath, inputContent, targetLanguage, tier, projectName, options } = params;

        // Load or create MC artifacts
        let mc5: any = mc5Path && fs.existsSync(mc5Path) ? JSON.parse(fs.readFileSync(mc5Path, 'utf8')) : null;
        let mc4: any = mc4Path && fs.existsSync(mc4Path) ? JSON.parse(fs.readFileSync(mc4Path, 'utf8')) : null;
        let mc3: any = mc3Path && fs.existsSync(mc3Path) ? JSON.parse(fs.readFileSync(mc3Path, 'utf8')) : null;

        const modelRouter = new ModelRouter({ apiKey: this.config.apiKey, debug: false });
        const engine = new TransformEngine({ modelRouter, ms5Invariants: '{}' });

        const outDir = path.join(process.cwd(), 'output', projectName);
        fs.mkdirSync(outDir, { recursive: true });

        // Determine what we're building
        const isNewModule = !mc3 || !moduleName;
        const targetModule = moduleName || path.basename(inputPath, path.extname(inputPath));

        console.log(`Module:    ${targetModule}`);
        console.log(`New:       ${isNewModule ? 'yes' : 'no (updating existing)'}`);
        console.log('');

        // ═══════════════════════════════════════════════════════════════
        // STAGE 1: Intent Convergence (MC5)
        // ═══════════════════════════════════════════════════════════════
        console.log('[Stage 1/5] Intent Convergence (MC5)');
        if (!mc5) {
            console.log('  → Generating MC5 from input...');
            const mc5Result = await engine.execute({
                transformType: 'intent_to_ms5',
                targetId: 'mc5',
                inputs: [{ content: Buffer.from(inputContent), kind: 'intent', hash: '' }],
                validationMode: 'fast',
                tokenBudget: 50000,
                attemptNo: 1,
                modelId: DEFAULT_MODEL_ID,
                idempotencyKey: `mc5-${Date.now()}`,
                policy: buildPolicyForTier(tier)
            });
            if (!mc5Result.success || mc5Result.artifacts.length === 0) {
                console.error('  ✗ MC5 generation failed:', mc5Result.error?.message);
                return;
            }
            mc5 = JSON.parse(mc5Result.artifacts[0].content.toString('utf8'));
            fs.writeFileSync(path.join(outDir, 'MC5.json'), JSON.stringify(mc5, null, 2));
            console.log('  ✓ MC5 generated and saved');
        } else {
            console.log('  → Using existing MC5');
        }

        // ═══════════════════════════════════════════════════════════════
        // STAGE 2: Constitutional Governance (MC4)
        // ═══════════════════════════════════════════════════════════════
        console.log('[Stage 2/5] Constitutional Governance (MC4)');
        if (!mc4) {
            console.log('  → Generating MC4 from MC5...');
            const mc4Result = await engine.execute({
                transformType: 'ms5_to_ms4',
                targetId: 'mc4',
                inputs: [{ content: Buffer.from(JSON.stringify(mc5)), kind: 'ms5', hash: '' }],
                validationMode: 'fast',
                tokenBudget: 50000,
                attemptNo: 1,
                modelId: DEFAULT_MODEL_ID,
                idempotencyKey: `mc4-${Date.now()}`,
                policy: buildPolicyForTier(tier)
            });
            if (!mc4Result.success || mc4Result.artifacts.length === 0) {
                console.error('  ✗ MC4 generation failed:', mc4Result.error?.message);
                return;
            }
            mc4 = JSON.parse(mc4Result.artifacts[0].content.toString('utf8'));
            fs.writeFileSync(path.join(outDir, 'MC4.json'), JSON.stringify(mc4, null, 2));
            console.log('  ✓ MC4 generated and saved');
        } else {
            console.log('  → Using existing MC4');
        }

        // ═══════════════════════════════════════════════════════════════
        // STAGE 3: Contract Definition (MC3)
        // ═══════════════════════════════════════════════════════════════
        console.log('[Stage 3/5] Contract Definition (MC3)');
        if (!mc3) {
            console.log('  → Generating MC3 from MC4...');
            const mc3Result = await engine.execute({
                transformType: 'ms4_to_ms3',
                targetId: 'mc3',
                inputs: [
                    { content: Buffer.from(JSON.stringify(mc5)), kind: 'ms5', hash: '' },
                    { content: Buffer.from(JSON.stringify(mc4)), kind: 'ms4', hash: '' }
                ],
                validationMode: 'fast',
                tokenBudget: 50000,
                attemptNo: 1,
                modelId: DEFAULT_MODEL_ID,
                idempotencyKey: `mc3-${Date.now()}`,
                policy: buildPolicyForTier(tier)
            });
            if (!mc3Result.success || mc3Result.artifacts.length === 0) {
                console.error('  ✗ MC3 generation failed:', mc3Result.error?.message);
                return;
            }
            mc3 = JSON.parse(mc3Result.artifacts[0].content.toString('utf8'));
            fs.writeFileSync(path.join(outDir, 'MC3.json'), JSON.stringify(mc3, null, 2));
            console.log('  ✓ MC3 generated and saved');
        } else {
            console.log('  → Using existing MC3 (symbol table)');
        }

        // Persist MC3 to global store (symbol table)
        const globalMc3Path = path.join(this.config.artifactRoot, '..', 'mc3_global.json');
        fs.writeFileSync(globalMc3Path, JSON.stringify(mc3, null, 2));
        console.log(`  → MC3 persisted to global store: ${globalMc3Path}`);

        // ═══════════════════════════════════════════════════════════════
        // GATE A: Semantic Validity
        // ═══════════════════════════════════════════════════════════════
        console.log('[Gate A] Semantic Validity Check');
        const gateAResult = this.validateSemanticValidity(mc5, mc4, mc3);
        if (!gateAResult.ok) {
            console.error('  ✗ Gate A failed:', gateAResult.errors.join(', '));
            return;
        }
        console.log('  ✓ Gate A passed');

        // ═══════════════════════════════════════════════════════════════
        // STAGE 4: Module Semantic Finalisation (MC2)
        // ═══════════════════════════════════════════════════════════════
        console.log('[Stage 4/5] Module Semantic Finalisation (MC2)');
        console.log(`  → Generating MC2 for module: ${targetModule}`);

        // Build MC2 with linkage_contract
        const mc2Result = await engine.execute({
            transformType: 'ms2_5_to_ms3', // We use this to generate module-level contracts
            targetId: 'mc2',
            inputs: [
                { content: Buffer.from(JSON.stringify(mc3)), kind: 'ms3', hash: '' },
                { content: Buffer.from(JSON.stringify({ module: targetModule, tier })), kind: 'config', hash: '' }
            ],
            validationMode: 'fast',
            tokenBudget: 50000,
            attemptNo: 1,
            modelId: DEFAULT_MODEL_ID,
            idempotencyKey: `mc2-${targetModule}-${Date.now()}`,
            policy: buildPolicyForTier(tier)
        });

        let mc2: any;
        if (!mc2Result.success || mc2Result.artifacts.length === 0) {
            // Fallback: construct MC2 from MC3
            console.log('  → Constructing MC2 from MC3...');
            mc2 = this.constructMc2FromMc3(mc3, targetModule, tier);
        } else {
            mc2 = JSON.parse(mc2Result.artifacts[0].content.toString('utf8'));
        }

        // Add linkage_contract
        mc2.linkage_contract = this.generateLinkageContract(mc3, targetModule);
        
        // Add enforcements[] for rebuildable semantics
        // This is the required schema field that makes MC2 "rebuildable without doubt"
        const enforcements = extractEnforcementRules(inputPath, inputContent);
        mc2.enforcements = enforcements;
        console.log(`  → Extracted ${enforcements.length} enforcement rules from source`);
        
        fs.writeFileSync(path.join(outDir, `MC2_${targetModule}.json`), JSON.stringify(mc2, null, 2));
        console.log('  ✓ MC2 generated with linkage_contract and enforcements');

        // ═══════════════════════════════════════════════════════════════
        // GATE B: Linkage Contract Validator
        // ═══════════════════════════════════════════════════════════════
        console.log('[Gate B] Linkage Contract Validation');
        const gateBResult = this.validateLinkageContract(mc2.linkage_contract);
        if (!gateBResult.ok) {
            console.error('  ✗ Gate B failed:', gateBResult.errors.join(', '));
            fs.writeFileSync(path.join(outDir, 'GATE_B_FAILURE.json'), JSON.stringify(gateBResult, null, 2));
            return;
        }
        console.log('  ✓ Gate B passed');

        // ═══════════════════════════════════════════════════════════════
        // GATE S: Semantic Conservation (refusal on under-specified MC)
        // ═══════════════════════════════════════════════════════════════
        console.log('[Gate S] Semantic Conservation Check');
        
        // Compute semantic mass ratio
        const semanticMassReport = computeSemanticMass(inputPath, inputContent, mc3, mc2);
        
        console.log(`  Source enforcement points: ${semanticMassReport.enforcement_points_source}`);
        console.log(`    - branches: ${semanticMassReport.source_breakdown.branches}`);
        console.log(`    - throws/raises: ${semanticMassReport.source_breakdown.throws}`);
        console.log(`    - early returns: ${semanticMassReport.source_breakdown.early_returns}`);
        console.log(`    - validations: ${semanticMassReport.source_breakdown.validations}`);
        console.log(`    - transitions: ${semanticMassReport.source_breakdown.transitions}`);
        console.log(`    - side effects: ${semanticMassReport.source_breakdown.side_effects}`);
        console.log(`  MC enforcement points: ${semanticMassReport.enforcement_points_mc}`);
        console.log(`    - denies: ${semanticMassReport.mc_breakdown.denies}`);
        console.log(`    - guards: ${semanticMassReport.mc_breakdown.guards}`);
        console.log(`    - constraints: ${semanticMassReport.mc_breakdown.constraints}`);
        console.log(`    - invariants: ${semanticMassReport.mc_breakdown.invariants}`);
        console.log(`    - enforcements: ${semanticMassReport.mc_breakdown.enforcements}`);
        console.log(`  Semantic mass ratio: ${semanticMassReport.semantic_mass_ratio}`);
        
        // Check threshold (0.60 for single file)
        const SEMANTIC_MASS_THRESHOLD = 0.60;
        const gateSResult = checkSemanticConservation(semanticMassReport, SEMANTIC_MASS_THRESHOLD);
        
        if (!gateSResult.ok) {
            console.error('  ✗ Gate S failed: UNDER_SPECIFIED_SEMANTICS');
            console.error(`    Ratio: ${semanticMassReport.semantic_mass_ratio} < ${SEMANTIC_MASS_THRESHOLD} threshold`);
            if (semanticMassReport.missing_families.length > 0) {
                console.error('  Missing enforcement families:');
                for (const family of semanticMassReport.missing_families) {
                    console.error(`    - ${family}`);
                }
            }
            
            // Write Gate S failure report
            const gateSFailure = {
                gate: 'S',
                name: 'semantic_conservation',
                passed: false,
                refusal_code: 'UNDER_SPECIFIED_SEMANTICS',
                semantic_mass_report: semanticMassReport,
                threshold: SEMANTIC_MASS_THRESHOLD,
                message: gateSResult.reason
            };
            fs.writeFileSync(path.join(outDir, 'GATE_S_FAILURE.json'), JSON.stringify(gateSFailure, null, 2));
            
            // Emit audit log with Gate S refusal
            const auditLogGateS = {
                pipeline: 'semantic_governed',
                timestamp: new Date().toISOString(),
                module: targetModule,
                tier,
                stages: [
                    { stage: 1, name: 'intent_convergence', artifact: 'MC5.json', status: 'completed' },
                    { stage: 2, name: 'constitutional_governance', artifact: 'MC4.json', status: 'completed' },
                    { stage: 3, name: 'contract_definition', artifact: 'MC3.json', status: 'completed' },
                    { stage: 4, name: 'module_semantic_finalisation', artifact: `MC2_${targetModule}.json`, status: 'completed' },
                    { stage: 5, name: 'implementation', artifact: null, status: 'NOT_REACHED' }
                ],
                gates: [
                    { gate: 'A', name: 'semantic_validity', passed: gateAResult.ok },
                    { gate: 'B', name: 'linkage_contract', passed: gateBResult.ok },
                    { gate: 'S', name: 'semantic_conservation', passed: false }
                ],
                refusal: {
                    code: 'UNDER_SPECIFIED_SEMANTICS',
                    message: gateSResult.reason,
                    semantic_mass_ratio: semanticMassReport.semantic_mass_ratio,
                    threshold: SEMANTIC_MASS_THRESHOLD,
                    missing_families: semanticMassReport.missing_families,
                    artifacts_produced: ['MC5.json', 'MC4.json', 'MC3.json', `MC2_${targetModule}.json`, 'GATE_S_FAILURE.json']
                },
                cost_usd: 0
            };
            fs.writeFileSync(path.join(outDir, 'AUDIT_LOG.json'), JSON.stringify(auditLogGateS, null, 2));
            
            console.log('\n[Output] Semantic artifacts only (Gate S refused):');
            console.log('  + MC5.json');
            console.log('  + MC4.json');
            console.log('  + MC3.json');
            console.log(`  + MC2_${targetModule}.json`);
            console.log('  + GATE_S_FAILURE.json');
            console.log('  + AUDIT_LOG.json');
            
            console.log('\n════════════════════════════════════════════════════════════');
            console.log('SEMANTIC GOVERNED PIPELINE REFUSED: UNDER_SPECIFIED_SEMANTICS');
            console.log(`Output: ${outDir}`);
            console.log('════════════════════════════════════════════════════════════');
            return;
        }
        console.log('  ✓ Gate S passed');

        // ═══════════════════════════════════════════════════════════════
        // STAGE 5: Implementation (CODE) - FORBIDDEN in semantic_governed
        // ═══════════════════════════════════════════════════════════════
        // In semantic_governed mode, the pipeline produces ONLY:
        // - MC artifacts (MC5, MC4, MC3, MC2)
        // - Evidence pack (AUDIT_LOG)
        // - REFUSAL
        // It is NOT allowed to emit: generated code, interfaces, stubs,
        // placeholders, API skeletons, or any implementation.
        console.log('[Stage 5/5] Implementation Check');
        console.log('  ✗ REFUSE: CODEGEN_FORBIDDEN_IN_SEMANTIC_GOVERNED');
        console.log('');
        console.log('  In semantic_governed mode, the compiler produces only:');
        console.log('    - MC artifacts (MC5, MC4, MC3, MC2)');
        console.log('    - Evidence pack (AUDIT_LOG.json)');
        console.log('    - Honest refusal');
        console.log('');
        console.log('  Code generation is explicitly forbidden.');
        console.log('  To generate code, use --mode default.');
        
        // Emit audit log with refusal
        const auditLogRefusal = {
            pipeline: 'semantic_governed',
            timestamp: new Date().toISOString(),
            module: targetModule,
            tier,
            stages: [
                { stage: 1, name: 'intent_convergence', artifact: 'MC5.json', status: 'completed' },
                { stage: 2, name: 'constitutional_governance', artifact: 'MC4.json', status: 'completed' },
                { stage: 3, name: 'contract_definition', artifact: 'MC3.json', status: 'completed' },
                { stage: 4, name: 'module_semantic_finalisation', artifact: `MC2_${targetModule}.json`, status: 'completed' },
                { stage: 5, name: 'implementation', artifact: null, status: 'REFUSED' }
            ],
            gates: [
                { gate: 'A', name: 'semantic_validity', passed: gateAResult.ok },
                { gate: 'B', name: 'linkage_contract', passed: gateBResult.ok }
            ],
            refusal: {
                code: 'CODEGEN_FORBIDDEN_IN_SEMANTIC_GOVERNED',
                message: 'Code generation is forbidden in semantic_governed mode. Only MC artifacts and evidence are produced.',
                artifacts_produced: ['MC5.json', 'MC4.json', 'MC3.json', `MC2_${targetModule}.json`]
            },
            cost_usd: 0
        };
        fs.writeFileSync(path.join(outDir, 'AUDIT_LOG.json'), JSON.stringify(auditLogRefusal, null, 2));
        console.log('\n[Output] Semantic artifacts only (code generation refused):');
        console.log('  + MC5.json');
        console.log('  + MC4.json');
        console.log('  + MC3.json');
        console.log(`  + MC2_${targetModule}.json`);
        console.log('  + AUDIT_LOG.json');
        
        console.log('\n════════════════════════════════════════════════════════════');
        console.log('SEMANTIC GOVERNED PIPELINE COMPLETE (NO CODE EMITTED)');
        console.log(`Output: ${outDir}`);
        console.log('════════════════════════════════════════════════════════════');
        return;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VALIDATION GATES
    // ═══════════════════════════════════════════════════════════════════════

    private validateSemanticValidity(mc5: any, mc4: any, mc3: any): { ok: boolean; errors: string[] } {
        const errors: string[] = [];

        // MC5 must have problem and goal
        if (!mc5?.problem && !mc5?.intent) errors.push('MC5 missing problem/intent');

        // MC4 must have invariants or constitution
        if (!mc4?.invariants && !mc4?.constitution && !mc4?.mc_family) errors.push('MC4 missing invariants/constitution');

        // MC3 must have modules or contracts
        if (!mc3?.modules && !mc3?.mc_family && !mc3?.contracts && !mc3?.DOES) errors.push('MC3 missing modules/contracts');

        return { ok: errors.length === 0, errors };
    }

    private validateLinkageContract(linkage: any): { ok: boolean; errors: string[] } {
        const errors: string[] = [];
        if (!linkage) {
            errors.push('linkage_contract is missing');
            return { ok: false, errors };
        }

        const linkageStr = JSON.stringify(linkage).toLowerCase();

        // Reject if imports, module names, file names appear
        if (linkageStr.includes('import ') || linkageStr.includes('require(')) {
            errors.push('linkage_contract contains import statements');
        }
        if (linkageStr.includes('.ts') || linkageStr.includes('.js') || linkageStr.includes('.py')) {
            errors.push('linkage_contract contains file extensions');
        }
        // Reject if control flow appears
        if (linkageStr.includes('if (') || linkageStr.includes('for (') || linkageStr.includes('while (')) {
            errors.push('linkage_contract contains control flow');
        }
        // Size cap (linkage should be small)
        if (linkageStr.length > LINKAGE_CONTRACT_MAX_CHARS) {
            errors.push(`linkage_contract exceeds size cap (${LINKAGE_CONTRACT_MAX_CHARS} chars)`);
        }

        return { ok: errors.length === 0, errors };
    }

    private validateCodeSafety(content: Buffer): { ok: boolean; errors: string[] } {
        const errors: string[] = [];
        const code = content.toString('utf8');

        // Basic syntax check - ensure it's parseable
        try {
            if (code.startsWith('{')) {
                JSON.parse(code); // If JSON, validate it
            }
        } catch (e: any) {
            errors.push(`JSON parse error: ${e.message}`);
        }

        // Check for obviously dangerous patterns
        if (code.includes('eval(') || code.includes('Function(')) {
            errors.push('Code contains eval() or Function() - potential security risk');
        }

        return { ok: errors.length === 0, errors };
    }

    private constructMc2FromMc3(mc3: any, moduleName: string, tier: string): any {
        // Extract module info from MC3
        const modules = mc3.modules || mc3.mc_family?.levels || [];
        const targetModule = modules.find((m: any) => 
            m.name?.toLowerCase() === moduleName.toLowerCase() ||
            m.module?.toLowerCase() === moduleName.toLowerCase()
        ) || {};

        return {
            module: moduleName,
            tier,
            responsibilities: targetModule.responsibilities || targetModule.DOES || [],
            behaviors: targetModule.behaviors || targetModule.METHODS || [],
            error_modes: targetModule.error_modes || targetModule.DENIES || [],
            state_transitions: targetModule.state_transitions || [],
            tests: targetModule.tests || []
        };
    }

    private generateLinkageContract(mc3: any, moduleName: string): any {
        // Generate mechanical linkage contract from MC3
        const modules = mc3.modules || mc3.mc_family?.levels || [];
        const dependencies: string[] = [];

        // Find what this module depends on
        for (const m of modules) {
            const name = m.name || m.module || '';
            if (name.toLowerCase() !== moduleName.toLowerCase()) {
                dependencies.push(name);
            }
        }

        return {
            module: moduleName,
            provides: ['capabilities defined in MC2'],
            requires: dependencies.slice(0, 5), // Limit to 5 dependencies
            constraints: [
                'Must not introduce new architecture',
                'Must reuse existing structures from MC3',
                'Must follow tier requirements'
            ]
        };
    }

    private async compileFromIntent(
        intent: string,
        targetLanguage: string | undefined,
        tier: 'toy' | 'personal' | 'experimental' | 'production' | 'enterprise',
        projectName: string,
        options: { diffMode: boolean; explainMode: boolean; lockArchitecture: boolean }
    ): Promise<void> {
        console.log('Pipeline: Intent → MS5 → MS4 → MS3 → MS2\n');

        const ms5Spec = {
            problem: intent,
            goal: `Build ${targetLanguage || 'TypeScript'} implementation at ${tier} tier`,
            product_definition: {
                name: projectName,
                description: intent.slice(0, 200),
            },
            stages: [
                {
                    name: 'architecture',
                    targets: [{ name: 'ms4', config: { transform_type: 'ms5_to_ms4' } }],
                },
                {
                    name: 'contracts',
                    targets: [{ name: 'ms3', config: { transform_type: 'ms4_to_ms3' } }],
                },
                {
                    name: 'implementation',
                    targets: [{ name: 'code', config: { transform_type: 'ms3_to_ms2', target_language: targetLanguage } }],
                },
            ],
            global_config: {
                tier,
                default_model: DEFAULT_MODEL_ID,
            },
        };

        const intentArtifact = { intent, timestamp: new Date().toISOString() };
        const intentStored = this.storeInputArtifact(Buffer.from(JSON.stringify(intentArtifact, null, 2)));

        const modelRouter = new ModelRouter({
            apiKey: this.config.apiKey,
            debug: false
        });

        const baseEngine = new TransformEngine({
            modelRouter,
            ms5Invariants: '{}'
        });

        const engineAdapter = new CliTransformAdapter(baseEngine, this.config.artifactRoot);

        const kernel = new KernelOrchestrator(
            this.config.dbPath,
            this.config.artifactRoot,
            engineAdapter
        );

        try {
            const init = kernel.initializeRecovery();
            if (!init.ok) {
                console.error('Kernel initialization failed:', init.error, init.message);
                return;
            }

            const result = await kernel.orchestrateBuild({
                ms5_spec: ms5Spec,
                budget_usd: 5.0,
                input_artifacts: [{ artifact_id: intentStored.sha256, sha256: intentStored.sha256, kind: 'intent' as const }]
            });

            if (!result.ok) {
                console.error('Compilation failed:', result.error, result.message);
                return;
            }

            const build = result.value;
            console.log(`\nCompilation ${build.final_state}`);
            console.log(`   Cost: $${parseFloat(String(build.cumulative_cost_usd || 0)).toFixed(4)}`);

            if (build.final_state === 'SUCCESS') {
                await this.exportBuildArtifacts(build.build_id, projectName);

                if (options.diffMode || options.explainMode) {
                    await this.emitCompilationReport(build.build_id, projectName, options);
                }
            }
        } finally {
            kernel.close();
        }
    }

    private async emitCompilationReport(
        buildId: string,
        projectName: string,
        options: { diffMode: boolean; explainMode: boolean; lockArchitecture: boolean }
    ): Promise<void> {
        console.log('\n════════════════════════════════════════════════════════════');
        console.log('                    COMPILATION REPORT');
        console.log('════════════════════════════════════════════════════════════\n');

        const db = new Database(this.config.dbPath, { readonly: true });
        const outDir = path.join(process.cwd(), 'output', projectName);

        try {
            const rows = db.prepare(`
                SELECT a.sha256, a.kind, a.storage_path, ar.target, ar.stage 
                FROM artifact_refs ar
                JOIN artifacts a ON ar.artifact_id = a.artifact_id
                WHERE ar.build_id = ?
                ORDER BY ar.created_at ASC
            `).all(buildId) as any[];

            let ms2_5Artifact: any = null;
            let ms3Artifact: any = null;

            for (const row of rows) {
                const artifactPath = row.storage_path
                    ? row.storage_path
                    : path.join(this.config.artifactRoot, row.sha256.slice(0, 2), row.sha256);

                if (fs.existsSync(artifactPath)) {
                    try {
                        const content = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
                        if (row.kind === 'ms2_5' || row.target === 'ms2_5') {
                            ms2_5Artifact = content;
                        } else if (row.kind === 'ms3' || row.target === 'ms3') {
                            ms3Artifact = content;
                        }
                    } catch { }
                }
            }

            if (options.diffMode) {
                console.log('┌─────────────────────────────────────────────────────────────┐');
                console.log('│                    SEMANTIC DIFF (MS2.5)                    │');
                console.log('└─────────────────────────────────────────────────────────────┘\n');

                if (ms2_5Artifact) {
                    const modules = ms2_5Artifact.modules || [];
                    for (const mod of modules) {
                        console.log(`Module: ${mod.name || mod.id}`);
                        console.log(`  Responsibilities: ${(mod.responsibilities || []).length}`);
                        for (const r of (mod.responsibilities || []).slice(0, 5)) {
                            console.log(`    • ${r}`);
                        }
                        console.log(`  Behaviors: ${(mod.behaviors || []).length}`);
                        for (const b of (mod.behaviors || []).slice(0, 5)) {
                            console.log(`    • ${b.name}: ${b.summary || ''}`);
                        }
                        console.log(`  Data Models: ${(mod.data_models || []).length}`);
                        console.log(`  Error Taxonomy: ${(mod.error_taxonomy || []).length}`);
                        console.log('');
                    }

                    const reportPath = path.join(outDir, 'SEMANTIC_DIFF.ms2_5.json');
                    fs.writeFileSync(reportPath, JSON.stringify(ms2_5Artifact, null, 2));
                    console.log(`  → Saved to ${reportPath}\n`);
                } else {
                    console.log('  (No MS2.5 artifact found)\n');
                }

                console.log('┌─────────────────────────────────────────────────────────────┐');
                console.log('│                    CONTRACT DIFF (MS3)                      │');
                console.log('└─────────────────────────────────────────────────────────────┘\n');

                if (ms3Artifact) {
                    const levels = ms3Artifact.mc_family?.levels || [];
                    for (const level of levels) {
                        const example = level.example || {};
                        console.log(`Level: ${level.level}`);
                        console.log(`  DOES: ${(example.DOES || []).length} assertions`);
                        for (const d of (example.DOES || []).slice(0, 5)) {
                            console.log(`    ✓ ${d}`);
                        }
                        console.log(`  DENIES: ${(example.DENIES || []).length} constraints`);
                        for (const d of (example.DENIES || []).slice(0, 5)) {
                            console.log(`    ✗ ${d}`);
                        }
                        console.log(`  METHODS: ${(example.METHODS || []).length} signatures`);
                        console.log('');
                    }

                    const reportPath = path.join(outDir, 'CONTRACT_DIFF.ms3.json');
                    fs.writeFileSync(reportPath, JSON.stringify(ms3Artifact, null, 2));
                    console.log(`  → Saved to ${reportPath}\n`);
                } else {
                    console.log('  (No MS3 artifact found)\n');
                }
            }

            if (options.explainMode) {
                console.log('┌─────────────────────────────────────────────────────────────┐');
                console.log('│                       EXPLANATION                           │');
                console.log('└─────────────────────────────────────────────────────────────┘\n');

                const explanation: string[] = [];

                if (ms2_5Artifact) {
                    const modules = ms2_5Artifact.modules || [];
                    explanation.push(`Semantic Analysis extracted ${modules.length} module(s):`);
                    for (const mod of modules) {
                        explanation.push(`  • ${mod.name || mod.id}: ${(mod.responsibilities || []).length} responsibilities, ${(mod.behaviors || []).length} behaviors`);
                    }
                    explanation.push('');
                }

                if (ms3Artifact) {
                    const levels = ms3Artifact.mc_family?.levels || [];
                    explanation.push(`Contract Elevation produced ${levels.length} contract level(s):`);
                    for (const level of levels) {
                        const example = level.example || {};
                        explanation.push(`  • ${level.level}: ${(example.DOES || []).length} DOES, ${(example.DENIES || []).length} DENIES, ${(example.METHODS || []).length} METHODS`);
                    }
                    explanation.push('');
                }

                explanation.push('What Changed:');
                explanation.push('  • Original code was analyzed for semantic meaning (not syntax)');
                explanation.push('  • Clean-room contracts were derived from semantics');
                explanation.push('  • New implementation was generated from contracts');
                explanation.push('');
                explanation.push('Why:');
                explanation.push('  • Semantics capture WHAT the code does, not HOW');
                explanation.push('  • Contracts define the architectural boundaries');
                explanation.push('  • Implementation follows contracts, not original structure');

                for (const line of explanation) {
                    console.log(line);
                }

                const reportPath = path.join(outDir, 'EXPLANATION.txt');
                fs.writeFileSync(reportPath, explanation.join('\n'));
                console.log(`\n  → Saved to ${reportPath}\n`);
            }

        } finally {
            db.close();
        }
    }

    private async exportBuildArtifacts(buildId: string, projectName: string): Promise<void> {
        console.log('\nExporting artifacts...');
        const db = new Database(this.config.dbPath, { readonly: true });

        try {
            const rows = db.prepare(`
                SELECT a.sha256, a.kind, a.storage_path, ar.target, ar.stage 
                FROM artifact_refs ar
                JOIN artifacts a ON ar.artifact_id = a.artifact_id
                WHERE ar.build_id = ?
            `).all(buildId) as any[];

            if (rows.length === 0) {
                console.log('   No generated artifacts found (check if implementation stage ran).');
                return;
            }

            const outDir = path.join(process.cwd(), 'output', projectName);
            fs.mkdirSync(outDir, { recursive: true });

            let count = 0;
            for (const row of rows) {
                // Use explicit storage path if available, otherwise fallback to standard layout
                const artifactPath = row.storage_path
                    ? row.storage_path
                    : path.join(this.config.artifactRoot, row.sha256.slice(0, 2), row.sha256);

                if (fs.existsSync(artifactPath)) {
                    const raw = fs.readFileSync(artifactPath, 'utf8');
                    try {
                        const json = JSON.parse(raw);
                        if (Array.isArray(json.files)) {
                            for (const file of json.files) {
                                const relPath = file.path.replace(/^[\\/\\\\]/, ''); // Strip leading slash
                                const fullPath = path.join(outDir, relPath);
                                const dir = path.dirname(fullPath);
                                fs.mkdirSync(dir, { recursive: true });
                                fs.writeFileSync(fullPath, file.content);
                                console.log(`   + ${relPath}`);
                                count++;
                            }
                        }
                    } catch (e) {
                        // Not JSON or schema mismatch, ignore
                    }
                }
            }
            console.log(`\nExported ${count} files to ${outDir}`);
        } catch (e: any) {
            console.error('Export failed:', e.message);
        } finally {
            db.close();
        }
    }

    private async runStatus(): Promise<void> {
        console.log('Director Kernel Status\n');

        const db = new Database(this.config.dbPath, { readonly: true });

        try {
            const tables = new Set(
                (db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as any[]).map((r) => r.name)
            );
            if (tables.size === 0) {
                console.log('Database not initialized. Run `dirkernel init` and then `dirkernel build ...`.');
                return;
            }

            const lockInfo = tables.has('singleton_lock')
                ? (db.prepare('SELECT * FROM singleton_lock WHERE lock_id=1').get() as any)
                : null;

            console.log('Lock Status:');
            if (lockInfo && lockInfo.build_id) {
                console.log(`   Status: LOCKED`);
                console.log(`   Build ID: ${lockInfo.build_id}`);
                console.log(`   PID: ${lockInfo.acquired_by_pid}`);
                console.log(`   Process: ${lockInfo.process_name}`);
                console.log(`   Acquired: ${lockInfo.acquired_at}`);
                console.log(`   Last Heartbeat: ${lockInfo.last_heartbeat_at}`);
            } else {
                console.log(`   Status: UNLOCKED`);
            }

            const hasCumulativeTokens = (() => {
                if (!tables.has('builds')) return false;
                const cols = new Set(
                    (db.prepare("PRAGMA table_info('builds')").all() as any[]).map((r) => String(r.name))
                );
                return cols.has('cumulative_tokens');
            })();

            const recentBuilds = tables.has('builds')
                ? (db.prepare(
                    hasCumulativeTokens
                        ? `SELECT build_id, state, created_at, cumulative_cost_usd, cumulative_tokens FROM builds ORDER BY created_at DESC LIMIT 5`
                        : `SELECT build_id, state, created_at, cumulative_cost_usd FROM builds ORDER BY created_at DESC LIMIT 5`
                ).all() as any[])
                : [];

            console.log('\nRecent Builds:');
            if (recentBuilds.length === 0) {
                console.log('   No builds found');
            } else {
                for (const build of recentBuilds) {
                    const cost = build.cumulative_cost_usd ? `$${parseFloat(String(build.cumulative_cost_usd || 0)).toFixed(2)}` : '$0.00';
                    const tokens = (build as any).cumulative_tokens || 0;
                    console.log(`   ${build.build_id} - ${build.state} (${cost}, ${tokens} tokens) - ${build.created_at}`);
                }
            }

            const artifactCount = tables.has('artifacts')
                ? (db.prepare('SELECT COUNT(*) as count FROM artifacts').get() as any)
                : { count: 0 };

            const hasSizeBytes = (() => {
                if (!tables.has('artifacts')) return false;
                const cols = new Set(
                    (db.prepare("PRAGMA table_info('artifacts')").all() as any[]).map((r) => String(r.name))
                );
                return cols.has('size_bytes');
            })();

            const totalSize = tables.has('artifacts') && hasSizeBytes
                ? (db.prepare('SELECT SUM(size_bytes) as total FROM artifacts').get() as any)
                : { total: 0 };

            console.log('\nArtifact Store:');
            console.log(`   Total Artifacts: ${artifactCount.count}`);
            console.log(`   Total Size: ${((totalSize.total || 0) / 1024 / 1024).toFixed(2)} MB`);
            console.log(`   Storage Path: ${this.config.artifactRoot}`);

            console.log('\nConfiguration:');
            console.log(`   Database: ${this.config.dbPath}`);
            console.log(`   API Key: configured`);
        } catch (error: any) {
            console.error('Error reading status:', error.message);
            console.log('\nTip: Run `dirkernel init` if database is not initialized');
        } finally {
            db.close();
        }

    }

    private showHelp(): void {
        console.log(`
Director Kernel - AI Coding Kernel

            USAGE:
            dirkernel < command > [options]

            COMMANDS:
  init                Initialize the kernel and create config file
  build <ms5_file>     Run a build from an MS5 specification
  status              Show build status and history
  clear-lock          Force clear the build lock (use if stuck)
  help                Show this help

            EXAMPLES:
  dirkernel init
  dirkernel build project.ms5.json --tier production
  dirkernel build project.ms5.json --tier production --input-ms4 examples\\director-kernel.mc4.json
  dirkernel build project.ms5.json --tier production --input-ms3 path\\to\\artifact.ms3.json
  dirkernel status

For more information, visit: https://github.com/director-kernel
            `);
    }
}

class CliTransformAdapter implements TransformEngineInterface {
    constructor(private engine: TransformEngine, private artifactRoot: string) { }

    async execute(
        stage: string,
        target: string,
        inputs: ArtifactRef[],
        config: any,
        attempt_no: number,
        idempotency_key: string
    ): Promise<KernelResult> {
        console.log(`[CliTransformAdapter] execute called: stage=${stage}, target=${target}, inputs=${inputs.length}`);

        // 1. Load artifact content from disk (Adapter responsibility)
        const loadedInputs = inputs.map(ref => {
            const p = path.join(this.artifactRoot, ref.sha256.slice(0, 2), ref.sha256);
            console.log(`[CliTransformAdapter] Loading artifact: ${ref.sha256} from ${p}`);
            if (!fs.existsSync(p)) throw new Error(`Artifact missing on disk: ${ref.sha256} `);
            return {
                content: fs.readFileSync(p),
                kind: ref.kind as any, // Cast to any to bypass Kind mismatch
                hash: ref.sha256
            };
        });

        // 2. Call Pure Compute Engine
        // TransformEngine expects TransformRequest
        // Prefer explicit config override (if provided by MS5 target config), otherwise infer
        // from primary input kind. Stage-name substring heuristics are too error-prone for
        // strings like "MS4->MS3" which contain multiple MS tokens.
        const transformType = this.deriveTransformType(stage, loadedInputs, config);
        console.log(`[CliTransformAdapter] Derived transformType: ${transformType}`);

        // Get tier from config (passed from MS5 global_config) or env or default
        const configTier = config?.tier || config?.global_config?.tier;
        const parsedTier = parseDirectorTier(configTier) || parseDirectorTier(process.env.DIRECTOR_TIER) || 'experimental';
        const policy = buildPolicyForTier(parsedTier);
        const req = {
            transformType: transformType,
            targetId: target,
            inputs: loadedInputs,
            validationMode: 'fast' as const,
            tokenBudget: 100000,
            attemptNo: attempt_no,
            modelId: DEFAULT_MODEL_ID,
            idempotencyKey: idempotency_key,
            policy
        };

        console.log(`[CliTransformAdapter] Calling engine.execute with modelId=${req.modelId}`);
        const res: ComputeResult = await this.engine.execute(req);
        console.log(`[CliTransformAdapter] engine.execute returned: success=${res.success}, artifacts=${res.artifacts.length}, costUsd=${res.costUsd}`);

        // OPTIMIZATION: Early tier validation after MS3 generation (before MS2)
        if (res.success && (target === 'ms3' || transformType === 'ms2_5_to_ms3' || transformType === 'ms4_to_ms3')) {
            const tierValidation = this.validateTierEarly(res.artifacts, parsedTier);
            if (!tierValidation.ok) {
                console.error('\n❌ TIER VALIDATION FAILED (early exit - MS2 generation skipped)');
                console.error(`   Tier: ${parsedTier}`);
                console.error(`   Violations (${tierValidation.violations.length}):`);
                for (const v of tierValidation.violations) {
                    console.error(`     • [MUST_HOLD] ${v}`);
                }

                // Emit partial report for reviewability (B)
                this.emitTierFailureReport(res.artifacts, parsedTier, tierValidation.violations);

                // Persist MS3 artifact for inspection (A) - return artifacts, not empty
                return {
                    success: false,
                    artifacts: res.artifacts.map(a => ({ kind: a.kind as any, content: a.content })),
                    logs: `Tier validation failed: ${tierValidation.violations.length} violations`,
                    cost_usd: res.costUsd,
                    tokens: res.tokenUsage.totalTokens,
                    error: { code: 'TIER_VALIDATION_FAILED', message: `${tierValidation.violations.length} must_hold violations for ${parsedTier} tier` }
                };
            }
        }

        // 3. Map result to Kernel format (snake_case)
        return {
            success: res.success,
            artifacts: res.artifacts.map(a => ({
                kind: a.kind as any,
                content: a.content,
            })),
            logs: res.logs.join('\n'),
            cost_usd: res.costUsd,
            tokens: res.tokenUsage.totalTokens,
            error: res.error ? { code: res.error.code, message: res.error.message } : undefined,
            provenance: res.provenance,
        };
    }

    private deriveTransformType(
        stage: string,
        loadedInputs: Array<{ kind: string }>,
        config: any
    ): any {
        // 0) Explicit override (supported as either camel or snake)
        const explicit = config?.transformType || config?.transform_type;
        if (explicit === 'ms5_to_ms4' || explicit === 'ms4_to_ms3' || explicit === 'ms3_to_ms2' || explicit === 'ms2_to_ms2_5' || explicit === 'ms2_5_to_ms3' || explicit === 'intent_to_ms5') return explicit;

        // 1) Infer from input kinds (deterministic)
        const kinds = (loadedInputs || []).map((x) => String(x.kind || '').toLowerCase());
        if (kinds.some((k) => k.includes('intent'))) return 'intent_to_ms5';
        if (kinds.some((k) => k.includes('ms2_5') || k.includes('ms2.5'))) return 'ms2_5_to_ms3';
        if (kinds.some((k) => k.includes('ms3'))) return 'ms3_to_ms2';
        if (kinds.some((k) => k.includes('ms4'))) return 'ms4_to_ms3';
        if (kinds.some((k) => k.includes('ms5'))) return 'ms5_to_ms4';

        // 2) LAST RESORT: heuristic on stage name
        const lower = stage.toLowerCase();
        // Look for explicit arrows first (e.g. "ms4->ms3", "ms2->ms2.5", "ms2.5->ms3", "intent->ms5")
        if (lower.includes('intent') && lower.includes('ms5') || lower.includes('expand')) return 'intent_to_ms5';
        if (lower.includes('ms2.5') && lower.includes('ms3') || lower.includes('ms2_5') && lower.includes('ms3') || lower.includes('elevat')) return 'ms2_5_to_ms3';
        if (lower.includes('ms2') && (lower.includes('ms2.5') || lower.includes('ms2_5') || lower.includes('compress') || lower.includes('analysis'))) return 'ms2_to_ms2_5';
        if (lower.includes('ms5') && lower.includes('ms4')) return 'ms5_to_ms4';
        if (lower.includes('ms4') && lower.includes('ms3')) return 'ms4_to_ms3';
        if (lower.includes('ms3') && lower.includes('ms2')) return 'ms3_to_ms2';

        // Fallback to keyword matching
        if (lower.includes('implement') || lower.includes('cod') || lower.includes('dev')) return 'ms3_to_ms2';
        if (lower.includes('contract') || lower.includes('api')) return 'ms4_to_ms3';
        if (lower.includes('architect') || lower.includes('design') || lower.includes('plan')) return 'ms5_to_ms4';

        // Default to architecture if unsure
        return 'ms5_to_ms4';
    }

    private validateTierEarly(
        artifacts: Array<{ kind: string; content: Buffer }>,
        tier: 'toy' | 'personal' | 'experimental' | 'production' | 'enterprise'
    ): { ok: boolean; violations: string[] } {
        const violations: string[] = [];

        for (const artifact of artifacts) {
            try {
                const ms3Content = JSON.parse(artifact.content.toString('utf8'));
                const levels = ms3Content.mc_family?.levels || [];
                
                for (const level of levels) {
                    const example = level.example || {};
                    const result = this.engine.validateTierContract(example, tier);
                    
                    for (const v of result.violations) {
                        if (v.severity === 'error') {
                            violations.push(v.invariant);
                        }
                    }
                }
            } catch { }
        }

        return { ok: violations.length === 0, violations };
    }

    private emitTierFailureReport(
        artifacts: Array<{ kind: string; content: Buffer }>,
        tier: string,
        violations: string[]
    ): void {
        const outDir = path.join(process.cwd(), 'output', 'FAILED_BUILD');
        fs.mkdirSync(outDir, { recursive: true });

        // 1. Save the failing MS3 for inspection
        for (const artifact of artifacts) {
            try {
                const ms3Content = JSON.parse(artifact.content.toString('utf8'));
                const ms3Path = path.join(outDir, 'FAILED_MS3.json');
                fs.writeFileSync(ms3Path, JSON.stringify(ms3Content, null, 2));
                console.log(`\n📄 Failing MS3 saved to: ${ms3Path}`);
            } catch { }
        }

        // 2. Save tier violations
        const violationsReport = {
            status: 'FAILED_TIER_VALIDATION',
            tier,
            timestamp: new Date().toISOString(),
            violation_count: violations.length,
            violations: violations.map(v => ({
                severity: 'MUST_HOLD',
                invariant: v,
                reason: `Missing for ${tier} tier`
            }))
        };
        const violationsPath = path.join(outDir, 'TIER_VIOLATIONS.json');
        fs.writeFileSync(violationsPath, JSON.stringify(violationsReport, null, 2));
        console.log(`📄 Tier violations saved to: ${violationsPath}`);

        // 3. Save explanation
        const explanation = [
            '# TIER VALIDATION FAILURE',
            '',
            `Status: FAILED`,
            `Tier: ${tier}`,
            `Timestamp: ${new Date().toISOString()}`,
            '',
            '## What Happened',
            `The generated MS3 contract does not satisfy the ${tier} tier requirements.`,
            'MS2 code generation was skipped to prevent non-compliant output.',
            '',
            '## Violations',
            ...violations.map(v => `  • [MUST_HOLD] ${v}`),
            '',
            '## What To Do',
            `1. Review FAILED_MS3.json to see the generated contract`,
            `2. Either:`,
            `   a) Lower the tier requirement (e.g., --tier production instead of --tier enterprise)`,
            `   b) Improve the source code to include missing requirements`,
            `   c) Accept that the source code is not ${tier}-ready`,
            '',
            '## Files',
            `  • FAILED_MS3.json - The MS3 contract that failed validation`,
            `  • TIER_VIOLATIONS.json - Structured violation data`,
            `  • EXPLANATION.txt - This file`,
        ];
        const explainPath = path.join(outDir, 'EXPLANATION.txt');
        fs.writeFileSync(explainPath, explanation.join('\n'));
        console.log(`📄 Explanation saved to: ${explainPath}`);
    }
}

// Run CLI
if (require.main === module) {
    const cli = new DirectorKernelCLI();
    cli.run(process.argv).catch((err: any) => {
        console.error('Fatal error:', err);
        process.exit(1);
    });
}

export { DirectorKernelCLI };

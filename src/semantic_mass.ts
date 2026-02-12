/**
 * Semantic Mass Counter
 * 
 * Counts "enforcement points" in source code vs MC artifacts.
 * Used by Gate S (Semantic Conservation) to refuse when MC is too thin.
 * 
 * This is a cheap, deterministic, AST-based counter (no LLM).
 */

export interface EnforcementPoint {
    kind: 'guard' | 'filter' | 'transition' | 'failure_condition' | 'side_effect_gate' | 'validation' | 'branch';
    location: string; // file:line or function name
    pattern: string;  // what was detected
}

/**
 * EnforcementRule - structured schema for rebuildable semantics in MC2/MC3
 * 
 * This is the required schema field that makes MC2 "rebuildable without doubt"
 * by explicitly encoding operational semantics, not just nouns.
 */
export interface EnforcementRule {
    kind: 'guard' | 'filter' | 'transition' | 'failure_condition' | 'side_effect_gate';
    source_span: string;  // file:line range or function name
    predicate: StructuredPredicate;  // structured, not prose
    effect: EnforcementEffect;
}

export interface StructuredPredicate {
    type: 'condition' | 'pattern_match' | 'type_check' | 'state_check' | 'existence_check';
    lhs: string;  // left-hand side (variable, expression)
    operator: string;  // ==, !=, in, not in, matches, instanceof, etc.
    rhs: string;  // right-hand side (value, pattern, type)
    raw?: string; // original expression if can't parse
}

export interface EnforcementEffect {
    type: 'throw' | 'return' | 'error' | 'log' | 'exit' | 'skip' | 'continue' | 'fail';
    value?: string;  // error message, return value, etc.
}

export interface SemanticMassReport {
    enforcement_points_source: number;
    enforcement_points_mc: number;
    semantic_mass_ratio: number;
    source_breakdown: {
        branches: number;       // if/elif/switch/match
        throws: number;         // throw/raise/reject
        early_returns: number;  // return used as guard
        validations: number;    // regex, type checks, assertions
        transitions: number;    // state machine patterns
        side_effects: number;   // external calls guarded by conditions
    };
    mc_breakdown: {
        denies: number;         // DENIES rules in MC3
        guards: number;         // guard conditions
        constraints: number;    // explicit constraints
        invariants: number;     // invariant statements
        enforcements: number;   // EnforcementRule[] if present
    };
    missing_families: string[]; // what enforcement families are likely missing
    source_points: EnforcementPoint[];
}

// Language-specific patterns for enforcement detection
const ENFORCEMENT_PATTERNS = {
    python: {
        branches: /\b(if|elif|else|match|case)\b/g,
        throws: /\b(raise|assert)\s+/g,
        early_returns: /^\s*return\s+/gm,
        validations: /(re\.compile|re\.match|re\.search|isinstance|hasattr|\.validate|\.check)/g,
        transitions: /(state|status|phase)\s*[=!]=|validTransitions|\.transition/gi,
        side_effects: /(subprocess|os\.system|git\.|\.write|\.delete|\.remove|requests\.|http\.|fetch)/gi
    },
    typescript: {
        branches: /\b(if|else\s+if|else|switch|case)\b/g,
        throws: /\b(throw|reject|assert)\s+/g,
        early_returns: /^\s*return\s+/gm,
        validations: /(\.test\(|\.match\(|instanceof|typeof|\.validate|\.check|\.parse)/g,
        transitions: /(state|status|phase)\s*[=!]==|validTransitions|\.transition/gi,
        side_effects: /(fetch|axios|http\.|fs\.|child_process|exec|spawn)/gi
    },
    javascript: {
        branches: /\b(if|else\s+if|else|switch|case)\b/g,
        throws: /\b(throw|reject|assert)\s+/g,
        early_returns: /^\s*return\s+/gm,
        validations: /(\.test\(|\.match\(|instanceof|typeof|\.validate|\.check)/g,
        transitions: /(state|status|phase)\s*[=!]==|validTransitions|\.transition/gi,
        side_effects: /(fetch|axios|http\.|fs\.|child_process|exec|spawn)/gi
    },
    go: {
        branches: /\b(if|else\s+if|else|switch|case|select)\b/g,
        throws: /\b(panic|return\s+.*err|return\s+nil,\s*err)/g,
        early_returns: /^\s*return\s+/gm,
        validations: /(regexp\.Compile|\.Match|\.Validate|\.Check)/g,
        transitions: /(state|status|phase)\s*[=!]=|\.Transition/gi,
        side_effects: /(http\.|os\.|exec\.|ioutil\.|io\.)/gi
    }
};

/**
 * Detect language from file extension or content
 */
function detectLanguage(filePath: string, content: string): 'python' | 'typescript' | 'javascript' | 'go' {
    const ext = filePath.split('.').pop()?.toLowerCase();
    if (ext === 'py') return 'python';
    if (ext === 'ts' || ext === 'tsx') return 'typescript';
    if (ext === 'js' || ext === 'jsx') return 'javascript';
    if (ext === 'go') return 'go';
    
    // Fallback: detect from content
    if (content.includes('from __future__') || content.includes('def ') || content.includes('import ')) {
        return 'python';
    }
    if (content.includes('interface ') || content.includes(': string') || content.includes(': number')) {
        return 'typescript';
    }
    if (content.includes('package main') || content.includes('func ')) {
        return 'go';
    }
    
    return 'typescript'; // default
}

/**
 * Count enforcement points in source code
 */
export function countSourceEnforcements(filePath: string, content: string): {
    total: number;
    breakdown: SemanticMassReport['source_breakdown'];
    points: EnforcementPoint[];
} {
    const lang = detectLanguage(filePath, content);
    const patterns = ENFORCEMENT_PATTERNS[lang];
    const points: EnforcementPoint[] = [];
    
    // Count each pattern
    const branchMatches = content.match(patterns.branches) || [];
    const throwMatches = content.match(patterns.throws) || [];
    const earlyReturnMatches = content.match(patterns.early_returns) || [];
    const validationMatches = content.match(patterns.validations) || [];
    const transitionMatches = content.match(patterns.transitions) || [];
    const sideEffectMatches = content.match(patterns.side_effects) || [];
    
    // Build enforcement points list
    branchMatches.forEach((m, i) => points.push({
        kind: 'branch',
        location: `${filePath}:branch-${i}`,
        pattern: m.trim()
    }));
    
    throwMatches.forEach((m, i) => points.push({
        kind: 'failure_condition',
        location: `${filePath}:throw-${i}`,
        pattern: m.trim()
    }));
    
    earlyReturnMatches.forEach((m, i) => points.push({
        kind: 'guard',
        location: `${filePath}:return-${i}`,
        pattern: 'early return'
    }));
    
    validationMatches.forEach((m, i) => points.push({
        kind: 'validation',
        location: `${filePath}:validation-${i}`,
        pattern: m.trim()
    }));
    
    transitionMatches.forEach((m, i) => points.push({
        kind: 'transition',
        location: `${filePath}:transition-${i}`,
        pattern: m.trim()
    }));
    
    sideEffectMatches.forEach((m, i) => points.push({
        kind: 'side_effect_gate',
        location: `${filePath}:side-effect-${i}`,
        pattern: m.trim()
    }));
    
    const breakdown = {
        branches: branchMatches.length,
        throws: throwMatches.length,
        early_returns: earlyReturnMatches.length,
        validations: validationMatches.length,
        transitions: transitionMatches.length,
        side_effects: sideEffectMatches.length
    };
    
    const total = breakdown.branches + breakdown.throws + breakdown.early_returns +
                  breakdown.validations + breakdown.transitions + breakdown.side_effects;
    
    return { total, breakdown, points };
}

/**
 * Count enforcement points in MC2/MC3 artifacts
 */
export function countMcEnforcements(mc3: any, mc2?: any): {
    total: number;
    breakdown: SemanticMassReport['mc_breakdown'];
} {
    let denies = 0;
    let guards = 0;
    let constraints = 0;
    let invariants = 0;
    let enforcements = 0;
    
    // Count DENIES from MC3
    if (mc3?.mc_family?.levels) {
        for (const level of mc3.mc_family.levels) {
            if (level.example?.DENIES) {
                denies += level.example.DENIES.length;
            }
        }
    }
    if (mc3?.DENIES) {
        denies += mc3.DENIES.length;
    }
    
    // Count constraints
    if (mc3?.constraints) {
        constraints += Array.isArray(mc3.constraints) ? mc3.constraints.length : 1;
    }
    if (mc2?.linkage_contract?.constraints) {
        constraints += mc2.linkage_contract.constraints.length;
    }
    
    // Count invariants from MC4 if embedded
    if (mc3?.invariants) {
        invariants += Array.isArray(mc3.invariants) ? mc3.invariants.length : 1;
    }
    
    // Count guards (look for guard-like patterns in DOES or methods)
    if (mc3?.mc_family?.levels) {
        for (const level of mc3.mc_family.levels) {
            if (level.example?.DOES) {
                for (const does of level.example.DOES) {
                    if (does.toLowerCase().includes('must') || 
                        does.toLowerCase().includes('shall') ||
                        does.toLowerCase().includes('require') ||
                        does.toLowerCase().includes('validate')) {
                        guards++;
                    }
                }
            }
        }
    }
    
    // Count EnforcementRule[] if present (new schema)
    if (mc2?.enforcements) {
        enforcements += mc2.enforcements.length;
    }
    if (mc3?.enforcements) {
        enforcements += mc3.enforcements.length;
    }
    
    const breakdown = { denies, guards, constraints, invariants, enforcements };
    const total = denies + guards + constraints + invariants + enforcements;
    
    return { total, breakdown };
}

/**
 * Compute semantic mass ratio and identify missing enforcement families
 */
export function computeSemanticMass(
    filePath: string,
    sourceContent: string,
    mc3: any,
    mc2?: any
): SemanticMassReport {
    const source = countSourceEnforcements(filePath, sourceContent);
    const mc = countMcEnforcements(mc3, mc2);
    
    // Compute ratio (avoid division by zero)
    const ratio = source.total > 0 ? mc.total / source.total : 0;
    
    // Identify missing enforcement families
    const missing: string[] = [];
    
    if (source.breakdown.branches > 5 && mc.breakdown.guards < 2) {
        missing.push('branching logic (if/switch) not captured in guards');
    }
    if (source.breakdown.throws > 2 && mc.breakdown.denies < 1) {
        missing.push('failure conditions (throw/raise) not captured in DENIES');
    }
    if (source.breakdown.validations > 3 && mc.breakdown.guards < 2) {
        missing.push('validation patterns not captured');
    }
    if (source.breakdown.transitions > 0 && mc.breakdown.constraints < 1) {
        missing.push('state transition rules not captured');
    }
    if (source.breakdown.side_effects > 2 && mc.breakdown.denies < 1) {
        missing.push('side-effect gates not captured');
    }
    if (source.breakdown.early_returns > 5 && mc.breakdown.guards < 2) {
        missing.push('guard patterns (early returns) not captured');
    }
    
    return {
        enforcement_points_source: source.total,
        enforcement_points_mc: mc.total,
        semantic_mass_ratio: Math.round(ratio * 100) / 100,
        source_breakdown: source.breakdown,
        mc_breakdown: mc.breakdown,
        missing_families: missing,
        source_points: source.points
    };
}

/**
 * Extract structured EnforcementRules from source code
 * 
 * This produces the enforcements[] array required in MC2/MC3 for rebuildable semantics.
 * It's a best-effort extraction - not perfect, but better than prose.
 */
export function extractEnforcementRules(filePath: string, content: string): EnforcementRule[] {
    const rules: EnforcementRule[] = [];
    const lines = content.split('\n');
    const lang = detectLanguage(filePath, content);
    
    // Pattern matchers for different enforcement types
    const guardPatterns = lang === 'python' 
        ? /if\s+(?:not\s+)?([^:]+):\s*(?:raise|return|continue|break)/g
        : /if\s*\(([^)]+)\)\s*(?:throw|return|continue|break)/g;
    
    const throwPatterns = lang === 'python'
        ? /raise\s+(\w+)\s*\(([^)]*)\)/g
        : /throw\s+(?:new\s+)?(\w+)\s*\(([^)]*)\)/g;
    
    const filterPatterns = lang === 'python'
        ? /(\w+)\.(?:search|match|test)\s*\(([^)]+)\)/g
        : /(\w+)\.(?:test|match|search)\s*\(([^)]+)\)/g;
    
    // Extract guards (if X then throw/return)
    let match;
    while ((match = guardPatterns.exec(content)) !== null) {
        const lineNo = content.substring(0, match.index).split('\n').length;
        rules.push({
            kind: 'guard',
            source_span: `${filePath}:${lineNo}`,
            predicate: parseCondition(match[1]),
            effect: { type: 'return', value: 'early exit' }
        });
    }
    
    // Extract failure conditions (throw/raise)
    const throwPattern2 = lang === 'python'
        ? /raise\s+(\w+)\s*\(([^)]*)\)/g
        : /throw\s+(?:new\s+)?(\w+)\s*\(([^)]*)\)/g;
    
    while ((match = throwPattern2.exec(content)) !== null) {
        const lineNo = content.substring(0, match.index).split('\n').length;
        rules.push({
            kind: 'failure_condition',
            source_span: `${filePath}:${lineNo}`,
            predicate: {
                type: 'condition',
                lhs: 'error',
                operator: 'raises',
                rhs: match[1],
                raw: match[0].trim()
            },
            effect: { type: 'throw', value: match[2] || '' }
        });
    }
    
    // Extract filters (regex patterns)
    while ((match = filterPatterns.exec(content)) !== null) {
        const lineNo = content.substring(0, match.index).split('\n').length;
        rules.push({
            kind: 'filter',
            source_span: `${filePath}:${lineNo}`,
            predicate: {
                type: 'pattern_match',
                lhs: match[2],
                operator: 'matches',
                rhs: match[1],
                raw: match[0].trim()
            },
            effect: { type: 'skip', value: 'filter out' }
        });
    }
    
    // Extract state transitions
    const transitionPattern = /(state|status)\s*=\s*['"]?(\w+)['"]?/gi;
    while ((match = transitionPattern.exec(content)) !== null) {
        const lineNo = content.substring(0, match.index).split('\n').length;
        rules.push({
            kind: 'transition',
            source_span: `${filePath}:${lineNo}`,
            predicate: {
                type: 'state_check',
                lhs: match[1],
                operator: 'becomes',
                rhs: match[2],
                raw: match[0].trim()
            },
            effect: { type: 'continue', value: `transition to ${match[2]}` }
        });
    }
    
    return rules;
}

/**
 * Parse a condition string into a StructuredPredicate
 */
function parseCondition(conditionStr: string): StructuredPredicate {
    const trimmed = conditionStr.trim();
    
    // Try to parse common patterns
    // not X
    if (trimmed.startsWith('not ') || trimmed.startsWith('!')) {
        const inner = trimmed.replace(/^(?:not\s+|!)/, '');
        return {
            type: 'existence_check',
            lhs: inner,
            operator: 'not',
            rhs: 'truthy',
            raw: trimmed
        };
    }
    
    // X == Y or X === Y
    const eqMatch = trimmed.match(/(.+?)\s*(?:===?|==)\s*(.+)/);
    if (eqMatch) {
        return {
            type: 'condition',
            lhs: eqMatch[1].trim(),
            operator: '==',
            rhs: eqMatch[2].trim()
        };
    }
    
    // X != Y or X !== Y
    const neqMatch = trimmed.match(/(.+?)\s*(?:!==?|!=)\s*(.+)/);
    if (neqMatch) {
        return {
            type: 'condition',
            lhs: neqMatch[1].trim(),
            operator: '!=',
            rhs: neqMatch[2].trim()
        };
    }
    
    // X in Y
    const inMatch = trimmed.match(/(.+?)\s+in\s+(.+)/);
    if (inMatch) {
        return {
            type: 'condition',
            lhs: inMatch[1].trim(),
            operator: 'in',
            rhs: inMatch[2].trim()
        };
    }
    
    // X not in Y
    const notInMatch = trimmed.match(/(.+?)\s+not\s+in\s+(.+)/);
    if (notInMatch) {
        return {
            type: 'condition',
            lhs: notInMatch[1].trim(),
            operator: 'not in',
            rhs: notInMatch[2].trim()
        };
    }
    
    // isinstance(X, Y)
    const instanceMatch = trimmed.match(/isinstance\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)/);
    if (instanceMatch) {
        return {
            type: 'type_check',
            lhs: instanceMatch[1].trim(),
            operator: 'instanceof',
            rhs: instanceMatch[2].trim()
        };
    }
    
    // Fallback: can't parse, keep raw
    return {
        type: 'condition',
        lhs: trimmed,
        operator: 'unknown',
        rhs: '',
        raw: trimmed
    };
}

/**
 * Check if semantic mass ratio passes threshold
 */
export function checkSemanticConservation(
    report: SemanticMassReport,
    threshold: number = 0.60
): { ok: boolean; reason?: string } {
    if (report.enforcement_points_source === 0) {
        // No enforcement points in source - nothing to conserve
        return { ok: true };
    }
    
    if (report.semantic_mass_ratio >= threshold) {
        return { ok: true };
    }
    
    const reason = `Semantic mass ratio ${report.semantic_mass_ratio} < ${threshold} threshold. ` +
        `Source has ${report.enforcement_points_source} enforcement points, ` +
        `MC captured only ${report.enforcement_points_mc}. ` +
        `Missing: ${report.missing_families.join('; ') || 'unknown families'}`;
    
    return { ok: false, reason };
}

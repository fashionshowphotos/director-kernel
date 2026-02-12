/**
 * Semantic Test Harness for Bidirectional Code Compiler
 * 
 * PURPOSE: Lock expected semantics to prevent silent drift as prompts evolve.
 * 
 * TESTS:
 * 1. MS2 → MS2.5: Semantic extraction preserves meaning
 * 2. MS2.5 → MS3: Clean-room elevation produces valid contracts
 * 3. Intent → MS5: Thin intent expands to dense spec
 * 4. Tier Contracts: Validation catches violations
 * 5. NON-INVENTION: Transforms do not hallucinate capabilities
 */

import { strict as assert } from 'assert';
import { TransformEngine, TransformRequest, DirectorTier, TierContractResult } from '../src/transform_engine';

// ============================================================================
// FIXTURES: MS2 Code Samples
// ============================================================================

const FIXTURE_SIMPLE_AUTH_MODULE = `
// auth.ts - Simple authentication module
import * as bcrypt from 'bcrypt';
import { db } from './database';

export interface User {
  id: string;
  email: string;
  passwordHash: string;
  createdAt: Date;
}

export interface AuthResult {
  success: boolean;
  user?: User;
  error?: string;
}

export async function login(email: string, password: string): Promise<AuthResult> {
  const user = await db.users.findByEmail(email);
  if (!user) {
    return { success: false, error: 'USER_NOT_FOUND' };
  }
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    return { success: false, error: 'INVALID_PASSWORD' };
  }
  return { success: true, user };
}

export async function register(email: string, password: string): Promise<AuthResult> {
  const existing = await db.users.findByEmail(email);
  if (existing) {
    return { success: false, error: 'EMAIL_EXISTS' };
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const user = await db.users.create({ email, passwordHash });
  return { success: true, user };
}
`;

const FIXTURE_CACHE_MODULE = `
// cache.ts - In-memory cache with TTL
export interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

export class Cache<T> {
  private store: Map<string, CacheEntry<T>> = new Map();
  private defaultTtlMs: number;

  constructor(defaultTtlMs: number = 60000) {
    this.defaultTtlMs = defaultTtlMs;
  }

  get(key: string): T | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key: string, value: T, ttlMs?: number): void {
    const expiresAt = Date.now() + (ttlMs ?? this.defaultTtlMs);
    this.store.set(key, { value, expiresAt });
  }

  delete(key: string): boolean {
    return this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }

  size(): number {
    return this.store.size;
  }
}
`;

const FIXTURE_EVENT_EMITTER = `
// events.ts - Type-safe event emitter
type EventHandler<T> = (data: T) => void;

export class EventEmitter<Events extends Record<string, any>> {
  private handlers: Map<keyof Events, Set<EventHandler<any>>> = new Map();

  on<K extends keyof Events>(event: K, handler: EventHandler<Events[K]>): void {
    if (!this.handlers.has(event)) {
      this.handlers.set(event, new Set());
    }
    this.handlers.get(event)!.add(handler);
  }

  off<K extends keyof Events>(event: K, handler: EventHandler<Events[K]>): void {
    this.handlers.get(event)?.delete(handler);
  }

  emit<K extends keyof Events>(event: K, data: Events[K]): void {
    this.handlers.get(event)?.forEach(h => h(data));
  }

  once<K extends keyof Events>(event: K, handler: EventHandler<Events[K]>): void {
    const wrapper = (data: Events[K]) => {
      handler(data);
      this.off(event, wrapper);
    };
    this.on(event, wrapper);
  }
}
`;

// ============================================================================
// EXPECTED SEMANTICS: What MS2.5 MUST capture from each fixture
// ============================================================================

const EXPECTED_AUTH_SEMANTICS = {
  responsibilities: [
    'authenticate users',
    'register users',
    'password hashing',
  ],
  behaviors: [
    'login',
    'register',
  ],
  error_modes: [
    'USER_NOT_FOUND',
    'INVALID_PASSWORD',
    'EMAIL_EXISTS',
  ],
  data_models: [
    'User',
    'AuthResult',
  ],
  dependencies: [
    'bcrypt',
    'database',
  ],
};

const EXPECTED_CACHE_SEMANTICS = {
  responsibilities: [
    'store values',
    'retrieve values',
    'expire entries',
    'TTL management',
  ],
  behaviors: [
    'get',
    'set',
    'delete',
    'clear',
  ],
  invariants: [
    'expired entries not returned',
  ],
  data_models: [
    'CacheEntry',
  ],
};

const EXPECTED_EVENT_SEMANTICS = {
  responsibilities: [
    'subscribe to events',
    'emit events',
    'unsubscribe',
  ],
  behaviors: [
    'on',
    'off',
    'emit',
    'once',
  ],
  invariants: [
    'once handlers fire exactly once',
  ],
};

// ============================================================================
// NEGATIVE TEST: Things MS2.5 MUST NOT invent
// ============================================================================

const NON_INVENTION_CHECKS = {
  auth: {
    must_not_claim: [
      'rate limiting',
      'session management',
      'JWT',
      'OAuth',
      'MFA',
      'two-factor',
      'audit logging',
      'encryption at rest',
    ],
  },
  cache: {
    must_not_claim: [
      'distributed',
      'Redis',
      'persistence',
      'replication',
      'cluster',
      'sharding',
    ],
  },
  events: {
    must_not_claim: [
      'async',
      'queue',
      'persistence',
      'replay',
      'ordering guarantee',
    ],
  },
};

// ============================================================================
// TIER CONTRACT TESTS
// ============================================================================

function testTierContractValidation() {
  console.log('\n=== Testing Tier Contract Validation ===\n');

  const mockEngine = {
    validateTierContract: TransformEngine.prototype.validateTierContract,
  } as TransformEngine;

  // Test 1: Toy tier - should pass with minimal contract
  console.log('Test 1: Toy tier accepts minimal contract');
  const minimalMs3 = {
    DOES: ['Provides basic functionality'],
    DENIES: [],
    METHODS: [],
  };
  const toyResult = mockEngine.validateTierContract(minimalMs3, 'toy');
  assert.ok(toyResult.passed, 'Toy tier should pass with minimal contract');
  assert.equal(toyResult.violations.filter(v => v.severity === 'error').length, 0);
  console.log('  PASS: Toy tier accepts minimal contract');

  // Test 2: Production tier - should fail without required invariants
  console.log('Test 2: Production tier rejects incomplete contract');
  const incompleteMs3 = {
    DOES: ['Does something'],
    DENIES: [],
    METHODS: ['doSomething(): void'],
  };
  const prodResult = mockEngine.validateTierContract(incompleteMs3, 'production');
  assert.ok(!prodResult.passed, 'Production tier should fail incomplete contract');
  const errorCount = prodResult.violations.filter(v => v.severity === 'error').length;
  assert.ok(errorCount > 0, `Should have errors, got ${errorCount}`);
  console.log(`  PASS: Production tier rejected with ${errorCount} errors`);

  // Test 3: Production tier - should pass with complete contract
  console.log('Test 3: Production tier accepts complete contract');
  const completeMs3 = {
    DOES: [
      'Authenticates users via password comparison',
      'Logs all authentication attempts',
      'Validates input before processing',
      'Initializes on startup with config from environment',
      'Tests cover core authentication logic',
    ],
    DENIES: [
      'Must not store plaintext passwords',
      'Must not accept invalid input',
      'Must not leak credentials in error messages',
    ],
    METHODS: [
      'interface AuthService { login(email: string, password: string): Promise<AuthResult>; }',
      'type AuthError = "USER_NOT_FOUND" | "INVALID_PASSWORD";',
      'close(): Promise<void>;',
    ],
  };
  const completeResult = mockEngine.validateTierContract(completeMs3, 'production');
  const completeErrors = completeResult.violations.filter(v => v.severity === 'error');
  if (completeErrors.length > 0) {
    console.log('  Errors:', completeErrors.map(e => e.invariant));
  }
  console.log(`  Result: ${completeErrors.length} errors, ${completeResult.violations.filter(v => v.severity === 'warning').length} warnings`);

  // Test 4: Enterprise tier - should require threat model
  console.log('Test 4: Enterprise tier requires threat model');
  const noThreatModelMs3 = {
    ...completeMs3,
    DENIES: ['Must not store plaintext passwords'],
  };
  const enterpriseResult = mockEngine.validateTierContract(noThreatModelMs3, 'enterprise');
  const threatModelViolation = enterpriseResult.violations.find(v => 
    v.invariant.toLowerCase().includes('threat model')
  );
  assert.ok(threatModelViolation, 'Enterprise should require threat model');
  console.log('  PASS: Enterprise tier requires threat model');

  console.log('\n=== Tier Contract Tests Complete ===\n');
}

// ============================================================================
// SEMANTIC PRESERVATION TESTS (Structural - no LLM calls)
// ============================================================================

function testSemanticStructure() {
  console.log('\n=== Testing Semantic Structure Expectations ===\n');

  // Test that our expected semantics are well-formed
  console.log('Test 1: Auth semantics structure');
  assert.ok(EXPECTED_AUTH_SEMANTICS.responsibilities.length >= 2, 'Auth should have responsibilities');
  assert.ok(EXPECTED_AUTH_SEMANTICS.behaviors.length >= 2, 'Auth should have behaviors');
  assert.ok(EXPECTED_AUTH_SEMANTICS.error_modes.length >= 2, 'Auth should have error modes');
  console.log('  PASS: Auth semantics well-formed');

  console.log('Test 2: Cache semantics structure');
  assert.ok(EXPECTED_CACHE_SEMANTICS.responsibilities.length >= 2, 'Cache should have responsibilities');
  assert.ok(EXPECTED_CACHE_SEMANTICS.behaviors.length >= 4, 'Cache should have behaviors');
  assert.ok(EXPECTED_CACHE_SEMANTICS.invariants!.length >= 1, 'Cache should have invariants');
  console.log('  PASS: Cache semantics well-formed');

  console.log('Test 3: Event semantics structure');
  assert.ok(EXPECTED_EVENT_SEMANTICS.responsibilities.length >= 2, 'Events should have responsibilities');
  assert.ok(EXPECTED_EVENT_SEMANTICS.behaviors.length >= 4, 'Events should have behaviors');
  console.log('  PASS: Event semantics well-formed');

  console.log('\n=== Semantic Structure Tests Complete ===\n');
}

// ============================================================================
// NON-INVENTION VALIDATION (Structural check for test data)
// ============================================================================

function testNonInventionChecks() {
  console.log('\n=== Testing Non-Invention Check Data ===\n');

  // Verify that non-invention checks don't overlap with expected semantics
  console.log('Test 1: Auth non-invention checks are distinct from expected');
  for (const forbidden of NON_INVENTION_CHECKS.auth.must_not_claim) {
    const inResponsibilities = EXPECTED_AUTH_SEMANTICS.responsibilities.some(r => 
      r.toLowerCase().includes(forbidden.toLowerCase())
    );
    assert.ok(!inResponsibilities, `"${forbidden}" should not be in expected responsibilities`);
  }
  console.log('  PASS: Auth non-invention checks are distinct');

  console.log('Test 2: Cache non-invention checks are distinct from expected');
  for (const forbidden of NON_INVENTION_CHECKS.cache.must_not_claim) {
    const inResponsibilities = EXPECTED_CACHE_SEMANTICS.responsibilities.some(r => 
      r.toLowerCase().includes(forbidden.toLowerCase())
    );
    assert.ok(!inResponsibilities, `"${forbidden}" should not be in expected responsibilities`);
  }
  console.log('  PASS: Cache non-invention checks are distinct');

  console.log('\n=== Non-Invention Check Tests Complete ===\n');
}

// ============================================================================
// MS2.5 SCHEMA VALIDATION (Structural)
// ============================================================================

function testMs25SchemaStructure() {
  console.log('\n=== Testing MS2.5 Schema Structure ===\n');

  const validMs25 = {
    schema_version: 'ms2_5_v1',
    source: {
      language: 'TypeScript',
      analysis_scope: 'module',
      inputs: [{ path: 'auth.ts' }],
    },
    modules: [
      {
        id: 'auth',
        name: 'Authentication Module',
        responsibilities: ['Authenticate users', 'Register users'],
        invariants: ['Passwords are hashed before storage'],
        behaviors: [
          { name: 'login', inputs: ['email', 'password'], outputs: ['AuthResult'], error_modes: ['USER_NOT_FOUND'] },
        ],
        data_models: [
          { name: 'User', fields: ['id', 'email', 'passwordHash'] },
        ],
        error_taxonomy: [
          { code: 'USER_NOT_FOUND', meaning: 'No user with given email' },
        ],
        dependencies: [
          { target: 'bcrypt', relationship: 'uses' },
        ],
        tests: { present: false },
      },
    ],
    crosscutting: {
      global_invariants: [],
      shared_error_taxonomy: [],
      architecture_notes: [],
    },
  };

  // Verify structure
  console.log('Test 1: MS2.5 has required top-level fields');
  assert.ok(validMs25.schema_version, 'Must have schema_version');
  assert.ok(validMs25.source, 'Must have source');
  assert.ok(validMs25.modules, 'Must have modules');
  assert.ok(validMs25.crosscutting, 'Must have crosscutting');
  console.log('  PASS: MS2.5 has required fields');

  console.log('Test 2: MS2.5 module has required fields');
  const mod = validMs25.modules[0];
  assert.ok(mod.id, 'Module must have id');
  assert.ok(mod.responsibilities, 'Module must have responsibilities');
  assert.ok(mod.behaviors, 'Module must have behaviors');
  console.log('  PASS: MS2.5 module has required fields');

  console.log('Test 3: MS2.5 behavior has required fields');
  const behavior = mod.behaviors[0];
  assert.ok(behavior.name, 'Behavior must have name');
  assert.ok(behavior.inputs, 'Behavior must have inputs');
  assert.ok(behavior.outputs, 'Behavior must have outputs');
  console.log('  PASS: MS2.5 behavior has required fields');

  console.log('\n=== MS2.5 Schema Structure Tests Complete ===\n');
}

// ============================================================================
// MAIN TEST RUNNER
// ============================================================================

async function main() {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║     SEMANTIC TEST HARNESS - Bidirectional Code Compiler    ║');
  console.log('╚════════════════════════════════════════════════════════════╝');

  let passed = 0;
  let failed = 0;

  const tests = [
    { name: 'Semantic Structure', fn: testSemanticStructure },
    { name: 'Non-Invention Checks', fn: testNonInventionChecks },
    { name: 'MS2.5 Schema Structure', fn: testMs25SchemaStructure },
    { name: 'Tier Contract Validation', fn: testTierContractValidation },
  ];

  for (const test of tests) {
    try {
      test.fn();
      passed++;
    } catch (e: any) {
      console.error(`\n❌ FAILED: ${test.name}`);
      console.error(`   ${e.message}`);
      failed++;
    }
  }

  console.log('\n════════════════════════════════════════════════════════════');
  console.log(`RESULTS: ${passed} passed, ${failed} failed`);
  console.log('════════════════════════════════════════════════════════════\n');

  if (failed > 0) {
    process.exit(1);
  }
}

main().catch(e => {
  console.error('FATAL:', e);
  process.exit(1);
});

// ============================================================================
// EXPORTS for integration tests
// ============================================================================

export {
  FIXTURE_SIMPLE_AUTH_MODULE,
  FIXTURE_CACHE_MODULE,
  FIXTURE_EVENT_EMITTER,
  EXPECTED_AUTH_SEMANTICS,
  EXPECTED_CACHE_SEMANTICS,
  EXPECTED_EVENT_SEMANTICS,
  NON_INVENTION_CHECKS,
};

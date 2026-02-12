# Director Kernel v6 - API Documentation

## Core Classes

### ArtifactStore

Content-addressed storage with optional encryption.

```typescript
import { ArtifactStore } from 'director-kernel';

const store = new ArtifactStore('artifacts.db', {
  encryptionKey: Buffer.from('...32 bytes...'),
  activeKeyVersion: 1,
  enableOrphanGc: false,
});

// Store artifact
const result = store.storeArtifact({
  content: Buffer.from('{"key": "value"}'),
  kind: 'ms4',
});
console.log(result.hash); // SHA-256 hash

// Retrieve artifact
const artifact = store.retrieveArtifact(result.hash);
console.log(artifact.content);

// Link to build
store.linkArtifactToBuild(buildId, result.hash, 'ms4');

// Close
store.close();
```

### KernelOrchestrator

Build lifecycle orchestration with state machine.

```typescript
import { KernelOrchestrator } from 'director-kernel';

const orchestrator = new KernelOrchestrator(
  'kernel.db',
  'artifacts/',
  transformEngine
);

// Initialize with crash recovery
const recovery = orchestrator.initializeRecovery();
if (!recovery.ok) {
  console.error('Recovery failed:', recovery.error);
  process.exit(1);
}

// Start build
const buildResult = orchestrator.orchestrateBuild({
  ms5_spec: ms5Spec,
  budget_usd: 10.0,
  input_artifacts: [],
});

if (buildResult.ok) {
  console.log('Build complete:', buildResult.value.final_state);
} else {
  console.error('Build failed:', buildResult.error);
}
```

### ModelRouter

OpenRouter LLM integration with retry logic.

```typescript
import { ModelRouter } from 'director-kernel';

const router = new ModelRouter({
  apiKey: process.env.OPENROUTER_API_KEY!,
  maxConcurrentCalls: 6,
  timeout: 120000,
});

const response = await router.executeModelCall({
  prompt: 'Generate an API endpoint',
  modelId: 'anthropic/claude-3.5-sonnet',
  temperature: 0.7,
  maxTokens: 4096,
});

console.log(response.completion);
console.log(response.tokenUsage);
```

### ContextSlicer

Bounded context generation with truncation thresholds.

```typescript
import { ContextSlicer } from 'director-kernel';

const slicer = new ContextSlicer({
  tokenBudget: 100000,
  truncationWarnThreshold: 20,
  truncationFailThreshold: 50,
});

const result = slicer.sliceContext(
  'MS5 Invariants: upstream-only fixes...',
  [
    {
      id: 'ms4_architecture',
      content: '...',
      priority: 10,
      estimatedTokens: 5000,
    },
    {
      id: 'dependency_graph',
      content: '...',
      priority: 7,
      estimatedTokens: 3000,
    },
  ],
  'target_id'
);

console.log(result.contextHash);
console.log(result.truncationRatio);
console.log(result.includedArtifacts);
```

### SchemaValidator

JSON schema validation for artifacts.

```typescript
import { SchemaValidator } from 'director-kernel';

const validator = new SchemaValidator();

// Register schema
validator.registerSchema('ms4_schema', {
  type: 'object',
  required: ['id', 'modules'],
  properties: {
    id: { type: 'string' },
    modules: {
      type: 'array',
      items: {
        type: 'object',
        required: ['name', 'id'],
        properties: {
          name: { type: 'string' },
          id: { type: 'string' },
        },
      },
    },
  },
});

// Validate artifact
const result = validator.validate(
  { id: 'DK6-MS4', modules: [] },
  'ms4_schema'
);

if (!result.valid) {
  console.error('Validation failed:', result.errors);
}
```

### CostController

Budget tracking and enforcement.

```typescript
import { CostController } from 'director-kernel';

const controller = new CostController('costs.db', {
  maxCostUsd: 10.0,
  warnThresholdPercent: 70,
  pauseThresholdPercent: 95,
});

// Record usage
controller.recordUsage({
  buildId: 'build_123',
  stage: 'ms4_to_ms3',
  target: 'api_module',
  modelId: 'anthropic/claude-3.5-sonnet',
  promptTokens: 5000,
  completionTokens: 2000,
  costUsd: 0.15,
  timestamp: new Date().toISOString(),
});

// Check budget
const check = controller.checkBudget('build_123');
console.log(check.state); // 'ok' | 'warn' | 'paused'
console.log(check.percentUsed);
console.log(check.remainingUsd);

controller.close();
```

## TransformEngine

Execute MS-layer transforms with atomic commits and validation.

```typescript
import { TransformEngine } from 'director-kernel';

const engine = new TransformEngine({
  dbPath: 'kernel.db',
  artifactStore,
  modelRouter,
  costController,
  ms5Invariants: 'Upstream-only fixes, traceability over determinism...',
});

// Initialize database schema
engine.initializeSchema();

// Execute transform (MS5→MS4)
const result = await engine.executeTransform({
  buildId: 'build_123',
  transformType: 'ms5_to_ms4',
  targetId: 'backend_architecture',
  upstreamHash: 'abc123...', // SHA-256 of MS5 spec
  validationMode: 'fast',
  tokenBudget: 100000,
  attemptNo: 1,
  modelId: 'anthropic/claude-3.5-sonnet',
});

if (result.status === 'SUCCESS') {
  console.log('✅ Transform complete');
  console.log('Downstream hash:', result.downstreamHash);
  console.log('Tokens:', result.metrics.tokenUsage.totalTokens);
  console.log('Cost:', result.metrics.tokenUsage.costUsd);
  console.log('Truncation:', result.metrics.truncation.truncationRatio);
} else {
  console.error('❌ Transform failed:', result.status);
  console.error('Error:', result.errorMessage);
}
```

### Critical Invariants

1. **Atomic Commits** - All or nothing (checkpoint + artifacts + cost)
2. **No External Side Effects** - Only writes via ArtifactStore/SQLite
3. **Schema Validation** - Mandatory for all outputs
4. **Truncation Safety** - Fails if >50% truncation
5. **Budget Gates** - Respects cost controller pause state
6. **Idempotency** - Short-circuits on matching context_hash
7. **MS5 Invariants** - Always included in context
8. **Deterministic Slicing** - Same inputs = same context_hash
9. **Strict Pipeline** - One transform at a time

### Transform Types

- `ms5_to_ms4` - Intent → Architecture
- `ms4_to_ms3` - Architecture → Contracts
- `ms3_to_ms2` - Contracts → Code

### Validation Modes

- `fast` - Basic schema validation
- `spec_pass` - Full specification compliance

### Return Statuses

- `SUCCESS` - Transform completed successfully
- `MODEL_ERROR` - LLM output invalid after retries
- `USER_ACTION_REQUIRED` - Excessive truncation or input issues
- `INFRA_ERROR` - Database, network, or filesystem failure
- `BUDGET_PAUSE` - Cost limit reached

### Retry Policy

- Max 3 attempts for retryable errors (429, 5xx, parse failures)
- Exponential backoff between retries
- Non-retryable: USER_ACTION_REQUIRED, BUDGET_PAUSE, corruption

### Resource Limits

- Transform timeout: 300s
- Model call timeout: 120s
- Max downstream size: 25MB
- Truncation warn threshold: 20%
- Truncation fail threshold: 50%

## Error Handling

All modules use a `Result<T>` pattern for fallible operations:

```typescript
type Result<T> = 
  | { ok: true; value: T }
  | { ok: false; error: ErrorCode; message?: string };

const result = orchestrator.orchestrateBuild(params);
if (result.ok) {
  // Success path
  console.log(result.value);
} else {
  // Error path
  console.error(result.error, result.message);
}
```

## Build State Machine

```
PENDING
  ↓
ACTIVE → SUCCESS
  ↓      FAILED
  ↓      CRASHED (auto-resume allowed)
  ↓      BUDGET_PAUSE (manual confirmation required)
  ↓
ABANDONED
```

## Event Types

- `build_state_changed` - Build state transitions
- `target_completed` - Transform target completion
- `budget_pause` - Budget threshold exceeded
- `artifact_stored` - New artifact persisted
- `cost_recorded` - Cost usage logged

Events are delivered exactly-once per consumer via transactional outbox pattern.

# Transform Engine v2.0 - Clean Architecture

## Refactored to Pure Compute Model

The TransformEngine has been refactored to follow **Option A** architecture, ensuring clean separation of concerns.

## Ownership Model

### ✅ TransformEngine (Pure Compute)
- **Executes** MS-layer transforms (MS5→MS4→MS3→MS2)
- **Validates** with schema registry
- **Slices** context with truncation safety
- **Estimates** cost
- **Returns** artifacts as Buffer + metadata

### ✅ StageExecutor (Durability)
- **Persists** artifacts to ArtifactStore
- **Writes** checkpoints to SQLite
- **Links** artifacts to builds
- **Records** cost usage
- **Emits** durable events via outbox

## What Was Removed

From TransformEngine v1.0:
- ❌ `better-sqlite3` import
- ❌ `this.db = new Database(...)`
- ❌ `initializeSchema()`
- ❌ `transform_checkpoints` table
- ❌ Idempotent checkpoint logic
- ❌ `artifactStore.linkArtifactToBuild()`
- ❌ Transaction blocks
- ❌ Cost persistence

## New Interface

```typescript
export interface TransformRequest {
  transformType: TransformType;
  targetId: string;
  inputs: TransformArtifactInput[];  // Buffers, not hashes
  validationMode: ValidationMode;
  tokenBudget: number;
  attemptNo: number;
  modelId: string;
  idempotencyKey: string;  // For StageExecutor
}

export interface TransformResult {
  success: boolean;
  artifacts: TransformArtifactOutput[];  // Buffer + kind
  costUsd: number;
  tokenUsage: { promptTokens, completionTokens, totalTokens };
  truncation: { tokensRequested, tokensSent, truncationRatio, contextHash };
  timing: { durationMs, modelCallMs, validationMs };
  logs: string[];
  error?: { code, message };
}
```

## Integration with StageExecutor

```typescript
// In StageExecutor:
const result = await transformEngine.execute({
  transformType: 'ms5_to_ms4',
  targetId: 'backend_architecture',
  inputs: [{ content: upstreamBuffer, kind: 'ms5', hash: upstreamHash }],
  validationMode: 'fast',
  tokenBudget: 100000,
  attemptNo: 1,
  modelId: 'anthropic/claude-3.5-sonnet',
  idempotencyKey: computeIdempotencyKey(...),
});

if (result.success) {
  // StageExecutor persists everything in ONE transaction:
  db.transaction(() => {
    // 1. Store artifacts
    for (const artifact of result.artifacts) {
      const hash = artifactStore.storeArtifact({
        content: artifact.content,
        kind: artifact.kind,
      });
      artifactStore.linkArtifactToBuild(buildId, hash, artifact.kind);
    }
    
    // 2. Write checkpoint
    writeCheckpoint(buildId, transformType, targetId, {
      status: 'SUCCESS',
      downstream_hash: hash,
      cost_usd: result.costUsd,
      tokens: result.tokenUsage.totalTokens,
    });
    
    // 3. Record cost
    costController.recordUsage({...});
  })();
}
```

## Key Benefits

1. **Clean Separation**: Compute vs Durability
2. **Testability**: TransformEngine is stateless and deterministic
3. **Single Transaction**: StageExecutor owns atomicity guarantee
4. **No Double Checkpoints**: Single source of truth
5. **Easier Mocking**: Pure function-like behavior

## Dependencies

TransformEngine depends on (injected):
- `ModelRouter` - LLM API calls
- `ContextSlicer` - Token budget management (created internally)
- `SchemaValidator` - Output validation (created internally)
- `ms5Invariants` - Global invariants string

TransformEngine does NOT depend on:
- ❌ SQLite/Database
- ❌ ArtifactStore
- ❌ CostController (only estimates, doesn't persist)
- ❌ Event emitters

## Critical Invariants Preserved

All 9 MC3 invariants still enforced:
1. ✅ Atomic commits (moved to StageExecutor)
2. ✅ No external side effects (pure compute)
3. ✅ Strict pipeline contract (MS5→MS4→MS3→MS2)
4. ✅ Mandatory schema validation
5. ✅ Deterministic slicing
6. ✅ Truncation safety (>50% = fail)
7. ✅ MS5 invariants always included
8. ✅ Budget gate enforcement (StageExecutor checks before + after)
9. ✅ Idempotent execution (StageExecutor handles)

## Contract Violations Fixed

All 6 issues from code review resolved:
1. ✅ Model timeout enforced (120s with cleanup)
2. ✅ Transform timeout leak fixed (clearTimeout in finally)
3. ✅ Not applicable (no idempotent short-circuit in pure engine)
4. ✅ Not applicable (no checkpoint overwrite in pure engine)
5. ✅ Error logging via logs[] array
6. ✅ Not applicable (StageExecutor handles budget TOCTOU)

## File Size

- **Before**: 635 lines (with SQLite, checkpoints, transactions)
- **After**: 426 lines (pure compute only)
- **Reduction**: 33% smaller, cleaner, more focused

## Migration Path

For existing KernelOrchestrator StageExecutor:
1. TransformEngine becomes one "engine" type
2. StageExecutor calls `engine.execute(inputs, config)`
3. StageExecutor persists results in its existing transaction
4. No changes needed to checkpoint schema or artifact_refs

This aligns perfectly with the existing Kernel architecture!

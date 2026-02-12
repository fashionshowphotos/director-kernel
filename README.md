# Director Kernel v6

**Intent compiler that transforms human intent into working software through layered constraints (MS5→MS4→MS3→MS2)**
**License:** Free for non-commercial use; paid license required for commercial use

## Architecture

Director Kernel prevents AI drift by enforcing intermediate constraints at each layer:

- **MS5** (Intent) - What you want to build
- **MS4** (Architecture) - Module structure & boundaries  
- **MS3** (Contracts) - Behavioral contracts per module
- **MS2** (Code) - Generated implementation

### Key Features

✅ **Content-addressed storage** with optional encryption  
✅ **Incremental builds** via checkpoint caching  
✅ **Budget controls** (70% warn, 95% pause)  
✅ **Upstream-only fixes** (fix intent, not code)  
✅ **Build state machine** with crash recovery  
✅ **Atomic handoff** to IDE

## Installation

```bash
npm install
npm run build
```

## Quick Start

```bash
# Initialize kernel
./dist/cli.js init

# Build from MS5 spec
./dist/cli.js build examples/todo-app.ms5.json

# Check status
./dist/cli.js status
```

## Project Structure

```
src/
├── artifact_store.ts      # Content-addressed storage (SHA-256)
├── kernel_orchestrator.ts # Build lifecycle & state machine
├── model_router.ts        # OpenRouter LLM integration
├── context_slicer.ts      # Bounded context generation
├── schema_validator.ts    # JSON schema validation
├── cost_controller.ts     # Budget tracking & enforcement
├── transform_engine.ts    # MS-layer transform executor
├── cli.ts                 # CLI entry point
└── index.ts              # Public API exports

specs/
├── director_kernel_v6_ms5_ms4.json  # MS5 + MS4 specification
└── ms3_contracts.json               # MS3 behavioral contracts
```

## Core Modules

### Artifact Store
- Content-addressed storage (SHA-256 over plaintext)
- Optional AES-256-GCM encryption with key versioning
- Collision detection & integrity checks
- LRU cache (512MB)

### Kernel Orchestrator
- Build state machine (PENDING→ACTIVE→SUCCESS/FAILED/CRASHED/BUDGET_PAUSE)
- Singleton execution lock with heartbeat
- Checkpoint-based incremental builds
- Event outbox for exactly-once delivery

### Model Router
- OpenRouter API integration
- Concurrency limiting (max 6 parallel calls)
- Retry logic (exponential backoff)
- Timeout enforcement (120s)

### Context Slicer
- Token budget enforcement
- Priority-based artifact selection
- Truncation thresholds (warn 20%, fail 50%)
- Context hashing for reproducibility

### Cost Controller
- Per-build budget tracking
- 70% warning threshold
- 95% pause threshold
- Token usage persistence

### Transform Engine
- MS-layer transform execution (MS5→MS4→MS3→MS2)
- Atomic commits (all or nothing)
- Schema validation for all outputs
- Truncation safety (>50% = fail)
- Budget gate enforcement
- Idempotent execution with context hashing
- 9 critical invariants per MC3 spec

## Configuration

Create `~/.director/config.json`:

```json
{
  "dbPath": "~/.director/kernel.db",
  "artifactRoot": "~/.director/artifacts",
  "apiKey": "sk-or-..."
}
```

Or set `OPENROUTER_API_KEY` environment variable.

## MS5 Example

```json
{
  "schema_version": "6.0.0",
  "ms5": {
    "id": "TODO-APP",
    "title": "Simple Todo Application",
    "problem": "Need a basic todo list manager",
    "goal": {
      "start_state": "Empty project",
      "end_state": "Working todo app with CRUD operations"
    },
    "stages": [
      {
        "name": "backend",
        "targets": [
          { "name": "api_server", "config": { "framework": "express" } },
          { "name": "database", "config": { "type": "sqlite" } }
        ]
      }
    ]
  }
}
```

## Development

```bash
# Watch mode
npm run dev

# Build
npm run build

# Test
npm test

# Clean
npm run clean
```

## Error Taxonomy

- **USER_ERROR** - Invalid/contradictory specification
- **MODEL_ERROR** - LLM output invalid after retries
- **INFRA_ERROR** - Filesystem/database/network failure
- **BUDGET_PAUSE** - Cost limit reached (requires confirmation)

## VS Code Extension

The **Director Kernel** VS Code extension provides an integrated development experience for the MC Language compiler.

- **Extension ID**: `coherent-light.code-compressor-vscode`
- **Display Name**: Director Kernel

### Commands

| Command | Description |
|---------|-------------|
| Director Kernel: Start | Start the kernel process |
| Director Kernel: Stop | Stop the kernel process |
| Director Kernel: Restart | Restart the kernel process |
| Director Kernel: Status | Show current build status |
| Director Kernel: Run Tests | Execute the test suite |
| Director Kernel: Open README | Open this README in the editor |
| Director Kernel: Open Project Root | Open the project root folder |

### Settings

| Setting | Description | Default |
|---------|-------------|---------|
| `directorKernel.rootPath` | Path to the project root | — |
| `directorKernel.runCommand` | Command used to run the kernel | — |
| `directorKernel.testCommand` | Command used to run tests | `"npm test"` |
| `directorKernel.autoStart` | Automatically start the kernel on workspace open | — |
| `directorKernel.showOutputOnStart` | Show the output panel when the kernel starts | — |

### Install

```bash
npm run vscode:install
```

## Smoke Tests

Run the following to verify a healthy build:

```bash
# Run the test suite — expect 8 passed across 6 test files
npm test

# Verify TypeScript compilation completes cleanly
npm run build
```

### Test Coverage

The test suite (8 tests, 6 files including 1 suite with 3 subtests) covers:

- **Output writer security** — safe file emission
- **MC2 baton integrity** — handoff correctness between layers
- **MC2 governance** — policy enforcement on generated code
- **Schema validation** — JSON schema conformance for all MS layers
- **Semantic harness** — end-to-end semantic compilation checks
- **Worker isolator** — sandboxed execution of build workers

## License

Director Kernel is source-available with dual usage terms:

- Non-commercial use is allowed under the terms in `LICENSE`.
- Commercial use requires a paid commercial license from Coherent Light.

See `LICENSE` for full terms.

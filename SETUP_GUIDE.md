# Director Kernel v6 - Setup & Usage Guide

## ✅ Current Status

Your Director Kernel installation is **fully functional** and ready to use!

### What's Working:
- ✅ Core kernel compiled successfully
- ✅ All dependencies installed (main + UI backend + UI frontend)
- ✅ Database initialized at `C:\Users\new\.director\kernel.db`
- ✅ Artifacts directory created at `C:\Users\new\.director\artifacts`
- ✅ OpenRouter API key configured
- ✅ CLI commands operational
- ✅ UI components ready to launch

---

## 🚀 Quick Start

### Option 1: Launch the Full UI (Recommended)

Double-click the PowerShell launcher:
```
Launch-DirectorUI.ps1
```

Or run from PowerShell:
```powershell
.\Launch-DirectorUI.ps1
```

This will:
1. Start the API bridge on http://127.0.0.1:3100
2. Start the frontend on http://localhost:3000
3. Automatically open your browser

### Option 2: Use CLI Only

```bash
# Check status
node dist/cli.js status

# Build from MS5 specification
node dist/cli.js build examples/todo-app.ms5.json

# Get help
node dist/cli.js --help
```

---

## 📋 Available Commands

### CLI Commands

```bash
# Initialize (already done)
node dist/cli.js init

# Build a project from MS5 spec
node dist/cli.js build <ms5_file.json>

# Check build status
node dist/cli.js status

# Show help
node dist/cli.js --help
```

### Example MS5 Files

- `examples/todo-app.ms5.json` - Full-featured todo app example
- `full_pipeline.ms5.json` - Web AI orchestrator example
- `init_db.ms5.json` - Minimal initialization example

---

## 🎯 How to Use Director Kernel

### 1. Create an MS5 Specification

MS5 is the "intent layer" - what you want to build. Example:

```json
{
  "schema_version": "6.0.0",
  "ms5": {
    "id": "MY-PROJECT",
    "title": "My Awesome Project",
    "problem": "What problem are you solving?",
    "goal": {
      "start_state": "Empty project",
      "end_state": "Working application"
    },
    "stages": [
      {
        "name": "backend",
        "targets": [
          { "name": "api_server", "config": { "framework": "express" } }
        ]
      }
    ]
  }
}
```

### 2. Build Your Project

```bash
node dist/cli.js build my-project.ms5.json
```

Director will:
1. **MS5 → MS4**: Generate architecture from intent
2. **MS4 → MS3**: Create behavioral contracts
3. **MS3 → MS2**: Generate implementation code
4. Store all artifacts in content-addressed storage

### 3. Monitor Progress

- **CLI**: `node dist/cli.js status`
- **UI**: Open http://localhost:3100 (after running launcher)

---

## 🔧 Configuration

### Config File Location
`C:\Users\new\.director\config.json`

Current configuration:
```json
{
  "dbPath": "C:\\Users\\new\\.director\\kernel.db",
  "artifactRoot": "C:\\Users\\new\\.director\\artifacts",
  "apiKey": "sk-or-v1-..." 
}
```

### Environment Variables (Optional)

```powershell
# OpenRouter API Key (for AI model calls)
$env:OPENROUTER_API_KEY = "sk-or-v1-..."

# Custom database path
$env:DIRECTOR_DB_PATH = "C:\custom\path\kernel.db"

# Custom artifact storage
$env:DIRECTOR_ARTIFACT_ROOT = "C:\custom\path\artifacts"
```

---

## 🏗️ Architecture Overview

```
Director Kernel v6
├── MS5 (Intent Layer)      - What you want to build
├── MS4 (Architecture)      - Module structure & boundaries
├── MS3 (Contracts)         - Behavioral contracts
└── MS2 (Code)              - Generated implementation

Core Components:
├── artifact_store.ts       - Content-addressed storage (SHA-256)
├── kernel_orchestrator.ts  - Build lifecycle & state machine
├── model_router.ts         - OpenRouter LLM integration
├── transform_engine.ts     - MS-layer transform executor
└── cli.ts                  - Command-line interface

UI Components:
├── ui/backend/             - API bridge (Fastify server)
└── ui/frontend/            - React dashboard
```

---

## 🎨 UI Features

The web UI provides:
- 📊 **Build Dashboard** - View all builds and their status
- 🔄 **Live Progress** - Real-time SSE event stream
- 📝 **Natural Language Input** - Convert plain text to MS5 specs
- 💰 **Budget Tracking** - Monitor token usage and costs
- 🔍 **Artifact Browser** - Explore generated artifacts
- ⚡ **Build Controls** - Start, resume, abort builds

---

## 🧪 Testing the System

### Test 1: Simple Build
```bash
node dist/cli.js build examples/todo-app.ms5.json
```

### Test 2: Check Status
```bash
node dist/cli.js status
```

### Test 3: Launch UI
```powershell
.\Launch-DirectorUI.ps1
```

---

## 🐛 Troubleshooting

### Issue: "Database not found"
**Solution**: Run `node dist/cli.js init` first

### Issue: "API key not configured"
**Solution**: Check `C:\Users\new\.director\config.json` has valid `apiKey`

### Issue: UI won't start
**Solution**: 
1. Check if ports 3000 and 3100 are available
2. Ensure dependencies installed: `npm install` in `ui/backend` and `ui/frontend`

### Issue: Build fails with MODEL_ERROR
**Solution**: Verify OpenRouter API key is valid and has credits

---

## 📚 Key Concepts

### Content-Addressed Storage
- All artifacts stored by SHA-256 hash
- Automatic deduplication
- Integrity verification
- Optional AES-256-GCM encryption

### Incremental Builds
- Checkpoint-based caching
- Only rebuild changed layers
- Context hashing for reproducibility

### Budget Controls
- 70% warning threshold
- 95% pause threshold
- Per-build cost tracking

### Upstream-Only Fixes
- Fix intent (MS5), not code (MS2)
- Rebuild from corrected specification
- Prevents AI drift

---

## 🎓 Next Steps

1. **Explore Examples**: Check `examples/todo-app.ms5.json`
2. **Create Your Own MS5**: Start with a simple project
3. **Launch the UI**: Run `.\Launch-DirectorUI.ps1`
4. **Read the Docs**: Check `docs/` folder for detailed specs

---

## 📞 Support

- **Documentation**: See `README.md` and files in `docs/`
- **Examples**: Check `examples/` directory
- **Logs**: Located in `.director/` folder

---

## ⚡ Performance Tips

1. **Use specific intents** - Clear MS5 specs produce better results
2. **Set realistic budgets** - Start with $1-2 for small projects
3. **Monitor checkpoints** - Review intermediate outputs
4. **Cache artifacts** - Reuse unchanged components

---

**Status**: ✅ Ready to build!

Run `.\Launch-DirectorUI.ps1` to get started with the visual interface, or use `node dist/cli.js build examples/todo-app.ms5.json` to try a CLI build.

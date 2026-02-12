# Director Kernel VS Code Extension

This extension wraps local Director Kernel workflows in VS Code.

## Commands

- `Director Kernel: Start`
- `Director Kernel: Stop`
- `Director Kernel: Restart`
- `Director Kernel: Status`
- `Director Kernel: Run Tests`
- `Director Kernel: Open README`
- `Director Kernel: Open Project Root`

## Settings

- `directorKernel.rootPath`: Absolute project root path override.
- `directorKernel.runCommand`: Command used by Start.
- `directorKernel.testCommand`: Command used by Run Tests.
- `directorKernel.autoStart`: Auto-start on VS Code startup.
- `directorKernel.showOutputOnStart`: Focus output channel on Start.

## Notes

- If your workspace is not this repo, set `directorKernel.rootPath` explicitly.

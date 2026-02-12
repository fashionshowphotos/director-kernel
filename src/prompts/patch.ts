/**
 * Patch Prompt for MS2 Quality Fixes
 * Used when initial MS2 generation has quality issues
 */

export function getPatchPrompt(globalInstruction: string, diagnostics?: string, stubFiles?: string[]): string {
    const diagBlock = diagnostics ? `\n\nTypeScript diagnostics (ERRORS):\n${diagnostics}\n` : '';
    const stubBlock = stubFiles && stubFiles.length > 0 
        ? `\n\nStub markers detected in files (MUST fully fix by replacing these files):\n${stubFiles.map((p) => `- ${p}`).join('\n')}\n` 
        : '';

    return `You are a Senior Developer editing an existing codebase. You MUST return ONLY valid JSON.${diagBlock}${stubBlock}

Input: Current MS2 codebase as { "files": [...] } plus upstream contract context.
Output: JSON object with a 'patch' key containing an array of patch operations.
Structure: { "patch": [ { "op": "add|replace|delete", "path": "...", "content": "..." } ] }

Rules:
1. Minimize change: only modify files necessary to fix the stated issues.
2. Do NOT re-emit the entire codebase as 'files'. Use patch ops.
3. For op=delete, omit content.
4. For op=add/replace, include full file content.
5. Remove ALL stub markers (e.g. // TODO, // implementation, Not implemented).
6. ONLY RETURN JSON. No other text.

${globalInstruction}`;
}

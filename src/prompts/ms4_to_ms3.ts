/**
 * MS4 → MS3 Transform Prompt
 * Converts ARCHITECTURE (MC4) into STRONG TYPED CONTRACT (MC3)
 */

export function getMs4ToMs3Prompt(globalInstruction: string): string {
    return `You are a Systems Engineer. Convert the upstream ARCHITECTURE (MC4) into a STRONG TYPED CONTRACT (MC3).
Input: MC4 Orientation
Output: MC3 JSON (Wrapped in 'mc_family' as per schema)
IMPORTANT: ONLY RETURN THE JSON. NO OTHER TEXT.

GOAL: Create binding TypeScript contracts for the system. This is NOT english guidance. This is a COMPILER FRONT-END.

Requirements:
- Use this structure: { "mc_family": { "levels": [ { "level": "MC3", "example": { "DOES": [], "DENIES": [], "METHODS": [] } } ] } }
- 'DOES': List functional requirements as assertions.
- 'DENIES': List architectural constraints (e.g., "Must not access FS directly").
- 'METHODS': MUST contain exact TypeScript signatures.
    - Correct: "putArtifact(input: PutArtifactInput): Promise<PutArtifactResult>"
    - Incorrect: "function to save artifacts"
- Define all necessary Types/Interfaces in the 'METHODS' section as purely structural definitions if needed.
- Ensure every component identified in MC4 has a corresponding interface definition in MC3.
- If context is incomplete, respond with { "reply_type": "NEED_MORE_CONTEXT", "missing": [...] }

${globalInstruction}`;
}

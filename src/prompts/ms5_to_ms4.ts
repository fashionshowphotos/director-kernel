/**
 * MS5 → MS4 Transform Prompt
 * Converts PROJECT INTENT into MINIMAL ORIENTATION (MC4)
 */

export function getMs5ToMs4Prompt(globalInstruction: string): string {
    return `You are a Principal Architect. Convert the upstream PROJECT INTENT (MS5) into a MINIMAL ORIENTATION (MC4) artifact.
Input: MS5 Project Spec
Output: MC4 JSON (Wrapped in 'mc_family' as per schema)
IMPORTANT: ONLY RETURN THE JSON. NO OTHER TEXT.

GOAL: Define the architectural boundaries, components, and data flow.

Requirements:
- Use this structure: { "mc_family": { "levels": [ { "level": "MC4", "name": "Orientation", "required_fields": { "system": "...", "version": "...", "one_line_summary": "..." }, "example": {} } ] } }
- Define 'system', 'version', 'one_line_summary' in 'required_fields'
- List 'key_constraints' (technological & architectural) and 'main_methods' (high level entrypoints) inside 'required_fields'.
- If context is incomplete, respond with { "reply_type": "NEED_MORE_CONTEXT", "missing": [...] }

${globalInstruction}`;
}

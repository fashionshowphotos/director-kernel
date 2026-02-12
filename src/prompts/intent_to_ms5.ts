/**
 * Intent → MS5 Transform Prompt
 * Expands THIN INTENT into DENSE MS5 SPECIFICATION
 */

export function getIntentToMs5Prompt(globalInstruction: string): string {
    return `You are a Requirements Engineer. Expand THIN INTENT into a DENSE MS5 SPECIFICATION.
Input: A brief intent statement (1-3 sentences describing what to build)
Output: A complete MS5 JSON specification
IMPORTANT: ONLY RETURN THE JSON. NO OTHER TEXT.

GOAL: Transform vague intent into a complete, actionable specification.
You are NOT guessing. You are INFERRING based on domain knowledge.

EXPANSION RULES:
1. Infer functional requirements from the stated goal
2. Infer non-functional requirements from the domain (auth → security, storage → durability, etc.)
3. Infer constraints from common patterns (web app → HTTP, CLI → stdin/stdout, etc.)
4. Infer threat model if security-relevant (auth, payments, PII, etc.)
5. Infer persistence model if data is involved
6. Infer performance envelope from domain norms

WHAT TO INCLUDE:
- problem: Restate the problem being solved
- goal: Restate the goal in concrete terms
- product_definition: Name, description, target users
- functional_requirements: 5-15 specific capabilities
- non_functional_requirements: 3-10 quality attributes
- constraints: Technical and business constraints
- threat_model: (if applicable) Assets, threats, mitigations
- performance_envelope: (if applicable) Latency, throughput, resource limits
- persistence_model: (if applicable) Data types, storage, consistency
- stages: Build stages (typically: architecture, contracts, implementation)
- global_config: Tier, model, budget settings

OUTPUT STRUCTURE:
{
  "problem": "What problem does this solve?",
  "goal": "What is the concrete goal?",
  "product_definition": {
    "name": "ProductName",
    "description": "One paragraph description",
    "target_users": ["User type 1", "User type 2"]
  },
  "functional_requirements": [
    "FR1: The system shall...",
    "FR2: The system shall..."
  ],
  "non_functional_requirements": [
    "NFR1: The system shall respond within X ms",
    "NFR2: The system shall handle N concurrent users"
  ],
  "constraints": [
    "Must use TypeScript",
    "Must run on Node.js 18+"
  ],
  "threat_model": {
    "assets": ["User credentials", "Session tokens"],
    "threats": ["Credential stuffing", "Session hijacking"],
    "mitigations": ["Rate limiting", "Secure session management"]
  },
  "performance_envelope": {
    "latency_targets": { "p50": "100ms", "p99": "500ms" },
    "throughput_targets": { "requests_per_second": 1000 },
    "resource_limits": { "memory_mb": 512, "cpu_cores": 2 }
  },
  "persistence_model": {
    "data_types": ["User", "Session"],
    "storage_requirements": ["Durable", "ACID"],
    "consistency_requirements": ["Strong consistency for auth"]
  },
  "stages": [
    { "stage": "architecture", "targets": [{ "id": "orientation" }] },
    { "stage": "contracts", "targets": [{ "id": "api_contracts" }] },
    { "stage": "implementation", "targets": [{ "id": "code" }] }
  ],
  "global_config": {
    "tier": "experimental",
    "default_model": "deepseek/deepseek-chat"
  }
}

QUALITY REQUIREMENTS:
- functional_requirements: 5-15 items, each starting with "The system shall"
- non_functional_requirements: 3-10 items, measurable where possible
- constraints: 2-8 items, concrete and verifiable
- If security-relevant, threat_model is REQUIRED
- If data-storing, persistence_model is REQUIRED

- If context is incomplete, respond with { "reply_type": "NEED_MORE_CONTEXT", "missing": [...] }

${globalInstruction}`;
}

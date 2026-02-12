
import { strict as assert } from 'assert';
import { MC2SerialEngine } from '../src/mc2_serial_engine';
import { MC2IterationRequest, MC2Artifact, GovernanceBundle } from '../src/mc2_types';
import * as crypto from 'crypto';

// Subclass to access private method for testing
class TestableMC2SerialEngine extends MC2SerialEngine {
    public testBuildIterationPrompt(
        artifact: MC2Artifact,
        objections: any[],
        stageGoal: string,
        modelId: string,
        iterationIndex: number,
        baton: any,
        governanceBundle?: any
    ): string {
        // @ts-ignore - Accessing private method
        return this.buildIterationPrompt(artifact, objections, stageGoal, modelId, iterationIndex, baton, governanceBundle);
    }
}

function testGovernanceInjection() {
    console.log('Testing Governance Bundle Injection...');
    const engine = new TestableMC2SerialEngine('dummy-key');

    const mockArtifact: MC2Artifact = {
        content: Buffer.from('code'),
        kind: 'ms2',
        hash: 'hash-1'
    };

    const mockBaton = {
        stage_id: 'stage-1',
        artifact_sha_before: 'hash-1',
        artifact_sha_after: 'PENDING',
        objection_ids_open_before: [],
        objection_ids_open_after: [],
        iteration_index: 0,
        model_id: 'test-model'
    };

    // Case 1: No Governance Bundle
    console.log('Case 1: No Governance Bundle');
    const promptNoGov = engine.testBuildIterationPrompt(
        mockArtifact, [], 'Goal', 'model-1', 0, mockBaton, undefined
    );
    assert.ok(promptNoGov.includes('No governance bundle provided'), 'Should state no bundle provided');
    assert.ok(!promptNoGov.includes('MC4_CONSTITUTION'), 'Should not include MC4 block');

    // Case 2: With Governance Bundle
    console.log('Case 2: With Governance Bundle');
    const mockBundle: GovernanceBundle = {
        mc4: { constitution: "Be safe", rules: ["no buffer overflows"] },
        mc3_index: { contracts: ["auth-v1"] },
        packets: [{ id: "auth-v1", content: "..." }],
        bundle_sha: "bundle-hash-123"
    };

    const promptWithGov = engine.testBuildIterationPrompt(
        mockArtifact, [], 'Goal', 'model-1', 0, mockBaton, mockBundle
    );

    assert.ok(promptWithGov.includes('GOVERNANCE BUNDLE (MUST FOLLOW)'), 'Should include header');
    assert.ok(promptWithGov.includes('MC_BUNDLE_SHA: bundle-hash-123'), 'Should include bundle SHA');
    assert.ok(promptWithGov.includes('"rules": [\n    "no buffer overflows"\n  ]'), 'Should include MC4 content');
    assert.ok(promptWithGov.includes('MC3_PACKETS'), 'Should include MC3 packets');

    console.log('PASS: Governance Injection Verified');
}

async function main() {
    try {
        testGovernanceInjection();
    } catch (e) {
        console.error('TEST FAILED:', e);
        process.exit(1);
    }
}

main();

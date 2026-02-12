
import { strict as assert } from 'assert';
import { MC2SerialEngine } from '../src/mc2_serial_engine';
import { MC2IterationResponse, MC2Artifact, Objection } from '../src/mc2_types';
import * as crypto from 'crypto';

// Subclass to access private method for testing
class TestableMC2SerialEngine extends MC2SerialEngine {
    public testParseIterationResponse(
        raw: string,
        modelId: string,
        iterationIndex: number,
        expectedBaton: any
    ): MC2IterationResponse {
        // @ts-ignore - Accessing private method
        return this.parseIterationResponse(raw, modelId, iterationIndex, expectedBaton);
    }

    public testComputeHash(content: Buffer): string {
        // @ts-ignore
        return this.computeHash(content);
    }
}

async function testBatonIntegrity() {
    console.log('Testing Baton Integrity...');
    const engine = new TestableMC2SerialEngine('dummy-key');
    const content = Buffer.from('Testing Content');
    const hash = engine.testComputeHash(content);

    // 1. Valid Success Case
    console.log('Case 1: Valid Baton Round Trip');
    const validBaton = {
        stage_id: 'stage-1',
        artifact_sha_before: 'prev-hash',
        artifact_sha_after: hash,
        iteration_index: 0,
        model_id: 'test-model'
    };

    const validResponse = JSON.stringify({
        status: 'COMPLETE',
        artifact: { content: 'Testing Content', kind: 'ms2', hash },
        new_objections: [],
        baton: validBaton
    });

    const res1 = engine.testParseIterationResponse(validResponse, 'test-model', 0, validBaton);

    assert.equal(res1.status, 'COMPLETE');
    assert.deepEqual(res1.baton, validBaton);
    assert.equal(res1.new_objections.length, 0, 'Should have no objections for valid baton');

    // 2. Tampered Baton (Stage ID Mismatch)
    console.log('Case 2: Tampered Baton (Stage ID Mismatch)');
    const tamperedBaton = { ...validBaton, stage_id: 'stage-HACKED' };
    const tamperedResponse = JSON.stringify({
        status: 'COMPLETE',
        artifact: { content: 'Testing Content', kind: 'ms2', hash },
        baton: tamperedBaton
    });

    const res2 = engine.testParseIterationResponse(tamperedResponse, 'test-model', 0, validBaton);
    const securityObj2 = res2.new_objections.find(o => o.category === 'SECURITY');
    assert.ok(securityObj2, 'Should raise SECURITY objection for stage_id mismatch');
    assert.ok(securityObj2?.message.includes('stage_id mismatch'), 'Message should specify mismatch');
    assert.equal(securityObj2?.severity, 'CRITICAL', 'Severity must be CRITICAL');

    // Verify Deterministic ID
    const expectedId = engine.testComputeHash(Buffer.from(`security:baton:${0}`));
    assert.equal(securityObj2?.id, expectedId, 'Objection ID must be deterministic (hash of security:baton:index)');

    // 3. Artifact Hash Mismatch (Hallucinated Hash)
    console.log('Case 3: Artifact Hash Mismatch');
    const mismatchBaton = { ...validBaton, artifact_sha_after: 'fake-hash' };
    const mismatchResponse = JSON.stringify({
        status: 'COMPLETE',
        artifact: { content: 'Testing Content', kind: 'ms2', hash },
        baton: mismatchBaton // Baton claims hash is 'fake-hash', actual is 'hash'
    });

    const res3 = engine.testParseIterationResponse(mismatchResponse, 'test-model', 0, validBaton);
    const securityObj3 = res3.new_objections.find(o => o.category === 'SECURITY');
    assert.ok(securityObj3, 'Should raise SECURITY objection for artifact hash mismatch');
    assert.ok(securityObj3?.message.includes('artifact_sha_after mismatch'), 'Message should specify mismatch');
    assert.equal(securityObj3?.severity, 'CRITICAL', 'Severity must be CRITICAL');
    assert.equal(securityObj3?.id, expectedId, 'Objection ID should still be deterministic');

    // 4. Governance Bundle Tampering (Constitution Rewrite Attempt)
    console.log('Case 4: Governance Bundle Tampering (Constitution Rewrite Attempt)');
    const validBatonWithGov = { ...validBaton, mc_bundle_sha: 'correct-constitution-hash' };
    const tamperedGovBaton = { ...validBatonWithGov, mc_bundle_sha: 'hacked-constitution-hash' };

    const govTamperedResponse = JSON.stringify({
        status: 'COMPLETE',
        artifact: { content: 'Testing Content', kind: 'ms2', hash },
        baton: tamperedGovBaton
    });

    const res4 = engine.testParseIterationResponse(govTamperedResponse, 'test-model', 0, validBatonWithGov);
    const securityObj4 = res4.new_objections.find(o => o.category === 'SECURITY');
    assert.ok(securityObj4, 'Should raise SECURITY objection for MC Bundle SHA mismatch');
    assert.ok(securityObj4?.message.includes('mc_bundle_sha mismatch'), 'Message should specify mismatch'); // Implicitly covered if we add the property check in engine, but wait, did we add it to the engine check loop?
    // NOTE: We need to verify that mc2_serial_engine.ts actually checks mc_bundle_sha.
    // Based on previous edits, we passed it into the baton, but did we add the CHECK line in parseIterationResponse?

    // 5. Missing Baton
    console.log('Case 5: Missing Baton');
    const missingBatonResponse = JSON.stringify({
        status: 'COMPLETE',
        artifact: { content: 'Testing Content', kind: 'ms2', hash }
        // No baton
    });

    const res5 = engine.testParseIterationResponse(missingBatonResponse, 'test-model', 0, validBaton);
    const securityObj5 = res5.new_objections.find(o => o.category === 'SECURITY');
    assert.ok(securityObj5, 'Should raise SECURITY objection for missing baton');
    assert.equal(securityObj5?.severity, 'CRITICAL');

    console.log('PASS: Baton Integrity Verified');
}

async function main() {
    try {
        await testBatonIntegrity();
        console.log('ALL TESTS PASSED');
    } catch (e) {
        console.error('TEST FAILED:', e);
        process.exit(1);
    }
}

main();

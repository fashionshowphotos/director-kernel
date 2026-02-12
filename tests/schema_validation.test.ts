
import { strict as assert } from 'assert';
import { SchemaValidator } from '../src/schema_validator';

// Replicate the schemas defined in TransformEngine
const OBJECTION_LEDGER_SCHEMA = {
    type: 'object',
    required: ['id', 'type', 'description', 'status'],
    properties: {
        id: { type: 'string' },
        type: { type: 'string', enum: ['logic', 'security', 'style', 'incomplete'] },
        description: { type: 'string' },
        status: { type: 'string', enum: ['open', 'resolved'] },
        resolution_context: { type: 'string' }
    }
};

const COMPLETION_DECLARATION_SCHEMA = {
    type: 'object',
    required: ['status', 'justification'],
    properties: {
        status: { type: 'string', enum: ['stage_complete', 'stage_incomplete'] },
        justification: { type: 'string' },
        objections: {
            type: 'array',
            items: {
                type: 'object',
                required: ['id', 'type', 'description', 'status'],
                properties: {
                    id: { type: 'string' },
                    type: { type: 'string', enum: ['logic', 'security', 'style', 'incomplete'] },
                    description: { type: 'string' },
                    status: { type: 'string', enum: ['open', 'resolved'] },
                    resolution_context: { type: 'string' }
                }
            }
        }
    }
};

async function testObjectionLedgerValidation() {
    console.log('Testing Objection Ledger Validation...');
    const validator = new SchemaValidator();
    validator.registerSchema('objection_ledger_v1', OBJECTION_LEDGER_SCHEMA as any);

    // Valid
    const valid = {
        id: '12345',
        type: 'security',
        description: 'Buffer overflow risk in parse logic',
        status: 'open'
    };
    const r1 = validator.validate(valid, 'objection_ledger_v1');
    assert.ok(r1.valid, 'Valid objection should pass');

    // Invalid Enum
    const invalidType = { ...valid, type: 'personal_dislike' };
    const r2 = validator.validate(invalidType, 'objection_ledger_v1');
    assert.ok(!r2.valid, 'Invalid type enum should fail');

    // Missing Field
    const missingDesc = { id: '123', type: 'logic', status: 'open' };
    const r3 = validator.validate(missingDesc, 'objection_ledger_v1');
    assert.ok(!r3.valid, 'Missing description should fail');

    console.log('PASS');
}

async function testCompletionDeclarationValidation() {
    console.log('Testing Completion Declaration Validation...');
    const validator = new SchemaValidator();
    validator.registerSchema('completion_declaration_v1', COMPLETION_DECLARATION_SCHEMA as any);

    // Valid Completion
    const valid = {
        status: 'stage_complete',
        justification: 'All tests passed',
        objections: []
    };
    const r1 = validator.validate(valid, 'completion_declaration_v1');
    assert.ok(r1.valid, 'Valid completion should pass');

    // Valid Incomplete with Objections
    const validIncomplete = {
        status: 'stage_incomplete',
        justification: 'Found security flaw',
        objections: [{
            id: 'obs-1',
            type: 'security',
            description: 'SQL Injection in query',
            status: 'open'
        }]
    };
    const r2 = validator.validate(validIncomplete, 'completion_declaration_v1');
    assert.ok(r2.valid, 'Valid incomplete declaration with objections should pass');

    // Invalid Status
    const invalidStatus = { ...valid, status: 'kinda_done' };
    const r3 = validator.validate(invalidStatus, 'completion_declaration_v1');
    assert.ok(!r3.valid, 'Invalid status enum should fail');

    // Malformed Objection inside Completion
    const malformedObjection = {
        status: 'stage_incomplete',
        justification: 'Bad objection',
        objections: [{ id: 'obs-1' }] // Missing type, description, status
    };
    const r4 = validator.validate(malformedObjection, 'completion_declaration_v1');
    assert.ok(!r4.valid, 'Malformed objection inside completion should fail');

    console.log('PASS');
}

async function main() {
    try {
        await testObjectionLedgerValidation();
        await testCompletionDeclarationValidation();
        console.log('ALL TESTS PASSED');
    } catch (e) {
        console.error('TEST FAILED:', e);
        process.exit(1);
    }
}

main();

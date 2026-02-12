import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { executeInWorker } from '../src/worker_isolator';

test('worker isolator constructs TransformEngine and surfaces execute-time schema errors', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'worker-isolator-'));
    try {
        const content = Buffer.from('intent: hello', 'utf8');
        const sha = crypto.createHash('sha256').update(content).digest('hex');
        const shard = path.join(tmp, sha.slice(0, 2));
        fs.mkdirSync(shard, { recursive: true });
        fs.writeFileSync(path.join(shard, sha), content);

        const result = await executeInWorker(
            {
                artifactRoot: tmp,
                apiKey: '',
                modelId: 'deepseek/deepseek-chat',
                timeoutMs: 10000,
            },
            'stage-1',
            'target-1',
            [{ artifact_id: 'a1', sha256: sha, kind: 'intent' }],
            { transformType: 'not_a_transform' },
            1,
            'idem-1'
        );

        assert.equal(result.success, false);
        assert.match(result.error?.message || '', /No schema registered/i);
    } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});

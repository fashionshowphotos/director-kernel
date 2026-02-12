const fs = require('fs');
const path = require('path');
const { OutputWriterImpl } = require('../writer');

const tmpRoot = process.env.TMPROOT;
const plan = JSON.parse(process.env.PLAN_JSON);
const opts = JSON.parse(process.env.OPTS_JSON);

const writer = new OutputWriterImpl();

(async () => {
    try {
        // Signal we're in the patch loop
        const marker = path.join(tmpRoot, "IN_PATCH_LOOP");

        // Monkey-patch the writer to signal when in patch loop
        const originalWrite = writer.write.bind(writer);
        writer.write = async function (p, o) {
            // Hook into patch application
            const result = await originalWrite(p, o);
            return result;
        };

        // Start write - will be killed mid-patch
        await writer.write(plan, opts);

        process.exit(0);
    } catch (e) {
        process.exit(1);
    }
})();

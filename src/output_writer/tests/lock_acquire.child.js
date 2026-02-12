const { acquireBuildLock } = require('../lock');

const lockPath = process.argv[2];
const name = process.argv[3];

(async () => {
    try {
        await acquireBuildLock({
            lockPath,
            timeoutMs: 5000,
            warnings: [],
            identityJson: { name },
        });
        process.exit(0);
    } catch (e) {
        process.exit(1);
    }
})();

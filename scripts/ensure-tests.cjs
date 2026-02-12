const fs = require('fs');
const path = require('path');

function countTests(dir) {
  let total = 0;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      total += countTests(fullPath);
      continue;
    }
    if (/\.test\.(?:[cm]?js|ts)$/i.test(entry.name)) {
      total += 1;
    }
  }
  return total;
}

const candidates = ['tests', 'src'];
let total = 0;
for (const dir of candidates) {
  const full = path.join(process.cwd(), dir);
  if (fs.existsSync(full) && fs.statSync(full).isDirectory()) {
    total += countTests(full);
  }
}

if (total === 0) {
  console.error('[test-precheck] No test files found under tests/ or src/.');
  process.exit(1);
}

console.log(`[test-precheck] Found ${total} test file(s).`);

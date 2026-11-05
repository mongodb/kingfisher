'use strict';
// Offline file scanning; the reusable scanner owns its compiled catalog.
const { Scanner } = require('../index.cjs');

(async () => {
  const scanner = await Scanner.create();
  try {
    const findings = process.argv[2] ? await scanner.scanFile(process.argv[2]) : await scanner.scan('ordinary application configuration');
    for (const finding of findings) if (finding.visible) console.log(finding.toJSON());
  } finally { await scanner.close(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });

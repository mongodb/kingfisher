'use strict';
// Acquisition, archive/content transforms, detection and reporting are independent.
const { Scanner, filesystem, expandArchives, expandContent } = require('../index.cjs');

(async () => {
  const scanner = await Scanner.create();
  try {
    const roots = process.argv.slice(2);
    if (!roots.length) throw new Error('Pass one or more local paths');
    const inputs = expandContent(expandArchives(filesystem(roots), { depth: 2 }));
    for await (const result of scanner.scanInputs(inputs)) console.log(result.toJSON());
  } finally { await scanner.close(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });

'use strict';
// Read-only local snapshot enumeration: no Git subprocess, fetch or checkout.
const { Scanner, gitInputs } = require('../index.cjs');

(async () => {
  const scanner = await Scanner.create();
  try {
    const inputs = gitInputs(process.argv[2] ?? '..', { mode: 'snapshot', refs: ['HEAD'], maxInputs: 10_000 });
    for await (const result of scanner.scanInputs(inputs)) console.log(result.toJSON());
  } finally { await scanner.close(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });

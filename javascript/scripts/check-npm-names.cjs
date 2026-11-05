'use strict';
const pkg = require('../package.json');
const targets = require('./targets.cjs');

(async () => {
  const names = [...new Set([pkg.name, 'kingfisher-core', 'kingfisher-rules', 'kingfisher-scanner',
    'kingfisher-sdk', 'kingfisher', ...targets.map(target => `${pkg.name}-${target.suffix}`)])];
  const results = await Promise.all(names.map(async name => {
    const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`, { signal: AbortSignal.timeout(15_000) });
    if (response.status === 404) return { name, status: 'unregistered' };
    if (!response.ok) throw new Error(`Registry lookup failed (${response.status}) for ${name}`);
    const metadata = await response.json();
    return { name, status: 'registered', latest: metadata['dist-tags']?.latest };
  }));
  console.table(results);
  console.log('Read-only registry check. Names are not reserved; npm policy may still reject publication.');
})().catch(error => { console.error(error.message); process.exitCode = 1; });

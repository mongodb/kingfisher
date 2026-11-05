'use strict';
// Custom-rule workflows: preparation is offline; live operations require flags.
const { Rules, Revoker, Validator } = require('../index.cjs');

(async () => {
  const [rulesPath, sourceFile, ...flags] = process.argv.slice(2);
  if (!rulesPath || !sourceFile) throw new Error('Usage: node examples/validate-revoke.cjs company.yml config.env [--validate] [--analyze] [--confirm-revoke]');
  if (flags.some(flag => !['--validate', '--analyze', '--confirm-revoke'].includes(flag))) throw new Error('Unknown workflow flag');
  if (flags.some(flag => flag === '--analyze' || flag === '--confirm-revoke') && !flags.includes('--validate')) {
    throw new Error('--analyze and --confirm-revoke require explicit --validate');
  }
  const rules = await Rules.load({ paths: [rulesPath], builtins: false });
  const revoker = await Revoker.create({ rules });
  const validator = new Validator();
  try {
    const plan = await revoker.prepareFromFile(sourceFile);
    console.log(plan.toJSON());
    if (!flags.includes('--validate')) return; // No provider requests by default.
    const results = await plan.validate(validator);
    results.forEach(result => console.log(result.toJSON()));
    if (flags.includes('--analyze')) {
      // Analysis is separately authorized and may disclose sensitive identity/permission data.
      for (const result of results) console.log(await validator.analyze(result));
    }
    if (flags.includes('--confirm-revoke')) {
      // Keep the original verified-active snapshots, not redacted JSON reports.
      // In an application, narrow this selection further to the intended credentials.
      const selected = results.filter(result => result.outcome === 'verified_active' && result.revocationReady);
      console.log(await revoker.revokeMany(selected, { confirm: true }));
    }
  } finally { await validator.close(); await revoker.close(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });

import sdk = require('kingfisher-secret-scanner');
import core = require('kingfisher-secret-scanner/core');
import rules = require('kingfisher-secret-scanner/rules');
import scanner = require('kingfisher-secret-scanner/scanner');
import inputs = require('kingfisher-secret-scanner/inputs');
import git = require('kingfisher-secret-scanner/git');
import validation = require('kingfisher-secret-scanner/validation');
import revocation = require('kingfisher-secret-scanner/revocation');

const classes: [typeof sdk.Finding, typeof sdk.Rules, typeof sdk.Scanner,
  typeof sdk.ScanInput, typeof sdk.gitInputs, typeof sdk.Validator, typeof sdk.Revoker] = [
  core.Finding, rules.Rules, scanner.Scanner, inputs.ScanInput,
  git.gitInputs, validation.Validator, revocation.Revoker,
];
void classes;

function selectedValidation(validator: sdk.Validator, findings: readonly sdk.Finding[]) {
  const options: validation.ValidationOptions = { candidates: Object.freeze([...findings]), timeoutMs: 1000 };
  const rootOptions: sdk.ValidationOptions = options;
  void validator.validate(findings, rootOptions);
  // @ts-expect-error candidate reports cannot stand in for original Finding objects
  void validator.validate(findings, { candidates: findings.map(finding => finding.toJSON()) });
  // @ts-expect-error candidate selection is an array, not an arbitrary iterable
  void validator.validate(findings, { candidates: new Set(findings) });
}
void selectedValidation;

const text: inputs.ScanInputOptions = { path: 'config.env', data: 'ordinary configuration' };
const file: inputs.ScanInputOptions = { path: 'config.env', file: 'config.env' };
new sdk.ScanInput(text);
new sdk.ScanInput(file);
// @ts-expect-error a source is mandatory
new sdk.ScanInput({ path: 'config.env' });
// @ts-expect-error sources are mutually exclusive
new sdk.ScanInput({ path: 'config.env', file: 'config.env', data: 'configuration' });
// @ts-expect-error undefined is not a payload source
new sdk.ScanInput({ path: 'config.env', data: undefined });

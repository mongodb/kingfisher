import sdk, {
  Rules, Scanner, DetectionScanner, DetectionPolicy, Validator, Revoker,
  ScanInput, CancellationToken, filesystem, expandArchives, expandContent, gitInputs,
  type Finding, type ValidationResult,
} from 'kingfisher-secret-scanner';
import { Rules as SubpathRules } from 'kingfisher-secret-scanner/rules';
import { Scanner as SubpathScanner } from 'kingfisher-secret-scanner/scanner';
import revocationSdk, { Revoker as SubpathRevoker } from 'kingfisher-secret-scanner/revocation';
import coreSdk from 'kingfisher-secret-scanner/core';
import rulesSdk from 'kingfisher-secret-scanner/rules';
import scannerSdk from 'kingfisher-secret-scanner/scanner';
import inputsSdk from 'kingfisher-secret-scanner/inputs';
import gitSdk from 'kingfisher-secret-scanner/git';
import validationSdk from 'kingfisher-secret-scanner/validation';

const defaultScanner: typeof Scanner = sdk.Scanner;
const defaultSubpaths = [coreSdk.Finding, rulesSdk.Rules, scannerSdk.Scanner, inputsSdk.ScanInput,
  gitSdk.gitInputs, validationSdk.Validator, revocationSdk.Revoker];
void [defaultScanner, defaultSubpaths];

const rules: Rules = await Rules.load({ paths: [], cache: false, confidence: 'low' });
const sameRules: typeof Rules = SubpathRules;
const sameScanner: typeof Scanner = SubpathScanner;
const sameRevoker: typeof Revoker = SubpathRevoker;
void [sameRules, sameScanner, sameRevoker];
const scanner = await Scanner.create({ rules, policy: new DetectionPolicy(), maxInputBytes: null });
const detection: DetectionScanner = await DetectionScanner.create({ rules });
// @ts-expect-error file scans cannot override the filesystem path
await scanner.scanFile('config.env', { path: 'logical.env' });
const signal = new AbortController().signal;
const cancellation = new CancellationToken();
const findings: Finding[] = await scanner.scan(new Uint8Array(), { signal, cancellation, path: 'config.env' });
const validator = new Validator({ httpFallbacks: false, timeoutMs: 0 });
const results: ValidationResult[] = await validator.validate(findings);
for await (const result of scanner.scanInputs(expandContent(expandArchives(filesystem(['.']))))) {
  const fingerprint: string | undefined = result.findings[0]?.fingerprint;
  void fingerprint;
}
for await (const input of gitInputs('.', { mode: 'snapshot', refs: ['HEAD'] })) {
  const data: Uint8Array | undefined = input.data;
  const timestamp: string | undefined = input.origins[0]?.author.timestamp;
  void [data, timestamp];
}
const revoker = await Revoker.create({ rules });
const plan = await revoker.prepare('synthetic', { provider: 'acme' });
await plan.validate(validator);
if (results[0]) await revoker.revoke(results[0], { confirm: true });
await revoker.revokeMany(results, { confirm: true });
// @ts-expect-error explicit confirmation is mandatory
await revoker.revoke(results[0]);
// @ts-expect-error JSON reports are not credential snapshots
await revoker.revoke(findings[0].toJSON(), { confirm: true });
// @ts-expect-error confidence is a constrained public option
await Rules.load({ confidence: 'anything' });
const input = new ScanInput({ path: 'config.env', data: 'synthetic' });
await scanner.scanInput(input);
await Promise.all([scanner.close(), detection.close(), validator.close(), revoker.close()]);

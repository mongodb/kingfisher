export const version: string;
/** SharedArrayBuffer-backed views require an explicit non-shared copy. */
export type Data = string | Uint8Array;
export type Confidence = 'low' | 'medium' | 'high';
export type ValidationOutcome = 'not_attempted' | 'verified_active' | 'verified_inactive' | 'unavailable' | 'skipped' | 'assumed' | 'locally_derived' | 'invalid_material';
export interface OperationOptions {
  /** Total operation deadline in milliseconds; positive when supplied. */
  timeoutMs?: number;
  cancellation?: CancellationToken;
  /** TimeoutError reasons yield SDK TimeoutError; other reasons yield SDK AbortError, with the reason as cause. */
  signal?: AbortSignal;
}
export interface ReportOptions { redact?: boolean }
export interface FindingLocation {
  readonly startOffset: number;
  readonly endOffset: number;
  readonly line: number;
  readonly column: number;
}
export interface FindingReport {
  ruleId: string;
  ruleName: string;
  visible: boolean;
  secret: string;
  confidence: Confidence;
  entropy: number;
  /** Lossless, opaque 16-character hexadecimal representation of a u64. */
  fingerprint: string;
  blobId: string;
  isBase64Encoded: boolean;
  captures: Record<string, string>;
  location: FindingLocation;
}
export class Finding {
  private constructor();
  readonly ruleId: string;
  readonly ruleName: string;
  readonly visible: boolean;
  readonly confidence: Confidence;
  readonly entropy: number;
  readonly fingerprint: string;
  readonly blobId: string;
  readonly isBase64Encoded: boolean;
  readonly location: FindingLocation;
  /** Explicit raw credential access; do not put this value in logs. */
  readonly secret: string;
  readonly captures: Record<string, string>;
  toObject(options?: ReportOptions): FindingReport;
  toJSON(): FindingReport;
  redacted(): Finding;
}
export class CancellationToken {
  constructor();
  readonly isCancelled: boolean;
  cancel(): void;
}
export interface RulesOptions extends OperationOptions {
  paths?: readonly string[];
  builtins?: boolean;
  confidence?: Confidence;
  /**
   * Opt in to retaining declared dependencies below `confidence`, transitively,
   * before rule compilation. Unrelated below-threshold rules remain excluded.
   * This affects detection only; use ValidationOptions.candidates to limit checks
   * and filter reports separately. Default false.
   */
  includeDependencies?: boolean;
  cache?: boolean;
  cacheDir?: string;
}
export interface RuleMetadata { id: string; name: string; visible: boolean; validation: boolean; revocation: boolean }
export interface RuleDefinition {
  id: string;
  name: string;
  pattern: string;
  detection_regex: string;
  depends_on_rule?: Array<{ rule_id: string; [field: string]: unknown } | null>;
  [field: string]: unknown;
}
export class Rules {
  private constructor();
  static load(options?: RulesOptions): Promise<Rules>;
  readonly length: number;
  readonly cacheStatus: 'loaded' | 'stored' | 'bypassed';
  metadata(): RuleMetadata[];
  detail(exactRuleId: string): RuleDefinition;
  resolve(selector: string): string[];
}
export interface DetectionPolicyOptions {
  inlineIgnores?: boolean;
  ignoreComments?: readonly string[];
  markupContext?: boolean;
  language?: 'html' | 'css';
  cliMatchSemantics?: boolean;
  base64MaxDepth?: number;
  base64MaxInputBytes?: number | null;
}
export class DetectionPolicy {
  constructor(options?: DetectionPolicyOptions);
  readonly inlineIgnores: boolean;
  readonly ignoreComments: readonly string[];
  readonly markupContext: boolean;
  readonly language: 'html' | 'css' | undefined;
  readonly cliMatchSemantics: boolean;
  readonly base64MaxDepth: number;
  readonly base64MaxInputBytes: number | undefined;
}
export interface ScannerOptions {
  rules?: Rules;
  policy?: DetectionPolicy | DetectionPolicyOptions | null;
  base64?: boolean;
  dedup?: boolean;
  redact?: boolean;
  minEntropy?: number;
  /** 64 MiB by default; null explicitly disables this per-input cap. */
  maxInputBytes?: number | null;
  /** Includes queued and executing calls; default 8. */
  maxPendingOperations?: number;
}
export interface ScanOptions extends OperationOptions { path?: string; attributes?: Readonly<Record<string, string>> }
export interface FileScanOptions extends OperationOptions {
  /** File scans always use the filesystem path; use scan(data, { path }) for logical paths. */
  path?: never;
  /** attributes.path, if supplied, must match the filesystem path. */
  attributes?: Readonly<Record<string, string>>;
}
export class Scanner implements AsyncDisposable {
  protected constructor();
  static create(options?: ScannerOptions): Promise<Scanner>;
  readonly rules: Rules;
  readonly policy: DetectionPolicy | null;
  scan(data: Data, options?: ScanOptions): Promise<Finding[]>;
  scanFile(path: string, options?: FileScanOptions): Promise<Finding[]>;
  scanInput(input: ScanInput, options?: OperationOptions): Promise<ScanResult>;
  scanInputs(inputs: Iterable<ScanInput> | AsyncIterable<ScanInput>, options?: OperationOptions): AsyncGenerator<ScanResult, void, unknown>;
  resetDedup(): void;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}
export class DetectionScanner extends Scanner {
  private constructor();
  static create(options?: ScannerOptions): Promise<DetectionScanner>;
}
export interface GitSignature {
  readonly name: string;
  readonly email: string;
  /** Decimal Unix seconds; a string preserves untrusted i64 timestamps exactly. */
  readonly timestamp: string;
  readonly timezoneOffset: number;
}
export interface GitCommit {
  readonly id: string;
  readonly author: GitSignature;
  readonly committer: GitSignature;
  readonly parents: readonly string[];
  readonly message: string;
}
/** Exactly one payload source is required; file inputs must retain their filesystem path. */
export type ScanInputOptions = {
  path: string;
  attributes?: Readonly<Record<string, string>>;
  repository?: string;
  commit?: string;
  blobId?: string;
  rawPath?: Uint8Array;
  origins?: readonly GitCommit[];
  staged?: boolean;
  unreachable?: boolean | null;
  extractionError?: string;
} & ({ data: Data; file?: never } | { file: string; data?: never });
export interface ScanInputReport {
  path: string;
  file?: string;
  repository?: string;
  commit?: string;
  blobId?: string;
  staged?: boolean;
  unreachable?: boolean | null;
  extractionError?: string;
  originIds: string[];
  hasData: boolean;
}
export class ScanInput {
  constructor(options: ScanInputOptions);
  static fromFile(path: string): ScanInput;
  readonly path: string;
  readonly file: string | undefined;
  /** Returns a copy, not the private input snapshot. */
  readonly data: Uint8Array | undefined;
  /** Byte length of in-memory `data` without copying it; `undefined` for file inputs. */
  readonly byteLength: number | undefined;
  readonly attributes: Readonly<Record<string, string>>;
  readonly repository: string | undefined;
  readonly commit: string | undefined;
  readonly blobId: string | undefined;
  readonly rawPath: Uint8Array | undefined;
  readonly origins: readonly GitCommit[];
  readonly staged: boolean | undefined;
  readonly unreachable: boolean | null | undefined;
  readonly extractionError: string | undefined;
  toJSON(): ScanInputReport;
}
export interface ScanResultReport { input: ScanInputReport; findings: FindingReport[] }
export class ScanResult {
  constructor(input: ScanInput, findings: readonly Finding[]);
  readonly input: ScanInput;
  readonly findings: readonly Finding[];
  toObject(options?: ReportOptions): ScanResultReport;
  toJSON(): ScanResultReport;
}
export interface InputIterator extends AsyncIterableIterator<ScanInput>, AsyncDisposable {
  return(): Promise<IteratorResult<ScanInput, undefined>>;
}
export interface FilesystemInputWarning { readonly path: string; readonly reason: 'walk_error' | 'ignore_error' }
export interface FilesystemOptions extends OperationOptions {
  gitignore?: boolean;
  hidden?: boolean;
  maxFileSize?: number | null;
  /** Enumeration continues after recoverable walk/ignore failures; defaults to a process warning. */
  onWarning?: (warning: FilesystemInputWarning) => void;
}
export interface GitInputWarning { readonly path: string; readonly blobId: string; readonly reason: 'oversized' | 'missing' }
export interface GitOptions extends OperationOptions {
  mode?: 'history' | 'snapshot' | 'diff' | 'staged';
  refs?: readonly string[] | null;
  sinceCommit?: string;
  sinceHours?: number;
  sinceTime?: number;
  untilTime?: number;
  branchRoot?: string;
  includeUnreachable?: boolean;
  discover?: boolean;
  maxBlobSize?: number | null;
  maxCommits?: number | null;
  maxInputs?: number | null;
  skipMissingBlobs?: boolean;
  onWarning?: (warning: GitInputWarning) => void;
}
export function filesystem(roots: readonly string[], options?: FilesystemOptions): InputIterator;
export function gitInputs(path: string, options?: GitOptions): InputIterator;
export function gitHistory(path: string, options?: Omit<GitOptions, 'mode'>): InputIterator;
export interface ArchiveOptions extends OperationOptions {
  /** Zero passes all sources through without opening files or applying archive caps. Default 1. */
  depth?: number;
  /** Applies to recognized archive inputs and cumulative extracted bytes, not ordinary pass-through sources. */
  maxBytes?: number;
  maxEntries?: number;
  tempDir?: string;
}
export interface ContentOptions extends OperationOptions { sqlite?: boolean; pyc?: boolean; pdf?: boolean; strict?: boolean; maxBytes?: number; tempDir?: string }
export function expandArchives(inputs: Iterable<ScanInput> | AsyncIterable<ScanInput>, options?: ArchiveOptions): AsyncGenerator<ScanInput, void, unknown>;
export function expandContent(inputs: Iterable<ScanInput> | AsyncIterable<ScanInput>, options?: ContentOptions): AsyncGenerator<ScanInput, void, unknown>;
export interface InputDiagnostic { readonly stage: string; readonly code: string; readonly variable: string | null; readonly ruleId: string | null }
export interface RevocationInputsReport { secret: string; variables: Record<string, string> }
export interface ResolvedCredentialReport {
  secret: string;
  variables: Record<string, string>;
  components: FindingReport[];
  revocation: RevocationInputsReport | null;
}
export interface ValidationReport {
  finding: FindingReport;
  outcome: ValidationOutcome;
  reason: string | null;
  httpStatus: number | null;
  revocationSupported: boolean;
  revocationReady: boolean;
  revocationReason: string | null;
  inputDiagnostics: InputDiagnostic[];
}
export class ValidationResult {
  private constructor();
  readonly finding: Finding;
  readonly outcome: ValidationOutcome;
  readonly reason: string | null;
  readonly httpStatus: number | null;
  readonly revocationSupported: boolean;
  readonly revocationReady: boolean;
  readonly revocationReason: string | null;
  readonly inputDiagnostics: readonly InputDiagnostic[];
  credential(options?: ReportOptions): ResolvedCredentialReport | null;
  toObject(options?: ReportOptions): ValidationReport;
  toJSON(): ValidationReport;
  /** Discards private analysis evidence and resolved action inputs in the copy. */
  redacted(): ValidationResult;
}
export interface ValidatorOptions {
  /** Per-check milliseconds; default 10,000. Zero disables native request deadlines. */
  timeoutMs?: number;
  concurrency?: number;
  retries?: number;
  maxResponseBytes?: number;
  allowInternalIps?: boolean;
  variables?: Readonly<Record<string, string>>;
  httpFallbacks?: boolean;
  maxPendingOperations?: number;
}
export interface ValidationOptions extends OperationOptions {
  /**
   * Validate only these unique original objects from `findings`, in this order.
   * Keep the complete same-input raw batch in `findings` for dependency resolution.
   * Helpers and other non-candidates are not independently validated. An empty
   * array performs no checks; omission preserves the default batch behavior.
   * Reports, redacted copies and findings from another batch cannot replace
   * the original objects from the supplied batch.
   *
   * Candidates are preflighted like `RevocationPlan.validate()`: a candidate with
   * a missing, ambiguous or unrenderable input is `skipped` before any provider
   * request, where whole-batch validation may still send the request. These are
   * original `Finding` objects, not `RevocationPlan.candidates` records.
   */
  candidates?: readonly Finding[];
}
export class Validator implements AsyncDisposable {
  constructor(options?: ValidatorOptions);
  withVariables(variables: Readonly<Record<string, string>>): Validator;
  /**
   * Explicit provider work; does not expand candidates to related providers.
   * @example
   * const candidates = findings.filter(finding => finding.visible && finding.confidence === 'high');
   * const results = await validator.validate(findings, { candidates });
   */
  validate(findings: readonly Finding[], options?: ValidationOptions): Promise<ValidationResult[]>;
  inspect(findings: readonly Finding[], options?: OperationOptions): Promise<InputDiagnostic[][]>;
  analyze(result: ValidationResult, options?: OperationOptions): Promise<unknown>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}
export interface RevokerOptions { rules?: Rules; timeoutMs?: number }
export interface PrepareOptions extends OperationOptions { provider?: string; path?: string; variables?: Readonly<Record<string, string>> }
export interface RevokeOptions extends OperationOptions { confirm: true }
export interface RevokeSecretOptions extends RevokeOptions { variables?: Readonly<Record<string, string>> }
export interface RevocationResult { ruleId: string; revoked: boolean; httpStatus: number | null }
export interface BatchRevocationResult {
  index: number;
  ruleId: string;
  outcome: 'revoked' | 'not_confirmed' | 'skipped' | 'duplicate' | 'failed' | 'unknown';
  reason?: string;
  duplicateOf?: number;
  result?: RevocationResult;
}
export interface RevocationCandidate {
  readonly finding: Finding;
  readonly validationSupported: boolean;
  readonly revocationSupported: boolean;
  readonly readyForValidation: boolean;
  readonly inputDiagnostics: readonly InputDiagnostic[];
}
export interface RevocationPlanReport {
  ruleIds: string[];
  candidateRuleIds: string[];
  sourcePath: string;
  candidates: Array<Omit<RevocationCandidate, 'finding'> & { finding: FindingReport }>;
}
export class RevocationPlan {
  private constructor();
  readonly ruleIds: readonly string[];
  readonly candidateRuleIds: readonly string[];
  readonly candidates: readonly RevocationCandidate[];
  readonly sourcePath: string;
  validate(validator?: Validator, options?: OperationOptions): Promise<ValidationResult[]>;
  toObject(options?: ReportOptions): RevocationPlanReport;
  toJSON(): RevocationPlanReport;
}
export class Revoker implements AsyncDisposable {
  private constructor();
  static create(options?: RevokerOptions): Promise<Revoker>;
  readonly rules: Rules;
  prepare(data: Data, options?: PrepareOptions): Promise<RevocationPlan>;
  prepareFromFile(path: string, options?: PrepareOptions): Promise<RevocationPlan>;
  revoke(result: ValidationResult, options: RevokeOptions): Promise<RevocationResult>;
  revokeSecret(exactRuleId: string, secret: string, options: RevokeSecretOptions): Promise<RevocationResult>;
  revokeMany(results: Iterable<ValidationResult>, options: RevokeOptions): Promise<BatchRevocationResult[]>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}
export class KingfisherError extends Error {
  constructor(message: string, code?: string, options?: ErrorOptions);
  code: string;
  outcomeUnknown?: boolean;
  completed?: readonly BatchRevocationResult[];
  pendingIndices?: readonly number[];
}
export class AbortError extends KingfisherError { constructor(message?: string, options?: ErrorOptions) }
export class TimeoutError extends KingfisherError { constructor(message?: string, options?: ErrorOptions) }
export function shannonEntropy(data: Data): number;

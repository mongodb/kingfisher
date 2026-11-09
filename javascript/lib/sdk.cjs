'use strict';

const { types } = require('node:util');
const { performance } = require('node:perf_hooks');
const { version } = require('../package.json');

const internal = Symbol('Kingfisher native ownership');
const inspectSymbol = Symbol.for('nodejs.util.inspect.custom');
const handles = new WeakMap();
const findingHandles = new WeakMap();
const validationHandles = new WeakMap();
const inputHandles = new WeakMap();
const tokenHandles = new WeakMap();
const planHandles = new WeakMap();
let addon;

function native() {
  if (!addon) {
    const loaded = require('../_native.cjs');
    if (loaded.sdkVersion() !== version) {
      throw new KingfisherError('Native binary and JavaScript SDK versions differ', 'ERR_KINGFISHER_VERSION');
    }
    addon = loaded;
  }
  return addon;
}

class KingfisherError extends Error {
  constructor(message, code = 'ERR_KINGFISHER_NATIVE', options) {
    super(message, options);
    this.name = 'KingfisherError';
    this.code = code;
  }
}
class AbortError extends KingfisherError {
  constructor(message = 'Operation cancelled', options) {
    super(message, 'ERR_KINGFISHER_CANCELLED', options);
    this.name = 'AbortError';
  }
}
class TimeoutError extends KingfisherError {
  constructor(message = 'Operation deadline exceeded', options) {
    super(message, 'ERR_KINGFISHER_TIMEOUT', options);
    this.name = 'TimeoutError';
  }
}

function translate(error, control, nativeFailure = false) {
  if (error instanceof KingfisherError || error instanceof TypeError || error instanceof RangeError) return error;
  const match = /^KF_([A-Z_]+): (.*)$/s.exec(error?.message ?? '');
  // Wrap untagged errors only at actual native invocations. Composition,
  // callbacks, iterators and addon loaders retain their original thrown values.
  if (!match) return nativeFailure ? new KingfisherError(error?.message ?? 'Native operation failed', 'ERR_KINGFISHER_NATIVE', { cause: error }) : error;
  const [_, code, message] = match;
  let result;
  if (code === 'CANCELLED' || code === 'REVOCATION_CANCELLED') result = control?.cancelled(error) ?? new AbortError(message, { cause: error });
  else if (code === 'TIMEOUT' || code === 'REVOCATION_TIMEOUT') result = new TimeoutError(message, { cause: error });
  else if (code === 'INVALID_ARGUMENT') result = new TypeError(message, { cause: error });
  else result = new KingfisherError(message, `ERR_KINGFISHER_${code}`, { cause: error });
  if (code.startsWith('REVOCATION_')) {
    result.outcomeUnknown = code !== 'REVOCATION_FAILED';
  }
  return result;
}

function object(value = {}, name = 'options') {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${name} must be an object`);
  return value;
}
function bool(value, fallback, name) {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') throw new TypeError(`${name} must be a boolean`);
  return value;
}
function string(value, name) {
  if (typeof value !== 'string') throw new TypeError(`${name} must be a string`);
  return value;
}
function strings(value, name) {
  if (!Array.isArray(value) || value.some(item => typeof item !== 'string')) throw new TypeError(`${name} must be an array of strings`);
  return [...value];
}
function integer(value, fallback, name, minimum = 0, maximum = 0xffffffff) {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new RangeError(`${name} must be an integer between ${minimum} and ${maximum}`);
  return value;
}
function nullableInteger(value, fallback, name, minimum = 0) {
  return value === null ? undefined : integer(value, fallback, name, minimum);
}
function timeout(value, fallback, allowZero = false) {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || (!allowZero && value === 0)) {
    throw new RangeError(`timeoutMs must be finite and ${allowZero ? 'nonnegative' : 'positive'}`);
  }
  return value;
}
function mapping(value = {}, name = 'variables') {
  object(value, name);
  const entries = Object.entries(value);
  if (entries.some(([_, value]) => typeof value !== 'string')) throw new TypeError(`${name} values must be strings`);
  return Object.fromEntries(entries);
}
function bytes(value) {
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  // A native Rust slice must not race writes from another JS worker. Callers
  // can explicitly copy shared data to an ordinary Buffer before submitting it.
  if (types.isUint8Array(value) && types.isSharedArrayBuffer(value.buffer)) {
    throw new TypeError('SharedArrayBuffer-backed inputs require an explicit non-shared copy');
  }
  if (Buffer.isBuffer(value)) return value;
  if (types.isUint8Array(value)) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  throw new TypeError('data must be a string, Buffer or Uint8Array');
}
function freeze(value) {
  if (value && typeof value === 'object' && !ArrayBuffer.isView(value)) {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}
function reportOptions(options) {
  object(options);
  return bool(options.redact, true, 'redact');
}

class CancellationToken {
  constructor() {
    tokenHandles.set(this, { native: new (native().NativeCancellationToken)(), listeners: new Set() });
    Object.freeze(this);
  }
  get isCancelled() { return tokenHandles.get(this).native.isCancelled; }
  cancel() {
    const state = tokenHandles.get(this);
    if (state.native.isCancelled) return;
    state.native.cancel();
    for (const listener of state.listeners) listener();
    state.listeners.clear();
  }
  [inspectSymbol]() { return { isCancelled: this.isCancelled }; }
}

function operationOptions(options = {}) {
  object(options);
  const timeoutMs = timeout(options.timeoutMs);
  const cancellation = options.cancellation;
  if (cancellation !== undefined && !(cancellation instanceof CancellationToken)) throw new TypeError('cancellation must be a CancellationToken');
  const signal = options.signal;
  if (signal !== undefined && (typeof signal?.aborted !== 'boolean' || typeof signal.addEventListener !== 'function' || typeof signal.removeEventListener !== 'function')) {
    throw new TypeError('signal must be an AbortSignal');
  }
  return { timeoutMs, cancellation, signal };
}
function scope(options = {}) {
  const { timeoutMs: milliseconds, cancellation, signal } = operationOptions(options);
  const deadline = milliseconds === undefined ? undefined : performance.now() + milliseconds;
  const token = new (native().NativeCancellationToken)();
  const cleanup = [];
  let abortReason;
  const abort = reason => {
    if (!token.isCancelled) abortReason = reason;
    token.cancel();
  };
  const cancelled = nativeError => {
    const ErrorClass = abortReason?.name === 'TimeoutError' ? TimeoutError : AbortError;
    const cause = abortReason === undefined ? nativeError : abortReason;
    const message = /^KF_REVOCATION_CANCELLED: (.*)$/s.exec(nativeError?.message ?? '')?.[1];
    return new ErrorClass(message, cause === undefined ? undefined : { cause });
  };
  if (cancellation !== undefined) {
    const source = tokenHandles.get(cancellation);
    source.listeners.add(abort);
    cleanup.push(() => source.listeners.delete(abort));
    if (source.native.isCancelled) abort();
  }
  if (signal !== undefined) {
    const signalAbort = () => abort(signal.reason);
    signal.addEventListener('abort', signalAbort, { once: true });
    cleanup.push(() => signal.removeEventListener('abort', signalAbort));
    if (signal.aborted) signalAbort();
  }
  return {
    token,
    abort,
    cancelled,
    remaining() {
      if (token.isCancelled) throw cancelled();
      if (deadline === undefined) return undefined;
      const remaining = deadline - performance.now();
      if (remaining <= 0) throw new TimeoutError();
      return remaining;
    },
    dispose() { cleanup.splice(0).forEach(dispose => dispose()); },
  };
}

// Translate only actual native invocations. Composition, callbacks, iterators
// and addon-loader errors must retain their original thrown values.
function nativeCall(execute, control) {
  try {
    const result = execute();
    return result instanceof Promise ? result.catch(error => { throw translate(error, control, true); }) : result;
  } catch (error) { throw translate(error, control, true); }
}

function owner(value, nativeValue, maxPending = 8) {
  handles.set(value, { native: nativeValue, active: new Map(), closed: false, maxPending });
}
function state(value) {
  const result = handles.get(value);
  if (!result || result.closed) throw new KingfisherError('Object is closed', 'ERR_KINGFISHER_CLOSED');
  return result;
}
function operation(value, options, execute, nativeBoundary = true) {
  const current = state(value);
  if (current.active.size >= current.maxPending) throw new KingfisherError('Too many pending operations; bound caller concurrency', 'ERR_KINGFISHER_BUSY');
  const control = scope(options);
  let promise;
  try {
    // Invoke synchronously: native buffer snapshots must happen before returning
    // control to a caller that can mutate its Buffer or Uint8Array.
    promise = Promise.resolve(nativeBoundary ? nativeCall(() => execute(current.native, control), control) : execute(current.native, control));
  } catch (error) {
    control.dispose();
    throw error;
  }
  const result = promise.finally(() => {
    current.active.delete(control);
    control.dispose();
  });
  current.active.set(control, result);
  return result;
}
async function close(value) {
  const current = handles.get(value);
  if (!current) return;
  current.closed = true;
  for (const control of current.active.keys()) control.abort();
  await Promise.allSettled([...current.active.values()]);
  current.native = undefined;
}

class Rules {
  constructor(key, value) {
    if (key !== internal) throw new TypeError('Use Rules.load()');
    owner(this, value);
    Object.freeze(this);
  }
  static async load(options = {}) {
    object(options);
    const paths = strings(options.paths ?? [], 'paths');
    const confidence = options.confidence ?? 'medium';
    if (!['low', 'medium', 'high'].includes(confidence)) throw new RangeError('confidence must be low, medium or high');
    const configuration = {
      paths, confidence,
      includeDependencies: bool(options.includeDependencies, false, 'includeDependencies'),
      builtins: bool(options.builtins, true, 'builtins'),
      cache: bool(options.cache, true, 'cache'),
      cacheDir: options.cacheDir === undefined ? undefined : string(options.cacheDir, 'cacheDir'),
    };
    const api = native();
    const control = scope(options);
    try {
      return new Rules(internal, await nativeCall(() => api.loadRules(configuration, control.remaining(), control.token), control));
    }
    finally { control.dispose(); }
  }
  get length() { return state(this).native.length; }
  get cacheStatus() { return state(this).native.cacheStatus; }
  metadata() { return state(this).native.metadata(); }
  detail(ruleId) {
    const id = string(ruleId, 'ruleId');
    return nativeCall(() => state(this).native.detail(id));
  }
  resolve(selector) {
    string(selector, 'selector');
    if (!selector || selector !== selector.trim()) throw new RangeError('selector must be nonempty without surrounding whitespace');
    const metadata = this.metadata();
    if (metadata.some(rule => rule.id === selector)) return [selector];
    const name = selector.toLowerCase();
    const named = metadata.filter(rule => rule.name.toLowerCase() === name).map(rule => rule.id).sort();
    if (named.length > 1) throw new RangeError('Ambiguous rule name; use an exact rule ID');
    if (named.length) return named;
    const unqualified = id => id.replace(/^(betterleaks\.|custom\.|kingfisher\.|veles\.secrets\/)/, '');
    const matches = id => [id, unqualified(id)].some(value => {
      value = value.toLowerCase();
      return value === name || value.startsWith(name) && ['.', '-', '/'].includes(value[name.length]);
    });
    const selected = metadata.filter(rule => matches(rule.id)).map(rule => rule.id).sort();
    if (!selected.length) throw new RangeError('Unknown rule selector');
    return selected;
  }
  [inspectSymbol]() { return { rules: this.length, cacheStatus: this.cacheStatus }; }
}

class DetectionPolicy {
  constructor(options = {}) {
    object(options);
    this.inlineIgnores = bool(options.inlineIgnores, true, 'inlineIgnores');
    this.ignoreComments = Object.freeze(strings(options.ignoreComments ?? [], 'ignoreComments'));
    this.markupContext = bool(options.markupContext, true, 'markupContext');
    this.language = options.language ?? undefined;
    if (this.language !== undefined && !['html', 'css'].includes(this.language)) throw new RangeError('language must be html or css');
    this.cliMatchSemantics = bool(options.cliMatchSemantics, true, 'cliMatchSemantics');
    this.base64MaxDepth = integer(options.base64MaxDepth, 2, 'base64MaxDepth', 0, 32);
    this.base64MaxInputBytes = nullableInteger(options.base64MaxInputBytes, 64 * 1024 * 1024, 'base64MaxInputBytes');
    Object.freeze(this);
  }
}

function finding(value) { return new Finding(internal, value); }
class Finding {
  constructor(key, value) {
    if (key !== internal) throw new TypeError('Findings are returned by Scanner');
    findingHandles.set(this, { native: value, metadata: freeze(value.toObject(true)) });
    Object.freeze(this);
  }
  get ruleId() { return findingHandles.get(this).metadata.ruleId; }
  get ruleName() { return findingHandles.get(this).metadata.ruleName; }
  get visible() { return findingHandles.get(this).metadata.visible; }
  get confidence() { return findingHandles.get(this).metadata.confidence; }
  get entropy() { return findingHandles.get(this).metadata.entropy; }
  get fingerprint() { return findingHandles.get(this).metadata.fingerprint; }
  get blobId() { return findingHandles.get(this).metadata.blobId; }
  get isBase64Encoded() { return findingHandles.get(this).metadata.isBase64Encoded; }
  get location() { return findingHandles.get(this).metadata.location; }
  get secret() { return findingHandles.get(this).native.secret; }
  get captures() { return findingHandles.get(this).native.captures; }
  toObject(options = {}) { return findingHandles.get(this).native.toObject(reportOptions(options)); }
  toJSON() { return this.toObject(); }
  redacted() { return finding(findingHandles.get(this).native.redacted()); }
  [inspectSymbol]() { return this.toJSON(); }
}
function nativeFindings(values) {
  if (!Array.isArray(values) || values.some(value => !findingHandles.has(value))) throw new TypeError('findings must be original Finding objects from one input');
  return values.map(value => findingHandles.get(value).native);
}

class Scanner {
  constructor(key, value, rules, configuration, maxPending) {
    if (key !== internal) throw new TypeError('Use Scanner.create()');
    owner(this, value, maxPending);
    this.rules = rules;
    this.policy = configuration.policy ?? null;
    Object.freeze(this);
  }
  static async create(options = {}) {
    object(options);
    if (options.rules !== undefined && !(options.rules instanceof Rules)) throw new TypeError('rules must be a Rules instance');
    const policy = options.policy === undefined || options.policy === null ? undefined :
      options.policy instanceof DetectionPolicy ? options.policy : new DetectionPolicy(options.policy);
    const minEntropy = options.minEntropy;
    if (minEntropy !== undefined && (typeof minEntropy !== 'number' || !Number.isFinite(minEntropy) || minEntropy < 0 || minEntropy > 8)) throw new RangeError('minEntropy must be between 0 and 8');
    const maxPending = integer(options.maxPendingOperations, 8, 'maxPendingOperations', 1);
    const configuration = {
      policy, minEntropy,
      base64: bool(options.base64, true, 'base64'),
      dedup: bool(options.dedup, false, 'dedup'),
      redact: bool(options.redact, false, 'redact'),
      maxInputBytes: nullableInteger(options.maxInputBytes, 64 * 1024 * 1024, 'maxInputBytes'),
    };
    const rules = options.rules ?? await Rules.load();
    const NativeScanner = native().NativeScanner;
    const value = nativeCall(() => new NativeScanner(state(rules).native, configuration));
    return new this(internal, value, rules, configuration, maxPending);
  }
  async scan(data, options = {}) {
    object(options);
    const input = bytes(data);
    const attributes = mapping(options.attributes, 'attributes');
    const path = string(options.path ?? attributes.path ?? '', 'path');
    const values = await operation(this, options, (value, control) =>
      value.scan(input, path, attributes, false, control.remaining(), control.token));
    return values.map(finding);
  }
  async scanFile(path, options = {}) {
    string(path, 'path');
    object(options);
    if (options.path !== undefined) throw new TypeError('scanFile does not accept options.path; use scan(data, { path }) for a logical path');
    const attributes = mapping(options.attributes, 'attributes');
    if (attributes.path !== undefined && attributes.path !== path) throw new TypeError('scanFile attributes.path must match the filesystem path');
    const values = await operation(this, options, (value, control) =>
      value.scanFile(path, attributes, false, control.remaining(), control.token));
    return values.map(finding);
  }
  async scanInput(input, options = {}) {
    if (!(input instanceof ScanInput)) throw new TypeError('input must be a ScanInput');
    const source = inputHandles.get(input);
    const findings = source.file === undefined ?
      await this.scan(source.data, { ...options, path: source.path, attributes: source.attributes }) :
      await this.scanFile(source.file, { ...options, attributes: source.attributes });
    return new ScanResult(input, findings);
  }
  async *scanInputs(inputs, options = {}) {
    if (!inputs || typeof inputs === 'string' || !(Symbol.iterator in Object(inputs) || Symbol.asyncIterator in Object(inputs))) throw new TypeError('inputs must be an iterable or async iterable');
    const control = scope(options);
    try {
      control.remaining();
      for await (const input of inputs) {
        yield await this.scanInput(input, { ...options, timeoutMs: control.remaining() });
        // Consumer time counts, and an expired operation must not pull another input.
        control.remaining();
      }
      control.remaining();
    } finally { control.dispose(); }
  }
  resetDedup() {
    const current = state(this);
    if (current.active.size) throw new KingfisherError('Finish scans before resetting deduplication', 'ERR_KINGFISHER_BUSY');
    current.native.resetDedup();
  }
  async close() { await close(this); }
  async [Symbol.asyncDispose]() { await this.close(); }
  [inspectSymbol]() { return { scanner: this.constructor.name, policy: this.policy, closed: handles.get(this).closed }; }
}
class DetectionScanner extends Scanner {
  static async create(options = {}) {
    return super.create({ ...object(options), policy: options.policy ?? new DetectionPolicy() });
  }
}

class ScanInput {
  constructor(options, key) {
    object(options, 'input');
    const path = string(options.path, 'path');
    if ((options.data === undefined) === (options.file === undefined)) throw new TypeError('provide exactly one of data or file');
    const file = options.file === undefined ? undefined : string(options.file, 'file');
    if (file !== undefined && path !== file) throw new RangeError('file inputs must retain their filesystem path; use data for logical paths');
    inputHandles.set(this, {
      ...options, path, file,
      data: options.data === undefined ? undefined : key === internal ? bytes(options.data) : Buffer.from(bytes(options.data)),
      attributes: freeze(mapping(options.attributes, 'attributes')),
      rawPath: options.rawPath === undefined ? undefined : Buffer.from(bytes(options.rawPath)),
      origins: key === internal ? options.origins ?? [] : freeze(structuredClone(options.origins ?? [])),
    });
    Object.freeze(this);
  }
  static fromFile(path) { return new ScanInput({ path: string(path, 'path'), file: path }); }
  get path() { return inputHandles.get(this).path; }
  get file() { return inputHandles.get(this).file; }
  get data() { const value = inputHandles.get(this).data; return value === undefined ? undefined : Buffer.from(value); }
  get byteLength() { return inputHandles.get(this).data?.byteLength; }
  get attributes() { return inputHandles.get(this).attributes; }
  get repository() { return inputHandles.get(this).repository; }
  get commit() { return inputHandles.get(this).commit; }
  get blobId() { return inputHandles.get(this).blobId; }
  get rawPath() { const value = inputHandles.get(this).rawPath; return value === undefined ? undefined : Buffer.from(value); }
  get origins() { return inputHandles.get(this).origins; }
  get staged() { return inputHandles.get(this).staged; }
  get unreachable() { return inputHandles.get(this).unreachable; }
  get extractionError() { return inputHandles.get(this).extractionError; }
  toJSON() {
    const source = inputHandles.get(this);
    return { path: source.path, file: source.file, repository: source.repository,
      commit: source.commit, blobId: source.blobId, staged: source.staged,
      unreachable: source.unreachable, extractionError: source.extractionError,
      originIds: source.origins.map(origin => origin.id), hasData: source.data !== undefined };
  }
  [inspectSymbol]() { return this.toJSON(); }
}
class ScanResult {
  constructor(input, findings) {
    if (!(input instanceof ScanInput)) throw new TypeError('input must be a ScanInput');
    nativeFindings(findings);
    this.input = input;
    this.findings = Object.freeze([...findings]);
    Object.freeze(this);
  }
  toObject(options = {}) {
    const redact = reportOptions(options);
    return { input: this.input.toJSON(), findings: this.findings.map(value => value.toObject({ redact })) };
  }
  toJSON() { return this.toObject(); }
  [inspectSymbol]() { return this.toJSON(); }
}

class ValidationResult {
  constructor(key, value) {
    if (key !== internal) throw new TypeError('Results are returned by Validator');
    validationHandles.set(this, { native: value, metadata: freeze(value.toObject(true)), finding: finding(value.finding) });
    Object.freeze(this);
  }
  get finding() { return validationHandles.get(this).finding; }
  get outcome() { return validationHandles.get(this).metadata.outcome; }
  get reason() { return validationHandles.get(this).metadata.reason; }
  get httpStatus() { return validationHandles.get(this).metadata.httpStatus; }
  get revocationSupported() { return validationHandles.get(this).metadata.revocationSupported; }
  get revocationReady() { return validationHandles.get(this).metadata.revocationReady; }
  get revocationReason() { return validationHandles.get(this).metadata.revocationReason ?? (this.revocationReady ? null : 'unresolved_inputs'); }
  get inputDiagnostics() { return validationHandles.get(this).metadata.inputDiagnostics; }
  credential(options = {}) { return validationHandles.get(this).native.credential(reportOptions(options)); }
  toObject(options = {}) { return validationHandles.get(this).native.toObject(reportOptions(options)); }
  toJSON() { return this.toObject(); }
  redacted() { return new ValidationResult(internal, validationHandles.get(this).native.redacted()); }
  [inspectSymbol]() { return this.toJSON(); }
}

class Validator {
  constructor(options = {}, key, value) {
    object(options);
    const configuration = {
      timeoutMs: timeout(options.timeoutMs, 10_000, true),
      concurrency: integer(options.concurrency, 8, 'concurrency', 1),
      retries: integer(options.retries, 0, 'retries'),
      maxResponseBytes: integer(options.maxResponseBytes, 1024 * 1024, 'maxResponseBytes'),
      allowInternalIps: bool(options.allowInternalIps, false, 'allowInternalIps'),
      httpFallbacks: bool(options.httpFallbacks, false, 'httpFallbacks'),
      variables: mapping(options.variables),
    };
    const maxPending = integer(options.maxPendingOperations, 8, 'maxPendingOperations', 1);
    const NativeValidator = key === internal ? undefined : native().NativeValidator;
    owner(this, key === internal ? value : nativeCall(() => new NativeValidator(configuration)), maxPending);
    Object.freeze(this);
  }
  withVariables(variables) {
    const values = mapping(variables);
    return new Validator({ maxPendingOperations: state(this).maxPending }, internal, nativeCall(() => state(this).native.withVariables(values)));
  }
  async validate(findings, options = {}) {
    object(options);
    // Snapshot both arrays before native work, retaining all raw helpers even
    // when the caller explicitly limits which findings may contact providers.
    const batch = Array.isArray(findings) ? Array.from(findings) : findings;
    const values = nativeFindings(batch);
    const candidates = options.candidates;
    let indices;
    if (candidates !== undefined) {
      if (!Array.isArray(candidates)) throw new TypeError('candidates must be an array of original Finding objects');
      const membership = new Map(batch.map((value, index) => [value, index]));
      const selected = new Set();
      indices = Array.from(candidates, candidate => {
        if (!findingHandles.has(candidate)) throw new TypeError('candidates must contain original Finding objects');
        if (!membership.has(candidate)) throw new TypeError('candidates must be original members of findings');
        if (selected.has(candidate)) throw new TypeError('candidates must not contain duplicates');
        selected.add(candidate);
        return membership.get(candidate);
      });
    }
    const results = await operation(this, options, (value, control) =>
      value.validate(values, indices, control.remaining(), control.token));
    return results.map(value => new ValidationResult(internal, value));
  }
  async inspect(findings, options = {}) {
    const values = nativeFindings(findings);
    return await operation(this, options, (value, control) => value.inspect(values, control.remaining(), control.token));
  }
  async analyze(result, options = {}) {
    if (!validationHandles.has(result)) throw new TypeError('result must be an original ValidationResult');
    return await operation(this, options, (value, control) =>
      value.analyze(validationHandles.get(result).native, control.remaining(), control.token));
  }
  async close() { await close(this); }
  async [Symbol.asyncDispose]() { await this.close(); }
  [inspectSymbol]() { return { validator: true, closed: handles.get(this).closed }; }
}

class RevocationPlan {
  constructor(key, data) {
    if (key !== internal) throw new TypeError('Use Revoker.prepare()');
    planHandles.set(this, data);
    this.ruleIds = Object.freeze([...data.ruleIds]);
    this.candidateRuleIds = Object.freeze([...data.candidateRuleIds]);
    this.candidates = Object.freeze(data.candidates.map(candidate => Object.freeze(candidate)));
    this.sourcePath = data.sourcePath;
    Object.freeze(this);
  }
  async validate(validator, options = {}) {
    const owned = validator === undefined;
    validator ??= new Validator();
    if (!(validator instanceof Validator)) throw new TypeError('validator must be a Validator');
    const plan = planHandles.get(this);
    try {
      const values = nativeFindings(plan.findings);
      const results = await operation(validator, options, (value, control) => {
        // Track the call on the caller's validator even with per-plan variables,
        // so its pending-work limit and close() still cover this operation.
        const execution = Object.keys(plan.variables).length ? value.withVariables(plan.variables) : value;
        return execution.validate(values, plan.indices, control.remaining(), control.token);
      });
      return results.map(value => new ValidationResult(internal, value));
    } finally {
      if (owned) await validator.close();
    }
  }
  toObject(options = {}) {
    const redact = reportOptions(options);
    return { ruleIds: [...this.ruleIds], candidateRuleIds: [...this.candidateRuleIds], sourcePath: this.sourcePath,
      candidates: this.candidates.map(candidate => ({ ...candidate, finding: candidate.finding.toObject({ redact }) })) };
  }
  toJSON() { return this.toObject(); }
  [inspectSymbol]() { return this.toJSON(); }
}

class Revoker {
  constructor(key, value, rules) {
    if (key !== internal) throw new TypeError('Use Revoker.create()');
    owner(this, value);
    this.rules = rules;
    const current = handles.get(this);
    current.scanner = undefined;
    current.inspector = new Validator();
    Object.freeze(this);
  }
  static async create(options = {}) {
    object(options);
    if (options.rules !== undefined && !(options.rules instanceof Rules)) throw new TypeError('rules must be a Rules instance');
    const milliseconds = timeout(options.timeoutMs, 10_000);
    const rules = options.rules ?? await Rules.load();
    const NativeRevoker = native().NativeRevoker;
    return new Revoker(internal, nativeCall(() => new NativeRevoker(state(rules).native, milliseconds)), rules);
  }
  async prepare(data, options = {}) { return await this._prepare(Buffer.from(bytes(data)), undefined, options); }
  async prepareFromFile(path, options = {}) { return await this._prepare(undefined, string(path, 'path'), options); }
  async _prepare(data, file, options) {
    object(options);
    const current = state(this);
    const variables = mapping(options.variables);
    const selected = new Set(options.provider === undefined ? this.rules.metadata().map(rule => rule.id) : this.rules.resolve(options.provider));
    const metadata = new Map(this.rules.metadata().map(rule => [rule.id, rule]));
    const sourcePath = file ?? string(options.path ?? '', 'path');
    return await operation(this, options, async (_, control) => {
      let inspector;
      try {
        if (!current.scanner) {
          const pending = Scanner.create({ rules: this.rules });
          current.scanner = pending;
          pending.catch(() => { if (current.scanner === pending) current.scanner = undefined; });
        }
        const preparedScanner = await current.scanner;
        // close() cancels in-flight preparation, then waits for it before
        // releasing the shared scanner. Never submit work after that cancel.
        control.remaining();
        const scanner = state(preparedScanner).native;
        const raw = file === undefined ?
          await nativeCall(() => scanner.scan(data, sourcePath, {}, true, control.remaining(), control.token), control) :
          await nativeCall(() => scanner.scanFile(file, {}, true, control.remaining(), control.token), control);
        const all = raw.map(finding);
        const required = new Set(all.filter(value => value.visible && selected.has(value.ruleId)).map(value => value.ruleId));
        const pending = [...required];
        while (pending.length) {
          for (const dependency of this.rules.detail(pending.pop()).depends_on_rule ?? []) {
            if (dependency && !required.has(dependency.rule_id)) { required.add(dependency.rule_id); pending.push(dependency.rule_id); }
          }
        }
        const retained = all.filter(value => required.has(value.ruleId));
        inspector = current.inspector.withVariables(variables);
        const values = nativeFindings(retained);
        const diagnostics = await nativeCall(() => state(inspector).native.inspect(values, control.remaining(), control.token), control);
        const candidates = [];
        const indices = [];
        const candidateRuleIds = new Set();
        retained.forEach((value, index) => {
          if (!value.visible || !selected.has(value.ruleId)) return;
          const rule = metadata.get(value.ruleId);
          if (rule.revocation) { indices.push(index); candidateRuleIds.add(value.ruleId); }
          candidates.push({ finding: value, validationSupported: rule.validation, revocationSupported: rule.revocation,
            readyForValidation: rule.validation && !diagnostics[index].some(issue => issue.stage !== 'revocation'),
            inputDiagnostics: freeze(diagnostics[index]) });
        });
        control.remaining();
        return new RevocationPlan(internal, { ruleIds: [...selected].sort(), candidateRuleIds: [...candidateRuleIds].sort(),
          candidates, findings: retained, indices, variables, sourcePath });
      } finally { if (inspector) await inspector.close(); }
    }, false);
  }
  async revoke(result, options = {}) {
    object(options);
    if (options.confirm !== true) throw new TypeError('revocation requires confirm=true');
    if (!validationHandles.has(result)) throw new TypeError('result must be an original ValidationResult; JSON reports cannot authorize revocation');
    return await operation(this, options, (value, control) =>
      value.revokeValidated(validationHandles.get(result).native, true, control.remaining(), control.token));
  }
  async revokeSecret(ruleId, secret, options = {}) {
    object(options);
    if (options.confirm !== true) throw new TypeError('revocation requires confirm=true');
    const variables = mapping(options.variables);
    return await operation(this, options, (value, control) =>
      value.revokeSecret(string(ruleId, 'ruleId'), string(secret, 'secret'), variables, true, control.remaining(), control.token));
  }
  async revokeMany(results, options = {}) {
    object(options);
    if (options.confirm !== true) throw new TypeError('revocation requires confirm=true');
    const values = Array.from(results);
    if (values.some(value => !validationHandles.has(value))) throw new TypeError('results must contain original ValidationResult objects');
    const completed = [];
    const attempted = new Map();
    return await operation(this, options, async (nativeValue, control) => {
      for (let index = 0; index < values.length; index++) {
        const result = values[index];
        const ruleId = result.finding.ruleId;
        try {
          control.remaining();
          if (!result.revocationReady) {
            completed.push({ index, ruleId, outcome: 'skipped', reason: result.revocationReason });
            continue;
          }
          const previous = attempted.get(ruleId) ?? [];
          const duplicate = nativeCall(() => previous.find(other =>
            validationHandles.get(result).native.sameRevocationAs(validationHandles.get(values[other]).native)), control);
          if (duplicate !== undefined) {
            completed.push({ index, ruleId, outcome: 'duplicate', duplicateOf: duplicate });
            continue;
          }
          previous.push(index);
          attempted.set(ruleId, previous);
          const response = await nativeCall(() => nativeValue.revokeValidated(validationHandles.get(result).native, true, control.remaining(), control.token), control);
          completed.push({ index, ruleId, outcome: response.revoked ? 'revoked' : 'not_confirmed', result: response });
        } catch (error) {
          error = translate(error, control);
          if (error instanceof AbortError || error instanceof TimeoutError) {
            if (error.outcomeUnknown) completed.push({ index, ruleId, outcome: 'unknown', reason: error.code });
            error.completed = Object.freeze([...completed]);
            error.pendingIndices = Object.freeze(Array.from({ length: values.length - index - (error.outcomeUnknown ? 1 : 0) }, (_, offset) => index + offset + (error.outcomeUnknown ? 1 : 0)));
            throw error;
          }
          completed.push({ index, ruleId, outcome: error.outcomeUnknown ? 'unknown' : 'failed', reason: error.code ?? 'invalid_inputs' });
        }
      }
      return completed;
    }, false);
  }
  async close() {
    const current = handles.get(this);
    await close(this);
    const scanner = await current.scanner?.catch(() => undefined);
    await scanner?.close();
    await current.inspector.close();
  }
  async [Symbol.asyncDispose]() { await this.close(); }
  [inspectSymbol]() { return { revoker: true, closed: handles.get(this).closed }; }
}

function shannonEntropy(data) {
  const input = bytes(data);
  const api = native();
  return nativeCall(() => api.shannonEntropy(input));
}

function inputIterator(initialize, options, convert) {
  let closed = false;
  let busy = false;
  let initial;
  let control;
  let pending;
  let closing;
  const start = () => {
    if (!initial) {
      control = scope(options);
      initial = (async () => {
        return await nativeCall(() => initialize(control), control);
      })();
      initial.catch(() => {});
    }
    return initial;
  };
  const iterator = {
    [Symbol.asyncIterator]() { return this; },
    async next() {
      if (closed) return { done: true, value: undefined };
      if (busy) throw new KingfisherError('Call next() sequentially', 'ERR_KINGFISHER_BUSY');
      busy = true;
      try {
        const cursor = await start();
        while (!closed) {
          control.remaining();
          let value;
          try {
            pending = nativeCall(() => cursor.next(), control);
            value = await pending;
          } catch (error) { throw translate(error, control); }
          pending = undefined;
          if (closed) return { done: true, value: undefined };
          control.remaining();
          if (value == null) { await iterator.return(); return { done: true, value: undefined }; }
          const input = convert(value);
          // Warning callbacks are user code and may abort or consume the rest
          // of the deadline. Do not yield that entry as a successful next().
          control.remaining();
          if (input !== undefined) return { done: false, value: input };
        }
        return { done: true, value: undefined };
      } catch (error) {
        pending = undefined;
        await iterator.return();
        // Conversion includes caller callbacks: preserve their thrown values,
        // even when an Error message resembles a tagged native failure.
        throw error;
      } finally { busy = false; }
    },
    async return() {
      if (closing) return await closing;
      closed = true;
      control?.abort();
      closing = (async () => {
        const cursor = await initial?.catch(() => undefined);
        cursor?.close();
        await pending?.catch(() => {});
        control?.dispose();
        return { done: true, value: undefined };
      })();
      return await closing;
    },
    async [Symbol.asyncDispose]() { await iterator.return(); },
    [inspectSymbol]() { return { inputIterator: true, closed }; },
  };
  return iterator;
}

function filesystem(roots, options = {}) {
  object(options);
  const configuration = {
    roots: strings(roots, 'roots'), gitignore: bool(options.gitignore, true, 'gitignore'),
    hidden: bool(options.hidden, false, 'hidden'),
    maxFileSize: nullableInteger(options.maxFileSize, undefined, 'maxFileSize'),
  };
  if (!configuration.roots.length) throw new RangeError('at least one filesystem root is required');
  if (options.onWarning !== undefined && typeof options.onWarning !== 'function') throw new TypeError('onWarning must be a function');
  const onWarning = options.onWarning;
  return inputIterator(control => native().filesystemInputs(configuration, control.remaining(), control.token), operationOptions(options), value => {
    if (value.skipped) {
      const warning = freeze({ path: value.path, reason: value.skipped });
      if (onWarning) onWarning(warning);
      else process.emitWarning(`Filesystem enumeration incomplete (${warning.reason}) at ${JSON.stringify(warning.path)}`, { type: 'KingfisherFilesystemWarning' });
    }
    return value.file == null ? undefined : ScanInput.fromFile(value.file);
  });
}

function gitInputs(path, options = {}) {
  object(options);
  const signedTime = (value, name) => {
    if (value === undefined) return undefined;
    if (!Number.isSafeInteger(value)) throw new RangeError(`${name} must be an exact integer Unix timestamp`);
    return value;
  };
  const mode = options.mode ?? 'history';
  if (!['history', 'snapshot', 'diff', 'staged'].includes(mode)) throw new RangeError('mode must be history, snapshot, diff or staged');
  if (options.sinceHours !== undefined && (typeof options.sinceHours !== 'number' || !Number.isFinite(options.sinceHours) || options.sinceHours < 0)) throw new RangeError('sinceHours must be finite and nonnegative');
  if (options.onWarning !== undefined && typeof options.onWarning !== 'function') throw new TypeError('onWarning must be a function');
  const configuration = {
    path: string(path, 'path'), mode,
    refs: options.refs === null ? undefined : strings(options.refs ?? ['HEAD'], 'refs'),
    sinceCommit: options.sinceCommit === undefined ? undefined : string(options.sinceCommit, 'sinceCommit'),
    sinceHours: options.sinceHours,
    sinceTime: signedTime(options.sinceTime, 'sinceTime'), untilTime: signedTime(options.untilTime, 'untilTime'),
    branchRoot: options.branchRoot === undefined ? undefined : string(options.branchRoot, 'branchRoot'),
    includeUnreachable: bool(options.includeUnreachable, false, 'includeUnreachable'),
    discover: bool(options.discover, true, 'discover'),
    maxBlobSize: nullableInteger(options.maxBlobSize, undefined, 'maxBlobSize'),
    maxCommits: nullableInteger(options.maxCommits, undefined, 'maxCommits', 1),
    maxInputs: nullableInteger(options.maxInputs, undefined, 'maxInputs', 1),
    skipMissingBlobs: bool(options.skipMissingBlobs, false, 'skipMissingBlobs'),
  };
  const onWarning = options.onWarning;
  const commits = new Map();
  return inputIterator(control => native().gitInputs(configuration, control.remaining(), control.token), operationOptions(options), value => {
      if (value.skipped) {
        const warning = freeze({ path: value.path, blobId: value.metadata.blobId, reason: value.skipped });
        if (onWarning) onWarning(warning);
        else process.emitWarning(`Git input skipped (${warning.reason}) at ${JSON.stringify(warning.path)}; scan coverage is incomplete`, { type: 'KingfisherGitWarning' });
        return undefined;
      }
      const origins = Object.freeze((value.metadata.origins ?? []).map(origin => {
        if (!commits.has(origin.id)) commits.set(origin.id, freeze(origin));
        return commits.get(origin.id);
      }));
      return new ScanInput({ path: value.path, data: value.data, rawPath: value.rawPath,
        attributes: value.attributes, repository: path, commit: origins[0]?.id,
        blobId: value.metadata.blobId, origins, staged: value.metadata.staged,
        unreachable: value.metadata.unreachable }, internal);
  });
}
function gitHistory(path, options = {}) { return gitInputs(path, { ...object(options), mode: 'history' }); }

function iterable(inputs) {
  if (!inputs || typeof inputs === 'string' || !(Symbol.iterator in Object(inputs) || Symbol.asyncIterator in Object(inputs))) throw new TypeError('inputs must be an iterable or async iterable');
}
function replaceInput(source, changes) {
  return new ScanInput({ ...inputHandles.get(source), ...changes }, internal);
}
function expandArchives(inputs, options = {}) {
  iterable(inputs);
  object(options);
  const depth = integer(options.depth, 1, 'depth', 0, 32);
  const maxBytes = integer(options.maxBytes, 256 * 1024 * 1024, 'maxBytes', 1);
  const maxEntries = integer(options.maxEntries, 10_000, 'maxEntries', 1);
  const tempDir = options.tempDir === undefined ? undefined : string(options.tempDir, 'tempDir');
  return (async function* () {
    const control = scope(options);
    try {
      control.remaining();
      for await (const source of inputs) {
        if (!(source instanceof ScanInput)) throw new TypeError('inputs must contain ScanInput objects');
        const original = inputHandles.get(source);
        const pending = [{ path: source.path, data: original.data, file: original.file, depth, root: true }];
        const output = [];
        let usedBytes = 0;
        let usedEntries = 0;
        while (pending.length) {
          const current = pending.pop();
          control.remaining();
          if (current.depth === 0) {
            output.push(current.root ? source : replaceInput(source, { path: current.path, data: current.data, file: current.file }));
            continue;
          }
          let expansion;
          try {
            expansion = await nativeCall(() => native().expandArchiveOnce(current.path, current.data, current.file,
              { expand: current.depth > 0, maxInputBytes: maxBytes, maxBytes: maxBytes - usedBytes,
                maxEntries: maxEntries - usedEntries, tempDir }, control.remaining(), control.token), control);
          } catch (error) { throw translate(error, control); }
          if (expansion.expanded) {
            usedBytes += expansion.items.reduce((total, item) => total + item.data.length, 0);
            usedEntries += expansion.inspectedEntries;
            if (usedBytes > maxBytes || usedEntries > maxEntries) throw new KingfisherError('Archive root exceeds its cumulative budget', 'ERR_KINGFISHER_LIMIT');
            for (const item of [...expansion.items].reverse()) pending.push({ ...item, file: undefined, depth: current.depth - 1 });
          } else {
            output.push(current.root ? source : replaceInput(source, { path: current.path, data: current.data, file: current.file }));
          }
        }
        // An entire root succeeds before any member is yielded; budget errors do
        // not turn partially extracted content into a successful scan.
        for (const item of output) {
          control.remaining();
          yield item;
        }
        control.remaining();
      }
      control.remaining();
    } finally { control.dispose(); }
  })();
}
function expandContent(inputs, options = {}) {
  iterable(inputs);
  object(options);
  const configuration = {
    sqlite: bool(options.sqlite, true, 'sqlite'), pyc: bool(options.pyc, true, 'pyc'),
    pdf: bool(options.pdf, false, 'pdf'), strict: bool(options.strict, false, 'strict'),
    maxBytes: integer(options.maxBytes, 256 * 1024 * 1024, 'maxBytes', 1),
    tempDir: options.tempDir === undefined ? undefined : string(options.tempDir, 'tempDir'),
  };
  return (async function* () {
    const control = scope(options);
    try {
      control.remaining();
      for await (const source of inputs) {
        if (!(source instanceof ScanInput)) throw new TypeError('inputs must contain ScanInput objects');
        const value = inputHandles.get(source);
        let expansion;
        try {
          expansion = await nativeCall(() => native().expandContent(source.path, value.data, value.file, configuration, control.remaining(), control.token), control);
        } catch (error) { throw translate(error, control); }
        control.remaining();
        if (expansion.items == null) {
          yield expansion.diagnostic == null ? source : replaceInput(source, { extractionError: expansion.diagnostic });
        } else {
          for (const item of expansion.items) {
            control.remaining();
            yield replaceInput(source, { path: item.path, data: item.data, file: undefined });
          }
        }
        control.remaining();
      }
      control.remaining();
    } finally { control.dispose(); }
  })();
}

module.exports = {
  version, Rules, Scanner, DetectionScanner, DetectionPolicy, Finding,
  CancellationToken, ScanInput, ScanResult, Validator, ValidationResult,
  Revoker, RevocationPlan, KingfisherError, AbortError, TimeoutError, shannonEntropy,
  filesystem, gitInputs, gitHistory, expandArchives, expandContent,
};

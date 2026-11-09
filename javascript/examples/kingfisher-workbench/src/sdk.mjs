// One SDK boundary for every stage. Normal consumers resolve the stable npm
// package. The explicit checkout runner selects the already-built facade instead;
// it never downloads a package or silently substitutes an unrelated installation.
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const selected = process.env.KINGFISHER_WORKBENCH_SDK;
const sdk = await import(selected ? pathToFileURL(path.resolve(selected)).href : 'kingfisher-secret-scanner');
export const {
  version, Rules, DetectionScanner, Validator, Revoker,
  filesystem, gitInputs, expandArchives, expandContent,
} = sdk;

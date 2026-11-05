use std::{collections::BTreeMap, path::Path, sync::Arc};

use kingfisher_scanner::{Blob, Scanner, ScannerConfig, context::DetectionOptions};
use napi::{
    Env, Result,
    bindgen_prelude::{Buffer, PromiseRaw},
};
use napi_derive::napi;

use crate::{
    control::{NativeCancellationToken, blocking, control, failure, invalid, scan_error},
    file_io,
    findings::NativeFinding,
    rules::NativeRules,
};

/// Caller-owned files may change or shrink during a scan. An owned, bounded
/// read avoids the invalid shared slices and process-killing faults of an mmap.
fn read_input(
    path: &Path,
    limit: Option<u32>,
    control: &kingfisher_scanner::ScanControl,
) -> Result<Vec<u8>> {
    file_io::read_bounded(
        file_io::open_regular(path, control)?,
        limit.map(u64::from),
        "input exceeds maxInputBytes",
        control,
    )
}

#[napi(object)]
pub struct NativeDetectionPolicy {
    pub inline_ignores: bool,
    pub ignore_comments: Vec<String>,
    pub markup_context: bool,
    pub language: Option<String>,
    pub cli_match_semantics: bool,
    pub base64_max_depth: u32,
    pub base64_max_input_bytes: Option<u32>,
}

impl From<NativeDetectionPolicy> for DetectionOptions {
    fn from(policy: NativeDetectionPolicy) -> Self {
        Self {
            inline_ignores: policy.inline_ignores,
            ignore_comments: policy.ignore_comments,
            markup_context: policy.markup_context,
            language: policy.language,
            cli_match_semantics: policy.cli_match_semantics,
            base64_max_depth: policy.base64_max_depth as usize,
            base64_max_input_bytes: policy.base64_max_input_bytes.map(|value| value as usize),
        }
    }
}

#[napi(object)]
pub struct NativeScannerOptions {
    pub base64: bool,
    pub dedup: bool,
    pub redact: bool,
    pub min_entropy: Option<f64>,
    pub max_input_bytes: Option<u32>,
    pub policy: Option<NativeDetectionPolicy>,
}

#[napi]
pub struct NativeScanner {
    scanner: Arc<Scanner>,
    policy: Option<DetectionOptions>,
    max_input_bytes: Option<u32>,
}

#[napi]
impl NativeScanner {
    #[napi(constructor, catch_unwind)]
    pub fn new(rules: &NativeRules, options: NativeScannerOptions) -> Result<Self> {
        if options
            .min_entropy
            .is_some_and(|value| !value.is_finite() || !(0.0..=8.0).contains(&value))
        {
            return Err(invalid("minEntropy must be between 0 and 8"));
        }
        if options
            .policy
            .as_ref()
            .and_then(|policy| policy.language.as_deref())
            .is_some_and(|language| !matches!(language, "html" | "css"))
        {
            return Err(invalid("policy language must be html or css"));
        }
        Ok(Self {
            scanner: Arc::new(Scanner::with_config(
                rules.db.clone(),
                ScannerConfig {
                    enable_base64_decoding: options.base64,
                    enable_dedup: options.dedup,
                    redact_secrets: options.redact,
                    min_entropy_override: options.min_entropy.map(|value| value as f32),
                },
            )),
            policy: options.policy.map(Into::into),
            max_input_bytes: options.max_input_bytes,
        })
    }

    #[napi(catch_unwind)]
    pub fn reset_dedup(&self) {
        self.scanner.reset_dedup();
    }

    #[napi(catch_unwind)]
    #[allow(clippy::too_many_arguments)] // Private FFI entrypoint; the JS API accepts an options object.
    pub fn scan<'env>(
        &self,
        env: &'env Env,
        data: Buffer,
        path: String,
        attributes: BTreeMap<String, String>,
        preparation: bool,
        timeout_ms: Option<f64>,
        token: Option<&NativeCancellationToken>,
    ) -> Result<PromiseRaw<'env, Vec<NativeFinding>>> {
        let control = control(timeout_ms, token)?;
        if self.max_input_bytes.is_some_and(|limit| data.len() > limit as usize) {
            return Err(failure("KF_LIMIT", "input exceeds maxInputBytes"));
        }
        // Snapshot before returning to JavaScript. Keeping a Buffer alive would
        // not prevent its caller from mutating bytes while native workers read it.
        let data = data.to_vec();
        let scanner = self.scanner.clone();
        let policy = self.policy.clone();
        env.spawn_future(blocking(control, move |control| {
            let blob = Blob::from_bytes(data);
            let mut attributes = attributes;
            attributes.insert("path".into(), path);
            let output = scanner
                .scan_blob_with_context_and_attributes_and_control(
                    &blob,
                    &attributes,
                    control,
                    preparation,
                    policy.as_ref(),
                )
                .map_err(scan_error)?;
            Ok(output
                .findings
                .into_iter()
                .map(|finding| NativeFinding { finding, context: output.context.clone() })
                .collect())
        }))
    }

    #[napi(catch_unwind)]
    pub fn scan_file<'env>(
        &self,
        env: &'env Env,
        path: String,
        attributes: BTreeMap<String, String>,
        preparation: bool,
        timeout_ms: Option<f64>,
        token: Option<&NativeCancellationToken>,
    ) -> Result<PromiseRaw<'env, Vec<NativeFinding>>> {
        let control = control(timeout_ms, token)?;
        let scanner = self.scanner.clone();
        let policy = self.policy.clone();
        let limit = self.max_input_bytes;
        env.spawn_future(blocking(control, move |control| {
            let path = Path::new(&path);
            let blob = Blob::from_bytes(read_input(path, limit, control)?);
            if limit.is_some_and(|limit| blob.len() > limit as usize) {
                return Err(failure("KF_LIMIT", "input exceeds maxInputBytes"));
            }
            let mut attributes = attributes;
            attributes.insert("path".into(), path.to_string_lossy().into_owned());
            let output = scanner
                .scan_blob_with_context_and_attributes_and_control(
                    &blob,
                    &attributes,
                    control,
                    preparation,
                    policy.as_ref(),
                )
                .map_err(scan_error)?;
            Ok(output
                .findings
                .into_iter()
                .map(|finding| NativeFinding { finding, context: output.context.clone() })
                .collect())
        }))
    }
}

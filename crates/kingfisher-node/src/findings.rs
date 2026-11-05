use std::{collections::HashMap, sync::Arc};

use kingfisher_scanner::{Confidence, Finding, ScanContext};
use napi::{Result, bindgen_prelude::Buffer};
use napi_derive::napi;
use serde_json::{Value, json};

use crate::control::failure;

#[napi]
#[derive(Clone)]
pub struct NativeFinding {
    pub(crate) finding: Finding,
    pub(crate) context: Arc<ScanContext>,
}

pub(crate) fn report(finding: &Finding, redact: bool) -> Value {
    let captures: HashMap<_, _> = finding
        .captures
        .iter()
        .map(|(name, value)| (name.as_str(), if redact { "[REDACTED]" } else { value.as_str() }))
        .collect();
    json!({
        "ruleId": finding.rule_id,
        "ruleName": finding.rule_name,
        "visible": finding.rule().visible(),
        "secret": if redact { "[REDACTED]" } else { &finding.secret },
        "confidence": match finding.confidence {
            Confidence::Low => "low", Confidence::Medium => "medium", Confidence::High => "high",
        },
        "entropy": finding.entropy,
        "fingerprint": format!("{:016x}", finding.fingerprint),
        "blobId": finding.blob_id.hex(),
        "isBase64Encoded": finding.is_base64_encoded,
        "captures": captures,
        "location": {
            "startOffset": finding.location.start_offset,
            "endOffset": finding.location.end_offset,
            "line": finding.location.line,
            "column": finding.location.column,
        },
    })
}

#[napi]
impl NativeFinding {
    #[napi(catch_unwind)]
    pub fn redacted(&self) -> Self {
        let mut finding = self.finding.clone();
        finding.secret = "[REDACTED]".into();
        finding.captures.values_mut().for_each(|value| *value = "[REDACTED]".into());
        Self { finding, context: self.context.clone() }
    }

    #[napi(catch_unwind)]
    pub fn to_object(&self, redact: bool) -> Value {
        report(&self.finding, redact)
    }

    #[napi(getter, catch_unwind)]
    pub fn secret(&self) -> &str {
        &self.finding.secret
    }

    #[napi(getter, catch_unwind)]
    pub fn captures(&self) -> HashMap<String, String> {
        self.finding.captures.clone()
    }
}

#[napi(catch_unwind)]
pub fn shannon_entropy(data: Buffer) -> Result<f64> {
    if data.is_empty() {
        return Ok(0.0);
    }
    let value = kingfisher_core::calculate_shannon_entropy(&data);
    if !value.is_finite() {
        return Err(failure("KF_NATIVE", "entropy calculation failed"));
    }
    Ok(value.into())
}

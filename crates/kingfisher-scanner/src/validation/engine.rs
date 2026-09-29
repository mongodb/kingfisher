//! Shared execution for already-resolved rule inputs.
use super::{ValidationReason, ValidationResult};
use super::{
    build_request_builder, check_url_resolvable, validate_response, with_request_template_globals,
};
use crate::ValidationOutcome;
use kingfisher_rules::{HttpValidation, ResponseMatcher, Rule, Validation};
use liquid::Object;
use liquid_core::ValueView;
use reqwest::{Client, StatusCode, Url};
#[cfg(any(feature = "validation-azure", feature = "validation-coinbase"))]
use std::sync::Arc;
use std::time::Duration;

/// Low-level execution for callers that already resolved a rule's input variables.
///
/// Most applications should use [`super::Validator`], which associates findings and
/// bounds concurrency. The CLI uses this same engine after its candidate selection.
/// No global cache or configuration is installed. Borrowed clients and parser can
/// be reused across calls. Clients must have redirects disabled.
pub struct ValidationEngine<'a> {
    client: &'a Client,
    credential_uri_client: &'a Client,
    parser: &'a liquid::Parser,
    timeout: Duration,
    retries: u32,
    max_response_bytes: usize,
    allow_internal_ips: bool,
    use_lax_tls: bool,
}
impl<'a> ValidationEngine<'a> {
    pub fn new(client: &'a Client, parser: &'a liquid::Parser) -> Self {
        Self {
            client,
            credential_uri_client: client,
            parser,
            timeout: Duration::from_secs(10),
            retries: 0,
            max_response_bytes: 1 << 20,
            allow_internal_ips: false,
            use_lax_tls: false,
        }
    }
    /// Set a separate client for credential-bearing URI challenges.
    pub fn credential_uri_client(mut self, client: &'a Client) -> Self {
        self.credential_uri_client = client;
        self
    }
    /// Bound the entire execution, including retries and multi-step validators.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    /// Number of HTTP retries after the initial attempt. Defaults to zero.
    pub fn retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }
    /// Maximum YAML HTTP response bytes retained and matched. Defaults to 1 MiB.
    pub fn max_response_bytes(mut self, limit: usize) -> Self {
        self.max_response_bytes = limit;
        self
    }
    /// Permit explicitly trusted private services. Defaults to false.
    pub fn allow_internal_ips(mut self, allow: bool) -> Self {
        self.allow_internal_ips = allow;
        self
    }
    /// TLS policy for typed database, JWT and Raw validators. HTTP follows the supplied client.
    pub fn use_lax_tls(mut self, allow: bool) -> Self {
        self.use_lax_tls = allow;
        self
    }

    /// Execute a rule using uppercase scalar variables, including `TOKEN`.
    ///
    /// Caller is responsible for associating components and selecting unambiguous
    /// inputs. Missing required components and redacted values are skipped.
    /// The returned response may contain credentials; its Debug output omits it.
    pub async fn validate(&self, rule: &Rule, globals: &Object) -> ValidationResult {
        let Some(validation) = &rule.syntax().validation else {
            return ValidationResult::outcome(ValidationOutcome::NotAttempted);
        };
        if !rule.syntax().is_authoritative() {
            return ValidationResult::outcome(ValidationOutcome::NotAttempted)
                .reason(ValidationReason::NonAuthoritative);
        }
        if self.timeout.is_zero() || self.max_response_bytes == 0 {
            return ValidationResult::unavailable(ValidationReason::InvalidConfiguration);
        }
        if matches!(validation, Validation::Assumed) {
            return ValidationResult::outcome(ValidationOutcome::Assumed);
        }
        if globals.values().any(|v| v.as_scalar().is_some_and(|v| v.to_kstr() == "[REDACTED]")) {
            return ValidationResult::skipped(ValidationReason::RedactedInput);
        }
        if rule
            .syntax()
            .depends_on_rule
            .iter()
            .flatten()
            .any(|dep| !dep.optional && text(globals, &dep.variable.to_uppercase()).is_empty())
        {
            return ValidationResult::skipped(ValidationReason::MissingDependency);
        }
        tokio::time::timeout(self.timeout, self.dispatch(rule, validation, globals))
            .await
            .unwrap_or_else(|_| ValidationResult::unavailable(ValidationReason::DeadlineExceeded))
    }
    async fn dispatch(
        &self,
        rule: &Rule,
        validation: &Validation,
        globals: &Object,
    ) -> ValidationResult {
        let _ = rule;
        match validation {
            Validation::Assumed => ValidationResult::outcome(ValidationOutcome::Assumed),
            Validation::Http(config) => self.http(config, globals).await,
            Validation::Betterleaks(config) => {
                let captures: Vec<_> = globals
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.to_kstr().to_string(), 0, 0))
                    .collect();
                let result = super::betterleaks::validate(
                    config,
                    &captures,
                    globals,
                    self.client,
                    self.allow_internal_ips,
                )
                .await;
                let mut check = ValidationResult::outcome(result.outcome)
                    .status(result.status)
                    .body(result.body.clone());
                check.reason = result.reason;
                if result.reason == Some(ValidationReason::RequestFailed) {
                    check.response_body = "Betterleaks validation request failed".into();
                }
                check
            }
            #[cfg(feature = "validation-ethereum")]
            Validation::Ethereum(kind) => {
                let result = super::ethereum::validate(*kind, &text(globals, "TOKEN"));
                ValidationResult::outcome(result.outcome).body(result.body)
            }
            #[cfg(feature = "validation-raw")]
            Validation::Raw(kind) => {
                if super::raw_required_vars(kind).iter().any(|name| text(globals, name).is_empty())
                {
                    return ValidationResult::skipped(ValidationReason::MissingDependency);
                }
                match super::validate_raw(
                    kind,
                    globals,
                    self.client,
                    self.use_lax_tls,
                    self.allow_internal_ips,
                )
                .await
                {
                    Ok(result) if result.status == StatusCode::NOT_IMPLEMENTED => {
                        ValidationResult::skipped(ValidationReason::UnsupportedValidator)
                    }
                    Ok(result) => classify_status(result.valid, result.status).body(result.body),
                    Err(_) => ValidationResult::unavailable(ValidationReason::RequestFailed),
                }
            }
            #[cfg(feature = "validation-aws")]
            Validation::AWS => {
                let akid = first_text(globals, &["AKID", "ACCESS_KEY_ID"]);
                let (secret, session) = aws_credential_shape(rule, globals);
                if akid.is_empty() || secret.is_empty() {
                    return ValidationResult::skipped(ValidationReason::MissingDependency);
                }
                let result =
                    super::aws::validate_aws_credential_pair(&akid, &secret, session.as_deref())
                        .await;
                ValidationResult::outcome(result.outcome).status(result.status).body(result.message)
            }
            #[cfg(feature = "validation-azure")]
            Validation::AzureStorage => {
                let account = first_text(globals, &["AZURENAME", "STORAGE_ACCOUNT"]);
                if account.is_empty() && !text(globals, "TOKEN").trim_start().starts_with('{') {
                    return ValidationResult::skipped(ValidationReason::MissingDependency);
                }
                let credentials = if text(globals, "TOKEN").trim_start().starts_with('{') {
                    text(globals, "TOKEN")
                } else {
                    serde_json::json!({"storage_account": account, "storage_key": text(globals, "TOKEN")}).to_string()
                };
                let cache = Arc::default();
                let result =
                    super::azure::validate_azure_storage_credentials(&credentials, &cache).await;
                let key = super::azure::generate_azure_cache_key(&credentials);
                if let Some(entry) = cache.get(&key) {
                    return classify_status(entry.value().is_valid, entry.value().status)
                        .body(super::validation_body::as_str(&entry.value().body).to_string());
                }
                positive_only(result.map(|(valid, body)| {
                    (valid, super::validation_body::as_str(&body).to_string())
                }))
            }
            #[cfg(feature = "validation-coinbase")]
            Validation::Coinbase => {
                let name = first_text(globals, &["CRED_NAME", "KEY_ID"]);
                if name.is_empty() {
                    return ValidationResult::skipped(ValidationReason::MissingDependency);
                }
                let token = text(globals, "TOKEN");
                let cache = Arc::default();
                let result = super::coinbase::validate_cdp_api_key(
                    &name,
                    &token,
                    self.client,
                    self.parser,
                    &cache,
                )
                .await;
                let key = super::coinbase::generate_coinbase_cache_key(&name, &token);
                if let Some(entry) = cache.get(&key) {
                    return classify_status(entry.value().is_valid, entry.value().status)
                        .body(super::validation_body::as_str(&entry.value().body).to_string());
                }
                positive_only(result.map(|(valid, body)| {
                    (valid, super::validation_body::as_str(&body).to_string())
                }))
            }
            #[cfg(feature = "validation-gcp")]
            Validation::GCP => match super::gcp::GcpValidator::global() {
                Ok(validator) => positive_only(
                    validator
                        .validate_gcp_credentials(text(globals, "TOKEN").as_bytes())
                        .await
                        .map(|(valid, body)| (valid, body.join("\n"))),
                ),
                Err(_) => ValidationResult::unavailable(ValidationReason::RequestFailed),
            },
            #[cfg(feature = "validation-jwt")]
            Validation::JWT => positive_only(
                super::jwt::validate_jwt(
                    &text(globals, "TOKEN"),
                    self.use_lax_tls,
                    self.allow_internal_ips,
                )
                .await,
            ),
            #[cfg(feature = "validation-database")]
            Validation::MongoDB | Validation::MySQL | Validation::Postgres | Validation::Jdbc => {
                self.database(validation, &text(globals, "TOKEN")).await
            }
            Validation::CredentialUri => self.credential_uri(globals).await,
            #[cfg(feature = "validation-grpc")]
            Validation::Grpc(config) => self.grpc(config, globals).await,
            #[allow(unreachable_patterns)]
            _ => ValidationResult::skipped(ValidationReason::FeatureDisabled),
        }
    }

    async fn url(
        &self,
        template: &str,
        globals: &Object,
    ) -> std::result::Result<Url, ValidationResult> {
        let rendered =
            self.parser.parse(template).and_then(|t| t.render(globals)).map_err(|_| {
                ValidationResult::unavailable(ValidationReason::InvalidConfiguration)
            })?;
        let url = Url::parse(&rendered)
            .map_err(|_| ValidationResult::unavailable(ValidationReason::InvalidConfiguration))?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(ValidationResult::skipped(ValidationReason::TargetBlocked));
        }
        check_url_resolvable(&url, self.allow_internal_ips)
            .await
            .map_err(|error| resolution_failure(error.as_ref()))?;
        Ok(url)
    }

    async fn http(&self, config: &HttpValidation, globals: &Object) -> ValidationResult {
        for attempt in 0..=self.retries {
            // Rebuild multipart requests rather than cloning their non-cloneable stream.
            let result = self.http_once(config, globals).await;
            let retryable = matches!(
                result.reason,
                Some(ValidationReason::RequestFailed | ValidationReason::DeadlineExceeded)
            ) && (result.http_status.is_none()
                || matches!(result.http_status, Some(408 | 429 | 502 | 503 | 504)));
            if !retryable || attempt == self.retries {
                return result;
            }
            tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt.min(2)))).await;
        }
        unreachable!("the inclusive retry range always executes")
    }

    async fn http_once(&self, config: &HttpValidation, globals: &Object) -> ValidationResult {
        let request = &config.request;
        let matchers = request.response_matcher.as_deref().unwrap_or_default();
        if !has_evidence_matcher(matchers) {
            return ValidationResult::unavailable(ValidationReason::InvalidConfiguration);
        }
        let globals = with_request_template_globals(globals);
        let url = match self.url(&request.url, &globals).await {
            Ok(url) => url,
            Err(check) => return check,
        };
        let mut builder = match build_request_builder(
            self.client,
            &request.method,
            &url,
            &request.headers,
            &request.body,
            self.timeout,
            self.parser,
            &globals,
        ) {
            Ok(builder) => builder,
            Err(_) => return ValidationResult::unavailable(ValidationReason::InvalidConfiguration),
        };
        if let Some(multipart) = request.multipart.as_ref().or(config.multipart.as_ref()) {
            let mut form = reqwest::multipart::Form::new();
            for part in &multipart.parts {
                let content =
                    match self.parser.parse(&part.content).and_then(|t| t.render(&globals)) {
                        Ok(content) => content,
                        Err(_) => {
                            return ValidationResult::unavailable(
                                ValidationReason::InvalidConfiguration,
                            );
                        }
                    };
                let mut value = match part.part_type.as_str() {
                    "text" => reqwest::multipart::Part::text(content),
                    // File parts are inline template bytes, never paths read from the host.
                    "file" => reqwest::multipart::Part::bytes(content.into_bytes())
                        .file_name(part.name.clone()),
                    _ => {
                        return ValidationResult::unavailable(
                            ValidationReason::InvalidConfiguration,
                        );
                    }
                };
                if let Some(content_type) = &part.content_type {
                    value = match value.mime_str(content_type) {
                        Ok(value) => value,
                        Err(_) => {
                            return ValidationResult::unavailable(
                                ValidationReason::InvalidConfiguration,
                            );
                        }
                    };
                }
                form = form.part(part.name.clone(), value);
            }
            builder = builder.multipart(form);
        }
        let mut response = match builder.send().await {
            Ok(response) => response,
            Err(error) => return request_failure(&error),
        };
        let status = response.status();
        if response.url() != &url {
            return ValidationResult::unavailable(ValidationReason::ResponseMismatch)
                .status(status);
        }
        let headers = response.headers().clone();
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len().saturating_add(chunk.len()) > self.max_response_bytes {
                        return ValidationResult::unavailable(ValidationReason::ResponseTooLarge)
                            .status(status);
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(error) => return request_failure(&error).status(status),
            }
        }
        let valid = validate_response(
            matchers,
            &String::from_utf8_lossy(&body),
            &status,
            &headers,
            request.response_is_html,
        );
        classify_status(valid, status).body(String::from_utf8_lossy(&body).into_owned())
    }

    #[cfg(feature = "validation-database")]
    async fn database(&self, validation: &Validation, uri: &str) -> ValidationResult {
        let result = match validation {
            Validation::MongoDB => {
                super::mongodb::validate_mongodb(uri, self.use_lax_tls, self.allow_internal_ips)
                    .await
            }
            Validation::MySQL => {
                super::mysql::validate_mysql(uri, self.use_lax_tls, self.allow_internal_ips)
                    .await
                    .map(|(valid, body)| (valid, body.join("\n")))
            }
            Validation::Postgres => {
                super::postgres::validate_postgres(uri, self.use_lax_tls, self.allow_internal_ips)
                    .await
                    .map(|(valid, body)| (valid, body.join("\n")))
            }
            Validation::Jdbc => {
                return match super::jdbc::validate_jdbc(
                    uri,
                    self.use_lax_tls,
                    self.allow_internal_ips,
                )
                .await
                {
                    Ok(result) => classify_status(result.valid, result.status).body(result.message),
                    Err(_) => ValidationResult::unavailable(ValidationReason::RequestFailed),
                };
            }
            _ => unreachable!(),
        };
        // Legacy boolean helpers also return false for connectivity failures.
        // Never promote those ambiguous failures to authoritative rejection.
        positive_only(result)
    }

    async fn credential_uri(&self, globals: &Object) -> ValidationResult {
        use super::credential_uri::{CredentialUriTarget, classify_credential_uri};
        let uri = first_text(globals, &["URI", "TOKEN"]);
        let scheme = text(globals, "SCHEME");
        let target = classify_credential_uri(&uri, (!scheme.is_empty()).then_some(scheme.as_str()));
        match target {
            CredentialUriTarget::Http(uri) => {
                if uri.starts_with("http:") {
                    return ValidationResult::unavailable(ValidationReason::InvalidConfiguration)
                        .body("HTTP credential URI validation requires HTTPS".into());
                }
                match super::credential_uri::validate_http_credential_uri(
                    &uri,
                    self.credential_uri_client,
                    self.timeout,
                    self.retries,
                    self.allow_internal_ips,
                )
                .await
                {
                    Ok((valid, status, body)) => classify_status(valid, status).body(body),
                    Err(_) => ValidationResult::unavailable(ValidationReason::RequestFailed),
                }
            }
            CredentialUriTarget::Unsupported(_) => {
                ValidationResult::outcome(ValidationOutcome::NotAttempted)
                    .reason(ValidationReason::UnsupportedValidator)
            }
            #[cfg(feature = "validation-database")]
            CredentialUriTarget::MongoDB(uri) => self.database(&Validation::MongoDB, &uri).await,
            #[cfg(feature = "validation-database")]
            CredentialUriTarget::MySQL(uri) => self.database(&Validation::MySQL, &uri).await,
            #[cfg(feature = "validation-database")]
            CredentialUriTarget::Postgres(uri) => self.database(&Validation::Postgres, &uri).await,
            #[cfg(feature = "validation-database")]
            CredentialUriTarget::Jdbc(uri) => self.database(&Validation::Jdbc, &uri).await,
            #[cfg(not(feature = "validation-database"))]
            _ => ValidationResult::skipped(ValidationReason::FeatureDisabled),
        }
    }

    #[cfg(feature = "validation-grpc")]
    async fn grpc(
        &self,
        config: &kingfisher_rules::GrpcValidation,
        globals: &Object,
    ) -> ValidationResult {
        let request = &config.request;
        let matchers = request.response_matcher.as_deref().unwrap_or_default();
        if !has_evidence_matcher(matchers) {
            return ValidationResult::unavailable(ValidationReason::InvalidConfiguration);
        }
        let globals = with_request_template_globals(globals);
        let url = match self.url(&request.url, &globals).await {
            Ok(url) => url,
            Err(check) => return check,
        };
        match super::grpc::grpc_unary_call_from_rule(
            &url,
            &request.headers,
            &request.body,
            self.parser,
            &globals,
            self.timeout,
        )
        .await
        {
            Ok(response) => {
                let grpc_status =
                    response.headers.get("grpc-status").and_then(|v| v.to_str().ok()).unwrap_or("");
                let valid = grpc_status == "0"
                    && validate_response(
                        matchers,
                        &format!("grpc-status={grpc_status}"),
                        &response.http_status,
                        &response.headers,
                        false,
                    );
                let check = if valid {
                    ValidationResult::outcome(ValidationOutcome::VerifiedActive)
                        .status(response.http_status)
                } else if grpc_status == "16" {
                    ValidationResult::outcome(ValidationOutcome::VerifiedInactive)
                        .status(response.http_status)
                } else {
                    ValidationResult::unavailable(ValidationReason::ResponseMismatch)
                        .status(response.http_status)
                };
                check.body(format!("grpc-status={grpc_status}"))
            }
            Err(_) => ValidationResult::unavailable(ValidationReason::RequestFailed)
                .body("gRPC validation failed".into()),
        }
    }
}

pub(crate) fn text(globals: &Object, name: &str) -> String {
    globals
        .get(name)
        .and_then(|v| v.as_scalar())
        .map(|v| v.to_kstr().to_string())
        .unwrap_or_default()
}

fn classify_status(valid: bool, status: StatusCode) -> ValidationResult {
    if status.is_server_error() || matches!(status.as_u16(), 408 | 429) {
        ValidationResult::unavailable(ValidationReason::RequestFailed).status(status)
    } else if valid {
        ValidationResult::outcome(ValidationOutcome::VerifiedActive).status(status)
    } else if status == StatusCode::UNAUTHORIZED {
        ValidationResult::outcome(ValidationOutcome::VerifiedInactive).status(status)
    } else if status == StatusCode::PRECONDITION_REQUIRED {
        ValidationResult::skipped(ValidationReason::TargetBlocked).status(status)
    } else {
        ValidationResult::unavailable(ValidationReason::ResponseMismatch).status(status)
    }
}

#[cfg(any(
    feature = "validation-azure",
    feature = "validation-coinbase",
    feature = "validation-gcp",
    feature = "validation-jwt",
    feature = "validation-database"
))]
fn positive_only(result: anyhow::Result<(bool, String)>) -> ValidationResult {
    match result {
        Ok((true, body)) => ValidationResult::outcome(ValidationOutcome::VerifiedActive).body(body),
        Ok((false, body)) => {
            ValidationResult::unavailable(ValidationReason::ResponseMismatch).body(body)
        }
        Err(_) => ValidationResult::unavailable(ValidationReason::RequestFailed),
    }
}

fn has_evidence_matcher(matchers: &[ResponseMatcher]) -> bool {
    matchers.iter().any(|matcher| match matcher {
        ResponseMatcher::WordMatch { words, .. } => !words.is_empty(),
        ResponseMatcher::StatusMatch { status, .. } => !status.is_empty(),
        ResponseMatcher::HeaderMatch { expected, .. } => !expected.is_empty(),
        _ => false,
    })
}

fn request_failure(error: &reqwest::Error) -> ValidationResult {
    ValidationResult::unavailable(if error.is_timeout() {
        ValidationReason::DeadlineExceeded
    } else {
        ValidationReason::RequestFailed
    })
}

fn resolution_failure(error: &(dyn std::error::Error + 'static)) -> ValidationResult {
    if error.is::<super::SsrfBlockedError>() {
        ValidationResult::skipped(ValidationReason::TargetBlocked)
    } else {
        ValidationResult::unavailable(ValidationReason::RequestFailed)
    }
}

fn first_text(globals: &Object, names: &[&str]) -> String {
    names.iter().map(|name| text(globals, name)).find(|value| !value.is_empty()).unwrap_or_default()
}
#[cfg(feature = "validation-aws")]
fn aws_credential_shape(rule: &Rule, globals: &Object) -> (String, Option<String>) {
    let token = text(globals, "TOKEN");
    if is_aws_session_token_rule(rule) {
        (text(globals, "AWS_SECRET_ACCESS_KEY"), Some(token))
    } else {
        let session = text(globals, "AWS_SESSION_TOKEN");
        (token, (!session.is_empty()).then_some(session))
    }
}

/// Whether TOKEN represents a session token rather than the AWS secret key.
pub fn is_aws_session_token_rule(rule: &Rule) -> bool {
    rule.id() == "kingfisher.aws.4"
        || rule
            .syntax()
            .depends_on_rule
            .iter()
            .flatten()
            .any(|dep| dep.variable.eq_ignore_ascii_case("AWS_SECRET_ACCESS_KEY"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolution_failures_distinguish_network_errors_from_policy_blocks() {
        let network = std::io::Error::other("resolver unavailable");
        assert_eq!(resolution_failure(&network).outcome, ValidationOutcome::Unavailable);
        let blocked = super::super::SsrfBlockedError("private address".into());
        assert_eq!(resolution_failure(&blocked).outcome, ValidationOutcome::Skipped);
    }
}

#[cfg(all(test, feature = "validation-aws"))]
mod aws_tests {
    use super::*;
    use liquid::model::Value;
    #[test]
    fn static_and_session_rules_bind_their_own_credential_shape() {
        let static_rule =
            Rule::new(kingfisher_rules::RuleSyntax::new("acme.static", "Static", "(token)"));
        let session_rule =
            Rule::new(kingfisher_rules::RuleSyntax::new("kingfisher.aws.4", "Session", "(token)"));
        let mut globals = Object::from_iter([
            ("TOKEN".into(), Value::scalar("primary")),
            ("AWS_SECRET_ACCESS_KEY".into(), Value::scalar("supporting-secret")),
        ]);
        assert_eq!(aws_credential_shape(&static_rule, &globals), ("primary".into(), None));
        assert_eq!(
            aws_credential_shape(&session_rule, &globals),
            ("supporting-secret".into(), Some("primary".into()))
        );
        globals.insert("AWS_SESSION_TOKEN".into(), Value::scalar("optional-session"));
        assert_eq!(
            aws_credential_shape(&static_rule, &globals),
            ("primary".into(), Some("optional-session".into()))
        );
        assert_eq!(
            aws_credential_shape(&session_rule, &globals),
            ("supporting-secret".into(), Some("primary".into()))
        );
    }
}

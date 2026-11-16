//! Smart HTTP transport with a single operation-wide deadline and native TLS.
//!
//! gix's reqwest backend doesn't apply the shared TLS/proxy options yet. Also,
//! setting `configure_request` prevents *all* redirects, even safe same-host
//! redirects. A fresh backend per request lets us set its remaining total budget
//! in `configure_client` instead, retaining gix's credential-safe redirect policy.
use std::{
    any::Any,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{Context, Result};
use gix::{
    bstr::ByteSlice,
    protocol::transport::client::blocking_io::http::{self, Http as _},
};

type Backend = http::reqwest::Remote;

pub(super) struct Http {
    backend: Option<Backend>,
    options: http::Options,
}

impl Http {
    pub(super) fn new(
        repo: &gix::Repository,
        remote: &gix::Remote<'_>,
        ignore_certs: bool,
        deadline: Option<Instant>,
    ) -> Result<Self> {
        let config = repo.config_snapshot();
        let remote_proxy = remote.name().map(|name| format!("remote.{}.proxy", name.as_bstr()));
        let proxy = remote_proxy
            .as_deref()
            .and_then(|key| config.string(key))
            .or_else(|| config.string("http.proxy"))
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()?;
        // Explicit Git CA settings fail closed, including files with no certificates.
        // The generic OpenSSL variables are ignored by many Git builds, so stale
        // values there are skipped instead of breaking every HTTPS clone; the
        // platform verifier still applies.
        let git_ca_file = std::env::var_os("GIT_SSL_CAINFO").map(PathBuf::from).or_else(|| {
            config
                .string("http.sslCAInfo")
                .map(|value| PathBuf::from(value.to_str_lossy().as_ref()))
        });
        let (ca_file, ca_file_required) = match git_ca_file {
            Some(path) => (Some(path), true),
            None => (std::env::var_os("SSL_CERT_FILE").map(PathBuf::from), false),
        };
        let (ca_directory, ca_directory_required) = match std::env::var_os("GIT_SSL_CAPATH") {
            Some(paths) => (Some(paths), true),
            None => (std::env::var_os("SSL_CERT_DIR"), false),
        };
        let mut certificates = Vec::new();
        if let Some(path) = ca_file {
            let loaded = std::fs::read(&path)
                .with_context(|| format!("Failed to read Git TLS CA file {}", path.display()))
                .and_then(|bytes| {
                    let certs = reqwest::Certificate::from_pem_bundle(&bytes)
                        .with_context(|| format!("Invalid Git TLS CA file {}", path.display()))?;
                    // A DER file or the wrong file parses as an empty PEM bundle.
                    anyhow::ensure!(
                        !certs.is_empty(),
                        "Invalid Git TLS CA file {}: no PEM certificates found",
                        path.display()
                    );
                    Ok(certs)
                });
            match loaded {
                Ok(certs) => certificates.extend(certs),
                Err(error) if !ca_file_required => {
                    tracing::debug!("Ignoring SSL_CERT_FILE: {error:#}");
                }
                Err(error) => return Err(error),
            }
        }
        if let Some(paths) = ca_directory {
            let mut loaded_from_directories = 0usize;
            for path in std::env::split_paths(&paths) {
                let entries = match std::fs::read_dir(&path) {
                    Ok(entries) => entries,
                    Err(error) if !ca_directory_required => {
                        tracing::debug!("Ignoring SSL_CERT_DIR entry {}: {error}", path.display());
                        continue;
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("Failed to read Git TLS CA directory {}", path.display())
                        });
                    }
                };
                for entry in entries {
                    // Like OpenSSL, skip unreadable entries instead of failing every fetch.
                    let path = match entry {
                        Ok(entry) => entry.path(),
                        Err(error) => {
                            tracing::debug!(
                                "Skipping unreadable TLS CA directory entry in {}: {error}",
                                path.display()
                            );
                            continue;
                        }
                    };
                    if path.is_file() {
                        // Hashed OpenSSL directories can also contain non-certificate files.
                        let Ok(bytes) = std::fs::read(&path) else { continue };
                        if let Ok(certs) = reqwest::Certificate::from_pem_bundle(&bytes) {
                            loaded_from_directories += certs.len();
                            certificates.extend(certs);
                        }
                    }
                }
            }
            anyhow::ensure!(
                !ca_directory_required || loaded_from_directories > 0,
                "Invalid Git TLS CA directory {}: no PEM certificates found",
                std::path::Path::new(&paths).display()
            );
        }
        // Explicit Git CA settings replace the default trust store, as they do for
        // OpenSSL-backed Git. Otherwise extra certificates add to the OS verifier.
        let certificates_only = ca_file_required || ca_directory_required;
        let ignore_certs = ignore_certs
            || config.boolean("http.sslVerify") == Some(false)
            || config.boolean("gitoxide.http.sslNoVerify") == Some(true)
            || std::env::var("GIT_SSL_NO_VERIFY").is_ok_and(|value| {
                !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
            });
        let user_agent = std::env::var("GIT_HTTP_USER_AGENT").ok().or_else(|| {
            config.string("http.userAgent").map(|value| value.to_str_lossy().into_owned())
        });
        let connect_timeout = config
            .integer("gitoxide.http.connectTimeout")
            .and_then(|value| u64::try_from(value).ok())
            .filter(|value| *value != 0)
            .map(std::time::Duration::from_millis);
        let http_version =
            config.string("http.version").map(|value| value.to_str_lossy().into_owned());
        let mut options = http::Options::default();
        if let Some(headers) = config.strings("http.extraHeader") {
            for value in headers {
                let value = value.to_str()?.to_owned();
                if value.is_empty() {
                    options.extra_headers.clear();
                } else {
                    options.extra_headers.push(value);
                }
            }
        }
        options.follow_redirects = match config.string("http.followRedirects").as_deref() {
            Some(value) if value.eq_ignore_ascii_case(b"false") => {
                http::options::FollowRedirects::None
            }
            Some(value) if value.eq_ignore_ascii_case(b"true") => {
                http::options::FollowRedirects::All
            }
            _ => http::options::FollowRedirects::Initial,
        };
        options.backend = Some(Arc::new(Mutex::new(http::reqwest::Options {
            configure_client: Some(Box::new(move |_| {
                // Build from scratch: the backend's default 20s connect and 30s
                // request timeouts must not defeat --no-timeouts/zero budgets.
                let mut builder = reqwest::blocking::Client::builder()
                    .http1_title_case_headers()
                    .timeout(
                        deadline.map(|deadline| deadline.saturating_duration_since(Instant::now())),
                    )
                    .tls_danger_accept_invalid_certs(ignore_certs);
                if let Some(timeout) = connect_timeout {
                    builder = builder.connect_timeout(timeout);
                }
                if let Some(proxy) = &proxy {
                    builder = if proxy.is_empty() {
                        builder.no_proxy()
                    } else {
                        builder.proxy(reqwest::Proxy::all(proxy).map_err(gix::Error::from_error)?)
                    };
                }
                if let Some(agent) = &user_agent {
                    builder = builder.user_agent(agent);
                }
                if http_version.as_deref() == Some("HTTP/1.1") {
                    builder = builder.http1_only();
                }
                builder = if certificates_only {
                    builder.tls_certs_only(certificates.iter().cloned())
                } else {
                    builder.tls_certs_merge(certificates.iter().cloned())
                };
                Ok(builder)
            })),
            configure_request: None,
        })));
        // Never install proxy credential helpers or consult a Git installation.
        Ok(Self { backend: None, options })
    }

    fn next(&mut self, initial: bool) -> gix::Result<&mut Backend> {
        let mut options = self.options.clone();
        // Authentication can retry the initial discovery GET. Keep redirects
        // enabled for that entire phase, but not subsequent upload-pack POSTs.
        if !initial && options.follow_redirects == http::options::FollowRedirects::Initial {
            options.follow_redirects = http::options::FollowRedirects::None;
        }
        let mut backend = Backend::default();
        backend.configure(&options)?;
        self.backend = Some(backend);
        Ok(self.backend.as_mut().expect("just initialized"))
    }
}

impl http::Http for Http {
    type Headers = <Backend as http::Http>::Headers;
    type ResponseBody = <Backend as http::Http>::ResponseBody;
    type PostBody = <Backend as http::Http>::PostBody;

    fn get(
        &mut self,
        url: &str,
        base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> gix::Result<http::GetResponse<Self::Headers, Self::ResponseBody>> {
        self.next(true)?.get(url, base_url, headers)
    }

    fn post(
        &mut self,
        url: &str,
        base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
        body: http::PostBodyDataKind,
    ) -> gix::Result<http::PostResponse<Self::Headers, Self::ResponseBody, Self::PostBody>> {
        self.next(false)?.post(url, base_url, headers, body)
    }

    fn configure(&mut self, _config: &dyn Any) -> gix::Result<()> {
        // Our fully native options were resolved above. In particular, do not
        // let repository config reintroduce a shell-based credential callback.
        Ok(())
    }

    fn redirected_base_url(&self) -> Option<String> {
        self.backend.as_ref().and_then(http::Http::redirected_base_url)
    }
}

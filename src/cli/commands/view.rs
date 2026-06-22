use std::{
    net::SocketAddr,
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderValue, StatusCode, Uri, header},
    response::Response,
    routing::get,
};
use include_dir::{Dir, include_dir};
use tokio::net::TcpListener;
use tracing::{info, warn};

pub const DEFAULT_PORT: u16 = 7890;
// Embedded viewer assets - force rebuild
static VIEWER_ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/docs/viewer");

/// Default bind address for the report viewer (localhost only for security).
pub const DEFAULT_ADDRESS: &str = "127.0.0.1";

/// View a Kingfisher access-map report locally.
#[derive(clap::Args, Debug)]
pub struct ViewArgs {
    /// Paths to JSON/JSONL reports or directories containing them.
    /// Multiple files are merged and deduplicated by fingerprint.
    /// Directories are scanned (non-recursively) for .json/.jsonl files.
    #[arg(value_name = "REPORT", value_hint = clap::ValueHint::AnyPath)]
    pub reports: Vec<PathBuf>,

    /// Local port for the embedded viewer (default 7890)
    #[arg(long, default_value_t = DEFAULT_PORT)]
    pub port: u16,

    /// Bind address for the report viewer (default 127.0.0.1). Use 0.0.0.0 to allow access from Docker or other hosts.
    #[arg(long, default_value = DEFAULT_ADDRESS, value_name = "ADDRESS")]
    pub address: String,

    #[arg(skip)]
    pub open_browser: bool,

    #[arg(skip)]
    pub report_bytes: Option<Vec<u8>>,
}

#[derive(Clone)]
struct AppState {
    report: Option<Vec<u8>>,
}

fn addr_in_use_error(port: u16, flag_name: &str) -> anyhow::Error {
    anyhow!(
        "Port {} is already in use. Re-run with {} <PORT> to choose a different port.",
        port,
        flag_name
    )
}

pub fn ensure_port_available(port: u16, address: &str, flag_name: &str) -> Result<()> {
    let addr: std::net::IpAddr =
        address.parse().context("Invalid bind address for report viewer")?;
    StdTcpListener::bind((addr, port)).map_err(|err| match err.kind() {
        std::io::ErrorKind::AddrInUse => addr_in_use_error(port, flag_name),
        _ => err.into(),
    })?;
    Ok(())
}

/// Resolve report paths: expand directories (non-recursively) into their
/// `.json` / `.jsonl` children, expand tildes, and filter to valid extensions.
/// Non-matching files inside directories are silently skipped.
async fn resolve_report_paths(raw: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();

    for raw_path in raw {
        let expanded = expand_tilde(raw_path)?;
        let meta = tokio::fs::metadata(&expanded)
            .await
            .with_context(|| format!("Cannot access path: {}", expanded.display()))?;

        if meta.is_dir() {
            let mut read_dir = tokio::fs::read_dir(&expanded)
                .await
                .with_context(|| format!("Cannot read directory: {}", expanded.display()))?;
            while let Some(entry) = read_dir.next_entry().await? {
                let child = entry.path();
                if child.is_file() && is_report_extension(&child) {
                    paths.push(child);
                }
            }
        } else if meta.is_file() {
            if !is_report_extension(&expanded) {
                warn!(path = %expanded.display(), "Skipping file with unsupported extension");
                continue;
            }
            paths.push(expanded);
        }
    }

    Ok(paths)
}

fn is_report_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            let lower = ext.to_ascii_lowercase();
            lower == "json" || lower == "jsonl"
        })
        .unwrap_or(false)
}

/// Load multiple report files and emit genuine JSONL so the viewer's
/// multi-document parser can split on newline boundaries. Kingfisher's
/// `json_format` writes pretty-printed (multi-line) documents; naive
/// concatenation would produce output that is neither valid JSON nor
/// valid JSONL and the viewer's fallback splitter would shatter nested
/// objects. For each file we try to parse the whole payload as a single
/// JSON value and emit it as one compact line; on failure we assume
/// JSONL input and re-emit each non-blank line compacted.
// nosemgrep: tokio::fs::read below operates on CLI-supplied paths (the
// user explicitly ran `kingfisher view <path>`); path-traversal rules
// designed for HTTP handlers don't apply to a CLI.
async fn load_and_combine_reports(paths: &[PathBuf]) -> Result<Vec<u8>> {
    let mut combined = Vec::new();
    let mut loaded = 0usize;

    for path in paths {
        // nosemgrep: CLI-supplied path — see function-level comment above.
        let bytes = match tokio::fs::read(path).await {
            Ok(b) => b,
            Err(err) => {
                warn!(path = %path.display(), %err, "Failed to read report file, skipping");
                continue;
            }
        };

        let mut push_compact = |value: &serde_json::Value| -> Result<()> {
            if !combined.is_empty() && !combined.ends_with(b"\n") {
                combined.push(b'\n');
            }
            serde_json::to_writer(&mut combined, value)?;
            combined.push(b'\n');
            Ok(())
        };

        match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(value) => {
                if let Err(err) = push_compact(&value) {
                    warn!(path = %path.display(), %err, "Failed to re-serialize report, skipping");
                    continue;
                }
            }
            Err(_) => {
                let mut any = false;
                for line in bytes.split(|b| *b == b'\n') {
                    let trimmed = match line.iter().position(|b| !b.is_ascii_whitespace()) {
                        Some(i) => &line[i..],
                        None => continue,
                    };
                    match serde_json::from_slice::<serde_json::Value>(trimmed) {
                        Ok(value) => {
                            if push_compact(&value).is_ok() {
                                any = true;
                            }
                        }
                        Err(err) => {
                            warn!(path = %path.display(), %err, "Skipping malformed JSONL line");
                        }
                    }
                }
                if !any {
                    warn!(path = %path.display(), "No parseable JSON in report, skipping");
                    continue;
                }
            }
        }
        loaded += 1;
    }

    if loaded == 0 && !paths.is_empty() {
        return Err(anyhow!("Failed to read any of the {} report file(s)", paths.len()));
    }

    if loaded > 0 {
        info!(loaded, total = paths.len(), "Loaded report files");
    }

    Ok(combined)
}

/// Run the `kingfisher view` subcommand.
pub async fn run(args: ViewArgs) -> Result<()> {
    let report = if let Some(report_bytes) = args.report_bytes.as_ref() {
        Some(report_bytes.clone())
    } else if !args.reports.is_empty() {
        let paths = resolve_report_paths(&args.reports).await?;
        if paths.is_empty() {
            warn!("No JSON/JSONL report files found in the provided paths");
            None
        } else {
            let combined = load_and_combine_reports(&paths).await?;
            if combined.is_empty() { None } else { Some(combined) }
        }
    } else {
        None
    };

    let addr: std::net::IpAddr =
        args.address.parse().context("Invalid bind address for report viewer")?;
    let listener = TcpListener::bind((addr, args.port)).await.map_err(|err| match err.kind() {
        std::io::ErrorKind::AddrInUse => addr_in_use_error(args.port, "--port"),
        _ => err.into(),
    })?;

    let address: SocketAddr =
        listener.local_addr().context("Failed to read local listener address")?;

    let url = format!("http://{}:{}", address.ip(), address.port());

    info!(%address, "Starting access-map viewer");
    eprintln!("Serving access-map viewer at {} (Ctrl+C to stop)", url);

    let open_browser = args.open_browser || !args.reports.is_empty() || args.report_bytes.is_some();
    if open_browser {
        let url = url.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(err) = webbrowser::open(&url) {
                warn!(%err, "Failed to open browser for access-map viewer");
            }
        });
    }

    let state = Arc::new(AppState { report });

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/report", get(serve_report))
        .route("/favicon.ico", get(serve_favicon))
        .fallback(get(serve_asset))
        .with_state(state);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn serve_index() -> Response {
    serve_asset_at("index.html").unwrap_or_else(not_found)
}

async fn serve_favicon() -> Response {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .map(apply_security_headers)
        .unwrap_or_else(|_| internal_error())
}

async fn serve_asset(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.is_empty() {
        return serve_index().await;
    }
    if !is_safe_path(path) {
        return not_found();
    }

    serve_asset_at(path).unwrap_or_else(not_found)
}

async fn serve_report(State(state): State<Arc<AppState>>) -> Response {
    if let Some(report) = &state.report {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type_for("report.json"))
            .body(Body::from(report.clone()))
            .map(apply_security_headers)
            .unwrap_or_else(|_| internal_error());
    }

    not_found()
}

fn serve_asset_at(path: &str) -> Option<Response> {
    let file = VIEWER_ASSETS.get_file(path)?;
    let body = Body::from(file.contents().to_vec());
    let content_type = content_type_for(path);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(body)
        .map(apply_security_headers)
        .ok()
}

fn content_type_for(path: &str) -> HeaderValue {
    if let Some(ext) = path.rsplit('.').next() {
        let mime = match ext {
            "html" => "text/html; charset=utf-8",
            "js" => "application/javascript; charset=utf-8",
            "css" => "text/css; charset=utf-8",
            "json" | "jsonl" => "application/json; charset=utf-8",
            _ => "application/octet-stream",
        };
        return HeaderValue::from_static(mime);
    }

    HeaderValue::from_static("application/octet-stream")
}

fn is_safe_path(path: &str) -> bool {
    let candidate = std::path::Path::new(path);
    candidate.components().all(|comp| matches!(comp, std::path::Component::Normal(_)))
}

fn not_found() -> Response {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("Not found"))
        .map(apply_security_headers)
        .unwrap_or_else(|_| internal_error())
}

fn internal_error() -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from("Internal server error"))
        .map(apply_security_headers)
        .unwrap()
}

fn apply_security_headers(response: Response) -> Response {
    let mut response = response;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'",
        ),
    );
    response
}

fn expand_tilde(path: &Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    if path_str == "~" || path_str.starts_with("~/") {
        let home = std::env::var("HOME")
            .context("Could not resolve home directory for tilde-expanded path")?;
        let trimmed = path_str.trim_start_matches("~/");
        return Ok(PathBuf::from(home).join(trimmed));
    }

    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::ensure_port_available;

    #[test]
    fn ensure_port_available_uses_passed_flag_name_in_error() {
        let listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("failed to bind local test port: {err}"),
        };
        let port = listener.local_addr().unwrap().port();

        let err = ensure_port_available(port, "127.0.0.1", "--view-report-port").unwrap_err();
        assert!(err.to_string().contains("--view-report-port <PORT>"));
    }
}

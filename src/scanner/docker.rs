use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use bollard::Docker as DockerClient;
use futures::TryStreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use oci_client::Reference;
use oci_client::client::{Client, ClientConfig, linux_amd64_resolver};
use oci_client::secrets::RegistryAuth;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tracing::debug;
use walkdir::WalkDir;

use crate::decompress::{CompressedContent, decompress_file_with_single_stream_cap_and_limits};

/// Docker/OCI image layers are often large tar streams. Keep this high enough
/// to avoid silently dropping scan coverage for normal base OS layers while
/// still bounding hostile compressed input.
// nosemgrep: this is the defensive cap — do not flag for missing-limit rules.
const MAX_DOCKER_SINGLE_STREAM_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("image is absent from the local Docker daemon")]
struct LocalImageAbsent;

#[derive(Debug, thiserror::Error)]
#[error("local Docker image was found but could not be exported")]
struct LocalImageExportFailed;

fn helper_get_creds(helper: &str, registry: &str) -> Option<(String, String)> {
    fn run(bin: &str, registry: &str) -> Option<(String, String)> {
        let mut child = Command::new(bin)
            .arg("get")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        {
            let stdin = child.stdin.as_mut()?;
            let _ = stdin.write_all(format!("{registry}\n").as_bytes());
        }
        let output = child.wait_with_output().ok()?;
        if !output.status.success() {
            return None;
        }
        let v: Value = serde_json::from_slice(&output.stdout).ok()?;
        let user = v.get("Username")?.as_str()?.to_string();
        let secret = v.get("Secret")?.as_str()?.to_string();
        Some((user, secret))
    }

    let bin = format!("docker-credential-{helper}");
    if let Some(creds) = run(&bin, registry) {
        return Some(creds);
    }
    if helper == "keychain"
        && bin != "docker-credential-osxkeychain"
        && let Some(creds) = run("docker-credential-osxkeychain", registry)
    {
        return Some(creds);
    }
    None
}

/// Turn `registry.example.com/foo/bar:latest` into something like
/// `registry.example.com_foo_bar_latest_4d3c9e83`
fn image_dir_name(reference: &str) -> String {
    // keep it readable
    let mut name = reference.replace(['/', ':'], "_");

    // Distinguish references that sanitize to the same readable name.
    let hash = Sha256::digest(reference.as_bytes());
    let short = &hex::encode(hash)[..8];
    name.push('_');
    name.push_str(short);
    name
}

fn archive_dir_name(path: &Path) -> String {
    image_dir_name(&path.display().to_string())
}

fn progress_bar(use_progress: bool) -> ProgressBar {
    if use_progress {
        let style =
            ProgressStyle::with_template("{spinner} {msg} {pos}/{len}").expect("progress template");
        let pb = ProgressBar::new(0).with_style(style);
        pb.enable_steady_tick(Duration::from_millis(100));
        pb
    } else {
        ProgressBar::hidden()
    }
}

fn tar_wrapped_intermediate_path(archive_path: &Path, out_dir: &Path) -> Option<PathBuf> {
    let filename = archive_path.file_name()?.to_str()?.to_ascii_lowercase();
    let is_tar_wrapped = filename.ends_with(".tgz")
        || filename.ends_with(".tar.gz")
        || filename.ends_with(".tar.gzip")
        || filename.ends_with(".tar.bz2")
        || filename.ends_with(".tar.bzip2")
        || filename.ends_with(".tar.xz");

    if !is_tar_wrapped {
        return None;
    }

    let stem = archive_path.file_stem()?;
    Some(out_dir.join(stem).with_extension("decomp.tar"))
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn push_manifest_layer(
    out_dir: &Path,
    layer_path: &str,
    layer_paths: &mut Vec<PathBuf>,
    seen: &mut HashSet<PathBuf>,
) -> Result<()> {
    let relative_path = Path::new(layer_path);
    if !is_safe_relative_path(relative_path) {
        return Err(anyhow!("unsafe Docker archive layer path {layer_path}"));
    }

    let path = out_dir.join(relative_path);
    if !path.is_file() {
        return Err(anyhow!("Docker archive layer {} was not found", path.display()));
    }

    if seen.insert(path.clone()) {
        layer_paths.push(path);
    }
    Ok(())
}

fn collect_docker_manifest_layers(
    out_dir: &Path,
    layer_paths: &mut Vec<PathBuf>,
    seen: &mut HashSet<PathBuf>,
) -> Result<()> {
    let manifest_path = out_dir.join("manifest.json");
    if !manifest_path.is_file() {
        return Ok(());
    }

    let manifest: Value = serde_json::from_reader(File::open(&manifest_path)?)
        .with_context(|| format!("parsing {}", manifest_path.display()))?;
    if let Some(images) = manifest.as_array() {
        for image in images {
            if let Some(layers) = image.get("Layers").and_then(|v| v.as_array()) {
                for layer in layers {
                    if let Some(layer_path) = layer.as_str() {
                        push_manifest_layer(out_dir, layer_path, layer_paths, seen)?;
                    }
                }
            }
        }
    }

    Ok(())
}

fn blob_path_from_digest(out_dir: &Path, digest: &str) -> Option<PathBuf> {
    let (algorithm, value) = digest.split_once(':')?;
    let relative_path = Path::new("blobs").join(algorithm).join(value);
    if is_safe_relative_path(&relative_path) { Some(out_dir.join(relative_path)) } else { None }
}

fn collect_oci_layers_from_value(
    out_dir: &Path,
    value: &Value,
    layer_paths: &mut Vec<PathBuf>,
    seen_layers: &mut HashSet<PathBuf>,
    seen_manifests: &mut HashSet<PathBuf>,
) -> Result<()> {
    if let Some(layers) = value.get("layers").and_then(|v| v.as_array()) {
        for layer in layers {
            if let Some(digest) = layer.get("digest").and_then(|v| v.as_str()) {
                let path = blob_path_from_digest(out_dir, digest)
                    .ok_or_else(|| anyhow!("invalid OCI layer digest {digest}"))?;
                if !path.is_file() {
                    return Err(anyhow!("OCI layer blob {} was not found", path.display()));
                }
                if seen_layers.insert(path.clone()) {
                    layer_paths.push(path);
                }
            }
        }
    }

    if let Some(manifests) = value.get("manifests").and_then(|v| v.as_array()) {
        for manifest in manifests {
            let is_attestation = manifest
                .get("annotations")
                .and_then(|v| v.get("vnd.docker.reference.type"))
                .and_then(|v| v.as_str())
                == Some("attestation-manifest");
            let is_unknown_platform =
                manifest.get("platform").and_then(|v| v.get("os")).and_then(|v| v.as_str())
                    == Some("unknown");
            if is_attestation || is_unknown_platform {
                continue;
            }

            if let Some(digest) = manifest.get("digest").and_then(|v| v.as_str()) {
                let path = blob_path_from_digest(out_dir, digest)
                    .ok_or_else(|| anyhow!("invalid OCI manifest digest {digest}"))?;
                if !path.is_file() || !seen_manifests.insert(path.clone()) {
                    continue;
                }
                let manifest_value: Value = serde_json::from_reader(File::open(&path)?)
                    .with_context(|| format!("parsing OCI manifest {}", path.display()))?;
                collect_oci_layers_from_value(
                    out_dir,
                    &manifest_value,
                    layer_paths,
                    seen_layers,
                    seen_manifests,
                )?;
            }
        }
    }

    Ok(())
}

fn collect_oci_layout_layers(
    out_dir: &Path,
    layer_paths: &mut Vec<PathBuf>,
    seen_layers: &mut HashSet<PathBuf>,
) -> Result<()> {
    let index_path = out_dir.join("index.json");
    if !index_path.is_file() {
        return Ok(());
    }

    let index: Value = serde_json::from_reader(File::open(&index_path)?)
        .with_context(|| format!("parsing {}", index_path.display()))?;
    let mut seen_manifests = HashSet::new();
    collect_oci_layers_from_value(out_dir, &index, layer_paths, seen_layers, &mut seen_manifests)
}

fn collect_saved_archive_layers(out_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut layer_paths = Vec::new();
    let mut seen = HashSet::new();

    collect_docker_manifest_layers(out_dir, &mut layer_paths, &mut seen)?;
    if layer_paths.is_empty() {
        collect_oci_layout_layers(out_dir, &mut layer_paths, &mut seen)?;
    }

    Ok(layer_paths)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn extension_for_extensionless_layer(path: &Path) -> Result<&'static str> {
    let mut file = File::open(path)?;
    let mut buf = [0_u8; 512];
    let len = file.read(&mut buf)?;

    if len >= 2 && buf[0] == 0x1f && buf[1] == 0x8b {
        return Ok("tar.gz");
    }
    if len >= 262 && &buf[257..262] == b"ustar" {
        return Ok("tar");
    }

    Err(anyhow!("unsupported Docker archive layer compression for {}", path.display()))
}

fn link_or_copy_layer(source: &Path, dest: &Path) -> Result<()> {
    match std::fs::hard_link(source, dest) {
        Ok(()) => Ok(()),
        Err(_) => {
            std::fs::copy(source, dest)?;
            Ok(())
        }
    }
}

fn remove_tar_wrapped_intermediate(path: &Path, out_dir: &Path) -> Result<()> {
    if let Some(intermediate) = tar_wrapped_intermediate_path(path, out_dir)
        && intermediate.exists()
    {
        std::fs::remove_file(intermediate)?;
    }
    Ok(())
}

/// Restore the logical Docker/OCI filesystem layout from the shared extractor's
/// per-occurrence storage. Docker consumers resolve manifests by their member
/// paths and apply layers in order; later occurrences replace earlier files.
/// Generic archive scanning still retains every occurrence independently.
fn extract_docker_filesystem(
    archive_path: &Path,
    out_dir: &Path,
    resources: crate::limits::ResourceLimits,
) -> Result<()> {
    // Stage on the same filesystem so hard links avoid copying large layer
    // blobs. The staging lifetime ends only after all members are materialized.
    let mut staging_builder = tempfile::Builder::new();
    staging_builder.prefix(".kingfisher-docker-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staging_builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let staging = staging_builder.tempdir_in(out_dir)?;
    let content = decompress_file_with_single_stream_cap_and_limits(
        archive_path,
        Some(staging.path()),
        MAX_DOCKER_SINGLE_STREAM_DECOMPRESSED_BYTES,
        resources,
    )?;
    let archive_prefix = format!("{}!", archive_path.display());
    let intermediate_prefix = tar_wrapped_intermediate_path(archive_path, staging.path())
        .map(|path| format!("{}!", path.display()));
    let relative_member = |logical: &str| -> Result<PathBuf> {
        // Strip the complete known label, rather than splitting on '!': caller
        // directory names may themselves contain the archive path delimiter.
        let name = logical
            .strip_prefix(&archive_prefix)
            .or_else(|| {
                intermediate_prefix.as_ref().and_then(|prefix| logical.strip_prefix(prefix))
            })
            .ok_or_else(|| anyhow!("Docker archive member has an unexpected source label"))?;
        let path = PathBuf::from(name);
        if !is_safe_relative_path(&path) {
            return Err(anyhow!("unsafe Docker archive member path"));
        }
        Ok(path)
    };
    match content {
        CompressedContent::ArchiveFiles(entries) => {
            for (logical, source) in entries {
                let destination = out_dir.join(relative_member(&logical)?);
                if let Some(parent) = destination.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                // Removing the destination before linking prevents two archived
                // occurrences from sharing one mutable inode. Handles are closed
                // by the extractor before this step, including on Windows.
                if destination.exists() {
                    std::fs::remove_file(&destination)?;
                }
                link_or_copy_layer(&source, &destination)?;
            }
        }
        CompressedContent::Archive(entries) => {
            for (logical, bytes) in entries {
                let destination = out_dir.join(relative_member(&logical)?);
                if let Some(parent) = destination.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                if destination.exists() {
                    std::fs::remove_file(&destination)?;
                }
                std::fs::write(destination, bytes)?;
            }
        }
        // Preserve the shared best-effort behavior for malformed/unsupported
        // layers. Their original archive bytes are handled by the caller.
        CompressedContent::Raw(_) | CompressedContent::RawFile(_) => {}
    }
    Ok(())
}

fn extract_layer_archive(
    path: &Path,
    out_dir: &Path,
    resources: crate::limits::ResourceLimits,
) -> Result<()> {
    let aliased_path;
    let layer_path = if path.extension().is_some() {
        path
    } else {
        let ext = extension_for_extensionless_layer(path)?;
        let digest = sha256_file(path)?;
        aliased_path = out_dir.join(format!("layer_{digest}.{ext}"));
        link_or_copy_layer(path, &aliased_path)?;
        &aliased_path
    };

    let result = extract_docker_filesystem(layer_path, out_dir, resources);
    let cleanup_result = if layer_path != path && layer_path.exists() {
        std::fs::remove_file(layer_path)
    } else {
        Ok(())
    };
    result?;
    cleanup_result?;
    remove_tar_wrapped_intermediate(layer_path, out_dir)?;

    if path.starts_with(out_dir) && path.exists() {
        std::fs::remove_file(path)?;
    }

    Ok(())
}

fn extract_saved_archive_layers(
    archive_path: &Path,
    out_dir: &Path,
    pb: &ProgressBar,
    resources: crate::limits::ResourceLimits,
) -> Result<usize> {
    pb.set_message("extracting layers");
    extract_docker_filesystem(archive_path, out_dir, resources)?;
    remove_tar_wrapped_intermediate(archive_path, out_dir)?;

    let layer_paths = collect_saved_archive_layers(out_dir)?;

    // Move every manifest-selected layer out before extracting any filesystem
    // members. A member named layer.tar may otherwise overwrite an archive or
    // be deleted by its cleanup, and one layer can shadow a later layer's path.
    let layers = tempfile::Builder::new()
        .prefix(".kingfisher-layers-")
        .tempdir_in(out_dir.parent().unwrap_or_else(|| Path::new(".")))?;
    let mut staged = Vec::with_capacity(layer_paths.len());
    for (index, path) in layer_paths.iter().enumerate() {
        let directory = layers.path().join(index.to_string());
        std::fs::create_dir(&directory)?;
        let destination = directory.join(path.file_name().context("Layer path has no filename")?);
        std::fs::rename(path, &destination)?;
        staged.push(destination);
    }
    pb.set_length(layer_paths.len() as u64);
    for p in &staged {
        extract_layer_archive(p, out_dir, resources)?;
        pb.inc(1);
    }

    Ok(layer_paths.len())
}

fn creds_from_docker_config(registry: &str) -> Option<(String, String)> {
    let config_dir = env::var("DOCKER_CONFIG")
        .map(PathBuf::from)
        .or_else(|_| env::var("HOME").map(|h| PathBuf::from(h).join(".docker")))
        .ok()?;
    let path = config_dir.join("config.json");
    let mut content = String::new();
    File::open(path).ok()?.read_to_string(&mut content).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;

    if let Some(ch) = json.get("credHelpers").and_then(|v| v.get(registry)).and_then(|v| v.as_str())
        && let Some(creds) = helper_get_creds(ch, registry)
    {
        return Some(creds);
    }
    if let Some(store) = json.get("credsStore").and_then(|v| v.as_str())
        && let Some(creds) = helper_get_creds(store, registry)
    {
        return Some(creds);
    }

    if let Some(auths) = json.get("auths").and_then(|v| v.as_object())
        && let Some(entry) = auths
            .get(registry)
            .or_else(|| auths.get(&format!("https://{registry}")))
            .or_else(|| auths.get(&format!("http://{registry}")))
        && let Some(auth) = entry.get("auth").and_then(|v| v.as_str())
    {
        let decoded = base64::engine::general_purpose::STANDARD.decode(auth).ok()?;
        let cred = String::from_utf8(decoded).ok()?;
        if let Some((u, p)) = cred.split_once(':') {
            return Some((u.to_string(), p.to_string()));
        }
    }
    None
}

fn registry_auth(reference: &Reference) -> RegistryAuth {
    if let Ok(token) = env::var("KF_DOCKER_TOKEN") {
        if let Some((user, pass)) = token.split_once(':') {
            return RegistryAuth::Basic(user.to_string(), pass.to_string());
        } else {
            return RegistryAuth::Bearer(token);
        }
    }
    if let Some((user, pass)) = creds_from_docker_config(reference.registry()) {
        RegistryAuth::Basic(user, pass)
    } else {
        RegistryAuth::Anonymous
    }
}

/// Resolve the endpoint before connecting: Bollard's defaults do not read Docker
/// contexts, and probing the default socket could scan an entirely different image.
fn docker_api_host(
    host: Option<&str>,
    context: Option<&str>,
    config_dir: Option<&Path>,
) -> Result<Option<String>> {
    if let Some(host) = host.filter(|value| !value.is_empty()) {
        return Ok(Some(host.to_owned()));
    }
    let context = context.filter(|value| !value.is_empty());

    let configured_context;
    let context = if let Some(context) = context {
        context
    } else if let Some(config_dir) = config_dir {
        configured_context = match std::fs::read(config_dir.join("config.json")) {
            Ok(bytes) => {
                let config: Value =
                    serde_json::from_slice(&bytes).context("reading Docker config")?;
                config.get("currentContext").and_then(Value::as_str).unwrap_or("default").to_owned()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => "default".to_owned(),
            Err(error) => return Err(error).context("reading Docker config"),
        };
        &configured_context
    } else {
        "default"
    };
    if context.is_empty() || context == "default" {
        return Ok(None);
    }

    let config_dir =
        config_dir.ok_or_else(|| anyhow!("Docker context directory is unavailable"))?;
    for entry in std::fs::read_dir(config_dir.join("contexts/meta"))? {
        let entry = entry?;
        let metadata = entry.path().join("meta.json");
        if !metadata.is_file() {
            continue;
        }
        let metadata: Value = serde_json::from_slice(&std::fs::read(metadata)?)?;
        if metadata.get("Name").and_then(Value::as_str) != Some(context) {
            continue;
        }
        let endpoint = metadata
            .get("Endpoints")
            .and_then(|endpoints| endpoints.get("docker"))
            .ok_or_else(|| anyhow!("Docker context {context} has no Docker endpoint"))?;
        let tls_dir = config_dir.join("contexts/tls").join(entry.file_name()).join("docker");
        if endpoint.get("SkipTLSVerify").and_then(Value::as_bool) == Some(true) || tls_dir.exists()
        {
            // The CLI knows how to apply context-specific certificate material
            // and verification settings; do not silently connect without them.
            return Err(anyhow!("Docker context {context} requires CLI TLS configuration"));
        }
        return endpoint
            .get("Host")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(|host| Some(host.to_owned()))
            .ok_or_else(|| anyhow!("Docker context {context} has no Docker endpoint"));
    }
    Err(anyhow!("Docker context {context} was not found"))
}

fn docker_api_client() -> Result<DockerClient> {
    // Let the CLI apply Docker's TLS settings and certificate material. Bollard
    // treats even an empty DOCKER_TLS_VERIFY as enabling verified TLS, unlike Docker.
    if ["DOCKER_API_VERSION", "DOCKER_TLS", "DOCKER_CERT_PATH"]
        .iter()
        .any(|name| env::var_os(name).is_some_and(|value| !value.is_empty()))
        || env::var_os("DOCKER_TLS_VERIFY").is_some()
    {
        return Err(anyhow!("Docker environment requires CLI connection configuration"));
    }
    let config_dir = env::var_os("DOCKER_CONFIG")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::home_dir().map(|home| home.join(".docker")));
    let host = docker_api_host(
        env::var("DOCKER_HOST").ok().as_deref(),
        env::var("DOCKER_CONTEXT").ok().as_deref(),
        config_dir.as_deref(),
    )?;
    let client = match host {
        Some(host) => DockerClient::connect_with_host(&host),
        None => DockerClient::connect_with_socket_defaults(),
    }?;
    Ok(client)
}

/// Publish only a completed local-image extraction. Failed attempts stay inside
/// their temporary directories, including partial tar downloads and extracted layers.
fn publish_local_image(staging: &Path, out_dir: &Path) -> Result<()> {
    prepare_image_directory(out_dir)?;
    for entry in WalkDir::new(staging).min_depth(1) {
        let entry = entry?;
        let destination = out_dir.join(entry.path().strip_prefix(staging)?);
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(destination)?;
        } else {
            if destination.exists() {
                std::fs::remove_file(&destination)?;
            }
            std::fs::rename(entry.path(), destination)?;
        }
    }
    Ok(())
}

fn prepare_image_directory(out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir)?;
    if std::fs::read_dir(out_dir)?.next().is_some() {
        return Err(anyhow!("Image output directory is not empty: {}", out_dir.display()));
    }
    Ok(())
}

pub struct Docker {
    resources: crate::limits::ResourceLimits,
}

impl Docker {
    #[cfg(test)]
    pub fn new() -> Self {
        Docker { resources: crate::limits::ResourceLimits::default() }
    }

    async fn try_save_local_image_via_api(
        &self,
        client: DockerClient,
        image: &str,
        out_dir: &Path,
        use_progress: bool,
    ) -> Result<()> {
        let client = client
            .with_timeout(Duration::from_secs(10))
            .negotiate_version()
            .await
            .context("negotiating Docker API version")?;
        match client.inspect_image(image).await {
            Ok(_) => {}
            Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => {
                return Err(LocalImageAbsent.into());
            }
            Err(error) => return Err(error).context("inspecting local Docker image"),
        }

        let pb = progress_bar(use_progress);
        pb.set_message(format!("saving local {image} via Docker API"));
        let result = async {
            let tar_path = out_dir.join("local_image.tar");
            let mut file = tokio::fs::File::create(&tar_path).await?;
            let client = client.with_timeout(Duration::from_secs(600));
            let mut stream = client.export_image(image);
            while let Some(bytes) =
                stream.try_next().await.context("exporting local Docker image")?
            {
                file.write_all(&bytes).await?;
            }
            file.flush().await?;
            // Close the archive before extraction/removal, including on Windows.
            drop(file);
            let count = extract_saved_archive_layers(&tar_path, out_dir, &pb, self.resources)?;
            if count == 0 {
                return Err(anyhow!("Docker API export did not contain image layers"));
            }
            Ok(())
        }
        .await;
        pb.finish_with_message(if result.is_ok() {
            format!("saved {image}")
        } else {
            "Docker API export failed".to_owned()
        });
        result.context(LocalImageExportFailed)
    }

    async fn try_save_local_image_with_fallback(
        &self,
        client: Result<DockerClient>,
        image: &str,
        out_dir: &Path,
        use_progress: bool,
        cli_save: impl FnOnce(&Path) -> Result<()>,
    ) -> Result<()> {
        let parent = out_dir.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let staging = tempfile::Builder::new().prefix(".kingfisher-image-").tempdir_in(parent)?;
        let api_result = match client {
            Ok(client) => {
                self.try_save_local_image_via_api(client, image, staging.path(), use_progress).await
            }
            Err(error) => Err(error),
        };
        let api_error = match api_result {
            Err(error) if error.is::<LocalImageAbsent>() => return Err(error),
            Ok(()) => return publish_local_image(staging.path(), out_dir),
            Err(error) => {
                debug!("Docker API lookup/export failed for {image}: {error:#}; trying CLI");
                error
            }
        };
        drop(staging);

        let staging = tempfile::Builder::new().prefix(".kingfisher-image-").tempdir_in(parent)?;
        if let Err(error) = cli_save(staging.path()) {
            if api_error.is::<LocalImageExportFailed>() {
                return Err(api_error)
                    .context(format!("Docker CLI fallback also failed: {error:#}"));
            }
            // Registry-only scanning still works when neither Docker surface is installed.
            let no_socket = matches!(
                api_error.downcast_ref::<bollard::errors::Error>(),
                Some(bollard::errors::Error::SocketNotFoundError(_))
            );
            let no_cli = error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound);
            if no_socket && no_cli {
                return Err(LocalImageAbsent.into());
            }
            return Err(error).context("Docker CLI lookup/export failed");
        }
        publish_local_image(staging.path(), out_dir)
    }

    fn try_save_local_image_via_cli(
        &self,
        image: &str,
        out_dir: &Path,
        use_progress: bool,
    ) -> Result<()> {
        let inspected = Command::new("docker")
            .args(["image", "inspect", "--", image])
            .output()
            .context("running docker image inspect")?;
        if !inspected.status.success() {
            let stderr = String::from_utf8_lossy(&inspected.stderr);
            if stderr
                .lines()
                .any(|line| line.starts_with("Error response from daemon: No such image:"))
            {
                return Err(LocalImageAbsent.into());
            }
            return Err(anyhow!("Docker image inspection failed: {}", stderr.trim()));
        }

        let pb = progress_bar(use_progress);
        pb.set_message(format!("saving local {image}"));

        std::fs::create_dir_all(out_dir)?;
        let tar_path = out_dir.join("local_image.tar");
        let status = Command::new("docker")
            .args(["image", "save", "-o"])
            .arg(&tar_path)
            .args(["--", image])
            .status()
            .with_context(|| "running docker save")?;
        if !status.success() {
            pb.finish_with_message("docker save failed");
            return Err(anyhow!("failed to save local image"));
        }

        extract_saved_archive_layers(&tar_path, out_dir, &pb, self.resources)?;

        pb.finish_with_message(format!("saved {image}"));
        Ok(())
    }

    pub fn save_archive_to_dir(
        &self,
        archive_path: &Path,
        out_dir: &Path,
        use_progress: bool,
    ) -> Result<()> {
        let pb = progress_bar(use_progress);
        pb.set_message(format!("extracting {}", archive_path.display()));

        std::fs::create_dir_all(out_dir)?;
        let layer_count = extract_saved_archive_layers(archive_path, out_dir, &pb, self.resources)?;
        if layer_count == 0 {
            pb.finish_with_message("no docker layers found");
            return Err(anyhow!(
                "archive {} did not contain Docker image layers",
                archive_path.display()
            ));
        }

        pb.finish_with_message(format!("extracted {}", archive_path.display()));
        Ok(())
    }

    pub async fn save_image_to_dir(
        &self,
        image: &str,
        out_dir: &Path,
        use_progress: bool,
    ) -> Result<()> {
        match self
            .try_save_local_image_with_fallback(
                docker_api_client(),
                image,
                out_dir,
                use_progress,
                |staging| self.try_save_local_image_via_cli(image, staging, use_progress),
            )
            .await
        {
            Ok(()) => return Ok(()),
            Err(error) if error.is::<LocalImageAbsent>() => {
                debug!("Image {image} is absent locally; trying OCI")
            }
            Err(error) => return Err(error).context(format!("saving local image {image}")),
        }
        let reference: Reference =
            image.parse().with_context(|| format!("invalid image reference {image}"))?;
        debug!("Pulling {image}");
        let pb = progress_bar(use_progress);
        pb.set_message(format!("pulling {image}"));
        let client = Client::new(ClientConfig {
            platform_resolver: Some(Box::new(linux_amd64_resolver)),
            ..Default::default()
        });
        let client = client;
        let auth = registry_auth(&reference);
        let accepted = vec![
            oci_client::manifest::IMAGE_LAYER_MEDIA_TYPE,
            oci_client::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
            oci_client::manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
            oci_client::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
        ];
        let pulled = client.pull(&reference, &auth, accepted).await?;
        pb.set_length(pulled.layers.len() as u64);
        pb.set_message("extracting layers");

        prepare_image_directory(out_dir)?;
        for layer in pulled.layers.into_iter() {
            let ext = match layer.media_type.as_str() {
                oci_client::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE
                | oci_client::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE => "tar.gz",
                oci_client::manifest::IMAGE_LAYER_MEDIA_TYPE
                | oci_client::manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE => "tar",
                _ => "bin",
            };
            let digest = layer.sha256_digest();
            let file_name = format!("layer_{}.{}", digest.replace(':', "_"), ext);
            let tmp_path = out_dir.join(file_name);
            let mut tmp = std::fs::File::create(&tmp_path)?;
            tmp.write_all(&layer.data)?;
            // Close before extraction/removal so the layer is readable and can
            // be removed on Windows without retaining a writer handle.
            drop(tmp);
            extract_docker_filesystem(&tmp_path, out_dir, self.resources)?;
            std::fs::remove_file(&tmp_path)?;
            pb.inc(1);
        }
        pb.finish_with_message(format!("saved {image}"));
        Ok(())
    }
}

pub async fn save_docker_images(
    images: &[String],
    clone_root: &Path,
    use_progress: bool,
    resources: crate::limits::ResourceLimits,
) -> Result<Vec<(PathBuf, String)>> {
    let docker = Docker { resources };
    let mut dirs = Vec::new();

    for image in images {
        let dir_name = image_dir_name(image);
        std::fs::create_dir_all(clone_root)?;
        let out_dir = tempfile::Builder::new()
            .prefix(&format!("docker_{dir_name}-"))
            .tempdir_in(clone_root)?;
        docker
            .save_image_to_dir(image, out_dir.path(), use_progress)
            .await
            .with_context(|| format!("saving image {image}"))?;
        dirs.push((out_dir.keep(), image.clone()));
    }

    Ok(dirs)
}

pub fn save_docker_archives(
    archives: &[PathBuf],
    clone_root: &Path,
    use_progress: bool,
    resources: crate::limits::ResourceLimits,
) -> Result<Vec<(PathBuf, String)>> {
    let docker = Docker { resources };
    let mut dirs = Vec::new();

    for archive in archives {
        let dir_name = archive_dir_name(archive);
        std::fs::create_dir_all(clone_root)?;
        let out_dir = tempfile::Builder::new()
            .prefix(&format!("docker_archive_{dir_name}-"))
            .tempdir_in(clone_root)?;
        let staging =
            tempfile::Builder::new().prefix(".kingfisher-image-").tempdir_in(clone_root)?;
        docker
            .save_archive_to_dir(archive, staging.path(), use_progress)
            .with_context(|| format!("extracting docker archive {}", archive.display()))?;
        publish_local_image(staging.path(), out_dir.path())?;
        dirs.push((out_dir.keep(), archive.display().to_string()));
    }

    Ok(dirs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use tempfile::tempdir;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path_regex},
    };

    #[test]
    fn docker_struct_new() {
        let _ = Docker::new();
    }

    fn append_bytes(tar: &mut tar::Builder<impl Write>, path: &str, data: &[u8]) -> Result<()> {
        let mut hdr = tar::Header::new_gnu();
        hdr.set_size(data.len() as u64);
        hdr.set_mode(0o644);
        hdr.set_cksum();
        tar.append_data(&mut hdr, path, data)?;
        Ok(())
    }

    fn build_layer_tar() -> Result<Vec<u8>> {
        let mut layer = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut layer);
            append_bytes(
                &mut tar,
                "app/secret.txt",
                // kingfisher:ignore (test fixture, not a real token)
                b"token=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\n",
            )?;
            tar.finish()?;
        }
        Ok(layer)
    }

    fn build_docker_archive(path: &Path, gzip: bool) -> Result<()> {
        let layer = build_layer_tar()?;
        let file = File::create(path)?;

        if gzip {
            let gz = GzEncoder::new(file, Compression::default());
            let mut tar = tar::Builder::new(gz);
            append_bytes(&mut tar, "manifest.json", br#"[{"Layers":["abc/layer.tar"]}]"#)?;
            append_bytes(&mut tar, "abc/layer.tar", &layer)?;
            tar.into_inner()?.finish()?;
        } else {
            let mut tar = tar::Builder::new(file);
            append_bytes(&mut tar, "manifest.json", br#"[{"Layers":["abc/layer.tar"]}]"#)?;
            append_bytes(&mut tar, "abc/layer.tar", &layer)?;
            tar.finish()?;
        }

        Ok(())
    }

    fn write_context(config_dir: &Path, name: &str, host: &str) -> Result<PathBuf> {
        let context_id = hex::encode(Sha256::digest(name.as_bytes()));
        let metadata_dir = config_dir.join("contexts/meta").join(&context_id);
        std::fs::create_dir_all(&metadata_dir)?;
        std::fs::write(
            metadata_dir.join("meta.json"),
            serde_json::to_vec(&serde_json::json!({
                "Name": name,
                "Endpoints": {"docker": {"Host": host, "SkipTLSVerify": false}},
            }))?,
        )?;
        Ok(config_dir.join("contexts/tls").join(context_id).join("docker"))
    }

    #[test]
    fn docker_api_host_honors_context_and_host_precedence() -> Result<()> {
        let dir = tempdir()?;
        let configured_host = "tcp://configured.example:2375";
        let explicit_host = "tcp://explicit.example:2375";
        write_context(dir.path(), "desktop", configured_host)?;
        std::fs::write(dir.path().join("config.json"), br#"{"currentContext":"desktop"}"#)?;

        assert_eq!(
            docker_api_host(None, None, Some(dir.path()))?,
            Some(configured_host.to_owned()),
        );
        assert_eq!(
            docker_api_host(Some(explicit_host), None, Some(dir.path()))?,
            Some(explicit_host.to_owned()),
        );
        assert_eq!(
            docker_api_host(Some(explicit_host), Some("desktop"), Some(dir.path()))?,
            Some(explicit_host.to_owned()),
        );
        // A nonempty DOCKER_HOST selects the default context before DOCKER_CONTEXT.
        assert_eq!(
            docker_api_host(Some(explicit_host), Some("default"), Some(dir.path()))?,
            Some(explicit_host.to_owned())
        );
        assert_eq!(docker_api_host(None, None, None)?, None);
        assert_eq!(docker_api_host(Some(""), Some(""), None)?, None);
        Ok(())
    }

    #[test]
    fn docker_api_host_delegates_context_tls_to_cli() -> Result<()> {
        let dir = tempdir()?;
        let tls_dir = write_context(dir.path(), "remote", "tcp://remote.example:2376")?;
        std::fs::create_dir_all(&tls_dir)?;
        std::fs::write(tls_dir.join("ca.pem"), b"context CA certificate")?;
        let error = docker_api_host(None, Some("remote"), Some(dir.path())).unwrap_err();
        assert!(error.to_string().contains("CLI TLS configuration"));
        Ok(())
    }

    #[test]
    fn docker_api_host_does_not_ignore_missing_or_invalid_contexts() -> Result<()> {
        let dir = tempdir()?;
        std::fs::write(dir.path().join("config.json"), br#"{"currentContext":"missing"}"#)?;
        assert!(docker_api_host(None, None, Some(dir.path())).is_err());
        std::fs::write(dir.path().join("config.json"), b"invalid JSON")?;
        assert!(docker_api_host(None, None, Some(dir.path())).is_err());
        Ok(())
    }

    #[test]
    fn docker_api_host_rejects_malformed_endpoints() -> Result<()> {
        let dir = tempdir()?;
        let metadata_dir = dir.path().join("contexts/meta/corrupt");
        std::fs::create_dir_all(&metadata_dir)?;
        let malformed = [
            serde_json::json!(null),
            serde_json::json!("corrupt"),
            serde_json::json!(true),
            serde_json::json!(42),
            serde_json::json!([]),
            serde_json::json!({}),
            serde_json::json!({"Host": ""}),
            serde_json::json!({"Host": 42}),
        ];
        for value in malformed {
            for endpoints in [value.clone(), serde_json::json!({"docker": value})] {
                std::fs::write(
                    metadata_dir.join("meta.json"),
                    serde_json::to_vec(&serde_json::json!({
                        "Name": "corrupt", "Endpoints": endpoints,
                    }))?,
                )?;
                let error = docker_api_host(None, Some("corrupt"), Some(dir.path())).unwrap_err();
                assert!(
                    error.to_string().contains("has no Docker endpoint"),
                    "unexpected error for {endpoints}: {error:#}",
                );
            }
        }
        Ok(())
    }

    async fn mock_docker_api(
        inspect_status: u16,
        export: ResponseTemplate,
    ) -> Result<(MockServer, DockerClient)> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^(/v[0-9.]+)?/version$"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"ApiVersion": "1.40"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^(/v[0-9.]+)?/images/local-test:latest/json$"))
            .respond_with(ResponseTemplate::new(inspect_status).set_body_json(serde_json::json!({
                "Id": "sha256:local-test", "message": "image not found",
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^(/v[0-9.]+)?/images/local-test:latest/get$"))
            .respond_with(export)
            .expect(u64::from(inspect_status == 200))
            .mount(&server)
            .await;
        let client =
            DockerClient::connect_with_http(&server.uri(), 10, bollard::API_DEFAULT_VERSION)?;
        Ok((server, client))
    }

    #[tokio::test]
    async fn local_image_absence_is_distinct_from_export_failure() -> Result<()> {
        let dir = tempdir()?;
        let (_server, client) = mock_docker_api(404, ResponseTemplate::new(500)).await?;
        let error = Docker::new()
            .try_save_local_image_with_fallback(
                Ok(client),
                "local-test:latest",
                &dir.path().join("out"),
                false,
                |_| panic!("confirmed absence needs no CLI export"),
            )
            .await
            .unwrap_err();
        assert!(error.is::<LocalImageAbsent>());
        let (_server, client) = mock_docker_api(200, ResponseTemplate::new(500)).await?;
        let error = Docker::new()
            .try_save_local_image_with_fallback(
                Ok(client),
                "local-test:latest",
                &dir.path().join("out"),
                false,
                |_| Err(LocalImageAbsent.into()),
            )
            .await
            .unwrap_err();
        assert!(error.is::<LocalImageExportFailed>());
        assert!(!error.is::<LocalImageAbsent>());
        Ok(())
    }

    #[test]
    fn publishing_local_image_preserves_existing_files() -> Result<()> {
        let dir = tempdir()?;
        let out = dir.path().join("out");
        let staging = dir.path().join("staging");
        std::fs::create_dir_all(&out)?;
        std::fs::create_dir_all(&staging)?;
        std::fs::write(out.join("stale-secret.txt"), b"old")?;
        std::fs::write(staging.join("current.txt"), b"new")?;
        assert!(publish_local_image(&staging, &out).is_err());
        assert_eq!(std::fs::read(out.join("stale-secret.txt"))?, b"old");
        assert!(!out.join("current.txt").exists());
        assert_eq!(std::fs::read(staging.join("current.txt"))?, b"new");
        Ok(())
    }

    #[test]
    fn layer_named_files_are_preserved_as_scan_inputs() -> Result<()> {
        let dir = tempdir()?;
        let archive = dir.path().join("image.tar");
        let mut layer = tar::Builder::new(Vec::new());
        append_bytes(&mut layer, "abc/layer.tar", b"token=inside-layer")?;
        let mut outer = tar::Builder::new(File::create(&archive)?);
        append_bytes(&mut outer, "manifest.json", br#"[{"Layers":["abc/layer.tar"]}]"#)?;
        append_bytes(&mut outer, "abc/layer.tar", &layer.into_inner()?)?;
        append_bytes(&mut outer, "unrelated/layer.tar", b"token=outer-file")?;
        outer.finish()?;
        drop(outer);
        let out = dir.path().join("out");
        Docker::new().save_archive_to_dir(&archive, &out, false)?;
        assert_eq!(std::fs::read(out.join("abc/layer.tar"))?, b"token=inside-layer");
        assert_eq!(std::fs::read(out.join("unrelated/layer.tar"))?, b"token=outer-file");
        Ok(())
    }

    #[tokio::test]
    async fn local_image_api_success_does_not_invoke_cli() -> Result<()> {
        let dir = tempdir()?;
        let archive = dir.path().join("image.tar");
        build_docker_archive(&archive, false)?;
        let (_server, client) = mock_docker_api(
            200,
            ResponseTemplate::new(200).set_body_bytes(std::fs::read(&archive)?),
        )
        .await?;
        let out = dir.path().join("out");
        Docker::new()
            .try_save_local_image_with_fallback(
                Ok(client),
                "local-test:latest",
                &out,
                false,
                |_| panic!("CLI must not be invoked after a successful API export"),
            )
            .await?;
        assert!(out.join("app/secret.txt").is_file());
        assert!(out.join("manifest.json").is_file());
        Ok(())
    }

    #[tokio::test]
    async fn local_image_api_failures_fall_back_to_cli() -> Result<()> {
        for inspect_status in [500, 200] {
            let dir = tempdir()?;
            let (_server, client) = mock_docker_api(
                inspect_status,
                ResponseTemplate::new(500)
                    .set_body_json(serde_json::json!({"message": "export failed"})),
            )
            .await?;
            let out = dir.path().join("out");
            let docker = Docker::new();
            let mut cli_called = false;
            docker
                .try_save_local_image_with_fallback(
                    Ok(client),
                    "local-test:latest",
                    &out,
                    false,
                    |staging| {
                        cli_called = true;
                        let archive = staging.join("local_image.tar");
                        build_docker_archive(&archive, false)?;
                        docker.save_archive_to_dir(&archive, staging, false)
                    },
                )
                .await?;
            assert!(cli_called);
            assert!(out.join("app/secret.txt").is_file());
        }
        Ok(())
    }

    #[tokio::test]
    async fn local_image_failed_api_extraction_does_not_contaminate_cli_result() -> Result<()> {
        let dir = tempdir()?;
        let mut broken_archive = tar::Builder::new(Vec::new());
        append_bytes(&mut broken_archive, "api-only.txt", b"failed API attempt")?;
        append_bytes(
            &mut broken_archive,
            "manifest.json",
            br#"[{"Layers":["missing/layer.tar"]}]"#,
        )?;
        let (_server, client) = mock_docker_api(
            200,
            ResponseTemplate::new(200).set_body_bytes(broken_archive.into_inner()?),
        )
        .await?;
        let out = dir.path().join("out");
        let docker = Docker::new();
        docker
            .try_save_local_image_with_fallback(
                Ok(client),
                "local-test:latest",
                &out,
                false,
                |staging| {
                    assert_eq!(std::fs::read_dir(staging)?.count(), 0);
                    let archive = staging.join("local_image.tar");
                    build_docker_archive(&archive, false)?;
                    docker.save_archive_to_dir(&archive, staging, false)
                },
            )
            .await?;
        assert!(out.join("app/secret.txt").is_file());
        assert!(!out.join("api-only.txt").exists());
        assert!(!std::fs::read_dir(dir.path())?.any(|entry| {
            entry.is_ok_and(|entry| {
                entry.file_name().to_string_lossy().starts_with(".kingfisher-image-")
            })
        }));
        Ok(())
    }

    #[tokio::test]
    async fn local_image_without_api_or_cli_leaves_no_partial_output() -> Result<()> {
        let dir = tempdir()?;
        let out = dir.path().join("out");
        let result = Docker::new()
            .try_save_local_image_with_fallback(
                Err(anyhow!("daemon unavailable")),
                "local-test:latest",
                &out,
                false,
                |staging| {
                    std::fs::write(staging.join("partial.tar"), b"partial CLI output")?;
                    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "docker CLI unavailable")
                        .into())
                },
            )
            .await;
        assert!(format!("{:#}", result.unwrap_err()).contains("docker CLI unavailable"));
        assert!(!out.exists());
        assert_eq!(std::fs::read_dir(dir.path())?.count(), 0);
        Ok(())
    }

    fn build_oci_layout_archive(path: &Path) -> Result<()> {
        let layer = build_layer_tar()?;
        let file = File::create(path)?;
        let gz = GzEncoder::new(Vec::new(), Compression::default());
        let mut layer_tar = tar::Builder::new(gz);
        append_bytes(
            &mut layer_tar,
            "app/secret.txt",
            // kingfisher:ignore (test fixture, not a real token)
            b"token=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\n",
        )?;
        let compressed_layer = layer_tar.into_inner()?.finish()?;

        let mut tar = tar::Builder::new(file);
        append_bytes(&mut tar, "oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#)?;
        append_bytes(
            &mut tar,
            "manifest.json",
            br#"[{"Config":"blobs/sha256/config","Layers":["blobs/sha256/layer"]}]"#,
        )?;
        append_bytes(&mut tar, "blobs/sha256/config", br#"{}"#)?;
        append_bytes(&mut tar, "blobs/sha256/layer", &compressed_layer)?;
        append_bytes(&mut tar, "blobs/sha256/unused", &layer)?;
        tar.finish()?;
        Ok(())
    }

    fn build_pure_oci_archive(path: &Path) -> Result<()> {
        let file = File::create(path)?;
        let gz = GzEncoder::new(Vec::new(), Compression::default());
        let mut layer_tar = tar::Builder::new(gz);
        // The token is a scanner test fixture.
        let secret = b"token=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\n"; // kingfisher:ignore
        append_bytes(&mut layer_tar, "app/secret.txt", secret)?;
        let compressed_layer = layer_tar.into_inner()?.finish()?;

        let mut tar = tar::Builder::new(file);
        append_bytes(&mut tar, "oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#)?;
        append_bytes(
            &mut tar,
            "index.json",
            br#"{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:manifest","platform":{"os":"linux","architecture":"amd64"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:attestation","platform":{"os":"unknown","architecture":"unknown"},"annotations":{"vnd.docker.reference.type":"attestation-manifest"}}]}"#,
        )?;
        append_bytes(
            &mut tar,
            "blobs/sha256/manifest",
            br#"{"schemaVersion":2,"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:layer"}]}"#,
        )?;
        append_bytes(
            &mut tar,
            "blobs/sha256/attestation",
            br#"{"schemaVersion":2,"layers":[{"mediaType":"application/vnd.in-toto+json","digest":"sha256:attestation-layer"}]}"#,
        )?;
        append_bytes(&mut tar, "blobs/sha256/layer", &compressed_layer)?;
        append_bytes(&mut tar, "blobs/sha256/attestation-layer", br#"{"predicate":{}}"#)?;
        tar.finish()?;
        Ok(())
    }

    #[test]
    fn save_archive_to_dir_extracts_docker_archive() -> Result<()> {
        let dir = tempdir()?;
        let archive = dir.path().join("image.tar");
        let out = dir.path().join("out");
        build_docker_archive(&archive, false)?;

        Docker::new().save_archive_to_dir(&archive, &out, false)?;

        assert!(out.join("app/secret.txt").exists());
        Ok(())
    }

    #[test]
    fn archive_scans_preserve_existing_and_previous_output_directories() -> Result<()> {
        let dir = tempdir()?;
        let archive = dir.path().join("image.tar");
        build_docker_archive(&archive, false)?;
        let clone_root = dir.path().join("scan output");
        let existing = clone_root.join(format!("docker_archive_{}", archive_dir_name(&archive)));
        std::fs::create_dir_all(&existing)?;
        std::fs::write(existing.join("caller.txt"), b"caller data")?;
        let resources = crate::limits::ResourceLimits::default();
        let first =
            save_docker_archives(std::slice::from_ref(&archive), &clone_root, false, resources)?;
        let second =
            save_docker_archives(std::slice::from_ref(&archive), &clone_root, false, resources)?;
        assert_ne!(first[0].0, second[0].0);
        for output in [first[0].0.as_path(), second[0].0.as_path()] {
            assert_ne!(output, existing);
            assert!(output.join("app/secret.txt").is_file());
        }
        assert_eq!(std::fs::read(existing.join("caller.txt"))?, b"caller data");
        Ok(())
    }

    #[test]
    fn save_archive_to_dir_extracts_gzipped_docker_archive() -> Result<()> {
        let dir = tempdir()?;
        let archive = dir.path().join("image.tar.gz");
        let out = dir.path().join("out");
        build_docker_archive(&archive, true)?;

        Docker::new().save_archive_to_dir(&archive, &out, false)?;

        assert!(out.join("app/secret.txt").exists());
        assert!(!out.join("image.decomp.tar").exists());
        Ok(())
    }

    #[test]
    fn save_archive_to_dir_extracts_oci_layout_archive() -> Result<()> {
        let dir = tempdir()?;
        let archive = dir.path().join("image.tar");
        let out = dir.path().join("out");
        build_oci_layout_archive(&archive)?;

        Docker::new().save_archive_to_dir(&archive, &out, false)?;

        assert!(out.join("app/secret.txt").exists());
        assert!(!out.join("blobs/sha256/layer").exists());
        Ok(())
    }

    #[test]
    fn save_archive_to_dir_extracts_pure_oci_archive() -> Result<()> {
        let dir = tempdir()?;
        let archive = dir.path().join("image.tar");
        let out = dir.path().join("out");
        build_pure_oci_archive(&archive)?;

        Docker::new().save_archive_to_dir(&archive, &out, false)?;

        assert!(out.join("app/secret.txt").exists());
        assert!(out.join("blobs/sha256/attestation-layer").exists());
        assert!(!out.join("blobs/sha256/layer").exists());
        Ok(())
    }
    #[test]
    fn docker_layout_restores_members_and_applies_duplicate_entries_in_order() -> Result<()> {
        let dir = tempdir()?;
        let root = dir.path().join("image!with delimiter");
        std::fs::create_dir_all(&root)?;
        let archive = root.join("image!backup.tar.gz");
        let out = root.join("output!directory");
        let mut layer = tar::Builder::new(Vec::new());
        append_bytes(&mut layer, "app/secret.txt", b"previous value")?;
        append_bytes(&mut layer, "app/secret.txt", b"current value")?;
        let layer_bytes = layer.into_inner()?;
        let gz = GzEncoder::new(File::create(&archive)?, Compression::default());
        let mut outer = tar::Builder::new(gz);
        append_bytes(&mut outer, "manifest.json", br#"[{"Layers":["abc/layer.tar"]}]"#)?;
        append_bytes(&mut outer, "abc/layer.tar", &layer_bytes)?;
        outer.into_inner()?.finish()?;

        Docker::new().save_archive_to_dir(&archive, &out, false)?;
        assert_eq!(std::fs::read(out.join("app/secret.txt"))?, b"current value");
        assert!(out.join("manifest.json").is_file());
        assert!(!out.join("abc/layer.tar").exists());
        assert!(!std::fs::read_dir(&out)?.any(|entry| entry.is_ok_and(|entry| {
            entry.file_name().to_string_lossy().starts_with(".kingfisher-docker-")
        })));
        Ok(())
    }
}

use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use indicatif::{ProgressBar, ProgressStyle};
use oci_client::Reference;
use oci_client::client::{Client, ClientConfig, linux_amd64_resolver};
use oci_client::secrets::RegistryAuth;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::debug;
use walkdir::WalkDir;

use crate::decompress::decompress_file_with_single_stream_cap;

/// Docker/OCI image layers are often large tar streams. Keep this high enough
/// to avoid silently dropping scan coverage for normal base OS layers while
/// still bounding hostile compressed input.
// nosemgrep: this is the defensive cap — do not flag for missing-limit rules.
const MAX_DOCKER_SINGLE_STREAM_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

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

    // add a truncated SHA-256 to guarantee uniqueness
    let hash = Sha256::digest(reference.as_bytes());
    let short = &hex::encode(hash)[..8]; // 8-char prefix is plenty
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

    for entry in WalkDir::new(out_dir) {
        let entry = entry?;
        if entry.file_name() == "layer.tar" {
            let path = entry.path().to_path_buf();
            if seen.insert(path.clone()) {
                layer_paths.push(path);
            }
        }
    }

    if layer_paths.is_empty() {
        collect_docker_manifest_layers(out_dir, &mut layer_paths, &mut seen)?;
    }
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

fn extract_layer_archive(path: &Path, out_dir: &Path) -> Result<()> {
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

    let result = decompress_file_with_single_stream_cap(
        layer_path,
        Some(out_dir),
        MAX_DOCKER_SINGLE_STREAM_DECOMPRESSED_BYTES,
    );
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
) -> Result<usize> {
    pb.set_message("extracting layers");
    decompress_file_with_single_stream_cap(
        archive_path,
        Some(out_dir),
        MAX_DOCKER_SINGLE_STREAM_DECOMPRESSED_BYTES,
    )?;
    remove_tar_wrapped_intermediate(archive_path, out_dir)?;

    let layer_paths = collect_saved_archive_layers(out_dir)?;

    pb.set_length(layer_paths.len() as u64);
    for p in &layer_paths {
        extract_layer_archive(p, out_dir)?;
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

pub struct Docker;

impl Docker {
    pub fn new() -> Self {
        Docker
    }

    fn try_save_local_image(&self, image: &str, out_dir: &Path, use_progress: bool) -> Result<()> {
        let docker = Command::new("docker")
            .args(["image", "inspect", image])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        if !matches!(docker, Ok(s) if s.success()) {
            return Err(anyhow!("image not local"));
        }

        let pb = progress_bar(use_progress);
        pb.set_message(format!("saving local {image}"));

        std::fs::create_dir_all(out_dir)?;
        let tar_path = out_dir.join("local_image.tar");
        let status = Command::new("docker")
            .args(["image", "save", image, "-o", &tar_path.to_string_lossy()])
            .status()
            .with_context(|| "running docker save")?;
        if !status.success() {
            pb.finish_with_message("docker save failed");
            return Err(anyhow!("failed to save local image"));
        }

        extract_saved_archive_layers(&tar_path, out_dir, &pb)?;

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
        let layer_count = extract_saved_archive_layers(archive_path, out_dir, &pb)?;
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
        if self.try_save_local_image(image, out_dir, use_progress).is_ok() {
            return Ok(());
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

        std::fs::create_dir_all(out_dir)?;
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
            decompress_file_with_single_stream_cap(
                &tmp_path,
                Some(out_dir),
                MAX_DOCKER_SINGLE_STREAM_DECOMPRESSED_BYTES,
            )?;
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
) -> Result<Vec<(PathBuf, String)>> {
    let docker = Docker::new();
    let mut dirs = Vec::new();

    for image in images {
        let dir_name = image_dir_name(image);
        let out_dir = clone_root.join(format!("docker_{dir_name}"));
        docker
            .save_image_to_dir(image, &out_dir, use_progress)
            .await
            .with_context(|| format!("saving image {image}"))?;
        dirs.push((out_dir, image.clone()));
    }

    Ok(dirs)
}

pub fn save_docker_archives(
    archives: &[PathBuf],
    clone_root: &Path,
    use_progress: bool,
) -> Result<Vec<(PathBuf, String)>> {
    let docker = Docker::new();
    let mut dirs = Vec::new();

    for archive in archives {
        let dir_name = archive_dir_name(archive);
        let out_dir = clone_root.join(format!("docker_archive_{dir_name}"));
        docker
            .save_archive_to_dir(archive, &out_dir, use_progress)
            .with_context(|| format!("extracting docker archive {}", archive.display()))?;
        dirs.push((out_dir, archive.display().to_string()));
    }

    Ok(dirs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use tempfile::tempdir;

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

    fn build_oci_layout_archive(path: &Path) -> Result<()> {
        let layer = build_layer_tar()?;
        let file = File::create(path)?;
        let gz = GzEncoder::new(Vec::new(), Compression::default());
        let mut layer_tar = tar::Builder::new(gz);
        append_bytes(
            &mut layer_tar,
            "app/secret.txt",
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
        append_bytes(
            &mut layer_tar,
            "app/secret.txt",
            b"token=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\n",
        )?;
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
}

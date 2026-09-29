use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use flate2::{Compression, write::GzEncoder};

const BUNDLE_MAGIC: &[u8] = b"KFVIEW\x01";

fn main() {
    #[cfg(feature = "gui")]
    build_wizard_icons();
    let viewer_dir = Path::new("docs/viewer");
    println!("cargo:rerun-if-changed={}", viewer_dir.display());
    emit_rerun_for_tree(viewer_dir);

    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR must be set"))
        .join("viewer-assets.gz");
    write_viewer_bundle(viewer_dir, &output)
        .expect("failed to create embedded viewer asset bundle");
}

fn emit_rerun_for_tree(path: &Path) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };

    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            emit_rerun_for_tree(&p);
            continue;
        }

        println!("cargo:rerun-if-changed={}", p.display());
    }
}

fn write_viewer_bundle(viewer_dir: &Path, output: &Path) -> std::io::Result<()> {
    let mut files = Vec::new();
    collect_files(viewer_dir, &mut files)?;
    files.sort();

    let mut encoder = GzEncoder::new(fs::File::create(output)?, Compression::best());
    encoder.write_all(BUNDLE_MAGIC)?;

    for path in files {
        let relative = path
            .strip_prefix(viewer_dir)
            .expect("viewer asset path must be under viewer directory");
        // Bundle paths are used as URL paths by the viewer, which always uses
        // forward slashes regardless of the platform that built the binary.
        let name = relative.to_str().expect("viewer asset paths must be UTF-8").replace('\\', "/");
        let contents = fs::read(&path)?;
        let name_len = u32::try_from(name.len()).expect("viewer asset path exceeds bundle limit");
        let contents_len =
            u64::try_from(contents.len()).expect("viewer asset file exceeds bundle limit");

        encoder.write_all(&name_len.to_le_bytes())?;
        encoder.write_all(&contents_len.to_le_bytes())?;
        encoder.write_all(name.as_bytes())?;
        encoder.write_all(&contents)?;
    }

    encoder.write_all(&0_u32.to_le_bytes())?;
    encoder.finish()?;
    Ok(())
}

fn collect_files(path: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(path)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files(&path, files)?;
        } else {
            files.push(path);
        }
    }
    Ok(())
}

/// Derive desktop icons from the existing logo, retaining its aspect ratio and alpha.
#[cfg(feature = "gui")]
fn build_wizard_icons() {
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    let logo = image::open("docs/viewer/kingfisher_logo.png")
        .expect("wizard logo must decode")
        .resize(512, 512, image::imageops::FilterType::Lanczos3)
        .to_rgba8();
    let mut icon = image::RgbaImage::new(512, 512);
    image::imageops::overlay(
        &mut icon,
        &logo,
        i64::from((512 - logo.width()) / 2),
        i64::from((512 - logo.height()) / 2),
    );
    icon.save(output.join("wizard-icon.png")).expect("could not write wizard icon");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let ico = output.join("wizard-icon.ico");
        image::DynamicImage::ImageRgba8(icon)
            .resize(256, 256, image::imageops::FilterType::Lanczos3)
            .save(&ico)
            .expect("could not write Windows icon");
        let resource = output.join("wizard.rc");
        fs::write(
            &resource,
            format!("1 ICON \"{}\"\n", ico.display().to_string().replace('\\', "/")),
        )
        .expect("could not write Windows icon resource");
        embed_resource::compile_for(&resource, ["kingfisher"], embed_resource::NONE)
            .manifest_optional()
            .expect("could not embed Windows wizard icon");
    }
}

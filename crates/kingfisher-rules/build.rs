use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use flate2::{Compression, write::GzEncoder};

const BUNDLE_MAGIC: &[u8] = b"KFRULES\x01";

fn main() {
    let data_dir = Path::new("data");
    println!("cargo:rerun-if-changed={}", data_dir.display());
    emit_rerun_for_tree(data_dir);

    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR must be set"))
        .join("builtin-rules.gz");
    write_rule_bundle(data_dir, &output).expect("failed to create embedded rule bundle");
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

fn write_rule_bundle(data_dir: &Path, output: &Path) -> std::io::Result<()> {
    let mut files = Vec::new();
    collect_yaml_files(data_dir, &mut files)?;
    files.sort();

    let mut encoder = GzEncoder::new(fs::File::create(output)?, Compression::best());
    encoder.write_all(BUNDLE_MAGIC)?;

    for path in files {
        let relative = path.strip_prefix(data_dir).expect("rule path must be under data directory");
        let name = relative.to_str().expect("builtin rule paths must be UTF-8");
        let contents = fs::read(&path)?;
        let name_len = u32::try_from(name.len()).expect("rule path exceeds bundle limit");
        let contents_len = u64::try_from(contents.len()).expect("rule file exceeds bundle limit");

        encoder.write_all(&name_len.to_le_bytes())?;
        encoder.write_all(&contents_len.to_le_bytes())?;
        encoder.write_all(name.as_bytes())?;
        encoder.write_all(&contents)?;
    }

    encoder.write_all(&0_u32.to_le_bytes())?;
    encoder.finish()?;
    Ok(())
}

fn collect_yaml_files(path: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(path)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_yaml_files(&path, files)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "yml" || extension == "yaml")
        {
            files.push(path);
        }
    }
    Ok(())
}

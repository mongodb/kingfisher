use std::{fs::File, io::BufReader, path::Path};

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;

/// Loads and deserializes a YAML file into a value of type `T`.
pub fn load_yaml_file<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<T> {
    let path = path.as_ref();
    let file = File::open(path)
        .with_context(|| format!("Failed to open YAML file: {}", path.display()))?;
    let reader = BufReader::new(file);
    let data = serde_yaml::from_reader(reader)
        .with_context(|| format!("Failed to parse YAML from file: {}", path.display()))?;
    Ok(data)
}

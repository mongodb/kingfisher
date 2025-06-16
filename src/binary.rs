use std::{fs, io::Read, path::Path};

use anyhow::Result;
use content_inspector::{inspect, ContentType};

use crate::util::is_safe_path;
const MAX_PEEK_SIZE: usize = 1024;
pub fn is_binary(data: &[u8]) -> bool {
    // Use content_inspector to determine if the data is binary
    matches!(inspect(&data[..std::cmp::min(data.len(), MAX_PEEK_SIZE)]), ContentType::BINARY)
}

pub fn is_binary_file(path: &Path) -> Result<bool> {
    if !is_safe_path(path)? {
        return Err(anyhow::anyhow!("Unsafe file path"));
    }

    let mut file = fs::File::open(path)?;

    let mut buffer = vec![0; 8192];
    let n = file.read(&mut buffer)?;
    buffer.truncate(n);
    Ok(is_binary(&buffer))
}

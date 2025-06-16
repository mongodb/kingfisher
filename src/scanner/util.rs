use std::path::Path;

use crate::decompress::ZIP_BASED_FORMATS;

pub fn is_compressed_file(path: &Path) -> bool {
    // Get the full filename
    let filename = match path.file_name().and_then(|s| s.to_str()) {
        Some(name) => name.to_lowercase(),
        None => return false,
    };
    // Check for compound extensions first
    if filename.ends_with(".tar.gz")
        || filename.ends_with(".tar.bz2")
        || filename.ends_with(".tar.xz")
    {
        return true;
    }
    // Then check single extensions
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        let ext_lower = ext.to_lowercase();
        ext_lower == "gz"
            || ext_lower == "tgz"
            || ext_lower == "bz2"
            || ext_lower == "xz"
            || ext_lower == "tar"
            || ext_lower == "zlib"
            || ext_lower == "asar"
            || ZIP_BASED_FORMATS.iter().any(|z| *z == ext)
    } else {
        false
    }
}

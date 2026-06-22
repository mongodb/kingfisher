use std::io::{self, Cursor, Read};
use std::path::Path;

use anyhow::{Context, Result, bail};
use tracing::debug;

const MAX_RECURSION_DEPTH: usize = 256;
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_COLLECTION_LEN: u32 = 1_000_000;

const FLAG_REF: u8 = 0x80;

const TYPE_NULL: u8 = b'0';
const TYPE_NONE: u8 = b'N';
const TYPE_FALSE: u8 = b'F';
const TYPE_TRUE: u8 = b'T';
const TYPE_STOPITER: u8 = b'S';
const TYPE_ELLIPSIS: u8 = b'.';
const TYPE_INT: u8 = b'i';
const TYPE_INT64: u8 = b'I';
const TYPE_FLOAT: u8 = b'f';
const TYPE_BINARY_FLOAT: u8 = b'g';
const TYPE_COMPLEX: u8 = b'x';
const TYPE_BINARY_COMPLEX: u8 = b'y';
const TYPE_LONG: u8 = b'l';
const TYPE_STRING: u8 = b's';
const TYPE_INTERNED: u8 = b't';
const TYPE_REF: u8 = b'r';
const TYPE_TUPLE: u8 = b'(';
const TYPE_LIST: u8 = b'[';
const TYPE_DICT: u8 = b'{';
const TYPE_CODE: u8 = b'c';
const TYPE_UNICODE: u8 = b'u';
const TYPE_SET: u8 = b'<';
const TYPE_FROZENSET: u8 = b'>';
const TYPE_ASCII: u8 = b'a';
const TYPE_ASCII_INTERNED: u8 = b'A';
const TYPE_SMALL_TUPLE: u8 = b')';
const TYPE_SHORT_ASCII: u8 = b'z';
const TYPE_SHORT_ASCII_INTERNED: u8 = b'Z';

/// Code object layout varies by Python version.
#[derive(Debug, Clone, Copy)]
enum CodeFormat {
    /// Python 3.3-3.7: 5 leading i32s, 8 objects, 1 i32, 1 object
    V33,
    /// Python 3.8-3.10: 6 leading i32s, 8 objects, 1 i32, 1 object
    V38,
    /// Python 3.11-3.12: 5 leading i32s, 9 objects, 1 i32, 2 objects
    V311,
    /// Python 3.13+: 5 leading i32s, 8 objects, 1 i32, 2 objects
    /// (varnames/freevars/cellvars replaced by localsplusnames/localspluskinds)
    V313,
}

impl CodeFormat {
    fn leading_longs(self) -> usize {
        match self {
            CodeFormat::V33 => 5,
            CodeFormat::V38 => 6,
            CodeFormat::V311 | CodeFormat::V313 => 5,
        }
    }

    fn middle_objects(self) -> usize {
        match self {
            CodeFormat::V33 | CodeFormat::V38 | CodeFormat::V313 => 8,
            CodeFormat::V311 => 9,
        }
    }

    fn trailing_objects(self) -> usize {
        match self {
            CodeFormat::V33 | CodeFormat::V38 => 1,
            CodeFormat::V311 | CodeFormat::V313 => 2,
        }
    }
}

/// Determine the header size and code format from the 2-byte magic number.
fn pyc_version_info(magic: u16) -> Option<(usize, CodeFormat)> {
    match magic {
        // Python 3.0-3.2: 8-byte header
        3000..=3189 => Some((8, CodeFormat::V33)),
        // Python 3.3-3.6: 12-byte header
        3190..=3379 => Some((12, CodeFormat::V33)),
        // Python 3.7: 16-byte header, same code format as 3.3
        3380..=3399 => Some((16, CodeFormat::V33)),
        // Python 3.8-3.10: 16-byte header
        3400..=3494 => Some((16, CodeFormat::V38)),
        // Python 3.11-3.12: 16-byte header
        3495..=3567 => Some((16, CodeFormat::V311)),
        // Python 3.13+: 16-byte header, changed code object layout
        3568..=3700 => Some((16, CodeFormat::V313)),
        _ => None,
    }
}

struct MarshalReader<'a> {
    cursor: Cursor<&'a [u8]>,
    code_format: CodeFormat,
    refs: Vec<()>,
    strings: Vec<u8>,
    total_extracted: usize,
    depth: usize,
}

impl<'a> MarshalReader<'a> {
    fn new(data: &'a [u8], code_format: CodeFormat) -> Self {
        Self {
            cursor: Cursor::new(data),
            code_format,
            refs: Vec::new(),
            strings: Vec::new(),
            total_extracted: 0,
            depth: 0,
        }
    }

    fn read_u8(&mut self) -> io::Result<u8> {
        let mut buf = [0u8; 1];
        self.cursor.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_i32(&mut self) -> io::Result<i32> {
        let mut buf = [0u8; 4];
        self.cursor.read_exact(&mut buf)?;
        Ok(i32::from_le_bytes(buf))
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        self.read_i32().map(|v| v as u32)
    }

    fn read_bytes(&mut self, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.cursor.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn skip(&mut self, n: usize) -> io::Result<()> {
        let mut remaining = n;
        let mut buf = [0u8; 512];
        while remaining > 0 {
            let to_read = remaining.min(buf.len());
            self.cursor.read_exact(&mut buf[..to_read])?;
            remaining -= to_read;
        }
        Ok(())
    }

    fn collect_string(&mut self, data: &[u8]) {
        if self.total_extracted >= MAX_TOTAL_BYTES {
            return;
        }
        if data.is_empty() {
            return;
        }
        if !self.strings.is_empty() {
            self.strings.push(b'\n');
            self.total_extracted += 1;
        }
        let allowed = MAX_TOTAL_BYTES.saturating_sub(self.total_extracted);
        let take = data.len().min(allowed);
        self.strings.extend_from_slice(&data[..take]);
        self.total_extracted += take;
    }

    fn read_object(&mut self) -> Result<()> {
        if self.depth > MAX_RECURSION_DEPTH {
            bail!("marshal recursion depth exceeded");
        }
        self.depth += 1;
        let result = self.read_object_inner();
        self.depth -= 1;
        result
    }

    fn read_object_inner(&mut self) -> Result<()> {
        let raw_type = self.read_u8().context("unexpected EOF reading type byte")?;
        let type_byte = raw_type & !FLAG_REF;
        let is_ref = raw_type & FLAG_REF != 0;

        if is_ref {
            self.refs.push(());
        }

        match type_byte {
            TYPE_NULL | TYPE_NONE | TYPE_STOPITER | TYPE_ELLIPSIS | TYPE_TRUE | TYPE_FALSE => {}

            TYPE_INT => {
                self.skip(4)?;
            }

            TYPE_INT64 => {
                self.skip(8)?;
            }

            TYPE_FLOAT => {
                let n = self.read_u8()? as usize;
                self.skip(n)?;
            }

            TYPE_BINARY_FLOAT => {
                self.skip(8)?;
            }

            TYPE_COMPLEX => {
                let n1 = self.read_u8()? as usize;
                self.skip(n1)?;
                let n2 = self.read_u8()? as usize;
                self.skip(n2)?;
            }

            TYPE_BINARY_COMPLEX => {
                self.skip(16)?;
            }

            TYPE_LONG => {
                let n = self.read_i32()?;
                let words = n.unsigned_abs() as usize;
                if words as u32 > MAX_COLLECTION_LEN {
                    bail!("long size {words} exceeds collection limit");
                }
                let bytes = words.checked_mul(2).context("long size overflow")?;
                if bytes > MAX_TOTAL_BYTES {
                    bail!("long size {bytes} exceeds total bytes limit");
                }
                self.skip(bytes)?;
            }

            TYPE_STRING | TYPE_INTERNED => {
                let len = self.read_u32()? as usize;
                if len > MAX_TOTAL_BYTES {
                    bail!("string length {len} exceeds limit");
                }
                let data = self.read_bytes(len)?;
                self.collect_string(&data);
            }

            TYPE_UNICODE => {
                let len = self.read_u32()? as usize;
                if len > MAX_TOTAL_BYTES {
                    bail!("unicode length {len} exceeds limit");
                }
                let data = self.read_bytes(len)?;
                self.collect_string(&data);
            }

            TYPE_ASCII | TYPE_ASCII_INTERNED => {
                let len = self.read_u32()? as usize;
                if len > MAX_TOTAL_BYTES {
                    bail!("ascii length {len} exceeds limit");
                }
                let data = self.read_bytes(len)?;
                self.collect_string(&data);
            }

            TYPE_SHORT_ASCII | TYPE_SHORT_ASCII_INTERNED => {
                let len = self.read_u8()? as usize;
                let data = self.read_bytes(len)?;
                self.collect_string(&data);
            }

            TYPE_REF => {
                self.skip(4)?;
            }

            TYPE_TUPLE => {
                let n = self.read_u32()?;
                if n > MAX_COLLECTION_LEN {
                    bail!("tuple length {n} exceeds limit");
                }
                for _ in 0..n {
                    self.read_object()?;
                }
            }

            TYPE_SMALL_TUPLE => {
                let n = self.read_u8()? as u32;
                for _ in 0..n {
                    self.read_object()?;
                }
            }

            TYPE_LIST => {
                let n = self.read_u32()?;
                if n > MAX_COLLECTION_LEN {
                    bail!("list length {n} exceeds limit");
                }
                for _ in 0..n {
                    self.read_object()?;
                }
            }

            TYPE_SET | TYPE_FROZENSET => {
                let n = self.read_u32()?;
                if n > MAX_COLLECTION_LEN {
                    bail!("set length {n} exceeds limit");
                }
                for _ in 0..n {
                    self.read_object()?;
                }
            }

            TYPE_DICT => {
                loop {
                    let peek = self.read_u8()?;
                    if peek == TYPE_NULL {
                        break;
                    }
                    // Put the byte back by seeking
                    let pos = self.cursor.position();
                    self.cursor.set_position(pos - 1);
                    self.read_object()?;
                    self.read_object()?;
                }
            }

            TYPE_CODE => {
                self.read_code_object()?;
            }

            other => {
                debug!("unknown marshal type byte 0x{other:02x}, stopping parse");
                bail!("unknown marshal type 0x{other:02x}");
            }
        }

        Ok(())
    }

    fn read_code_object(&mut self) -> Result<()> {
        let fmt = self.code_format;

        for _ in 0..fmt.leading_longs() {
            self.skip(4)?;
        }
        for _ in 0..fmt.middle_objects() {
            self.read_object()?;
        }
        // firstlineno
        self.skip(4)?;
        for _ in 0..fmt.trailing_objects() {
            self.read_object()?;
        }

        Ok(())
    }
}

/// Extract all string constants from a `.pyc` file.
///
/// Returns the extracted strings concatenated with newlines, suitable for
/// scanning. Returns an empty vec if the file contains no extractable strings.
pub fn extract_pyc_strings(path: &Path) -> Result<Vec<u8>> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read .pyc file: {}", path.display()))?;

    if data.len() < 8 {
        bail!("file too small to be a valid .pyc: {} bytes", data.len());
    }

    let magic = u16::from_le_bytes([data[0], data[1]]);
    // Bytes 2-3 should be \r\n
    if data[2] != b'\r' || data[3] != b'\n' {
        bail!("invalid .pyc magic suffix (expected \\r\\n)");
    }

    let (header_size, code_format) = match pyc_version_info(magic) {
        Some(info) => info,
        None => {
            debug!("unsupported .pyc magic number {magic} in {}, skipping", path.display());
            return Ok(Vec::new());
        }
    };

    if data.len() < header_size {
        bail!(".pyc header requires {header_size} bytes but file is only {} bytes", data.len());
    }

    let marshal_data = &data[header_size..];
    if marshal_data.is_empty() {
        return Ok(Vec::new());
    }

    let mut reader = MarshalReader::new(marshal_data, code_format);
    match reader.read_object() {
        Ok(()) => {}
        Err(e) => {
            debug!(
                "marshal parse error in {} (extracted {} bytes before error): {e:#}",
                path.display(),
                reader.strings.len()
            );
        }
    }

    Ok(reader.strings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pyc_header(magic: u16, header_size: usize) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&magic.to_le_bytes());
        header.push(b'\r');
        header.push(b'\n');
        // Fill remaining header bytes with zeros
        header.resize(header_size, 0);
        header
    }

    fn marshal_short_ascii(s: &str) -> Vec<u8> {
        assert!(s.len() < 256);
        let mut buf = Vec::new();
        buf.push(TYPE_SHORT_ASCII);
        buf.push(s.len() as u8);
        buf.extend_from_slice(s.as_bytes());
        buf
    }

    fn marshal_ascii(s: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(TYPE_ASCII);
        buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
        buf.extend_from_slice(s.as_bytes());
        buf
    }

    fn marshal_unicode(s: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(TYPE_UNICODE);
        buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
        buf.extend_from_slice(s.as_bytes());
        buf
    }

    fn marshal_none() -> Vec<u8> {
        vec![TYPE_NONE]
    }

    fn marshal_int(val: i32) -> Vec<u8> {
        let mut buf = vec![TYPE_INT];
        buf.extend_from_slice(&val.to_le_bytes());
        buf
    }

    fn marshal_long(words: i32) -> Vec<u8> {
        let mut buf = vec![TYPE_LONG];
        buf.extend_from_slice(&words.to_le_bytes());
        buf
    }

    fn marshal_small_tuple(items: &[Vec<u8>]) -> Vec<u8> {
        assert!(items.len() < 256);
        let mut buf = Vec::new();
        buf.push(TYPE_SMALL_TUPLE);
        buf.push(items.len() as u8);
        for item in items {
            buf.extend_from_slice(item);
        }
        buf
    }

    fn marshal_tuple(items: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(TYPE_TUPLE);
        buf.extend_from_slice(&(items.len() as u32).to_le_bytes());
        for item in items {
            buf.extend_from_slice(item);
        }
        buf
    }

    fn marshal_string(s: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(TYPE_STRING);
        buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
        buf.extend_from_slice(s);
        buf
    }

    /// Build a minimal Python 3.8 code object with the given consts tuple.
    fn marshal_code_38(consts: Vec<u8>, names: Vec<u8>) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(TYPE_CODE);
        // 6 leading i32s (argcount, posonlyargcount, kwonlyargcount, nlocals,
        // stacksize, flags)
        for _ in 0..6 {
            buf.extend_from_slice(&0i32.to_le_bytes());
        }
        // 8 middle objects: code, consts, names, varnames, freevars, cellvars,
        // filename, name
        buf.extend_from_slice(&marshal_string(b"")); // code (bytecode)
        buf.extend_from_slice(&consts); // consts
        buf.extend_from_slice(&names); // names
        buf.extend_from_slice(&marshal_small_tuple(&[])); // varnames
        buf.extend_from_slice(&marshal_small_tuple(&[])); // freevars
        buf.extend_from_slice(&marshal_small_tuple(&[])); // cellvars
        buf.extend_from_slice(&marshal_short_ascii("<test>")); // filename
        buf.extend_from_slice(&marshal_short_ascii("<module>")); // name
        // firstlineno
        buf.extend_from_slice(&1i32.to_le_bytes());
        // 1 trailing object: lnotab
        buf.extend_from_slice(&marshal_string(b""));
        buf
    }

    #[test]
    fn extracts_short_ascii_string() {
        let mut data = make_pyc_header(3413, 16); // Python 3.8
        data.extend_from_slice(&marshal_short_ascii("secret_api_key_12345"));
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path()).unwrap();
        assert_eq!(result, b"secret_api_key_12345");
    }

    #[test]
    fn extracts_ascii_string() {
        let mut data = make_pyc_header(3413, 16);
        data.extend_from_slice(&marshal_ascii("AKIAIOSFODNN7EXAMPLE"));
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path()).unwrap();
        assert_eq!(result, b"AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn extracts_unicode_string() {
        let mut data = make_pyc_header(3413, 16);
        data.extend_from_slice(&marshal_unicode("password=hunter2"));
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path()).unwrap();
        assert_eq!(result, b"password=hunter2");
    }

    #[test]
    fn extracts_strings_from_tuple() {
        let mut data = make_pyc_header(3413, 16);
        let tuple = marshal_small_tuple(&[
            marshal_none(),
            marshal_short_ascii("first"),
            marshal_int(42),
            marshal_short_ascii("second"),
        ]);
        data.extend_from_slice(&tuple);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path()).unwrap();
        assert_eq!(result, b"first\nsecond");
    }

    #[test]
    fn extracts_strings_from_code_object() {
        let mut data = make_pyc_header(3413, 16);
        let consts =
            marshal_small_tuple(&[marshal_none(), marshal_short_ascii("ghp_abc123def456")]);
        let names = marshal_small_tuple(&[marshal_short_ascii("api_key")]);
        let code = marshal_code_38(consts, names);
        data.extend_from_slice(&code);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path()).unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("ghp_abc123def456"), "missing secret from consts");
        assert!(result_str.contains("api_key"), "missing name");
    }

    #[test]
    fn handles_large_tuple() {
        let mut data = make_pyc_header(3413, 16);
        let items: Vec<Vec<u8>> =
            (0..50).map(|i| marshal_short_ascii(&format!("item_{i}"))).collect();
        let tuple = marshal_tuple(&items);
        data.extend_from_slice(&tuple);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path()).unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("item_0"));
        assert!(result_str.contains("item_49"));
    }

    #[test]
    fn handles_python_33_header() {
        let mut data = make_pyc_header(3230, 12); // Python 3.3
        data.extend_from_slice(&marshal_short_ascii("py33_secret"));
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path()).unwrap();
        assert_eq!(result, b"py33_secret");
    }

    #[test]
    fn handles_python_37_header() {
        let mut data = make_pyc_header(3394, 16); // Python 3.7
        data.extend_from_slice(&marshal_short_ascii("py37_secret"));
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path()).unwrap();
        assert_eq!(result, b"py37_secret");
    }

    #[test]
    fn handles_python_311_header() {
        let mut data = make_pyc_header(3495, 16); // Python 3.11
        data.extend_from_slice(&marshal_short_ascii("py311_secret"));
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path()).unwrap();
        assert_eq!(result, b"py311_secret");
    }

    #[test]
    fn rejects_file_too_small() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), [0u8; 4]).unwrap();
        let result = extract_pyc_strings(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn rejects_bad_magic_suffix() {
        let mut data = vec![0x00, 0x0D, 0x00, 0x00]; // wrong suffix
        data.resize(16, 0);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn ignores_overlarge_long_objects() {
        let mut data = make_pyc_header(3413, 16);
        data.extend_from_slice(&marshal_long(i32::MIN));
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();

        let result = extract_pyc_strings(tmp.path()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn skips_unknown_magic() {
        let mut data = vec![0x00, 0x00, b'\r', b'\n'];
        data.resize(16, 0);
        data.extend_from_slice(&marshal_short_ascii("should_not_appear"));
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn handles_empty_marshal_data() {
        let data = make_pyc_header(3413, 16);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn handles_flag_ref_bit() {
        let mut data = make_pyc_header(3413, 16);
        // Short ASCII with FLAG_REF set
        data.push(TYPE_SHORT_ASCII | FLAG_REF);
        data.push(5);
        data.extend_from_slice(b"hello");
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path()).unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn handles_nested_tuples() {
        let mut data = make_pyc_header(3413, 16);
        let inner = marshal_small_tuple(&[marshal_short_ascii("inner_secret")]);
        let outer = marshal_small_tuple(&[marshal_short_ascii("outer"), inner]);
        data.extend_from_slice(&outer);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path()).unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("outer"));
        assert!(result_str.contains("inner_secret"));
    }

    #[test]
    fn handles_type_string_bytes() {
        let mut data = make_pyc_header(3413, 16);
        data.extend_from_slice(&marshal_string(b"raw_bytes_secret"));
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path()).unwrap();
        assert_eq!(result, b"raw_bytes_secret");
    }

    /// Build a minimal Python 3.13+ code object (8 middle objects instead of 9).
    fn marshal_code_313(consts: Vec<u8>, names: Vec<u8>) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(TYPE_CODE);
        // 5 leading i32s (argcount, posonlyargcount, kwonlyargcount, stacksize,
        // flags)
        for _ in 0..5 {
            buf.extend_from_slice(&0i32.to_le_bytes());
        }
        // 8 middle objects: code, consts, names, localsplusnames,
        // localspluskinds, filename, name, qualname
        buf.extend_from_slice(&marshal_string(b"")); // code
        buf.extend_from_slice(&consts); // consts
        buf.extend_from_slice(&names); // names
        buf.extend_from_slice(&marshal_small_tuple(&[])); // localsplusnames
        buf.extend_from_slice(&marshal_string(b"")); // localspluskinds
        buf.extend_from_slice(&marshal_short_ascii("<test>")); // filename
        buf.extend_from_slice(&marshal_short_ascii("<module>")); // name
        buf.extend_from_slice(&marshal_short_ascii("<module>")); // qualname
        // firstlineno
        buf.extend_from_slice(&1i32.to_le_bytes());
        // 2 trailing objects: linetable, exceptiontable
        buf.extend_from_slice(&marshal_string(b""));
        buf.extend_from_slice(&marshal_string(b""));
        buf
    }

    #[test]
    fn extracts_strings_from_code_object_v313() {
        let mut data = make_pyc_header(3627, 16); // Python 3.14
        let consts =
            marshal_small_tuple(&[marshal_none(), marshal_short_ascii("sk-proj-ABCDEF123456")]);
        let names = marshal_small_tuple(&[marshal_short_ascii("openai_key")]);
        let code = marshal_code_313(consts, names);
        data.extend_from_slice(&code);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let result = extract_pyc_strings(tmp.path()).unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("sk-proj-ABCDEF123456"), "missing secret from consts");
        assert!(result_str.contains("openai_key"), "missing name");
        assert!(result_str.contains("<test>"), "missing filename");
    }

    #[test]
    fn extracts_from_real_pyc() {
        use std::process::Command;
        let python = Command::new("python3").arg("--version").output();
        if python.is_err() {
            return; // skip if python3 not available
        }
        let tmp_dir = tempfile::tempdir().unwrap();
        let py_path = tmp_dir.path().join("test_secrets.py");
        let pyc_path = tmp_dir.path().join("test_secrets.pyc");
        std::fs::write(
            &py_path,
            "DB_PASSWORD = 'xK9#mP2$vL5nQ8wR'\nAPI_ENDPOINT = 'https://api.example.com/v1'\n",
        )
        .unwrap();
        let status = Command::new("python3")
            .args([
                "-c",
                &format!(
                    "import py_compile; py_compile.compile('{}', cfile='{}')",
                    py_path.display(),
                    pyc_path.display()
                ),
            ])
            .status();
        if status.is_err() || !status.unwrap().success() {
            return; // skip if compilation fails
        }
        let result = extract_pyc_strings(&pyc_path).unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(
            result_str.contains("DB_PASSWORD") || result_str.contains("xK9#mP2$vL5nQ8wR"),
            "expected to find secret string in extracted pyc content, got: {result_str}"
        );
    }
}

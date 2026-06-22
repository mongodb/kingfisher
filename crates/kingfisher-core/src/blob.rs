//! Blob representation for scannable content.
//!
//! A [`Blob`] represents content that can be scanned for secrets. It can be
//! created from:
//! - In-memory bytes ([`Blob::from_bytes`])
//! - A file path ([`Blob::from_file`])
//! - Borrowed data ([`Blob::from_borrowed`])
//!
//! Large files are automatically memory-mapped for efficiency.

use std::{
    borrow::Cow,
    convert::TryInto,
    fs::File,
    io::Read,
    path::Path,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use bstr::{BString, ByteSlice};
use gix::ObjectId;
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha1::{Digest, Sha1};
use smallvec::SmallVec;

use crate::error::Result;
use crate::git_commit_metadata::CommitMetadata;

/// Threshold above which files are memory-mapped instead of read into memory.
const LARGE_FILE_THRESHOLD: u64 = 0; // Currently: always mmap

/// Global counter for temporary blob IDs.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Tracks where a blob was seen in git history.
#[derive(Clone, Debug, serde::Serialize)]
pub struct BlobAppearance {
    /// Metadata about the commit where this blob appeared.
    pub commit_metadata: Arc<CommitMetadata>,

    /// The path of the blob within the repository.
    pub path: BString,
}

impl BlobAppearance {
    /// Returns the path as a `&Path`, if it's valid UTF-8.
    #[inline]
    pub fn path(&self) -> std::result::Result<&Path, bstr::Utf8Error> {
        self.path.to_path()
    }
}

/// A set of [`BlobAppearance`] entries, optimized for the common case of a single appearance.
pub type BlobAppearanceSet = SmallVec<[BlobAppearance; 1]>;

/// The underlying data storage for a [`Blob`].
pub enum BlobData<'a> {
    /// Small blobs stored as owned bytes.
    Owned(Vec<u8>),

    /// Large blobs that are memory-mapped from disk.
    Mapped(memmap2::Mmap),

    /// Borrowed bytes (e.g., from a git pack file).
    Borrowed(&'a [u8]),
}

impl<'a> AsRef<[u8]> for BlobData<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            BlobData::Owned(v) => v,
            BlobData::Mapped(m) => m,
            BlobData::Borrowed(slice) => slice,
        }
    }
}

impl<'a> BlobData<'a> {
    /// Returns the length of the blob data in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.as_ref().len()
    }

    /// Returns true if the blob data is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }
}

/// A scannable blob of content.
///
/// `Blob` is the primary type for representing content to be scanned. It lazily
/// computes a content-based ID (SHA-1) and supports multiple backing storage types.
///
/// # Examples
///
/// ```
/// use kingfisher_core::Blob;
///
/// // Create from bytes
/// let blob = Blob::from_bytes(b"my secret content".to_vec());
/// assert_eq!(blob.len(), 17);
///
/// // Create from file
/// // let blob = Blob::from_file("path/to/file.txt")?;
/// ```
pub struct Blob<'a> {
    /// Lazily computed content-based ID.
    id: OnceLock<BlobId>,
    /// The underlying data.
    data: BlobData<'a>,
    /// Temporary ID assigned at creation (for debugging/tracking).
    temp_id: u64,
}

impl Blob<'_> {
    /// Create a new `Blob` by reading from a file.
    ///
    /// Large files are automatically memory-mapped for efficiency.
    #[inline]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(&path)?;
        let file_size = file.metadata()?.len();
        let temp_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

        if file_size > LARGE_FILE_THRESHOLD {
            // Large files: one mmap, zero extra copies.
            let mmap = unsafe { memmap2::Mmap::map(&file)? };
            Ok(Blob { id: OnceLock::new(), data: BlobData::Mapped(mmap), temp_id })
        } else {
            // Small files: read into memory.
            let mut bytes = Vec::with_capacity(file_size as usize);
            file.read_to_end(&mut bytes)?;
            Ok(Blob { id: OnceLock::new(), data: BlobData::Owned(bytes), temp_id })
        }
    }

    /// Create a new `Blob` from a vector of bytes.
    #[inline]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let temp_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        Blob { id: OnceLock::new(), data: BlobData::Owned(bytes), temp_id }
    }

    /// Create a new `Blob` with a pre-computed ID and owned data.
    #[inline]
    pub fn new(id: BlobId, bytes: Vec<u8>) -> Self {
        let temp_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let cell = OnceLock::new();
        let _ = cell.set(id);
        Blob { id: cell, data: BlobData::Owned(bytes), temp_id }
    }

    /// Returns the blob's content as a byte slice.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        self.data.as_ref()
    }

    /// Lazily computes and returns the blob's content-based [`BlobId`].
    #[inline]
    pub fn id(&self) -> BlobId {
        *self.id.get_or_init(|| BlobId::new(self.bytes()))
    }

    /// Returns a reference to the blob's [`BlobId`], computing it if necessary.
    #[inline]
    pub fn id_ref(&self) -> &BlobId {
        self.id.get_or_init(|| BlobId::new(self.bytes()))
    }

    /// Returns the temporary ID assigned when this blob was created.
    #[inline]
    pub fn temp_id(&self) -> u64 {
        self.temp_id
    }

    /// Returns the length of the blob in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes().len()
    }

    /// Returns true if the blob is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes().is_empty()
    }
}

impl<'a> Blob<'a> {
    /// Create a new `Blob` from borrowed bytes.
    ///
    /// This is useful for zero-copy scanning of data that already exists
    /// in memory (e.g., from a git pack file).
    #[inline]
    pub fn from_borrowed(bytes: &'a [u8]) -> Self {
        let temp_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        Blob { id: OnceLock::new(), data: BlobData::Borrowed(bytes), temp_id }
    }
}

impl Drop for Blob<'_> {
    fn drop(&mut self) {
        // For owned data, clear and shrink to free memory promptly.
        if let BlobData::Owned(ref mut v) = self.data {
            v.clear();
            v.shrink_to_fit();
        }
    }
}

/// A content-based identifier for a blob, computed as a Git-compatible SHA-1 hash.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Copy, Clone, Serialize)]
#[serde(into = "String")]
pub struct BlobId([u8; 20]);

impl Default for BlobId {
    /// Creates a zero-filled `BlobId`.
    fn default() -> Self {
        BlobId([0; 20])
    }
}

impl BlobId {
    /// Computes a `BlobId` from raw bytes.
    ///
    /// For large inputs, only the first and last 64KB are hashed for performance.
    #[inline]
    pub fn new(input: &[u8]) -> Self {
        const CHUNK: usize = 64 * 1024; // 64KB from start and end
        let mut hasher = Sha1::new();
        update_git_blob_header(&mut hasher, input.len());
        if input.len() <= CHUNK * 2 {
            hasher.update(input);
        } else {
            hasher.update(&input[..CHUNK]);
            hasher.update(&input[input.len() - CHUNK..]);
        }
        let digest: [u8; 20] = hasher.finalize().into();
        BlobId(digest)
    }

    /// Computes a `BlobId` from the complete bytes (no truncation).
    pub fn compute_from_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha1::new();
        update_git_blob_header(&mut hasher, bytes.len());
        hasher.update(bytes);
        let digest: [u8; 20] = hasher.finalize().into();
        BlobId(digest)
    }

    /// Parses a `BlobId` from a hex string.
    #[inline]
    pub fn from_hex(v: &str) -> crate::Result<Self> {
        let bytes = hex::decode(v)?;
        let arr: [u8; 20] =
            bytes.as_slice().try_into().map_err(|_| crate::Error::InvalidBlobId(v.to_string()))?;
        Ok(BlobId(arr))
    }

    /// Returns the blob ID as a hex string.
    #[inline]
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Returns the raw bytes of the blob ID.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn update_git_blob_header(hasher: &mut Sha1, len: usize) {
    let mut digits = [0u8; 20];
    let mut n = len;
    let mut i = digits.len();

    if n == 0 {
        i -= 1;
        digits[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }

    hasher.update(b"blob ");
    hasher.update(&digits[i..]);
    hasher.update(b"\0");
}

impl<'de> Deserialize<'de> for BlobId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Vis;
        impl serde::de::Visitor<'_> for Vis {
            type Value = BlobId;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a 40-character hex string")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                BlobId::from_hex(v).map_err(|e| serde::de::Error::custom(e))
            }
        }
        d.deserialize_str(Vis)
    }
}

impl std::fmt::Debug for BlobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlobId({})", self.hex())
    }
}

impl std::fmt::Display for BlobId {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl JsonSchema for BlobId {
    fn schema_name() -> Cow<'static, str> {
        "BlobId".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let mut schema = String::json_schema(generator);
        schema.insert("pattern".to_owned(), json!("[0-9a-f]{40}"));
        schema.insert("description".to_owned(), json!("A hex-encoded blob ID as computed by Git"));
        schema
    }
}

impl From<BlobId> for String {
    #[inline]
    fn from(blob_id: BlobId) -> String {
        blob_id.hex()
    }
}

impl TryFrom<&str> for BlobId {
    type Error = crate::Error;

    #[inline]
    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        BlobId::from_hex(s)
    }
}

impl<'a> From<&'a gix::ObjectId> for BlobId {
    #[inline]
    fn from(id: &'a gix::ObjectId) -> Self {
        BlobId(id.as_bytes().try_into().expect("oid should be a 20-byte value"))
    }
}

impl From<gix::ObjectId> for BlobId {
    #[inline]
    fn from(id: gix::ObjectId) -> Self {
        BlobId(id.as_bytes().try_into().expect("oid should be a 20-byte value"))
    }
}

impl<'a> From<&'a BlobId> for gix::ObjectId {
    #[inline]
    fn from(blob_id: &'a BlobId) -> Self {
        gix::hash::ObjectId::try_from(blob_id.as_bytes()).unwrap()
    }
}

impl From<BlobId> for gix::ObjectId {
    #[inline]
    fn from(blob_id: BlobId) -> Self {
        gix::hash::ObjectId::try_from(blob_id.as_bytes()).unwrap()
    }
}

/// A concurrent map with [`BlobId`] keys, optimized for low contention.
///
/// This implementation uses 256 shards (based on the first byte of the blob ID)
/// to minimize lock contention during parallel scanning.
pub struct BlobIdMap<V> {
    maps: [Mutex<FxHashMap<ObjectId, V>>; 256],
}

impl<V> BlobIdMap<V> {
    /// Creates a new empty `BlobIdMap`.
    pub fn new() -> Self {
        BlobIdMap { maps: std::array::from_fn(|_| Mutex::new(FxHashMap::default())) }
    }

    /// Inserts a value, returning the previous value if one existed.
    #[inline]
    pub fn insert(&self, blob_id: BlobId, v: V) -> Option<V> {
        let idx = blob_id.as_bytes()[0] as usize;
        self.maps[idx].lock().insert(blob_id.into(), v)
    }

    /// Returns true if the map contains the given key.
    #[inline]
    pub fn contains_key(&self, blob_id: &BlobId) -> bool {
        let idx = blob_id.as_bytes()[0] as usize;
        self.maps[idx].lock().contains_key(&ObjectId::from(blob_id))
    }

    /// Returns the total number of entries in the map.
    ///
    /// Note: This is not a cheap operation as it must lock all shards.
    pub fn len(&self) -> usize {
        self.maps.iter().map(|m| m.lock().len()).sum()
    }

    /// Returns true if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.maps.iter().all(|m| m.lock().is_empty())
    }

    /// Removes all entries from the map.
    ///
    /// Note: This locks each shard in sequence.
    pub fn clear(&self) {
        for map in &self.maps {
            map.lock().clear();
        }
    }
}

impl<V: Copy> BlobIdMap<V> {
    /// Gets a copy of the value for the given key.
    #[inline]
    pub fn get(&self, blob_id: &BlobId) -> Option<V> {
        let idx = blob_id.as_bytes()[0] as usize;
        self.maps[idx].lock().get(&ObjectId::from(blob_id)).copied()
    }
}

impl<V> Default for BlobIdMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

/// Metadata about a blob.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
pub struct BlobMetadata {
    /// The blob's content-based ID.
    pub id: BlobId,

    /// The length of the blob in bytes.
    pub num_bytes: usize,

    /// The guessed MIME type of the blob (e.g., "text/plain").
    pub mime_essence: Option<String>,

    /// The guessed programming language of the blob (e.g., "Python").
    pub language: Option<String>,
}

impl BlobMetadata {
    /// Returns the size in bytes.
    #[inline]
    pub fn num_bytes(&self) -> usize {
        self.num_bytes
    }

    /// Returns the size in megabytes, rounded to 3 decimal places.
    #[inline]
    pub fn num_megabytes(&self) -> f64 {
        let mb = self.num_bytes as f64 / 1_048_576.0;
        format!("{:.3}", mb).parse::<f64>().unwrap_or(mb)
    }

    /// Returns the MIME essence if known.
    #[inline]
    pub fn mime_essence(&self) -> Option<&str> {
        self.mime_essence.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_id_empty() {
        assert_eq!(BlobId::new(&[]).hex(), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
    }

    #[test]
    fn test_blob_id_small() {
        assert_eq!(BlobId::new(&vec![0; 1024]).hex(), "06d7405020018ddf3cacee90fd4af10487da3d20");
    }

    #[test]
    fn test_blob_from_bytes() {
        let blob = Blob::from_bytes(b"hello world".to_vec());
        assert_eq!(blob.len(), 11);
        assert_eq!(blob.bytes(), b"hello world");
    }

    #[test]
    fn test_blob_id_roundtrip() {
        let original = BlobId::new(b"test data");
        let hex = original.hex();
        let parsed = BlobId::from_hex(&hex).unwrap();
        assert_eq!(original, parsed);
    }
}

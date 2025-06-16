use std::{
    convert::TryInto,
    fs::File,
    io::{Read, Write},
    path::Path,
    sync::Arc,
};

use anyhow::Result;
use bstr::{BString, ByteSlice};
use gix::ObjectId;
use hex;
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use smallvec::SmallVec;

use crate::git_commit_metadata::CommitMetadata;
// const LARGE_FILE_THRESHOLD: u64 = 512 * 1024; // 512 KB
const LARGE_FILE_THRESHOLD: u64 = 0; // always mmap

/// The data of a blob, either owned (small files) or memory mapped (large files).
pub enum BlobData<'a> {
    /// Small blobs – remains as-is.
    Owned(Vec<u8>),

    /// Large blobs read from disk with `memmap2`.
    Mapped(memmap2::Mmap),

    /// Bytes that already live inside gix’s pack-file mmap;
    /// we only keep a pointer and length.
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
    #[inline]
    pub fn len(&self) -> usize {
        self.as_ref().len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }
}
/// Where was a particular blob seen?
#[derive(Clone, Debug, serde::Serialize)]
pub struct BlobAppearance {
    pub commit_metadata: Arc<CommitMetadata>,

    /// The path given to the blob
    pub path: BString,
}
impl BlobAppearance {
    #[inline]
    pub fn path(&self) -> Result<&Path, bstr::Utf8Error> {
        self.path.to_path()
    }
}
/// A set of `BlobAppearance` entries
pub type BlobAppearanceSet = SmallVec<[BlobAppearance; 1]>;
// -------------------------------------------------------------------------------------------------
// Blob
// -------------------------------------------------------------------------------------------------
/// A Git blob, storing its SHA-1 id and its contents.

pub struct Blob<'a> {
    pub id: BlobId,
    pub data: BlobData<'a>,
}

impl Blob<'_> {
    #[inline]

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(&path)?;
        let file_size = file.metadata()?.len();

        if file_size > LARGE_FILE_THRESHOLD {
            // Large files: one mmap, zero extra copies.
            let mmap = unsafe { memmap2::Mmap::map(&file)? };
            let id = BlobId::new(mmap.as_ref());
            Ok(Blob { id, data: BlobData::Mapped(mmap) })
        } else {
            // Small files: reuse the same handle and pre-allocate exact capacity
            let mut bytes = Vec::with_capacity(file_size as usize);
            file.read_to_end(&mut bytes)?;
            let id = BlobId::new(&bytes);
            Ok(Blob { id, data: BlobData::Owned(bytes) })
        }
    }
    /// Returns the blob's bytes as a slice.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        self.data.as_ref()
    }

    /// Create a new `Blob` from a vector of bytes.
    #[inline]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let id = BlobId::compute_from_bytes(&bytes);
        Blob { id, data: BlobData::Owned(bytes) }
    }

    /// Create a new `Blob` with the given id and data.
    #[inline]
    pub fn new(id: BlobId, bytes: Vec<u8>) -> Self {
        Blob { id, data: BlobData::Owned(bytes) }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytes().len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes().is_empty()
    }
}

impl Drop for Blob<'_> {
    fn drop(&mut self) {
        // For owned data, clear the Vec. For memory-mapped data, the mmap will be unmapped
        // automatically.
        if let BlobData::Owned(ref mut v) = self.data {
            v.clear();
            v.shrink_to_fit();
        }
    }
}
/// A finite map with `BlobId` values as keys, designed for concurrent
/// modification.
///
/// This implementation imposes an equivalence relation on blob IDs, assigning
/// each to one of 256 classes (based on its first byte). Each class is
/// represented by a standard `HashMap` protected by a `Mutex`. Since blob IDs
/// are SHA-1 digests, and hence effectively random, the odds that two
/// random blob IDs appear in the same class is 1/256.
///
/// We can model this as a generalized birthday problem. With 256
/// mutex-protected hash maps, (i.e., "days in the year" or "possible
/// birthdays"), you would need 20 threads (i.e., "people") accessing the set
/// simultaneously to exceed 50% probability of 2 threads contending.
///
/// Or in other words, there should be relatively little contention on that
/// global data structure even when using lots of threads.
pub struct BlobIdMap<V> {
    maps: [Mutex<FxHashMap<ObjectId, V>>; 256],
}

impl<V> BlobIdMap<V> {
    pub fn new() -> Self {
        BlobIdMap { maps: std::array::from_fn(|_| Mutex::new(FxHashMap::default())) }
    }

    /// Add the given `BlobId` to the map.
    ///
    /// Returns the old value mapped to the `BlobId`, if any.
    #[inline]
    pub fn insert(&self, blob_id: BlobId, v: V) -> Option<V> {
        let idx = blob_id.as_bytes()[0] as usize;
        self.maps[idx].lock().insert(blob_id.into(), v)
    }

    /// Check if the given `BlobId` is in the map without modifying it.
    #[inline]
    pub fn contains_key(&self, blob_id: &BlobId) -> bool {
        let idx = blob_id.as_bytes()[0] as usize;
        self.maps[idx].lock().contains_key(&ObjectId::from(blob_id))
    }

    /// Return the total number of blob IDs contained in the map.
    ///
    /// Note: this is not a cheap operation.
    pub fn len(&self) -> usize {
        self.maps.iter().map(|m| m.lock().len()).sum()
    }

    /// Is the map empty?
    ///
    /// Note: this is not a cheap operation.
    pub fn is_empty(&self) -> bool {
        self.maps.iter().all(|m| m.lock().is_empty())
    }
}
impl<V: Copy> BlobIdMap<V> {
    /// Get the value mapped to the given `BlobId`.
    #[inline]
    pub fn get(&self, blob_id: &BlobId) -> Option<V>
    where
        V: Copy,
    {
        let idx = blob_id.as_bytes()[0] as usize;
        self.maps[idx].lock().get(&ObjectId::from(blob_id)).copied()
    }
}
impl<V> Default for BlobIdMap<V> {
    fn default() -> Self {
        Self::new()
    }
}
// -------------------------------------------------------------------------------------------------
// BlobId
// -------------------------------------------------------------------------------------------------
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Copy, Clone, Serialize)]
#[serde(into = "String")]
pub struct BlobId([u8; 20]);
impl BlobId {
    // Create a new method to get a default (zero-filled) BlobId
    pub fn default() -> Self {
        BlobId([0; 20])
    }

    pub fn compute_from_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha1::new();
        write!(&mut hasher, "blob {}\0", bytes.len()).unwrap();
        hasher.update(bytes);
        BlobId(hasher.finalize().as_slice().try_into().expect("SHA-1 output size mismatch"))
    }
}
impl<'de> Deserialize<'de> for BlobId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Vis;
        impl serde::de::Visitor<'_> for Vis {
            type Value = BlobId;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
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
impl schemars::JsonSchema for BlobId {
    fn schema_name() -> String {
        "BlobId".into()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        let s = String::json_schema(gen);
        let mut o = s.into_object();
        o.string().pattern = Some("[0-9a-f]{40}".into());
        let md = o.metadata();
        md.description = Some("A hex-encoded blob ID as computed by Git".into());
        schemars::schema::Schema::Object(o)
    }
}
impl BlobId {
    /// Create a new BlobId computed from the given input.
    #[inline]
    pub fn new(input: &[u8]) -> Self {
        let mut hasher = Sha1::new();
        write!(&mut hasher, "blob {}\0", input.len()).unwrap();
        hasher.update(input);
        BlobId(hasher.finalize().as_slice().try_into().expect("SHA-1 output size mismatch"))
    }

    #[inline]
    pub fn from_hex(v: &str) -> Result<Self> {
        Ok(BlobId(hex::decode(v)?.as_slice().try_into()?))
    }

    #[inline]
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl From<BlobId> for String {
    #[inline]
    fn from(blob_id: BlobId) -> String {
        blob_id.hex()
    }
}
impl TryFrom<&str> for BlobId {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        BlobId::from_hex(s)
    }
}
impl std::fmt::Display for BlobId {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
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
// -------------------------------------------------------------------------------------------------
// test
// -------------------------------------------------------------------------------------------------
#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;

    use super::*;
    #[test]
    fn simple() {
        assert_eq!(BlobId::new(&vec![0; 0]).hex(), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
        assert_eq!(BlobId::new(&vec![0; 1024]).hex(), "06d7405020018ddf3cacee90fd4af10487da3d20");
    }
}
/// Metadata about a blob
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, schemars::JsonSchema)]
pub struct BlobMetadata {
    /// The blob ID this metadata applies to
    pub id: BlobId,

    /// The length in bytes of the blob
    pub num_bytes: usize,

    /// The guessed multimedia type of the blob
    pub mime_essence: Option<String>,

    /// The guessed charset of the blob
    pub charset: Option<String>,

    /// The guessed programming language of the blob
    pub language: Option<String>,
}
impl BlobMetadata {
    /// Get the length of the blob in bytes.
    #[inline]
    pub fn num_bytes(&self) -> usize {
        self.num_bytes
    }

    /// Get the size of the blob in megabytes, rounded to 3 significant digits.
    #[inline]
    pub fn num_megabytes(&self) -> f64 {
        let mb = self.num_bytes as f64 / 1_048_576.0;
        format!("{:.3}", mb).parse::<f64>().unwrap_or(mb)
    }

    #[inline]
    pub fn mime_essence(&self) -> Option<&str> {
        self.mime_essence.as_deref()
    }

    #[inline]
    pub fn charset(&self) -> Option<&str> {
        self.charset.as_deref()
    }
}

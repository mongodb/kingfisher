//! Read-only ASAR indexing. ASAR is a Pickle-framed JSON directory followed by
//! uncompressed bytes; decompression, external unpacked files and link traversal
//! are deliberately not part of this reader.
use std::{
    cell::Cell,
    collections::{BTreeMap, HashMap},
    fmt,
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use serde::de::{Deserialize, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};

// Bound index allocation independently of output bytes (empty/external members
// need no output budget). These caps bound parser memory, not coverage: an
// index over a cap falls back to scanning the archive's raw (uncompressed) bytes.
// They are sized for Electron apps that bundle `node_modules`, whose indexes can
// hold tens of thousands of files plus directories, each carrying ~200 bytes of
// integrity metadata. Metadata is skipped in both the guard and typed passes, so
// large integrity fields cannot defeat the node cap or amplify memory.
pub(super) const MAX_HEADER_BYTES: usize = 32 * 1024 * 1024;
pub(super) const MAX_INDEX_ENTRIES: usize = 100_000;
// Shared directory names expand once per descendant path. Bound that expansion
// independently of the compact JSON header and extracted payload bytes.
pub(super) const MAX_INDEX_PATH_BYTES: usize = 32 * 1024 * 1024;

/// Streaming structural pass before building the typed index tree.
/// `files` maps count all index nodes; caller entry budgets retain their existing
/// file-only meaning. Unknown metadata is skipped without constructing Values.
struct IndexGuard<'a> {
    control: Option<&'a ScanControl>,
    max_entries: Option<usize>,
    max_nodes: Option<usize>,
    entries: Cell<usize>,
    nodes: Cell<usize>,
    aborted: Cell<Option<crate::ScanAborted>>,
}

#[derive(Clone, Copy)]
struct GuardSeed<'a> {
    guard: &'a IndexGuard<'a>,
    children: bool,
}

impl<'de> DeserializeSeed<'de> for GuardSeed<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        // Non-object nodes and `files` values are skipped here, as the typed pass
        // maps them to defaults; only objects can add index nodes.
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for GuardSeed<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an ASAR index object")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        use serde::de::Error;
        let mut counted_file = false;
        while let Some(key) = map.next_key::<String>()? {
            if let Some(control) = self.guard.control
                && let Err(error) = control.check()
            {
                self.guard.aborted.set(Some(error));
                return Err(M::Error::custom(error));
            }
            if self.children {
                let count = self.guard.nodes.get();
                if self.guard.max_nodes.is_some_and(|limit| count >= limit) {
                    return Err(M::Error::custom("ASAR exceeds index entry cap"));
                }
                self.guard.nodes.set(count.saturating_add(1));
                map.next_value_seed(GuardSeed { children: false, ..self })?;
            } else if key == "files" {
                map.next_value_seed(GuardSeed { children: true, ..self })?;
            } else {
                if key == "size" && !counted_file {
                    let count = self.guard.entries.get();
                    if self.guard.max_entries.is_some_and(|limit| count >= limit) {
                        return Err(M::Error::custom("archive exceeds max_entries budget"));
                    }
                    self.guard.entries.set(count.saturating_add(1));
                    counted_file = true;
                }
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

use crate::ScanControl;

struct Layout {
    json_end: usize,
    payload_start: usize,
}

fn layout(data: &[u8]) -> Result<Layout> {
    let prefix = data.get(..16).context("truncated ASAR header")?;
    let header_size = u32::from_le_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]) as usize;
    let json_size = u32::from_le_bytes([prefix[12], prefix[13], prefix[14], prefix[15]]) as usize;
    let payload_start = 8usize.checked_add(header_size).context("ASAR header size overflow")?;
    let json_end = 16usize.checked_add(json_size).context("ASAR JSON size overflow")?;
    if json_end > payload_start || payload_start > data.len() {
        bail!("truncated or overlapping ASAR header");
    }
    Ok(Layout { json_end, payload_start })
}

/// Length of the member payload that follows the JSON index. Non-overlapping
/// members can never sum past it.
pub(super) fn payload_len(data: &[u8]) -> Result<usize> {
    Ok(data.len() - layout(data)?.payload_start)
}

pub(super) fn files<'a>(
    data: &'a [u8],
    control: Option<&ScanControl>,
    max_entries: Option<usize>,
    max_header_bytes: Option<usize>,
    max_index_entries: Option<usize>,
    max_path_bytes: Option<usize>,
) -> Result<BTreeMap<PathBuf, &'a [u8]>> {
    if let Some(control) = control {
        control.check()?;
    }
    // Reject a declared oversized header before slicing or parsing it.
    let prefix = data.get(..16).context("truncated ASAR header")?;
    let header_size = u32::from_le_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]) as usize;
    if max_header_bytes.is_some_and(|limit| header_size > limit) {
        bail!("ASAR exceeds header byte cap");
    }
    let Layout { json_end, payload_start } = layout(data)?;
    let json = data.get(16..json_end).context("truncated ASAR JSON header")?;
    let guard = IndexGuard {
        control,
        max_entries,
        max_nodes: max_index_entries,
        entries: Cell::new(0),
        nodes: Cell::new(0),
        aborted: Cell::new(None),
    };
    let mut deserializer = serde_json::Deserializer::from_slice(json);
    let result = GuardSeed { guard: &guard, children: false }.deserialize(&mut deserializer);
    // Preserve the typed cancellation/timeout error instead of the serde wrapper.
    if let Some(error) = guard.aborted.get() {
        return Err(error.into());
    }
    result.map_err(|error| {
        let message = format!("invalid or excessive ASAR index: {error}");
        anyhow::Error::new(error).context(message)
    })?;
    deserializer.end().context("invalid ASAR JSON header")?;
    // Keep serde_json's default recursion limit. The typed tree retains only the
    // fields used for scanning, so metadata skipped by the guard is never rebuilt.
    let header: Node = serde_json::from_slice(json).context("invalid ASAR JSON header")?;
    let payload = &data[payload_start..];
    let mut files = BTreeMap::new();
    let mut directories = Vec::new();
    let mut path_bytes = 0usize;
    let mut next = Some((PathBuf::new(), &header));
    while let Some((path, node)) = next {
        if let Some(control) = control {
            control.check()?;
        }
        if let Some((size, offset)) = file_location(node) {
            let bytes = if let Some(offset) = offset {
                let end = offset.checked_add(size).context("ASAR member size overflow")?;
                payload.get(offset..end).context("truncated ASAR member")?
            } else {
                // Preserve the previous reader's behavior with no archive path:
                // unpacked members have no bytes, and no filesystem reads occur.
                &[]
            };
            if let Some(limit) = max_entries
                && files.len() >= limit
                && !files.contains_key(&path)
            {
                bail!("archive exceeds max_entries budget");
            }
            files.insert(path, bytes);
        } else if let Some(children) = &node.files {
            directories.push((path, children.iter()));
        } else if !matches!(node.link, Scalar::Str(_)) {
            bail!("invalid ASAR member header");
        }
        // Walk with one iterator per directory, not a queue containing all paths.
        // JSON's recursion limit bounds depth; the traversal itself is iterative.
        next = loop {
            let Some((path, children)) = directories.last_mut() else {
                break None;
            };
            if let Some((name, node)) = children.next() {
                let name = name.as_str();
                // Charge every joined path before allocating it, including the
                // directories retained on the traversal stack. Counting only
                // files would leave deeply nested, long prefixes unbounded.
                let joined_bytes = path
                    .as_os_str()
                    .len()
                    .checked_add(usize::from(!path.as_os_str().is_empty()))
                    .and_then(|length| length.checked_add(name.len()))
                    .context("ASAR index path size overflow")?;
                path_bytes = path_bytes
                    .checked_add(joined_bytes)
                    .context("ASAR index path size overflow")?;
                if max_path_bytes.is_some_and(|limit| path_bytes > limit) {
                    bail!("ASAR exceeds index path byte cap");
                }
                break Some((path.join(name), node));
            }
            directories.pop();
        };
    }
    Ok(files)
}

/// Packed offsets are decimal strings, whereas sizes are JSON integers. An
/// `unpacked` boolean (including false) selects external storage in legacy ASAR
/// readers. File metadata such as executable/integrity is not used for scanning;
/// the previous reader did not verify integrity hashes either.
fn file_location(node: &Node) -> Option<(usize, Option<usize>)> {
    let Scalar::U64(size) = node.size else { return None };
    let size = usize::try_from(size).ok()?;
    if let Scalar::Str(offset) = &node.offset
        && let Ok(offset) = offset.parse()
    {
        Some((size, Some(offset)))
    } else {
        matches!(node.unpacked, Scalar::Bool).then_some((size, None))
    }
}

/// A JSON value reduced to the scalar kinds the index reader inspects. Arrays and
/// objects are drained without allocation, matching `Value::as_*` returning `None`.
#[derive(Default)]
enum Scalar {
    #[default]
    Other,
    U64(u64),
    Str(String),
    Bool,
}

struct ScalarVisitor;

impl<'de> Visitor<'de> for ScalarVisitor {
    type Value = Scalar;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Scalar, E> {
        Ok(Scalar::Bool)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Scalar, E> {
        Ok(Scalar::U64(value))
    }

    fn visit_i64<E>(self, _: i64) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }

    fn visit_str<E>(self, value: &str) -> Result<Scalar, E> {
        Ok(Scalar::Str(value.to_owned()))
    }

    fn visit_unit<E>(self) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Scalar, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Scalar::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Scalar, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Scalar::Other)
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ScalarVisitor)
    }
}

/// One index node with only the fields used for scanning. Non-object nodes and
/// wrongly typed fields deserialize to defaults, so they fail the same validity
/// checks a `serde_json::Value` lookup would. Later duplicate keys win, and
/// duplicate child names keep their first position, as in `serde_json::Map`.
#[derive(Default)]
struct Node {
    size: Scalar,
    offset: Scalar,
    unpacked: Scalar,
    link: Scalar,
    files: Option<Vec<(String, Node)>>,
}

struct NodeVisitor;

impl<'de> Visitor<'de> for NodeVisitor {
    type Value = Node;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an ASAR index node")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Node, E> {
        Ok(Node::default())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Node, E> {
        Ok(Node::default())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Node, E> {
        Ok(Node::default())
    }

    fn visit_f64<E>(self, _: f64) -> Result<Node, E> {
        Ok(Node::default())
    }

    fn visit_str<E>(self, _: &str) -> Result<Node, E> {
        Ok(Node::default())
    }

    fn visit_unit<E>(self) -> Result<Node, E> {
        Ok(Node::default())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Node, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Node::default())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Node, A::Error> {
        let mut node = Node::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "size" => node.size = map.next_value()?,
                "offset" => node.offset = map.next_value()?,
                "unpacked" => node.unpacked = map.next_value()?,
                "link" => node.link = map.next_value()?,
                "files" => node.files = map.next_value::<Children>()?.0,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(node)
    }
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NodeVisitor)
    }
}

/// A `files` value: `Some` only for a JSON object, like `Value::as_object`.
struct Children(Option<Vec<(String, Node)>>);

struct ChildrenVisitor;

impl<'de> Visitor<'de> for ChildrenVisitor {
    type Value = Children;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an ASAR files object")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Children, E> {
        Ok(Children(None))
    }

    fn visit_u64<E>(self, _: u64) -> Result<Children, E> {
        Ok(Children(None))
    }

    fn visit_i64<E>(self, _: i64) -> Result<Children, E> {
        Ok(Children(None))
    }

    fn visit_f64<E>(self, _: f64) -> Result<Children, E> {
        Ok(Children(None))
    }

    fn visit_str<E>(self, _: &str) -> Result<Children, E> {
        Ok(Children(None))
    }

    fn visit_unit<E>(self) -> Result<Children, E> {
        Ok(Children(None))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Children, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Children(None))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Children, A::Error> {
        let mut children: Vec<(String, Node)> = Vec::new();
        let mut positions = HashMap::<String, usize>::new();
        while let Some((name, node)) = map.next_entry::<String, Node>()? {
            if let Some(&index) = positions.get(&name) {
                children[index].1 = node;
            } else {
                positions.insert(name.clone(), children.len());
                children.push((name, node));
            }
        }
        Ok(Children(Some(children)))
    }
}

impl<'de> Deserialize<'de> for Children {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ChildrenVisitor)
    }
}

//! Filesystem fetches without `git-upload-pack` or another child process.
//!
//! gix's regular file transport runs `git-upload-pack`. Opening the source repository directly
//! instead lets us import the reachable object graph up to its shallow boundaries and apply the
//! refspecs using native APIs. Ref updates and pruning happen only after that graph was copied. Objects
//! left behind by an interrupted operation are harmless and are traversed again on the next fetch.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    io::Write as _,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::{Context, Result, bail, ensure};
use gix::{
    ObjectId,
    bstr::{BString, ByteSlice},
    objs::Kind,
    refs::{
        Target,
        transaction::{PreviousValue, RefEdit},
    },
    refspec::{
        Instruction, MatchGroup, RefSpec,
        instruction::Fetch,
        match_group::{Item, SourceRef},
    },
};

#[derive(Clone)]
struct AdvertisedRef {
    name: BString,
    id: ObjectId,
}

impl AdvertisedRef {
    fn item(&self) -> Item<'_> {
        Item { full_ref_name: self.name.as_bstr(), target: self.id.as_ref(), object: None }
    }
}

/// Fetch selected refs and their reachable history, respecting the source's shallow boundaries.
///
/// Return the source's advertised names, including HEAD when it is born. Tag selection, the
/// initial clone's additional branch mappings, HEAD, remote configuration, and checkout are the
/// caller's responsibility. Symbolic source refs are advertised at their direct object target;
/// symbolic destination refs are never dereferenced when updating or pruning.
pub(super) fn fetch(
    source: &Path,
    destination: &gix::Repository,
    specs: &[RefSpec],
    interrupt: &AtomicBool,
) -> Result<Vec<BString>> {
    check_interrupt(interrupt)?;
    let source = gix::open_opts(source, destination.open_options().clone())
        .context("Failed to open local Git source")?;
    ensure!(source.object_hash() == destination.object_hash(), "Git object hash formats differ");
    let advertised = advertised_refs(&source, interrupt)?;
    let items = || advertised.iter().map(AdvertisedRef::item);

    // A missing explicit source is an error, not an empty successful fetch followed by pruning.
    // Test the positive spec alone so an intentional negative refspec doesn't look like a missing
    // source. Object-ID specs produce a mapping here and are validated during graph traversal.
    for spec in specs {
        let source = match spec.to_ref().instruction() {
            Instruction::Fetch(Fetch::Only { src } | Fetch::AndUpdate { src, .. }) => src,
            _ => continue,
        };
        if !source.contains(&b'*') {
            ensure!(
                !MatchGroup::from_fetch_specs([spec.to_ref()])
                    .match_lhs(items())
                    .mappings
                    .is_empty(),
                "Local Git source has no ref matching {source}"
            );
        }
    }

    let (mappings, fixes) = MatchGroup::from_fetch_specs(specs.iter().map(RefSpec::to_ref))
        .match_lhs(items())
        .validated()
        .context("Invalid local Git refspec mappings")?;
    ensure!(fixes.is_empty(), "Local Git refspec has a partial destination");

    let mut roots = HashSet::new();
    let mut updates = BTreeMap::<BString, (ObjectId, bool)>::new();
    for mapping in mappings.mappings {
        check_interrupt(interrupt)?;
        let id = match mapping.lhs {
            SourceRef::ObjectId(id) => id,
            SourceRef::FullName(_) => {
                advertised[mapping.item_index.context("Missing source ref index")?].id
            }
        };
        roots.insert(id);
        if let Some(name) = mapping.rhs {
            ensure!(name.starts_with(b"refs/"), "Local Git fetch cannot update a pseudo ref");
            let force =
                mappings.group.specs[mapping.spec_index].to_owned().allow_non_fast_forward();
            updates
                .entry(name.into_owned())
                .and_modify(|update| update.1 |= force)
                .or_insert((id, force));
        }
    }
    let source_shallow = shallow_commits(&source)?;
    let previous_shallow = shallow_commits(destination)?;
    let existing = reference_targets(destination)?;
    let mut complete = HashSet::new();
    if source_shallow.iter().any(|id| destination.has_object(*id)) {
        // Probe referenced history before importing. Unreferenced objects from a failed fetch
        // must not make a newly shallow tip appear complete on retry, even if its parents exist.
        let tips = existing
            .values()
            .filter_map(|target| match target {
                Target::Object(id) => Some(*id),
                Target::Symbolic(_) => None,
            })
            .chain(destination.head()?.id().map(|id| id.detach()));
        for id in tips {
            has_complete_graph(destination, id, &previous_shallow, &mut complete, interrupt)?;
        }
    }
    let reachable = copy_reachable(&source, destination, roots, &source_shallow, interrupt)?;
    let mut shallow = previous_shallow.clone();
    shallow.extend(
        source_shallow
            .iter()
            .copied()
            .filter(|id| reachable.contains(id) && !complete.contains(id)),
    );

    let mut edits = Vec::new();
    for (name, (id, force)) in updates {
        check_interrupt(interrupt)?;
        let previous = existing.get(&name);
        if previous == Some(&Target::Object(id)) {
            continue;
        }
        if name.starts_with(b"refs/heads/") {
            ensure!(
                destination.find_object(id)?.kind == Kind::Commit,
                "A Git branch must point to a commit"
            );
            if destination.workdir().is_some()
                && destination
                    .head()?
                    .referent_name()
                    .is_some_and(|head| head.as_bstr() == name.as_bstr())
            {
                bail!("Cannot fetch into the checked-out Git branch {name}");
            }
        }
        if !force && let Some(Target::Object(old)) = previous {
            if name.starts_with(b"refs/tags/") {
                bail!("Refusing to overwrite Git tag {name} without a forced refspec");
            }
            ensure!(
                !name.starts_with(b"refs/heads/")
                    || is_ancestor(destination, *old, id, &shallow, interrupt)?,
                "Refusing non-fast-forward Git branch update {name}"
            );
        }
        let expected =
            previous.cloned().map_or(PreviousValue::MustNotExist, PreviousValue::MustExistAndMatch);
        edits.push(RefEdit::update(
            name.try_into()?,
            Target::Object(id),
            expected,
            "fetch: local source",
        ));
    }

    let advertised_names: Vec<_> = advertised.into_iter().map(|reference| reference.name).collect();
    edits.extend(prune_edits(destination, specs, &advertised_names, &existing)?);
    check_interrupt(interrupt)?;
    update_shallow(destination, &previous_shallow, &shallow)?;
    apply_edits(destination, edits)?;
    Ok(advertised_names)
}

/// Select additional, unforced tag refs for the requested tag mode.
///
/// Included-tag mode skips existing local tags and follows any new tag whose fully peeled target
/// is in the selected object graph, including trees and blobs. All-tag mode includes existing tags
/// too, so the subsequent fetch rejects moved tags rather than silently ignoring them. Matching the
/// entire advertisement at once preserves raw object-ID, HEAD, negative, and overlapping refspec
/// semantics. This must not invoke the file transport.
pub(super) fn auto_follow_tag_specs(
    source: &gix::Repository,
    destination: &gix::Repository,
    specs: &[RefSpec],
    all: bool,
    interrupt: &AtomicBool,
) -> Result<Vec<RefSpec>> {
    check_interrupt(interrupt)?;
    let advertised = advertised_refs(source, interrupt)?;
    let reachable = if all {
        HashSet::new()
    } else {
        let (mappings, fixes) = MatchGroup::from_fetch_specs(specs.iter().map(RefSpec::to_ref))
            .match_lhs(advertised.iter().map(AdvertisedRef::item))
            .validated()
            .context("Invalid local Git tag-selection refspec mappings")?;
        ensure!(fixes.is_empty(), "Local Git refspec has a partial destination");
        let mut roots = HashSet::new();
        for mapping in mappings.mappings {
            check_interrupt(interrupt)?;
            roots.insert(match mapping.lhs {
                SourceRef::ObjectId(id) => id,
                SourceRef::FullName(_) => {
                    advertised[mapping.item_index.context("Missing source ref index")?].id
                }
            });
        }
        visit_reachable(source, roots, &shallow_commits(source)?, interrupt, |_| Ok(()))?
    };
    let mut result = Vec::new();
    for reference in advertised {
        check_interrupt(interrupt)?;
        if !reference.name.starts_with(b"refs/tags/")
            || (!all && destination.try_find_reference(reference.name.as_bstr())?.is_some())
        {
            continue;
        }
        if !all {
            let mut id = reference.id;
            let mut seen = HashSet::new();
            loop {
                check_interrupt(interrupt)?;
                ensure!(seen.insert(id), "Cyclic local Git tag {id}");
                let object = source.find_object(id)?;
                if object.kind != Kind::Tag {
                    break;
                }
                id = gix::objs::TagRef::from_bytes(&object.data, id.kind())?.target();
            }
            if !reachable.contains(&id) {
                continue;
            }
        }
        let mut spec = reference.name.clone();
        spec.push(b':');
        spec.extend_from_slice(&reference.name);
        result.push(
            gix::refspec::parse(spec.as_bstr(), gix::refspec::parse::Operation::Fetch)?.to_owned(),
        );
    }
    check_interrupt(interrupt)?;
    Ok(result)
}

/// Prune only direct references covered by the destination side of these fetch refspecs.
///
/// Reverse matching honors negative source refspecs; a separate forward match prevents deleting
/// a destination that is still populated by another spec. Unmapped refs and symbolic refs (in
/// particular `refs/remotes/origin/HEAD`) are left alone. Return the deleted destination names.
pub(super) fn prune(
    destination: &gix::Repository,
    specs: &[RefSpec],
    advertised_names: &[BString],
) -> Result<Vec<BString>> {
    let existing = reference_targets(destination)?;
    let edits = prune_edits(destination, specs, advertised_names, &existing)?;
    let names = edits.iter().map(|edit| edit.name.as_bstr().to_owned()).collect();
    apply_edits(destination, edits)?;
    Ok(names)
}

fn advertised_refs(source: &gix::Repository, interrupt: &AtomicBool) -> Result<Vec<AdvertisedRef>> {
    // Drop the iterator's packed-refs snapshot before resolving symbolic references.
    let references = {
        let platform = source.references()?;
        let mut references = Vec::new();
        for reference in platform.all()? {
            check_interrupt(interrupt)?;
            references.push(reference?);
        }
        references
    };
    let mut advertised = Vec::with_capacity(references.len() + 1);
    for mut reference in references {
        check_interrupt(interrupt)?;
        let name = reference.name().as_bstr().to_owned();
        let id = reference.follow_to_object()?.detach();
        advertised.push(AdvertisedRef { name, id });
    }
    if let Some(id) = source.head()?.id() {
        advertised.push(AdvertisedRef { name: "HEAD".into(), id: id.detach() });
    }
    Ok(advertised)
}

fn reference_targets(repository: &gix::Repository) -> Result<BTreeMap<BString, Target>> {
    repository
        .references()?
        .all()?
        .map(|reference| {
            let reference = reference?;
            Ok((reference.name().as_bstr().to_owned(), reference.target().into_owned()))
        })
        .collect()
}

fn prune_edits(
    destination: &gix::Repository,
    specs: &[RefSpec],
    advertised_names: &[BString],
    existing: &BTreeMap<BString, Target>,
) -> Result<Vec<RefEdit>> {
    let null = destination.object_hash().null();
    let (forward, fixes) = MatchGroup::from_fetch_specs(specs.iter().map(RefSpec::to_ref))
        .match_lhs(advertised_names.iter().map(|name| Item {
            full_ref_name: name.as_bstr(),
            target: null.as_ref(),
            object: None,
        }))
        .validated()
        .context("Invalid Git pruning refspec mappings")?;
    ensure!(fixes.is_empty(), "Git pruning refspec has a partial destination");
    let retained: BTreeSet<_> = forward
        .mappings
        .into_iter()
        .filter_map(|mapping| mapping.rhs.map(|name| name.into_owned()))
        .collect();
    let direct: Vec<_> = existing
        .iter()
        .filter_map(|(name, target)| match target {
            Target::Object(id) => Some(AdvertisedRef { name: name.clone(), id: *id }),
            Target::Symbolic(_) => None,
        })
        .collect();
    let reverse = MatchGroup::from_fetch_specs(specs.iter().map(RefSpec::to_ref))
        .match_rhs(direct.iter().map(AdvertisedRef::item));
    let mut stale = BTreeSet::new();
    for mapping in reverse.mappings {
        let name = mapping.rhs.context("Missing reverse-mapped Git ref name")?.into_owned();
        if name.starts_with(b"refs/") && !retained.contains(&name) {
            stale.insert(name);
        }
    }
    stale
        .into_iter()
        .map(|name| {
            let target = existing.get(&name).context("Missing local Git ref target")?.clone();
            Ok(RefEdit::delete(name.try_into()?, PreviousValue::MustExistAndMatch(target)))
        })
        .collect()
}

fn copy_reachable(
    source: &gix::Repository,
    destination: &gix::Repository,
    roots: impl IntoIterator<Item = ObjectId>,
    shallow: &BTreeSet<ObjectId>,
    interrupt: &AtomicBool,
) -> Result<HashSet<ObjectId>> {
    let mut missing = Vec::new();
    let reachable = visit_reachable(source, roots, shallow, interrupt, |object| {
        if !destination.has_object(object.id) {
            missing.push(object.id);
        }
        Ok(())
    })?;
    if !missing.is_empty() {
        write_pack(source, destination, &missing, interrupt)?;
    }
    Ok(reachable)
}

/// Copy objects into one pack and index, as a network fetch would, instead of one loose
/// file per object (millions of files for a large repository, slow on Windows). The pack
/// is streamed to a temporary file; objects are undeltified and individually verified.
fn write_pack(
    source: &gix::Repository,
    destination: &gix::Repository,
    ids: &[ObjectId],
    interrupt: &AtomicBool,
) -> Result<()> {
    use std::io::{BufReader, BufWriter, Seek as _};

    let hash_kind = destination.object_hash();
    let directory = destination.common_dir().join("objects").join("pack");
    std::fs::create_dir_all(&directory)?;
    let mut file = tempfile::tempfile_in(&directory)?;
    {
        let mut writer = HashingWriter {
            inner: BufWriter::new(&mut file),
            hasher: gix::hash::hasher(hash_kind),
        };
        writer.write_all(b"PACK")?;
        writer.write_all(&2u32.to_be_bytes())?;
        writer.write_all(&u32::try_from(ids.len())?.to_be_bytes())?;
        for id in ids {
            check_interrupt(interrupt)?;
            let object = source
                .find_object(*id)
                .with_context(|| format!("Missing local Git source object {id}"))?;
            ensure!(
                gix::objs::compute_hash(hash_kind, object.kind, &object.data)? == *id,
                "Local Git source object {id} does not match its content hash"
            );
            writer.write_all(&pack_entry_header(object.kind, object.data.len()))?;
            let mut encoder =
                flate2::write::ZlibEncoder::new(&mut writer, flate2::Compression::default());
            encoder.write_all(&object.data)?;
            encoder.finish()?;
        }
        let HashingWriter { mut inner, hasher } = writer;
        inner.write_all(hasher.try_finalize()?.as_bytes())?;
        inner.flush()?;
    }
    file.rewind()?;
    gix::odb::pack::Bundle::write_to_directory(
        &mut BufReader::new(file),
        Some(&directory),
        &mut gix::progress::Discard,
        interrupt,
        Some(&destination.objects),
        hash_kind,
        Default::default(),
    )
    .context("Failed to index the local Git fetch pack")?;
    Ok(())
}

/// A pack entry header: the object type and its uncompressed size as a varint.
fn pack_entry_header(kind: Kind, size: usize) -> Vec<u8> {
    let type_id: u8 = match kind {
        Kind::Commit => 1,
        Kind::Tree => 2,
        Kind::Blob => 3,
        Kind::Tag => 4,
    };
    let mut size = size as u64;
    let mut header = vec![(type_id << 4) | (size & 0x0f) as u8];
    size >>= 4;
    while size > 0 {
        *header.last_mut().expect("header has a first byte") |= 0x80;
        header.push((size & 0x7f) as u8);
        size >>= 7;
    }
    header
}

struct HashingWriter<W> {
    inner: W,
    hasher: gix::hash::Hasher,
}

impl<W: std::io::Write> std::io::Write for HashingWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn visit_reachable(
    source: &gix::Repository,
    roots: impl IntoIterator<Item = ObjectId>,
    shallow: &BTreeSet<ObjectId>,
    interrupt: &AtomicBool,
    mut visit: impl FnMut(&gix::Object<'_>) -> Result<()>,
) -> Result<HashSet<ObjectId>> {
    let mut pending: VecDeque<_> = roots.into_iter().collect();
    let mut visited = HashSet::new();
    while let Some(id) = pending.pop_front() {
        check_interrupt(interrupt)?;
        if !visited.insert(id) {
            continue;
        }
        let object = source
            .find_object(id)
            .with_context(|| format!("Missing local Git source object {id}"))?;
        enqueue_children(&object, shallow, &mut pending, interrupt)?;
        // Never skip traversal just because the destination already has the object: a cancelled
        // earlier operation may have written a parent but not all of its children yet.
        visit(&object)?;
    }
    Ok(visited)
}

fn enqueue_children(
    object: &gix::Object<'_>,
    shallow: &BTreeSet<ObjectId>,
    pending: &mut VecDeque<ObjectId>,
    interrupt: &AtomicBool,
) -> Result<()> {
    match object.kind {
        Kind::Commit => {
            let commit = object.try_to_commit_ref()?;
            pending.push_back(commit.tree());
            if !shallow.contains(&object.id) {
                pending.extend(commit.parents());
            }
        }
        Kind::Tree => {
            for entry in gix::objs::TreeRefIter::from_bytes(&object.data, object.id.kind()) {
                check_interrupt(interrupt)?;
                let entry = entry?;
                // Gitlinks name commits in a *different* object database.
                if !entry.mode.is_commit() {
                    pending.push_back(entry.oid.to_owned());
                }
            }
        }
        Kind::Tag => pending
            .push_back(gix::objs::TagRef::from_bytes(&object.data, object.id.kind())?.target()),
        Kind::Blob => {}
    }
    Ok(())
}

fn has_complete_graph(
    repository: &gix::Repository,
    root: ObjectId,
    shallow: &BTreeSet<ObjectId>,
    complete: &mut HashSet<ObjectId>,
    interrupt: &AtomicBool,
) -> Result<bool> {
    let mut pending = VecDeque::from([root]);
    let mut visited = HashSet::new();
    while let Some(id) = pending.pop_front() {
        check_interrupt(interrupt)?;
        if complete.contains(&id) || !visited.insert(id) {
            continue;
        }
        let Some(object) = repository.try_find_object(id)? else {
            return Ok(false);
        };
        enqueue_children(&object, shallow, &mut pending, interrupt)?;
    }
    complete.extend(visited);
    Ok(true)
}

fn shallow_commits(repository: &gix::Repository) -> Result<BTreeSet<ObjectId>> {
    Ok(repository.shallow_commits()?.map(|ids| ids.iter().copied().collect()).unwrap_or_default())
}

fn update_shallow(
    repository: &gix::Repository,
    previous: &BTreeSet<ObjectId>,
    shallow: &BTreeSet<ObjectId>,
) -> Result<()> {
    if shallow == previous {
        return Ok(());
    }
    let mut lock = gix::lock::File::acquire_to_update_resource(
        repository.shallow_file()?,
        gix::lock::acquire::Fail::Immediately,
        None,
        0,
    )
    .context("Failed to lock local Git shallow boundary")?;
    ensure!(
        shallow_commits(repository)? == *previous,
        "Local Git shallow boundary changed during fetch"
    );
    for id in shallow {
        writeln!(lock, "{id}")?;
    }
    lock.flush()?;
    // Publish the boundary before the refs that depend on it. Existing boundaries are retained,
    // matching an ordinary fetch without --unshallow; extra imported objects remain harmless.
    lock.commit().context("Failed to update local Git shallow boundary")?;
    Ok(())
}

fn is_ancestor(
    repository: &gix::Repository,
    old: ObjectId,
    new: ObjectId,
    shallow: &BTreeSet<ObjectId>,
    interrupt: &AtomicBool,
) -> Result<bool> {
    let mut pending = vec![new];
    let mut visited = HashSet::new();
    while let Some(id) = pending.pop() {
        check_interrupt(interrupt)?;
        if id == old {
            return Ok(true);
        }
        if visited.insert(id) && !shallow.contains(&id) {
            let object = repository.find_object(id)?;
            if object.kind == Kind::Commit {
                pending.extend(object.try_to_commit_ref()?.parents());
            }
        }
    }
    Ok(false)
}

fn apply_edits(repository: &gix::Repository, edits: Vec<RefEdit>) -> Result<()> {
    if !edits.is_empty() {
        // Fetching must not require a configured author/committer or consult ambient identity
        // environment variables. Use an explicit, non-secret reflog identity instead.
        let actor = gix::actor::Signature {
            name: "Kingfisher".into(),
            email: "kingfisher@localhost".into(),
            time: gix::date::Time::now_utc(),
        };
        repository.edit_references_as(
            edits,
            Some(actor.to_ref(&mut gix::date::parse::TimeBuf::default())),
        )?;
    }
    Ok(())
}

fn check_interrupt(interrupt: &AtomicBool) -> Result<()> {
    ensure!(!interrupt.load(Ordering::Relaxed), "Git fetch interrupted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::git_test_fixture as fixture;
    use gix::objs::Write as _;

    // All fixtures use gix object/ref writes. No test setup requires a Git binary, a shell,
    // a network, environment mutation, or an external credential helper.
    fn repository(path: &Path, kind: gix::create::Kind) -> gix::Repository {
        gix::ThreadSafeRepository::init_opts(
            path,
            kind,
            Default::default(),
            gix::open::Options::isolated(),
        )
        .unwrap()
        .to_thread_local()
    }

    fn destination(path: &Path) -> gix::Repository {
        repository(path, gix::create::Kind::Bare)
    }

    fn specs(values: &[&str]) -> Vec<RefSpec> {
        values
            .iter()
            .map(|value| {
                gix::refspec::parse(
                    value.as_bytes().as_bstr(),
                    gix::refspec::parse::Operation::Fetch,
                )
                .unwrap()
                .to_owned()
            })
            .collect()
    }

    fn commit(source: &gix::Repository, contents: &[u8], parents: &[ObjectId]) -> ObjectId {
        let blob = source.write_blob(contents).unwrap().detach();
        let mut tree = source.empty_tree().edit().unwrap();
        fixture::insert(&mut tree, "secret.txt", blob, 0o100644).unwrap();
        commit_tree(source, tree.write().unwrap().detach(), parents)
    }

    fn commit_tree(source: &gix::Repository, tree: ObjectId, parents: &[ObjectId]) -> ObjectId {
        let signature = fixture::signature("fixture", "fixture@example.invalid");
        fixture::commit(
            source,
            None,
            &signature,
            &signature,
            "fixture",
            &tree,
            &parents.iter().collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn set_ref(source: &gix::Repository, name: &str, target: ObjectId) {
        fixture::reference(source, name, target, PreviousValue::Any, "fixture").unwrap();
    }

    fn set_native_ref(repository: &gix::Repository, name: &str, target: Target) {
        apply_edits(
            repository,
            vec![RefEdit::update(name.try_into().unwrap(), target, PreviousValue::Any, "fixture")],
        )
        .unwrap();
    }

    fn assert_ref(repository: &gix::Repository, name: &str, target: ObjectId) {
        assert_eq!(repository.find_reference(name).unwrap().id().detach(), target, "{name}");
    }

    fn assert_absent(repository: &gix::Repository, name: &str) {
        assert!(repository.try_find_reference(name).unwrap().is_none(), "{name}");
    }

    fn tag_names(selected: Vec<RefSpec>) -> BTreeSet<BString> {
        selected
            .iter()
            .map(|spec| match spec.to_ref().instruction() {
                Instruction::Fetch(Fetch::AndUpdate { src, dst, allow_non_fast_forward }) => {
                    assert_eq!(src, dst);
                    assert!(!allow_non_fast_forward, "implicit tag updates must not be forced");
                    src.to_owned()
                }
                other => panic!("unexpected implicit tag refspec: {other:?}"),
            })
            .collect()
    }

    fn set_shallow(repository: &gix::Repository, ids: &[ObjectId]) {
        let contents: String = ids.iter().map(|id| format!("{id}\n")).collect();
        std::fs::write(repository.shallow_file().unwrap(), contents).unwrap();
    }

    fn assert_shallow(repository: &gix::Repository, expected: &[ObjectId]) {
        let actual: BTreeSet<_> = repository
            .shallow_commits()
            .unwrap()
            .map(|ids| ids.iter().copied().collect())
            .unwrap_or_default();
        assert_eq!(actual, expected.iter().copied().collect());
        assert_eq!(repository.is_shallow().unwrap(), !expected.is_empty());
    }

    #[test]
    fn shallow_fetch_copies_only_reached_boundaries_and_follows_their_tags() {
        for keep_parent in [false, true] {
            for partial_destination in [false, true] {
                let temp = tempfile::tempdir().unwrap();
                let source_path = temp.path().join("source");
                let source = repository(&source_path, gix::create::Kind::Bare);
                let parent = if keep_parent {
                    commit(&source, b"outside the shallow boundary", &[])
                } else {
                    ObjectId::from_hex(b"1111111111111111111111111111111111111111").unwrap()
                };
                let boundary = commit(&source, b"boundary content", &[parent]);
                let tip = commit(&source, b"tip content", &[boundary]);
                let unrelated = commit(&source, b"unselected branch", &[parent]);
                set_ref(&source, "refs/heads/main", tip);
                set_ref(&source, "refs/heads/unselected", unrelated);
                fixture::set_head(&source, "refs/heads/main").unwrap();
                set_shallow(&source, &[boundary, unrelated]);
                let actor = fixture::signature("fixture", "fixture@example.invalid");
                fixture::tag(&source, "boundary", boundary, &actor, "included").unwrap();
                if keep_parent {
                    fixture::tag(&source, "parent", parent, &actor, "excluded").unwrap();
                }
                let destination = destination(&temp.path().join("destination"));
                if partial_destination {
                    let object = source.find_object(boundary).unwrap();
                    destination.objects.write_buf(object.kind, &object.data).unwrap();
                    if keep_parent {
                        let object = source.find_object(parent).unwrap();
                        destination.objects.write_buf(object.kind, &object.data).unwrap();
                        set_ref(&destination, "refs/heads/partial", boundary);
                    }
                }
                let interrupt = AtomicBool::new(false);
                let mut selected = specs(&["refs/heads/main:refs/remotes/origin/main"]);
                let tags =
                    auto_follow_tag_specs(&source, &destination, &selected, false, &interrupt)
                        .unwrap();
                assert_eq!(tag_names(tags.clone()), BTreeSet::from(["refs/tags/boundary".into()]));
                selected.extend(tags);
                fetch(&source_path, &destination, &selected, &interrupt).unwrap();

                assert_ref(&destination, "refs/remotes/origin/main", tip);
                assert_shallow(&destination, &[boundary]);
                assert_eq!(destination.has_object(parent), partial_destination && keep_parent);
                if keep_parent {
                    let tree =
                        source.find_object(parent).unwrap().try_to_commit_ref().unwrap().tree();
                    assert!(!destination.has_object(tree));
                }
                assert!(!destination.has_object(unrelated));
                for id in [boundary, tip] {
                    let tree =
                        destination.find_object(id).unwrap().try_to_commit_ref().unwrap().tree();
                    let tree = destination.find_object(tree).unwrap();
                    let entry = gix::objs::TreeRefIter::from_bytes(&tree.data, id.kind())
                        .next()
                        .unwrap()
                        .unwrap();
                    assert!(destination.has_object(entry.oid));
                }
            }
        }
    }

    #[test]
    fn shallow_fetch_preserves_existing_and_unrelated_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        let source = repository(&source_path, gix::create::Kind::Bare);
        let root = commit(&source, b"root", &[]);
        let boundary = commit(&source, b"boundary", &[root]);
        let tip = commit(&source, b"tip", &[boundary]);
        set_ref(&source, "refs/heads/main", tip);
        set_shallow(&source, &[boundary]);
        let destination = destination(&temp.path().join("destination"));
        let selected = specs(&["refs/heads/main:refs/remotes/origin/main"]);
        let interrupt = AtomicBool::new(false);
        fetch(&source_path, &destination, &selected, &interrupt).unwrap();
        assert_shallow(&destination, &[boundary]);
        assert!(!destination.has_object(root));

        let unrelated = commit(&destination, b"local shallow history", &[root]);
        set_ref(&destination, "refs/heads/local", unrelated);
        set_shallow(&destination, &[boundary, unrelated]);
        set_shallow(&source, &[]);
        let next = commit(&source, b"next", &[tip]);
        set_ref(&source, "refs/heads/main", next);
        fetch(&source_path, &destination, &selected, &interrupt).unwrap();
        assert_shallow(&destination, &[boundary, unrelated]);
        assert!(destination.has_object(root));
        assert_ref(&destination, "refs/remotes/origin/main", next);
        assert_ref(&destination, "refs/heads/local", unrelated);
    }

    #[test]
    fn shallow_source_does_not_truncate_existing_complete_destination_history() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        let source = repository(&source_path, gix::create::Kind::Bare);
        let root = commit(&source, b"root", &[]);
        let tip = commit(&source, b"tip", &[root]);
        set_ref(&source, "refs/heads/main", tip);
        let destination = destination(&temp.path().join("destination"));
        let selected = specs(&["refs/heads/main:refs/remotes/origin/main"]);
        let interrupt = AtomicBool::new(false);
        fetch(&source_path, &destination, &selected, &interrupt).unwrap();
        assert_shallow(&destination, &[]);

        set_shallow(&source, &[tip]);
        fetch(&source_path, &destination, &selected, &interrupt).unwrap();
        assert_shallow(&destination, &[]);
        assert!(destination.has_object(root));
    }

    #[test]
    fn shallow_branch_updates_require_provable_fast_forwards_unless_forced() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        let source = repository(&source_path, gix::create::Kind::Bare);
        let missing = ObjectId::from_hex(b"1111111111111111111111111111111111111111").unwrap();
        let root = commit(&source, b"root", &[missing]);
        set_ref(&source, "refs/heads/main", root);
        set_shallow(&source, &[root]);
        let destination = destination(&temp.path().join("destination"));
        let selected = specs(&["refs/heads/main:refs/heads/local"]);
        let interrupt = AtomicBool::new(false);
        fetch(&source_path, &destination, &selected, &interrupt).unwrap();
        let next = commit(&source, b"next", &[root]);
        set_ref(&source, "refs/heads/main", next);
        fetch(&source_path, &destination, &selected, &interrupt).unwrap();
        assert_ref(&destination, "refs/heads/local", next);

        let shallow_tip = commit(&source, b"new shallow tip", &[next]);
        set_ref(&source, "refs/heads/main", shallow_tip);
        set_shallow(&source, &[root, shallow_tip]);
        let error = fetch(&source_path, &destination, &selected, &interrupt).unwrap_err();
        assert!(error.to_string().contains("Refusing non-fast-forward"), "{error:#}");
        assert_ref(&destination, "refs/heads/local", next);
        assert_shallow(&destination, &[root]);

        fetch(
            &source_path,
            &destination,
            &specs(&["+refs/heads/main:refs/heads/local"]),
            &interrupt,
        )
        .unwrap();
        assert_ref(&destination, "refs/heads/local", shallow_tip);
        assert_shallow(&destination, &[root, shallow_tip]);
    }

    #[test]
    fn shallow_fetch_failure_does_not_publish_refs_or_boundaries_and_retry_completes() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        let source = repository(&source_path, gix::create::Kind::Bare);
        let missing_parent =
            ObjectId::from_hex(b"1111111111111111111111111111111111111111").unwrap();
        let contents = b"boundary blob supplied on retry";
        let missing_blob =
            gix::objs::compute_hash(source.object_hash(), Kind::Blob, contents).unwrap();
        let mut raw_tree = b"100644 secret.txt\0".to_vec();
        raw_tree.extend_from_slice(missing_blob.as_bytes());
        let tree = source.objects.write_buf(Kind::Tree, &raw_tree).unwrap();
        let boundary = commit_tree(&source, tree, &[missing_parent]);
        set_ref(&source, "refs/heads/main", boundary);
        set_shallow(&source, &[boundary]);
        let destination = destination(&temp.path().join("destination"));
        let old = commit(&destination, b"old", &[]);
        set_ref(&destination, "refs/remotes/origin/main", old);
        set_ref(&destination, "refs/remotes/origin/stale", old);
        let selected = specs(&["+refs/heads/*:refs/remotes/origin/*"]);
        assert!(fetch(&source_path, &destination, &selected, &AtomicBool::new(true)).is_err());
        let interrupt = AtomicBool::new(false);
        let error = fetch(&source_path, &destination, &selected, &interrupt).unwrap_err();
        assert!(error.to_string().contains(&missing_blob.to_string()), "{error:#}");
        assert_ref(&destination, "refs/remotes/origin/main", old);
        assert_ref(&destination, "refs/remotes/origin/stale", old);
        assert_shallow(&destination, &[]);
        // Objects are packed only after the whole graph was read, so a failed
        // traversal leaves no partial graph behind.
        assert!(!destination.has_object(boundary));

        assert_eq!(source.write_blob(contents).unwrap().detach(), missing_blob);
        let lock = gix::lock::File::acquire_to_update_resource(
            destination.shallow_file().unwrap(),
            gix::lock::acquire::Fail::Immediately,
            None,
            0,
        )
        .unwrap();
        let error = fetch(&source_path, &destination, &selected, &interrupt).unwrap_err();
        assert!(
            error.to_string().contains("Failed to lock local Git shallow boundary"),
            "{error:#}"
        );
        assert_ref(&destination, "refs/remotes/origin/main", old);
        assert_ref(&destination, "refs/remotes/origin/stale", old);
        assert_shallow(&destination, &[]);
        drop(lock);

        fetch(&source_path, &destination, &selected, &interrupt).unwrap();
        assert_ref(&destination, "refs/remotes/origin/main", boundary);
        assert_absent(&destination, "refs/remotes/origin/stale");
        assert_shallow(&destination, &[boundary]);
        assert!(destination.has_object(missing_blob));
        assert!(!destination.has_object(missing_parent));
    }

    #[test]
    fn auto_follow_tags_uses_complete_graph_head_raw_ids_and_negative_specs() {
        let temp = tempfile::tempdir().unwrap();
        let source = repository(&temp.path().join("source"), gix::create::Kind::Bare);
        let destination = destination(&temp.path().join("destination"));
        let blob = source.write_blob(b"reachable blob").unwrap().detach();
        let mut tree = source.empty_tree().edit().unwrap();
        fixture::insert(&mut tree, "secret.txt", blob, 0o100644).unwrap();
        let tree = tree.write().unwrap().detach();
        let root = commit_tree(&source, tree, &[]);
        let unrelated = commit(&source, b"unrelated", &[]);
        set_ref(&source, "refs/heads/main", root);
        set_ref(&source, "refs/heads/private", unrelated);
        fixture::detach_head(&source, root).unwrap();
        let actor = fixture::signature("fixture", "fixture@example.invalid");
        let commit_tag = fixture::tag(&source, "commit", root, &actor, "commit").unwrap();
        fixture::tag(&source, "nested", commit_tag, &actor, "nested").unwrap();
        fixture::tag(&source, "tree", tree, &actor, "tree").unwrap();
        fixture::tag(&source, "blob", blob, &actor, "blob").unwrap();
        fixture::tag(&source, "unrelated", unrelated, &actor, "unrelated").unwrap();
        set_ref(&source, "refs/tags/existing", root);
        let previous = destination.write_blob(b"local existing tag").unwrap().detach();
        set_ref(&destination, "refs/tags/existing", previous);
        let expected = BTreeSet::from([
            "refs/tags/commit".into(),
            "refs/tags/nested".into(),
            "refs/tags/tree".into(),
            "refs/tags/blob".into(),
        ]);
        for selected in [
            specs(&["refs/heads/main"]),
            specs(&["HEAD"]),
            specs(&["+refs/heads/*:refs/remotes/origin/*", "^refs/heads/private"]),
        ] {
            assert_eq!(
                tag_names(
                    auto_follow_tag_specs(
                        &source,
                        &destination,
                        &selected,
                        false,
                        &AtomicBool::new(false)
                    )
                    .unwrap()
                ),
                expected
            );
        }
        let selected = specs(&[&blob.to_string()]);
        assert_eq!(
            tag_names(
                auto_follow_tag_specs(
                    &source,
                    &destination,
                    &selected,
                    false,
                    &AtomicBool::new(false)
                )
                .unwrap()
            ),
            BTreeSet::from(["refs/tags/blob".into()]),
            "an object-ID source must not accidentally select unrelated advertised roots"
        );
        assert!(
            auto_follow_tag_specs(
                &source,
                &destination,
                &specs(&["refs/heads/main", "^refs/heads/main"]),
                false,
                &AtomicBool::new(false)
            )
            .unwrap()
            .is_empty()
        );
        let mut all = expected;
        all.insert("refs/tags/unrelated".into());
        all.insert("refs/tags/existing".into());
        assert_eq!(
            tag_names(
                auto_follow_tag_specs(&source, &destination, &[], true, &AtomicBool::new(false))
                    .unwrap()
            ),
            all
        );
        assert_ref(&destination, "refs/tags/existing", previous);
        assert!(
            !destination.has_object(root),
            "tag selection must not import objects or edit refs"
        );
    }

    #[test]
    fn all_tags_rejects_moved_tags_while_included_preserves_them() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        let source = repository(&source_path, gix::create::Kind::Bare);
        let destination = destination(&temp.path().join("destination"));
        let root = commit(&source, b"root", &[]);
        set_ref(&source, "refs/heads/main", root);
        set_ref(&source, "refs/tags/v1", root);
        let interrupt = AtomicBool::new(false);
        let selected = specs(&["refs/heads/main:refs/remotes/origin/main"]);
        let mut initial = selected.clone();
        initial.extend(
            auto_follow_tag_specs(&source, &destination, &selected, true, &interrupt).unwrap(),
        );
        fetch(&source_path, &destination, &initial, &interrupt).unwrap();
        assert_ref(&destination, "refs/tags/v1", root);

        let advanced = commit(&source, b"advanced", &[root]);
        set_ref(&source, "refs/heads/main", advanced);
        set_ref(&source, "refs/tags/v1", advanced);
        let mut all = selected.clone();
        let all_tags =
            auto_follow_tag_specs(&source, &destination, &selected, true, &interrupt).unwrap();
        assert_eq!(tag_names(all_tags.clone()), BTreeSet::from(["refs/tags/v1".into()]));
        all.extend(all_tags);
        let error = fetch(&source_path, &destination, &all, &interrupt).unwrap_err();
        assert!(error.to_string().contains("Refusing to overwrite Git tag"), "{error:#}");
        assert_ref(&destination, "refs/tags/v1", root);
        assert_ref(&destination, "refs/remotes/origin/main", root);

        let mut included = selected.clone();
        let included_tags =
            auto_follow_tag_specs(&source, &destination, &selected, false, &interrupt).unwrap();
        assert!(included_tags.is_empty());
        included.extend(included_tags);
        fetch(&source_path, &destination, &included, &interrupt).unwrap();
        assert_ref(&destination, "refs/tags/v1", root);
        assert_ref(&destination, "refs/remotes/origin/main", advanced);
    }

    #[test]
    fn fetching_into_checked_out_born_or_unborn_branch_is_rejected_even_when_forced() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        let source = repository(&source_path, gix::create::Kind::Bare);
        let destination =
            repository(&temp.path().join("destination"), gix::create::Kind::WithWorktree);
        let root = commit(&source, b"root", &[]);
        set_ref(&source, "refs/heads/main", root);
        fixture::set_head(&destination, "refs/heads/main").unwrap();
        for spec in ["refs/heads/main:refs/heads/main", "+refs/heads/main:refs/heads/main"] {
            let error = fetch(&source_path, &destination, &specs(&[spec]), &AtomicBool::new(false))
                .unwrap_err();
            assert!(error.to_string().contains("checked-out Git branch"), "{error:#}");
            assert_absent(&destination, "refs/heads/main");
        }
        set_ref(&destination, "refs/heads/main", root);
        let advanced = commit(&source, b"advanced", &[root]);
        set_ref(&source, "refs/heads/main", advanced);
        for spec in ["refs/heads/main:refs/heads/main", "+refs/heads/main:refs/heads/main"] {
            let error = fetch(&source_path, &destination, &specs(&[spec]), &AtomicBool::new(false))
                .unwrap_err();
            assert!(error.to_string().contains("checked-out Git branch"), "{error:#}");
            assert_ref(&destination, "refs/heads/main", root);
        }
    }

    #[test]
    fn auto_follow_tags_surfaces_interruption_and_missing_source_objects() {
        let temp = tempfile::tempdir().unwrap();
        let source = repository(&temp.path().join("source"), gix::create::Kind::Bare);
        let destination = destination(&temp.path().join("destination"));
        let root = commit(&source, b"root", &[]);
        set_ref(&source, "refs/heads/main", root);
        let selected = specs(&["refs/heads/main"]);
        assert!(
            auto_follow_tag_specs(&source, &destination, &selected, false, &AtomicBool::new(true))
                .is_err()
        );
        let missing = ObjectId::from_hex(b"1111111111111111111111111111111111111111").unwrap();
        let mut raw_tree = b"100644 missing.txt\0".to_vec();
        raw_tree.extend_from_slice(missing.as_slice());
        let tree = source.objects.write_buf(Kind::Tree, &raw_tree).unwrap();
        let broken = commit_tree(&source, tree, &[]);
        set_ref(&source, "refs/heads/main", broken);
        assert!(
            auto_follow_tag_specs(&source, &destination, &selected, false, &AtomicBool::new(false))
                .is_err()
        );
        assert!(destination.references().unwrap().all().unwrap().next().is_none());
    }

    #[test]
    fn imports_complete_graph_tags_custom_objects_and_symbolic_sources_but_not_gitlinks() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source with spaces");
        let source = repository(&source_path, gix::create::Kind::WithWorktree);
        let root = commit(&source, b"original", &[]);
        let left = commit(&source, b"left", &[root]);
        let right = commit(&source, b"right", &[root]);
        let blob = source.write_blob(b"nested contents").unwrap().detach();
        let link = source.write_blob(b"nested/file.txt").unwrap().detach();
        let mut nested = source.empty_tree().edit().unwrap();
        fixture::insert(&mut nested, "file.txt", blob, 0o100644).unwrap();
        let nested = nested.write().unwrap().detach();
        let gitlink = ObjectId::from_hex(b"1111111111111111111111111111111111111111").unwrap();
        let mut tree = source.empty_tree().edit().unwrap();
        fixture::insert(&mut tree, "nested", nested, 0o40000).unwrap();
        fixture::insert(&mut tree, "submodule", gitlink, 0o160000).unwrap();
        fixture::insert(&mut tree, "symlink", link, 0o120000).unwrap();
        let tree = tree.write().unwrap().detach();
        let merge = commit_tree(&source, tree, &[left, right]);
        set_ref(&source, "refs/heads/main", merge);
        set_ref(&source, "refs/custom/blob", blob);
        set_ref(&source, "refs/custom/tree", tree);
        fixture::set_head(&source, "refs/heads/main").unwrap();
        set_native_ref(
            &source,
            "refs/aliases/default",
            Target::Symbolic("refs/heads/main".try_into().unwrap()),
        );
        let signature = fixture::signature("fixture", "fixture@example.invalid");
        let tag = fixture::tag(&source, "v1", merge, &signature, "annotated").unwrap();
        let nested_tag = fixture::tag(&source, "v2", tag, &signature, "nested").unwrap();
        let unreachable = source.write_blob(b"not reachable from a ref").unwrap().detach();
        let destination = destination(&temp.path().join("destination with spaces"));

        let advertised = fetch(
            &source_path,
            &destination,
            &specs(&["+refs/*:refs/remotes/origin/*"]),
            &AtomicBool::new(false),
        )
        .unwrap();
        for (name, target) in [
            ("refs/remotes/origin/heads/main", merge),
            ("refs/remotes/origin/custom/blob", blob),
            ("refs/remotes/origin/custom/tree", tree),
            ("refs/remotes/origin/aliases/default", merge),
            ("refs/remotes/origin/tags/v1", tag),
            ("refs/remotes/origin/tags/v2", nested_tag),
        ] {
            assert_ref(&destination, name, target);
        }
        assert!(advertised.iter().any(|name| name.as_bstr() == "HEAD"));
        for oid in [root, left, right, merge, tree, nested, blob, link, tag, nested_tag] {
            let copied = destination.find_object(oid).unwrap();
            let original = source.find_object(oid).unwrap();
            assert_eq!(copied.data, original.data, "{oid}");
        }
        assert!(!destination.has_object(gitlink));
        assert!(!destination.has_object(unreachable));
        assert_absent(&destination, "refs/heads/main");
        assert_absent(&destination, "refs/tags/v1");
    }

    #[test]
    fn updates_and_prunes_mapped_refs_while_preserving_local_heads_tags_and_symbolic_head() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        let source = repository(&source_path, gix::create::Kind::Bare);
        let root = commit(&source, b"root", &[]);
        for name in [
            "refs/heads/main",
            "refs/heads/gone",
            "refs/heads/private",
            "refs/notes/custom",
            "refs/tags/v1",
        ] {
            set_ref(&source, name, root);
        }
        fixture::set_head(&source, "refs/heads/main").unwrap();
        let destination = destination(&temp.path().join("destination"));
        let initial_specs = specs(&["+refs/*:refs/remotes/origin/*", "+refs/notes/*:refs/notes/*"]);
        fetch(&source_path, &destination, &initial_specs, &AtomicBool::new(false)).unwrap();
        set_native_ref(&destination, "refs/heads/local-only", Target::Object(root));
        set_native_ref(&destination, "refs/tags/v1", Target::Object(root));
        set_native_ref(
            &destination,
            "refs/remotes/origin/HEAD",
            Target::Symbolic("refs/remotes/origin/heads/main".try_into().unwrap()),
        );

        let next = commit(&source, b"next", &[root]);
        set_ref(&source, "refs/heads/main", next);
        for name in ["refs/heads/gone", "refs/heads/private", "refs/notes/custom", "refs/tags/v1"] {
            apply_edits(
                &source,
                vec![RefEdit::delete(name.try_into().unwrap(), PreviousValue::Any)],
            )
            .unwrap();
        }
        let update_specs = specs(&[
            "+refs/*:refs/remotes/origin/*",
            "+refs/notes/*:refs/notes/*",
            "^refs/heads/private",
        ]);
        fetch(&source_path, &destination, &update_specs, &AtomicBool::new(false)).unwrap();
        assert_ref(&destination, "refs/remotes/origin/heads/main", next);
        assert_ref(&destination, "refs/heads/local-only", root);
        assert_ref(&destination, "refs/tags/v1", root);
        assert_ref(&destination, "refs/remotes/origin/heads/private", root);
        for name in [
            "refs/remotes/origin/heads/gone",
            "refs/remotes/origin/notes/custom",
            "refs/notes/custom",
            "refs/remotes/origin/tags/v1",
        ] {
            assert_absent(&destination, name);
        }
        assert_eq!(
            destination.find_reference("refs/remotes/origin/HEAD").unwrap().target(),
            gix::refs::TargetRef::Symbolic("refs/remotes/origin/heads/main".try_into().unwrap())
        );
    }

    #[test]
    fn standalone_pruning_handles_overlapping_shorthand_object_id_and_negative_specs() {
        let temp = tempfile::tempdir().unwrap();
        let destination = destination(&temp.path().join("destination"));
        let oid = destination.objects.write_buf(Kind::Blob, b"fixture").unwrap();
        for name in [
            "refs/tracking/shared",
            "refs/tracking/main",
            "refs/tracking/private",
            "refs/tracking/stale",
            "refs/tracking/raw",
            "refs/tags/stale",
            "refs/heads/local",
        ] {
            set_native_ref(&destination, name, Target::Object(oid));
        }
        set_native_ref(
            &destination,
            "refs/tracking/HEAD",
            Target::Symbolic("refs/tracking/main".try_into().unwrap()),
        );
        let raw_spec = format!("+{oid}:refs/tracking/raw");
        let fetch_specs = specs(&[
            "+refs/heads/gone:refs/tracking/shared",
            "+main:refs/tracking/shared",
            "+refs/heads/*:refs/tracking/*",
            "^refs/heads/private",
            &raw_spec,
            "+refs/tags/*:refs/tags/*",
        ]);
        let deleted = prune(&destination, &fetch_specs, &["refs/heads/main".into()]).unwrap();
        assert_eq!(
            deleted,
            vec![BString::from("refs/tags/stale"), BString::from("refs/tracking/stale")]
        );
        for name in [
            "refs/tracking/shared",
            "refs/tracking/main",
            "refs/tracking/private",
            "refs/tracking/raw",
            "refs/heads/local",
            "refs/tracking/HEAD",
        ] {
            assert!(destination.try_find_reference(name).unwrap().is_some(), "{name}");
        }
        assert!(prune(&destination, &[], &[]).unwrap().is_empty());
    }

    #[test]
    fn interrupted_or_incomplete_fetch_does_not_update_or_prune_and_retry_is_complete() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        let source = repository(&source_path, gix::create::Kind::Bare);
        let old = commit(&source, b"old", &[]);
        set_ref(&source, "refs/heads/main", old);
        fixture::set_head(&source, "refs/heads/main").unwrap();
        let destination = destination(&temp.path().join("destination"));
        let fetch_specs = specs(&["+refs/heads/*:refs/remotes/origin/*"]);
        fetch(&source_path, &destination, &fetch_specs, &AtomicBool::new(false)).unwrap();
        set_native_ref(&destination, "refs/remotes/origin/stale", Target::Object(old));
        let contents = b"object created only after the interrupted fetch";
        let missing_blob =
            gix::objs::compute_hash(source.object_hash(), Kind::Blob, contents).unwrap();
        let mut raw_tree = b"100644 missing.txt\0".to_vec();
        raw_tree.extend_from_slice(missing_blob.as_bytes());
        let tree = source.objects.write_buf(Kind::Tree, &raw_tree).unwrap();
        let next = commit_tree(&source, tree, &[old]);
        set_ref(&source, "refs/heads/main", next);

        assert!(fetch(&source_path, &destination, &fetch_specs, &AtomicBool::new(true)).is_err());
        assert!(!destination.has_object(next));
        assert!(fetch(&source_path, &destination, &fetch_specs, &AtomicBool::new(false)).is_err());
        assert_ref(&destination, "refs/remotes/origin/main", old);
        assert_ref(&destination, "refs/remotes/origin/stale", old);
        // Objects are packed only after the whole graph was read; nothing partial remains.
        assert!(!destination.has_object(next));

        assert_eq!(source.write_blob(contents).unwrap().detach(), missing_blob);
        fetch(&source_path, &destination, &fetch_specs, &AtomicBool::new(false)).unwrap();
        assert_ref(&destination, "refs/remotes/origin/main", next);
        assert!(destination.has_object(missing_blob));
        assert_absent(&destination, "refs/remotes/origin/stale");
    }

    #[test]
    fn branch_fast_forwards_tag_updates_and_forced_refspecs_match_git_rules() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        let source = repository(&source_path, gix::create::Kind::Bare);
        let root = commit(&source, b"root", &[]);
        set_ref(&source, "refs/heads/main", root);
        set_ref(&source, "refs/tags/v1", root);
        let destination = destination(&temp.path().join("destination"));
        let branch = specs(&["refs/heads/main:refs/heads/local"]);
        let tag = specs(&["refs/tags/v1:refs/tags/v1"]);
        fetch(&source_path, &destination, &branch, &AtomicBool::new(false)).unwrap();
        fetch(&source_path, &destination, &tag, &AtomicBool::new(false)).unwrap();
        let next = commit(&source, b"next", &[root]);
        set_ref(&source, "refs/heads/main", next);
        fetch(&source_path, &destination, &branch, &AtomicBool::new(false)).unwrap();
        assert_ref(&destination, "refs/heads/local", next);
        let unrelated = commit(&source, b"unrelated", &[]);
        set_ref(&source, "refs/heads/main", unrelated);
        assert!(fetch(&source_path, &destination, &branch, &AtomicBool::new(false)).is_err());
        assert_ref(&destination, "refs/heads/local", next);
        fetch(
            &source_path,
            &destination,
            &specs(&["+refs/heads/main:refs/heads/local"]),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_ref(&destination, "refs/heads/local", unrelated);
        set_ref(&source, "refs/tags/v1", next);
        assert!(fetch(&source_path, &destination, &tag, &AtomicBool::new(false)).is_err());
        assert_ref(&destination, "refs/tags/v1", root);
        fetch(
            &source_path,
            &destination,
            &specs(&["+refs/tags/v1:refs/tags/v1"]),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_ref(&destination, "refs/tags/v1", next);
    }

    #[test]
    fn source_only_and_object_id_specs_import_without_unrelated_ref_updates() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        let source = repository(&source_path, gix::create::Kind::Bare);
        let root = commit(&source, b"root", &[]);
        let blob = source.write_blob(b"unadvertised blob").unwrap().detach();
        set_ref(&source, "refs/heads/main", root);
        fixture::set_head(&source, "refs/heads/main").unwrap();
        let destination = destination(&temp.path().join("destination"));
        fetch(
            &source_path,
            &destination,
            &specs(&["HEAD", &format!("{blob}")]),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(destination.has_object(root));
        assert!(destination.has_object(blob));
        assert!(reference_targets(&destination).unwrap().is_empty());
    }

    #[test]
    fn missing_explicit_sources_and_mapping_conflicts_fail_before_pruning() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        let source = repository(&source_path, gix::create::Kind::Bare);
        let root = commit(&source, b"root", &[]);
        set_ref(&source, "refs/heads/main", root);
        set_ref(&source, "refs/heads/other", root);
        let destination = destination(&temp.path().join("destination"));
        let stale = destination.objects.write_buf(Kind::Blob, b"stale").unwrap();
        set_native_ref(&destination, "refs/tracking/stale", Target::Object(stale));
        for invalid in [
            vec!["+refs/heads/missing:refs/tracking/stale"],
            vec!["+refs/heads/main:refs/tracking/shared", "+refs/heads/other:refs/tracking/shared"],
        ] {
            assert!(
                fetch(&source_path, &destination, &specs(&invalid), &AtomicBool::new(false))
                    .is_err()
            );
            assert!(destination.try_find_reference("refs/tracking/stale").unwrap().is_some());
            assert!(!destination.has_object(root));
        }
    }

    #[test]
    fn empty_source_prunes_only_selected_direct_destinations() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("empty source");
        drop(repository(&source_path, gix::create::Kind::Bare));
        let destination = destination(&temp.path().join("destination"));
        let oid = destination.objects.write_buf(Kind::Blob, b"old").unwrap();
        set_native_ref(&destination, "refs/tracking/stale", Target::Object(oid));
        set_native_ref(&destination, "refs/heads/local", Target::Object(oid));
        set_native_ref(
            &destination,
            "refs/tracking/HEAD",
            Target::Symbolic("refs/tracking/stale".try_into().unwrap()),
        );
        let advertised = fetch(
            &source_path,
            &destination,
            &specs(&["+refs/heads/*:refs/tracking/*"]),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(advertised.is_empty());
        assert_absent(&destination, "refs/tracking/stale");
        assert!(destination.try_find_reference("refs/heads/local").unwrap().is_some());
        assert!(destination.try_find_reference("refs/tracking/HEAD").unwrap().is_some());
    }
}

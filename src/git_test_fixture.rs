//! Small, test-only Git fixture operations using the application's existing gix dependency.
//!
//! Objects, references, indexes and packs are serialized by gix, not by a second Git
//! implementation or an external executable. Integration tests include this private module.
#![allow(dead_code)]

use std::{io::Cursor, path::Path, sync::atomic::AtomicBool};

use anyhow::{Result, anyhow};
use bstr::ByteSlice;
use gix::{
    ObjectId, Repository,
    actor::Signature,
    refs::transaction::{PreviousValue, RefEdit},
};

pub(crate) fn signature(name: &str, email: &str) -> Signature {
    Signature { name: name.into(), email: email.into(), time: gix::date::Time::now_local_or_utc() }
}

/// Write a commit, optionally advancing a reference (including symbolic HEAD).
/// Parent order and independent author/committer dates are significant to history tests.
pub(crate) fn commit(
    repo: &Repository,
    reference: Option<&str>,
    author: &Signature,
    committer: &Signature,
    message: &str,
    tree: &ObjectId,
    parents: &[&ObjectId],
) -> Result<ObjectId> {
    let id = repo
        .write_object(&gix::objs::Commit {
            tree: *tree,
            parents: parents.iter().map(|id| **id).collect(),
            author: author.clone(),
            committer: committer.clone(),
            encoding: None,
            message: message.into(),
            extra_headers: Vec::new(),
        })?
        .detach();
    if let Some(reference) = reference {
        let edit = RefEdit::update(reference.try_into()?, id, PreviousValue::Any, message)
            .with_deref(true);
        repo.edit_references_as([edit], Some(committer.to_ref(&mut Default::default())))?;
    }
    Ok(id)
}

/// Apply a reference edit with an explicit fixture identity, independent of user config.
pub(crate) fn reference(
    repo: &Repository,
    name: &str,
    target: impl Into<gix::refs::Target>,
    expected: PreviousValue,
    message: &str,
) -> Result<()> {
    let actor = signature("tester", "tester@example.com");
    repo.edit_references_as(
        [RefEdit::update(name.try_into()?, target, expected, message)],
        Some(actor.to_ref(&mut Default::default())),
    )?;
    Ok(())
}

pub(crate) fn set_head(repo: &Repository, name: &str) -> Result<()> {
    reference(
        repo,
        "HEAD",
        gix::refs::Target::Symbolic(name.try_into()?),
        PreviousValue::Any,
        "set HEAD",
    )
}

pub(crate) fn detach_head(repo: &Repository, id: ObjectId) -> Result<()> {
    reference(repo, "HEAD", id, PreviousValue::Any, "detach HEAD")
}

pub(crate) fn tag(
    repo: &Repository,
    name: &str,
    target: ObjectId,
    signature: &Signature,
    message: &str,
) -> Result<ObjectId> {
    let id = repo
        .write_object(&gix::objs::Tag {
            target,
            target_kind: repo.find_object(target)?.kind,
            name: name.into(),
            tagger: Some(signature.clone()),
            message: message.into(),
            signature: None,
        })?
        .detach();
    reference(repo, &format!("refs/tags/{name}"), id, PreviousValue::MustNotExist, message)?;
    Ok(id)
}

/// Preserve the simple integer file modes used throughout the fixture declarations.
pub(crate) fn insert(
    builder: &mut gix::object::tree::Editor<'_>,
    name: impl AsRef<str>,
    id: ObjectId,
    mode: u32,
) -> Result<()> {
    let mode = gix::objs::tree::EntryMode::try_from(mode)
        .map_err(|mode| anyhow!("invalid fixture tree mode {mode:o}"))?;
    builder.upsert(name.as_ref(), mode.kind(), id)?;
    Ok(())
}

pub(crate) fn config(repo: &Repository, key: &str, value: &str) -> Result<()> {
    let path = repo.config_path(gix::config::Source::Local)?;
    let mut config = repo.config_file_mut(path)?;
    config.set_raw_value(key, value)?;
    config.commit()?;
    Ok(())
}

pub(crate) fn origin(repo: &Repository, url: &str) -> Result<()> {
    let path = repo.config_path(gix::config::Source::Local)?;
    let mut config = repo.config_file_mut(path)?;
    config.set_raw_value("remote.origin.url", url)?;
    config.set_raw_value("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")?;
    config.commit()?;
    Ok(())
}

/// Read the on-disk index, or start from HEAD when earlier fixture commits only
/// wrote trees. This keeps unstaged fixtures independent of Git's checkout features.
pub(crate) fn index(repo: &Repository) -> Result<gix::index::File> {
    if repo.index_path().is_file() {
        return Ok(gix::index::File::at(
            repo.index_path(),
            repo.object_hash(),
            false,
            Default::default(),
        )?);
    }
    let state = match repo.head_id() {
        Ok(id) => {
            let tree = repo.find_commit(id)?.tree_id()?;
            gix::index::State::from_tree(tree.as_ref(), &repo.objects, Default::default())?
        }
        Err(_) => gix::index::State::new(repo.object_hash()),
    };
    Ok(gix::index::File::from_state(state, repo.index_path()))
}

pub(crate) fn stage(repo: &Repository, index: &mut gix::index::State, path: &Path) -> Result<()> {
    let root = repo.workdir().ok_or_else(|| anyhow!("staging fixture requires a worktree"))?;
    let id = repo.write_blob(std::fs::read(root.join(path))?)?.detach();
    // Fixture paths are known UTF-8 repository-relative names. Index paths always
    // use '/', even when the corresponding filesystem path uses Windows separators.
    let path = path.to_str().ok_or_else(|| anyhow!("non-UTF-8 fixture path"))?.replace('\\', "/");
    unstage(index, Path::new(&path))?;
    index.dangerously_push_entry(
        Default::default(),
        id,
        gix::index::entry::Flags::empty(),
        gix::index::entry::Mode::FILE,
        path.as_bytes().as_bstr(),
    );
    index.sort_entries();
    Ok(())
}

pub(crate) fn unstage(index: &mut gix::index::State, path: &Path) -> Result<()> {
    let path = path.to_str().ok_or_else(|| anyhow!("non-UTF-8 fixture path"))?.replace('\\', "/");
    index.remove_entries(|_, candidate, _| candidate == path.as_bytes().as_bstr());
    Ok(())
}

pub(crate) fn write_tree(repo: &Repository, index: &gix::index::State) -> Result<ObjectId> {
    let mut tree = repo.empty_tree().edit()?;
    for entry in index.entries() {
        let mode = gix::objs::tree::EntryMode::try_from(entry.mode.bits())
            .map_err(|mode| anyhow!("invalid fixture index mode {mode:o}"))?;
        tree.upsert(entry.path(index), mode.kind(), entry.id)?;
    }
    Ok(tree.write()?.detach())
}

/// Install a native gix pack/index while deliberately retaining loose copies.
pub(crate) fn pack(repo: &Repository, ids: &[ObjectId]) -> Result<()> {
    use gix_pack::{
        self as pack,
        data::output::{Count, Entry, bytes::FromEntriesIter},
    };
    let entries = ids
        .iter()
        .map(|id| {
            let object = repo.find_object(*id)?;
            Entry::from_data(
                &Count::from_data(*id, None),
                &gix::objs::Data {
                    kind: object.kind,
                    data: &object.data,
                    object_hash: repo.object_hash(),
                },
                gix::zlib::Compression::DEFAULT,
            )
        })
        .collect::<gix::Result<Vec<_>>>()?;
    let mut output = FromEntriesIter::new(
        std::iter::once(Ok(entries)),
        Vec::new(),
        ids.len().try_into()?,
        pack::data::Version::V2,
        repo.object_hash(),
    );
    for chunk in output.by_ref() {
        chunk?;
    }
    let bytes = output.into_write();
    let directory = repo.git_dir().join("objects").join("pack");
    std::fs::create_dir_all(&directory)?;
    pack::Bundle::write_to_directory(
        &mut Cursor::new(bytes),
        Some(&directory),
        &mut gix::progress::Discard,
        &AtomicBool::new(false),
        Some(&repo.objects),
        repo.object_hash(),
        Default::default(),
    )?;
    Ok(())
}

//! Offline, read-only Git scopes with lazy blob reads and shared commit provenance.
//!
//! Enable the `git` feature to use this module. Preparation stores selected
//! ancestry and distinct file versions; configure limits when embedding in a
//! service. History compares each commit to its first parent, traversing every
//! merge parent and respecting shallow boundaries. Identical subtrees are never
//! traversed during a diff. No subprocess, fetch, checkout or repository writes
//! are performed, including for partial clones.
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result, bail};

use crate::ScanControl;

/// The content selected by a Git scope.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GitMode {
    /// File versions added or modified by selected commits.
    #[default]
    History,
    /// Regular files at one target revision.
    Snapshot,
    /// Target file versions different from a required baseline.
    Diff,
    /// Index versions different from the baseline (HEAD by default).
    Staged,
}

/// Selection policy. Revisions use gix's Git revision grammar, including reflogs
/// and `@{...}` forms. Revision evaluation is local and never executes commands.
#[derive(Clone, Debug)]
pub struct GitScope {
    /// Scope mode.
    pub mode: GitMode,
    /// Selected refs, or all refs plus HEAD when absent.
    pub refs: Option<Vec<String>>,
    /// Exclude this baseline's ancestors in history; compare against it in diffs.
    pub since_commit: Option<String>,
    /// Inclusive committer timestamp lower bound, relative to preparation time.
    pub since_hours: Option<f64>,
    /// Inclusive committer Unix timestamp lower bound.
    pub since_time: Option<i64>,
    /// Inclusive committer Unix timestamp upper bound.
    pub until_time: Option<i64>,
    /// Include this reachable root but exclude its ancestors.
    pub branch_root: Option<String>,
    /// Include stored unreachable commits and unassociated blobs.
    pub include_unreachable: bool,
}

impl Default for GitScope {
    fn default() -> Self {
        Self {
            mode: GitMode::History,
            refs: Some(vec!["HEAD".into()]),
            since_commit: None,
            since_hours: None,
            since_time: None,
            until_time: None,
            branch_root: None,
            include_unreachable: false,
        }
    }
}

/// Bounds apply to the complete iterator operation. Unset limits are unlimited.
#[derive(Clone, Debug)]
pub struct GitOptions {
    /// Search parent directories for a repository. Set false for explicit roots.
    pub discover: bool,
    /// Skip and report blobs larger than this size before allocating payloads.
    pub max_blob_size: Option<u64>,
    /// Reject preparation after this many distinct commits have been visited,
    /// including ancestry examined for time and revision exclusions.
    pub max_commits: Option<usize>,
    /// Reject preparation after this many distinct `(raw path, blob)` descriptors.
    pub max_inputs: Option<usize>,
    /// Report missing blobs as skipped events. Missing trees/commits still fail.
    pub skip_missing_blobs: bool,
}

impl Default for GitOptions {
    fn default() -> Self {
        Self {
            discover: true,
            max_blob_size: None,
            max_commits: None,
            max_inputs: None,
            skip_missing_blobs: false,
        }
    }
}

/// Git identity; offset is seconds east of UTC.
#[derive(Clone, PartialEq, Eq)]
pub struct GitSignature {
    /// Display name.
    pub name: String,
    /// Email address (excluded from Debug output).
    pub email: String,
    /// Unix timestamp.
    pub timestamp: i64,
    /// Timezone offset in seconds.
    pub timezone_offset: i32,
}
impl std::fmt::Debug for GitSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitSignature")
            .field("name", &self.name)
            .field("timestamp", &self.timestamp)
            .field("timezone_offset", &self.timezone_offset)
            .finish_non_exhaustive()
    }
}

/// One selected change occurrence, not a claim of first introduction.
#[derive(Clone, PartialEq, Eq)]
pub struct GitCommit {
    /// Commit object ID.
    pub id: gix::ObjectId,
    /// Original author.
    pub author: GitSignature,
    /// Original committer.
    pub committer: GitSignature,
    /// All original parent IDs (even at a shallow boundary).
    pub parents: Vec<gix::ObjectId>,
    /// Original commit message (excluded from Debug output).
    pub message: String,
}
impl std::fmt::Debug for GitCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitCommit")
            .field("id", &self.id)
            .field("author", &self.author)
            .field("committer", &self.committer)
            .field("parents", &self.parents)
            .finish_non_exhaustive()
    }
}

/// One distinct regular-file version and its selected change occurrences.
///
/// Commit metadata is shared across inputs. Non-UTF-8 raw paths are retained;
/// `path` is their lossy display form, so identity must use `raw_path`.
pub struct GitInput {
    /// Repository-relative path for path-aware scanning.
    pub path: String,
    /// Exact path bytes, including non-UTF-8 names.
    pub raw_path: Vec<u8>,
    /// Blob object ID.
    pub blob_id: gix::ObjectId,
    /// Blob payload, excluded from default Debug output.
    pub data: Vec<u8>,
    /// Shared commit metadata, one per selected occurrence.
    pub origins: Vec<Arc<GitCommit>>,
    /// Whether this came from the staged index.
    pub staged: bool,
    /// Unknown for stored blobs without regular-file provenance.
    pub unreachable: Option<bool>,
}

impl std::fmt::Debug for GitInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitInput")
            .field("path", &self.path)
            .field("blob_id", &self.blob_id)
            .field("origins", &self.origins)
            .field("staged", &self.staged)
            .field("unreachable", &self.unreachable)
            .finish_non_exhaustive()
    }
}

/// A skipped blob reason. A skip never implies a clean scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitSkipReason {
    /// The blob exceeded the configured size limit.
    Oversized,
    /// The blob is absent (for example in a partial/blobless clone).
    Missing,
}

/// A blob or an explicit coverage gap, in unspecified order.
pub enum GitEvent {
    /// A file version ready for scanning.
    Input(GitInput),
    /// A descriptor could not be read under the configured acquisition policy.
    Skipped {
        /// Lossy display path.
        path: String,
        /// Exact repository-relative path bytes.
        raw_path: Vec<u8>,
        /// Original blob ID.
        blob_id: gix::ObjectId,
        /// Why scanning this descriptor was skipped.
        reason: GitSkipReason,
    },
}

#[derive(Default)]
struct Record {
    origins: Vec<Arc<GitCommit>>,
    unreachable: Option<bool>,
}
type Records = BTreeMap<(Vec<u8>, gix::ObjectId), Record>;
type Files = BTreeMap<Vec<u8>, (gix::ObjectId, u16)>;
type CommitGraph = BTreeMap<gix::ObjectId, Vec<gix::ObjectId>>;

fn resolve(repo: &gix::Repository, name: &str) -> Result<gix::ObjectId> {
    if name.is_empty() || name.starts_with('-') {
        bail!("Git revision must be nonempty and must not start with '-'");
    }
    Ok(repo.rev_parse_single(name)?.object()?.peel_to_commit()?.id)
}

#[allow(clippy::too_many_arguments)]
fn walk(
    repo: &gix::Repository,
    mut pending: Vec<gix::ObjectId>,
    shallow: &HashSet<gix::ObjectId>,
    visited: &mut HashSet<gix::ObjectId>,
    options: &GitOptions,
    control: &ScanControl,
    known: Option<&CommitGraph>,
) -> Result<CommitGraph> {
    let mut commits = CommitGraph::new();
    while let Some(id) = pending.pop() {
        control.check()?;
        if commits.contains_key(&id) || known.is_some_and(|graph| graph.contains_key(&id)) {
            continue;
        }
        if !visited.contains(&id) {
            if options.max_commits.is_some_and(|limit| visited.len() >= limit) {
                bail!("Git preparation exceeds max_commits budget");
            }
            visited.insert(id);
        }
        let commit = repo.find_commit(id)?;
        let parents = if shallow.contains(&id) {
            Vec::new()
        } else {
            commit.parent_ids().map(|p| p.detach()).collect()
        };
        pending.extend(parents.iter().copied());
        commits.insert(id, parents);
    }
    Ok(commits)
}

fn regular(mode: u16) -> bool {
    gix::object::tree::EntryMode::try_from(u32::from(mode)).is_ok_and(|mode| {
        matches!(
            mode.kind(),
            gix::object::tree::EntryKind::Blob | gix::object::tree::EntryKind::BlobExecutable
        )
    })
}

fn canonical_mode(mode: gix::object::tree::EntryMode) -> u16 {
    gix::object::tree::EntryMode::from(mode.kind()).value()
}

/// Stream the low-level Git tree diff without loading blobs, external filters,
/// rename detection, attribute caches, or complete flattened snapshots.
/// The shared state reuses tree buffers across commit diffs.
fn tree_changes(
    repo: &gix::Repository,
    current: gix::ObjectId,
    base: Option<gix::ObjectId>,
    state: &mut gix::diff::tree::State,
    control: &ScanControl,
    add: impl FnMut(gix::diff::tree::recorder::Change) -> Result<()>,
) -> Result<()> {
    control.check()?;
    if Some(current) == base {
        return Ok(());
    }
    let current = repo.find_tree(current)?;
    let previous = match base {
        Some(base) => repo.find_tree(base)?,
        None => repo.empty_tree(),
    };
    tree_changes_loaded(repo, &current, &previous, state, control, add)
}

fn tree_changes_loaded(
    repo: &gix::Repository,
    current: &gix::Tree<'_>,
    previous: &gix::Tree<'_>,
    state: &mut gix::diff::tree::State,
    control: &ScanControl,
    add: impl FnMut(gix::diff::tree::recorder::Change) -> Result<()>,
) -> Result<()> {
    use gix::diff::tree::{
        Visit,
        visit::{Action, Change},
    };
    struct Delegate<'a, F> {
        path: gix::diff::tree::Recorder,
        add: F,
        control: &'a ScanControl,
        error: Option<anyhow::Error>,
    }
    impl<F: FnMut(gix::diff::tree::recorder::Change) -> Result<()>> Visit for Delegate<'_, F> {
        fn pop_front_tracked_path_and_set_current(&mut self) {
            self.path.pop_front_tracked_path_and_set_current();
        }
        fn push_back_tracked_path_component(&mut self, component: &bstr::BStr) {
            self.path.push_back_tracked_path_component(component);
        }
        fn push_path_component(&mut self, component: &bstr::BStr) {
            self.path.push_path_component(component);
        }
        fn pop_path_component(&mut self) {
            self.path.pop_path_component();
        }
        fn visit(&mut self, change: Change) -> Action {
            let record = match change {
                Change::Addition { entry_mode, oid, relation } => {
                    gix::diff::tree::recorder::Change::Addition {
                        entry_mode,
                        oid,
                        relation,
                        path: self.path.path_clone(),
                    }
                }
                Change::Deletion { entry_mode, oid, relation } => {
                    gix::diff::tree::recorder::Change::Deletion {
                        entry_mode,
                        oid,
                        relation,
                        path: self.path.path_clone(),
                    }
                }
                Change::Modification { previous_entry_mode, previous_oid, entry_mode, oid } => {
                    gix::diff::tree::recorder::Change::Modification {
                        previous_entry_mode,
                        previous_oid,
                        entry_mode,
                        oid,
                        path: self.path.path_clone(),
                    }
                }
            };
            match self
                .control
                .check()
                .map_err(anyhow::Error::from)
                .and_then(|()| (self.add)(record))
            {
                Ok(()) => Action::Continue(()),
                Err(error) => {
                    self.error = Some(error);
                    Action::Break(())
                }
            }
        }
    }
    control.check()?;
    if current.id == previous.id {
        return Ok(());
    }
    let mut delegate = Delegate { path: Default::default(), add, control, error: None };
    let outcome = gix::diff::tree(
        gix::objs::TreeRefIter::from_bytes(&previous.data, previous.id.kind()),
        gix::objs::TreeRefIter::from_bytes(&current.data, current.id.kind()),
        state,
        &repo.objects,
        &mut delegate,
    );
    if let Some(error) = delegate.error {
        return Err(error);
    }
    outcome?;
    control.check()?;
    Ok(())
}

#[cfg(test)]
fn changed_files(
    repo: &gix::Repository,
    current: gix::ObjectId,
    base: Option<gix::ObjectId>,
    control: &ScanControl,
    mut add: impl FnMut(Vec<u8>, gix::ObjectId) -> Result<()>,
) -> Result<()> {
    changed_files_with_state(repo, current, base, &mut Default::default(), control, &mut add)
}

fn changed_files_with_state(
    repo: &gix::Repository,
    current: gix::ObjectId,
    base: Option<gix::ObjectId>,
    state: &mut gix::diff::tree::State,
    control: &ScanControl,
    mut add: impl FnMut(Vec<u8>, gix::ObjectId) -> Result<()>,
) -> Result<()> {
    use gix::diff::tree::recorder::Change;
    tree_changes(repo, current, base, state, control, |change| match change {
        Change::Addition { entry_mode, oid, path, .. }
        | Change::Modification { entry_mode, oid, path, .. }
            if regular(entry_mode.value()) =>
        {
            add(path.to_vec(), oid)
        }
        _ => Ok(()),
    })
}

/// Unsupported adapter for CLI integration; preserves all tree entry kinds.
#[cfg(feature = "__cli-internals")]
pub(crate) fn cli_tree_changes(
    repo: &gix::Repository,
    current: &gix::Tree<'_>,
    base: Option<&gix::Tree<'_>>,
    control: &ScanControl,
) -> Result<Vec<gix::diff::tree::recorder::Change>> {
    let mut output = Vec::new();
    let empty = repo.empty_tree();
    tree_changes_loaded(
        repo,
        current,
        base.unwrap_or(&empty),
        &mut Default::default(),
        control,
        |change| {
            output.push(change);
            Ok(())
        },
    )?;
    Ok(output)
}

fn snapshot(repo: &gix::Repository, id: gix::ObjectId, control: &ScanControl) -> Result<Files> {
    let mut files = Files::new();
    // Track ancestors, not all visited OIDs: the same subtree can legitimately
    // appear under several paths. Exit markers keep the ancestry set bounded.
    let mut ancestors = HashSet::new();
    let mut pending = vec![(repo.find_commit(id)?.tree_id()?.detach(), Some(Vec::new()))];
    while let Some((id, prefix)) = pending.pop() {
        control.check()?;
        let Some(prefix) = prefix else {
            ancestors.remove(&id);
            continue;
        };
        if !ancestors.insert(id) {
            bail!("cyclic Git tree in staged baseline");
        }
        pending.push((id, None));
        for entry in repo.find_tree(id)?.iter() {
            control.check()?;
            let entry = entry?;
            let mut path = prefix.clone();
            path.extend_from_slice(entry.filename());
            if entry.mode().kind() == gix::object::tree::EntryKind::Tree {
                path.push(b'/');
                pending.push((entry.object_id(), Some(path)));
            } else if regular(entry.mode().value()) {
                files.insert(path, (entry.object_id(), canonical_mode(entry.mode())));
            }
        }
    }
    Ok(files)
}

fn metadata(commit: &gix::Commit<'_>) -> Result<GitCommit> {
    let signature = |sig: gix::actor::SignatureRef<'_>| -> Result<GitSignature> {
        let time = sig.time()?;
        Ok(GitSignature {
            name: String::from_utf8_lossy(sig.name).into_owned(),
            email: String::from_utf8_lossy(sig.email).into_owned(),
            timestamp: time.seconds,
            timezone_offset: time.offset,
        })
    };
    Ok(GitCommit {
        id: commit.id,
        author: signature(commit.author()?)?,
        committer: signature(commit.committer()?)?,
        parents: commit.parent_ids().map(|p| p.detach()).collect(),
        message: String::from_utf8_lossy(commit.decode()?.message).into_owned(),
    })
}

fn add(
    records: &mut Records,
    path: Vec<u8>,
    id: gix::ObjectId,
    origin: Option<&Arc<GitCommit>>,
    unreachable: Option<bool>,
    options: &GitOptions,
) -> Result<()> {
    let key = (path, id);
    let at_limit = options.max_inputs.is_some_and(|limit| records.len() >= limit);
    let record = match records.entry(key) {
        std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
        std::collections::btree_map::Entry::Vacant(entry) => {
            if at_limit {
                bail!("Git preparation exceeds max_inputs budget");
            }
            entry.insert(Record { origins: Vec::new(), unreachable })
        }
    };
    if unreachable == Some(false) {
        record.unreachable = Some(false);
    }
    if let Some(origin) = origin {
        record.origins.push(Arc::clone(origin));
    }
    Ok(())
}

fn validate_scope(scope: &GitScope) -> Result<()> {
    let history = scope.mode == GitMode::History;
    let time_filters =
        scope.since_hours.is_some() || scope.since_time.is_some() || scope.until_time.is_some();
    if scope.refs.as_ref().is_some_and(|refs| refs.is_empty() || refs.iter().any(|r| r.is_empty()))
    {
        bail!("refs must contain nonempty revisions");
    }
    if matches!(scope.mode, GitMode::Snapshot | GitMode::Diff)
        && !scope.refs.as_ref().is_some_and(|refs| refs.len() == 1)
    {
        bail!("snapshot/diff require exactly one ref");
    }
    if scope.mode == GitMode::Staged && scope.refs != Some(vec!["HEAD".into()]) {
        bail!("staged refs must stay at the default");
    }
    if (scope.since_commit.is_some() && scope.branch_root.is_some())
        || (scope.since_hours.is_some() && scope.since_time.is_some())
        || scope.since_hours.is_some_and(|hours| {
            !hours.is_finite() || hours <= 0.0 || hours * 3600.0 >= i64::MAX as f64
        })
        || scope.since_time.zip(scope.until_time).is_some_and(|(since, until)| since > until)
    {
        bail!("invalid Git scope bounds");
    }
    if !history && (time_filters || scope.branch_root.is_some()) {
        bail!("time and branch-root filters require history mode");
    }
    if scope.mode == GitMode::Snapshot && scope.since_commit.is_some() {
        bail!("snapshot does not accept since_commit");
    }
    if scope.mode == GitMode::Diff && scope.since_commit.is_none() {
        bail!("diff requires since_commit");
    }
    if scope.include_unreachable
        && (!history
            || scope.refs.is_some()
            || scope.since_commit.is_some()
            || time_filters
            || scope.branch_root.is_some())
    {
        bail!("include_unreachable requires unbounded all-ref history");
    }
    Ok(())
}

fn enumerate(
    repo: &gix::Repository,
    scope: &GitScope,
    options: &GitOptions,
    control: &ScanControl,
) -> Result<Records> {
    validate_scope(scope)?;
    let shallow: HashSet<_> =
        repo.shallow_commits()?.map(|ids| ids.iter().copied().collect()).unwrap_or_default();
    let mut tips = Vec::new();
    if scope.mode != GitMode::Staged {
        if let Some(refs) = &scope.refs {
            for reference in refs {
                control.check()?;
                tips.push(resolve(repo, reference)?);
            }
        } else {
            for reference in repo.references()?.all()? {
                control.check()?;
                let mut reference = reference.map_err(anyhow::Error::from_boxed)?;
                let object = reference.peel_to_id()?.object()?;
                if object.kind == gix::object::Kind::Commit {
                    tips.push(object.id);
                }
            }
            if let Some(head) = repo.head()?.try_into_peeled_id()? {
                tips.push(head.object()?.peel_to_commit()?.id);
            }
        }
    }
    tips.sort_unstable();
    tips.dedup();
    let mut records = Records::new();
    let mut diff_state = gix::diff::tree::State::default();
    match scope.mode {
        GitMode::Snapshot | GitMode::Diff => {
            let target = *tips.first().context("scope requires one commit ref")?;
            if options.max_commits == Some(0) {
                bail!("Git preparation exceeds max_commits budget");
            }
            let commit = repo.find_commit(target)?;
            let origin = Arc::new(metadata(&commit)?);
            let baseline =
                scope.since_commit.as_deref().map(|base| resolve(repo, base)).transpose()?;
            let commits = 1 + usize::from(baseline.is_some_and(|base| base != target));
            if options.max_commits.is_some_and(|limit| commits > limit) {
                bail!("Git preparation exceeds max_commits budget");
            }
            let base = baseline
                .map(|base| -> Result<_> { Ok(repo.find_commit(base)?.tree_id()?.detach()) })
                .transpose()?;
            changed_files_with_state(
                repo,
                commit.tree_id()?.detach(),
                base,
                &mut diff_state,
                control,
                |path, id| add(&mut records, path, id, Some(&origin), Some(false), options),
            )?;
        }
        GitMode::Staged => {
            let baseline = match scope.since_commit.as_deref() {
                Some(base) => Some(resolve(repo, base)?),
                None => repo
                    .head()?
                    .try_into_peeled_id()?
                    .map(|head| -> Result<_> { Ok(head.object()?.peel_to_commit()?.id) })
                    .transpose()?,
            };
            if baseline.is_some() && options.max_commits == Some(0) {
                bail!("Git preparation exceeds max_commits budget");
            }
            let base =
                baseline.map(|id| snapshot(repo, id, control)).transpose()?.unwrap_or_default();
            let index = repo.index()?;
            for entry in index.entries() {
                control.check()?;
                if entry.stage() != gix::index::entry::Stage::Unconflicted {
                    bail!("staged enumeration requires an index without conflicts");
                }
                if entry.mode.is_sparse() {
                    bail!("staged enumeration requires a non-sparse index");
                }
                if entry.flags.contains(gix::index::entry::Flags::INTENT_TO_ADD) {
                    continue;
                }
                if let Some(mode) = entry.mode.to_tree_entry_mode()
                    && regular(mode.value())
                    && base.get::<[u8]>(entry.path(&index).as_ref())
                        != Some(&(entry.id, canonical_mode(mode)))
                {
                    add(
                        &mut records,
                        entry.path(&index).to_vec(),
                        entry.id,
                        None,
                        Some(false),
                        options,
                    )?;
                }
            }
        }
        GitMode::History => {
            let mut visited = HashSet::new();
            let reachable = walk(repo, tips, &shallow, &mut visited, options, control, None)?;
            let mut excluded = HashSet::new();
            if let Some(base) = scope.since_commit.as_deref() {
                excluded.extend(
                    walk(
                        repo,
                        vec![resolve(repo, base)?],
                        &shallow,
                        &mut visited,
                        options,
                        control,
                        None,
                    )?
                    .keys()
                    .copied(),
                );
            }
            if let Some(root) = scope.branch_root.as_deref() {
                let root = resolve(repo, root)?;
                if !reachable.contains_key(&root) {
                    bail!("branch_root is not reachable from the selected refs");
                }
                excluded.extend(
                    walk(
                        repo,
                        reachable[&root].clone(),
                        &shallow,
                        &mut visited,
                        options,
                        control,
                        None,
                    )?
                    .keys()
                    .copied(),
                );
            }
            let reachable_ids: HashSet<_> = if scope.include_unreachable {
                reachable.keys().copied().collect()
            } else {
                HashSet::new()
            };
            let mut selected = reachable;
            if scope.include_unreachable {
                let mut stored_commits = Vec::new();
                for id in repo.objects.iter()? {
                    control.check()?;
                    let id = id?;
                    if !selected.contains_key(&id)
                        && repo.find_header(id)?.kind() == gix::object::Kind::Commit
                    {
                        if !visited.contains(&id) {
                            if options.max_commits.is_some_and(|limit| visited.len() >= limit) {
                                bail!("Git preparation exceeds max_commits budget");
                            }
                            visited.insert(id);
                        }
                        stored_commits.push(id);
                    }
                }
                let stored = walk(
                    repo,
                    stored_commits,
                    &shallow,
                    &mut visited,
                    options,
                    control,
                    Some(&selected),
                )?;
                selected.extend(stored);
            }
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()
                as i64;
            let since = scope.since_time.or_else(|| {
                scope.since_hours.map(|hours| now.saturating_sub((hours * 3600.0) as i64))
            });
            // Filtering after traversal is essential: committer timestamps can be skewed.
            for (id, parents) in selected {
                control.check()?;
                if excluded.contains(&id) {
                    continue;
                }
                let commit = repo.find_commit(id)?;
                let timestamp = commit.committer()?.time()?.seconds;
                if since.is_some_and(|t| timestamp < t)
                    || scope.until_time.is_some_and(|t| timestamp > t)
                {
                    continue;
                }
                let base = parents
                    .first()
                    .map(|id| -> Result<_> { Ok(repo.find_commit(*id)?.tree_id()?.detach()) })
                    .transpose()?;
                // Allocate metadata once only when this commit changes a regular file.
                let mut origin = None;
                changed_files_with_state(
                    repo,
                    commit.tree_id()?.detach(),
                    base,
                    &mut diff_state,
                    control,
                    |path, blob| {
                        if origin.is_none() {
                            origin = Some(Arc::new(metadata(&commit)?));
                        }
                        add(
                            &mut records,
                            path,
                            blob,
                            origin.as_ref(),
                            Some(scope.include_unreachable && !reachable_ids.contains(&id)),
                            options,
                        )
                    },
                )?;
            }
            if scope.include_unreachable {
                let associated: HashSet<_> = records.keys().map(|(_, id)| *id).collect();
                // Iterate storage again instead of retaining every stored blob ID
                // during commit preparation. Raw-object descriptors obey max_inputs.
                for id in repo.objects.iter()? {
                    control.check()?;
                    let id = id?;
                    if !associated.contains(&id)
                        && repo.find_header(id)?.kind() == gix::object::Kind::Blob
                    {
                        add(
                            &mut records,
                            format!("@git/{id}").into_bytes(),
                            id,
                            None,
                            None,
                            options,
                        )?;
                    }
                }
            }
        }
    }
    Ok(records)
}

/// Prepared descriptor iterator; payloads are read only in `next()`.
///
/// Controls cover preparation and the iterator's lifetime, including consumer
/// time. Deadlines and cancellation are cooperative around individual native
/// object reads. Each error is returned without a partial input; a failed blob
/// remains pending. Missing blobs are errors unless explicitly configured to skip.
pub struct GitInputs {
    repo: gix::ThreadSafeRepository,
    pending: VecDeque<((Vec<u8>, gix::ObjectId), Record)>,
    options: GitOptions,
    control: ScanControl,
    staged: bool,
}

impl GitInputs {
    /// Prepare an offline scope without changing repository files.
    pub fn open(
        path: impl AsRef<Path>,
        scope: GitScope,
        options: GitOptions,
        control: ScanControl,
    ) -> Result<Self> {
        control.check()?;
        let repo = if options.discover {
            gix::discover(path.as_ref())?
        } else {
            gix::open(path.as_ref())?
        };
        let pending = enumerate(&repo, &scope, &options, &control)?.into_iter().collect();
        control.check()?;
        Ok(Self {
            repo: repo.into_sync(),
            pending,
            options,
            control,
            staged: scope.mode == GitMode::Staged,
        })
    }

    fn next_event(&mut self) -> Result<Option<GitEvent>> {
        self.control.check()?;
        let Some(((raw_path, id), _)) = self.pending.front() else { return Ok(None) };
        let repo = self.repo.to_thread_local();
        let header = repo.try_find_header(*id)?;
        let skipped = match header {
            None if self.options.skip_missing_blobs => Some(GitSkipReason::Missing),
            None => bail!(
                "Git blob {id} is missing; partial clones are not fetched automatically; use skip_missing_blobs to report and skip"
            ),
            Some(header)
                if self.options.max_blob_size.is_some_and(|limit| header.size() > limit) =>
            {
                Some(GitSkipReason::Oversized)
            }
            Some(header) if header.kind() != gix::object::Kind::Blob => {
                bail!("Git object {id} is not a blob")
            }
            _ => None,
        };
        if let Some(reason) = skipped {
            let path = String::from_utf8_lossy(raw_path).into_owned();
            let ((raw_path, blob_id), _) = self.pending.pop_front().expect("pending descriptor");
            return Ok(Some(GitEvent::Skipped { path, raw_path, blob_id, reason }));
        }
        let data = std::mem::take(&mut repo.find_blob(*id)?.data);
        self.control.check()?;
        let ((raw_path, blob_id), record) = self.pending.pop_front().expect("pending descriptor");
        Ok(Some(GitEvent::Input(GitInput {
            path: String::from_utf8_lossy(&raw_path).into_owned(),
            raw_path,
            blob_id,
            data,
            origins: record.origins,
            staged: self.staged,
            unreachable: record.unreachable,
        })))
    }
}

impl Iterator for GitInputs {
    type Item = Result<GitEvent>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_event().transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tree(
        repo: &gix::Repository,
        entries: Vec<(&[u8], gix::ObjectId, gix::object::tree::EntryKind)>,
    ) -> gix::ObjectId {
        let mut entries: Vec<_> = entries
            .into_iter()
            .map(|(name, oid, kind)| gix::objs::tree::Entry {
                mode: kind.into(),
                filename: name.into(),
                oid,
            })
            .collect();
        entries.sort();
        repo.write_object(gix::objs::Tree { entries }).unwrap().detach()
    }

    #[test]
    fn malformed_tree_modes_are_skipped_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(dir.path()).unwrap();
        let blob = repo.write_blob(b"data").unwrap().detach();
        let mut entries = Vec::new();
        for (name, mode) in [("invalid", "77777 "), ("zero", "0 "), ("valid", "100644 ")] {
            entries.push(gix::objs::tree::Entry {
                mode: gix::object::tree::EntryMode::from_bytes(mode.as_bytes()).unwrap(),
                filename: name.into(),
                oid: blob,
            });
        }
        entries.sort();
        let id = repo.write_object(gix::objs::Tree { entries }).unwrap().detach();
        let mut changed = Vec::new();
        changed_files(&repo, id, None, &ScanControl::default(), |path, _| {
            changed.push(path);
            Ok(())
        })
        .unwrap();
        assert_eq!(changed, vec![b"valid".to_vec()]);
    }

    #[test]
    fn snapshot_preserves_shared_subtrees_and_canonicalizes_legacy_modes() {
        use gix::object::tree::EntryKind::{Blob, Tree};
        let dir = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(dir.path()).unwrap();
        let blob = repo.write_blob(b"data").unwrap().detach();
        let subtree = tree(&repo, vec![(b"file", blob, Blob)]);
        let root = tree(&repo, vec![(b"a", subtree, Tree), (b"b", subtree, Tree)]);
        let sig = gix::actor::SignatureRef::from_bytes(b"test <test@example.com> 1700000000 +0000")
            .unwrap();
        let commit = repo
            .commit_as(sig, sig, "refs/heads/test", "test", root, Vec::<gix::ObjectId>::new())
            .unwrap()
            .detach();
        let files = snapshot(&repo, commit, &ScanControl::default()).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[b"a/file".as_slice()], files[b"b/file".as_slice()]);
        let legacy = gix::object::tree::EntryMode::try_from(0o100664).unwrap();
        assert_eq!(canonical_mode(legacy), 0o100644);
    }

    #[test]
    fn stored_walk_does_not_reopen_known_reachable_commits() {
        let dir = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(dir.path()).unwrap();
        // A missing object proves the known graph is checked before any read.
        let id = gix::ObjectId::null(repo.object_hash());
        let known = CommitGraph::from([(id, Vec::new())]);
        assert!(
            walk(
                &repo,
                vec![id],
                &HashSet::new(),
                &mut HashSet::new(),
                &GitOptions::default(),
                &ScanControl::default(),
                Some(&known)
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn identical_subtrees_are_skipped_without_loading_their_objects() {
        let dir = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(dir.path()).unwrap();
        let before = repo.write_blob(b"before").unwrap().detach();
        let after = repo.write_blob(b"after").unwrap().detach();
        // A deliberately missing subtree makes an accidental full flatten fail.
        let missing = gix::ObjectId::null(repo.object_hash());
        let previous = tree(
            &repo,
            vec![
                (b"a", before, gix::object::tree::EntryKind::Blob),
                (b"unchanged", missing, gix::object::tree::EntryKind::Tree),
            ],
        );
        let current = tree(
            &repo,
            vec![
                (b"a", after, gix::object::tree::EntryKind::Blob),
                (b"unchanged", missing, gix::object::tree::EntryKind::Tree),
            ],
        );
        let mut changes = Vec::new();
        changed_files(&repo, current, Some(previous), &ScanControl::default(), |path, id| {
            changes.push((path, id));
            Ok(())
        })
        .unwrap();
        assert_eq!(changes, vec![(b"a".to_vec(), after)]);
    }

    #[test]
    fn tree_diff_handles_replacements_modes_raw_paths_and_nested_changes() {
        use gix::object::tree::EntryKind::{Blob, BlobExecutable, Tree};
        let dir = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(dir.path()).unwrap();
        let id = repo.write_blob(b"data").unwrap().detach();
        let nested = tree(&repo, vec![(b"raw-\xff", id, Blob)]);
        let previous =
            tree(&repo, vec![(b"mode", id, Blob), (b"replace", id, Blob), (b"removed", id, Blob)]);
        let current = tree(&repo, vec![(b"mode", id, BlobExecutable), (b"replace", nested, Tree)]);
        let mut changes = Vec::new();
        changed_files(&repo, current, Some(previous), &ScanControl::default(), |path, id| {
            changes.push((path, id));
            Ok(())
        })
        .unwrap();
        changes.sort();
        assert_eq!(changes, vec![(b"mode".to_vec(), id), (b"replace/raw-\xff".to_vec(), id)]);
    }

    #[test]
    fn history_shares_origins_and_applies_preparation_and_blob_limits() {
        use gix::object::tree::EntryKind::Blob;
        let dir = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(dir.path()).unwrap();
        let first = repo.write_blob(b"first").unwrap().detach();
        let second = repo.write_blob(b"second").unwrap().detach();
        let root_tree = tree(&repo, vec![(b"a", first, Blob), (b"b", first, Blob)]);
        let next_tree = tree(&repo, vec![(b"a", second, Blob), (b"b", first, Blob)]);
        let sig =
            gix::actor::SignatureRef::from_bytes(b"person <private@example.com> 1700000000 +0000")
                .unwrap();
        let root = repo
            .commit_as(
                sig,
                sig,
                "refs/heads/test",
                "private message",
                root_tree,
                Vec::<gix::ObjectId>::new(),
            )
            .unwrap()
            .detach();
        repo.commit_as(sig, sig, "refs/heads/test", "change", next_tree, [root]).unwrap();
        drop(repo);
        let scope = GitScope { refs: Some(vec!["refs/heads/test".into()]), ..Default::default() };
        let events: Vec<_> = GitInputs::open(
            dir.path(),
            scope.clone(),
            GitOptions::default(),
            ScanControl::default(),
        )
        .unwrap()
        .map(|event| match event.unwrap() {
            GitEvent::Input(input) => input,
            _ => panic!("unexpected skip"),
        })
        .collect();
        assert_eq!(events.len(), 3);
        let original: Vec<_> = events.iter().filter(|input| input.blob_id == first).collect();
        assert!(Arc::ptr_eq(&original[0].origins[0], &original[1].origins[0]));
        assert_eq!(original[0].origins[0].id, root);
        assert!(!format!("{:?}", original[0]).contains("private message"));
        assert!(!format!("{:?}", original[0]).contains("private@example.com"));
        for options in [
            GitOptions { max_commits: Some(1), ..Default::default() },
            GitOptions { max_inputs: Some(2), ..Default::default() },
        ] {
            assert!(
                GitInputs::open(dir.path(), scope.clone(), options, ScanControl::default())
                    .is_err()
            );
        }
        let options = GitOptions { max_blob_size: Some(0), ..Default::default() };
        let skipped: Vec<_> =
            GitInputs::open(dir.path(), scope, options, ScanControl::default()).unwrap().collect();
        assert_eq!(skipped.len(), 3);
        assert!(skipped.into_iter().all(|event| matches!(
            event.unwrap(),
            GitEvent::Skipped { reason: GitSkipReason::Oversized, .. }
        )));
    }

    #[test]
    fn scope_validation_and_private_metadata() {
        assert!(validate_scope(&GitScope::default()).is_ok());
        assert!(validate_scope(&GitScope { mode: GitMode::Diff, ..GitScope::default() }).is_err());
        assert!(
            validate_scope(&GitScope { since_hours: Some(f64::NAN), ..GitScope::default() })
                .is_err()
        );
        assert!(
            validate_scope(&GitScope { since_hours: Some(1e300), ..Default::default() }).is_err()
        );
        let sig = GitSignature {
            name: "person".into(),
            email: "private@example.com".into(),
            timestamp: 0,
            timezone_offset: 0,
        };
        assert!(!format!("{sig:?}").contains("private@example.com"));
    }
}

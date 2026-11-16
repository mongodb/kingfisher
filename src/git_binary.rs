//! Native repository acquisition. The module name is retained for API compatibility;
//! no operation needs a local Git executable or credential helper. SSH uses the
//! system SSH client; all Git protocol, object and reference work remains native.
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use gix::{
    ObjectId,
    bstr::{BString, ByteSlice},
    refs::{
        Target,
        transaction::{PreviousValue, RefEdit},
    },
    remote::{Direction, fetch::Tags},
};
use tracing::debug;
use url::Url;

use crate::{git_auth::GitAuth, git_url::GitUrl};

mod http;
mod local;
mod ssh;

const DEFAULT_GIT_CLONE_TIMEOUT_SECS: u64 = 1200;
const DEFAULT_GIT_UPDATE_TIMEOUT_SECS: u64 = 600;

fn timeout_from_env(var: &str, default_secs: u64) -> Duration {
    std::env::var(var)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(default_secs))
}

/// Exact HTTPS authorities each provider's in-memory credentials may target.
#[derive(Debug, Clone, Default)]
pub struct ProviderHosts {
    pub github: Vec<String>,
    pub gitlab: Vec<String>,
    pub gitea: Vec<String>,
    pub bitbucket: Vec<String>,
    pub azure: Vec<String>,
    pub huggingface: Vec<String>,
}

impl ProviderHosts {
    pub fn saas_defaults() -> Self {
        Self {
            github: vec!["github.com".into()],
            gitlab: vec!["gitlab.com".into()],
            gitea: vec!["gitea.com".into()],
            bitbucket: vec!["bitbucket.org".into()],
            azure: vec!["dev.azure.com".into()],
            huggingface: vec!["huggingface.co".into()],
        }
    }

    pub fn add(list: &mut Vec<String>, host: &str) {
        let host = host.trim().to_ascii_lowercase();
        if !host.is_empty() && !list.contains(&host) {
            list.push(host);
        }
    }

    pub fn is_github_url(&self, repo_url: &GitUrl) -> bool {
        let Ok(url) = Url::parse(repo_url.as_str()) else {
            return false;
        };
        // Provider tokens (including minted GitHub App tokens) are only usable over
        // HTTP(S); an ssh:// URL must not trigger token setup it can never use.
        if !matches!(url.scheme(), "https" | "http") {
            return false;
        }
        let Some(host) = url.host_str() else {
            return false;
        };
        let authority = match url.port() {
            Some(port) => format!("{}:{port}", host.to_ascii_lowercase()),
            None => host.to_ascii_lowercase(),
        };
        self.github.iter().any(|trusted| trusted.eq_ignore_ascii_case(&authority))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("Git operation failed: {0:#}")]
    Operation(#[from] anyhow::Error),
    #[error("Git operation timed out after {secs} seconds")]
    Timeout { secs: u64 },
}

/// Native clone/fetch with noninteractive, authority-scoped authentication.
pub struct Git {
    auth: GitAuth,
    no_timeouts: bool,
    ignore_certs: bool,
}

impl Default for Git {
    fn default() -> Self {
        Self::new(false)
    }
}

impl Git {
    pub fn new(ignore_certs: bool) -> Self {
        Self::with_provider_hosts(ignore_certs, &ProviderHosts::saas_defaults())
    }

    pub fn with_provider_hosts(ignore_certs: bool, provider_hosts: &ProviderHosts) -> Self {
        Self { auth: GitAuth::from_env(provider_hosts), no_timeouts: false, ignore_certs }
    }

    /// Explicit GitHub App credentials replace, rather than fall back to, the environment token.
    pub fn with_provider_hosts_and_github_token(
        ignore_certs: bool,
        provider_hosts: &ProviderHosts,
        github_token: Option<String>,
    ) -> Self {
        Self {
            auth: GitAuth::with_github_token(provider_hosts, github_token),
            no_timeouts: false,
            ignore_certs,
        }
    }

    pub fn without_timeouts(mut self, disabled: bool) -> Self {
        self.no_timeouts = disabled;
        self
    }

    pub fn create_fresh_clone(
        &self,
        repo_url: &GitUrl,
        output_dir: &Path,
        clone_mode: CloneMode,
    ) -> Result<(), GitError> {
        self.clone(repo_url, output_dir, clone_mode, None)
    }

    /// Bare, full-history clone of one branch or tag, without automatically following tags.
    pub fn create_branch_clone(
        &self,
        repo_url: &GitUrl,
        output_dir: &Path,
        branch: &str,
    ) -> Result<(), GitError> {
        self.clone(repo_url, output_dir, CloneMode::Bare, Some(branch))
    }

    fn clone(
        &self,
        repo_url: &GitUrl,
        output_dir: &Path,
        mode: CloneMode,
        branch: Option<&str>,
    ) -> Result<(), GitError> {
        let operation = Operation::new(
            timeout_from_env("KF_GIT_CLONE_TIMEOUT_SECS", DEFAULT_GIT_CLONE_TIMEOUT_SECS),
            self.no_timeouts,
        );
        let mut cleanup = None;
        let result = (|| -> Result<()> {
            let kind = if matches!(mode, CloneMode::Checkout) {
                gix::create::Kind::WithWorktree
            } else {
                gix::create::Kind::Bare
            };
            let absolute = std::path::absolute(output_dir)?;
            ensure!(absolute.parent().is_some(), "Cannot clone into a filesystem root");
            if let Ok(metadata) = std::fs::symlink_metadata(&absolute) {
                ensure!(
                    !metadata.file_type().is_symlink(),
                    "Clone destination must not be a symlink"
                );
                ensure!(
                    absolute.canonicalize()?.parent().is_some(),
                    "Cannot clone into a filesystem root"
                );
            }
            operation.check()?;
            std::fs::create_dir_all(absolute.parent().context("Clone destination has no parent")?)
                .context("Failed to create clone parent directories")?;
            operation.check()?;
            let mut repo = gix::ThreadSafeRepository::init_opts(
                &absolute,
                kind,
                gix::create::Options {
                    destination_must_be_empty: Some(true),
                    ..Default::default()
                },
                open_options(),
            )?
            .to_thread_local();
            // Only arm cleanup after init has verified an empty destination. Resolve
            // the actual target once; never delete a caller's preexisting repository.
            cleanup = Some(CloneDestination::new(&absolute)?);
            let mut specs = vec!["+refs/*:refs/remotes/origin/*".to_owned()];
            if let Some(branch) = branch {
                let name = format!("refs/heads/{branch}");
                let _: gix::refs::FullName = name.as_str().try_into()?;
                specs = vec![format!("+{name}:{name}")];
            } else if matches!(mode, CloneMode::Mirror) {
                specs.push("+refs/*:refs/*".into());
            } else if matches!(mode, CloneMode::Checkout) {
                specs.push("+refs/heads/*:refs/remotes/origin/*".into());
            }
            let mut remote = repo
                .remote_at(repo_url.as_str())?
                .with_refspecs(specs.iter().map(String::as_str), Direction::Fetch)?;
            if branch.is_some() {
                remote = remote.with_fetch_tags(Tags::None);
            }
            let mut config = repo.config_file_mut(repo.common_dir().join("config"))?;
            remote.save_as_to("origin", &mut config)?;
            if matches!(mode, CloneMode::Mirror) {
                config.set_raw_value("remote.origin.mirror", "true")?;
            }
            config.commit()?;
            repo.reload()?;
            // Network fetch writes reflogs for worktree clones. Unlike Git,
            // gix requires an explicit identity; install a memory-only fallback
            // without changing the user's configured name or repository config.
            repo.committer_or_set_fallback("Kingfisher", "kingfisher@localhost")?;

            let remote = repo.find_remote("origin")?;
            let mut extra = Vec::new();
            if branch.is_none() {
                if matches!(mode, CloneMode::Bare) {
                    extra.push(parse_refspec("+refs/heads/*:refs/heads/*")?);
                }
                if !matches!(mode, CloneMode::Mirror) {
                    extra.push(parse_refspec("refs/tags/*:refs/tags/*")?);
                }
            }
            let head = self.fetch(&repo, &remote, &extra, &operation, true)?;
            operation.check()?;
            let head = if let Some(branch) = branch {
                let name = format!("refs/heads/{branch}");
                if let Some(reference) = repo.try_find_reference(name.as_str())? {
                    RemoteHead { target: Some(name.into()), id: Some(reference.id().detach()) }
                } else {
                    let id = repo
                        .find_reference(format!("refs/tags/{branch}").as_str())
                        .with_context(|| format!("Remote branch or tag '{branch}' was not found"))?
                        .peel_to_commit()?
                        .id;
                    RemoteHead { target: None, id: Some(id) }
                }
            } else {
                head
            };
            set_initial_head(&repo, &head, mode)?;
            if matches!(mode, CloneMode::Checkout) {
                checkout(&repo, &operation.interrupt)?;
            }
            operation.check()?;
            Ok(())
        })();
        let result = operation.finish(result);
        if result.is_ok()
            && let Some(cleanup) = cleanup.as_mut()
        {
            cleanup.keep = true;
        }
        result
    }

    /// Fetch and prune every configured remote; leave the user's HEAD and worktree untouched.
    pub fn update_clone(&self, _repo_url: &GitUrl, output_dir: &Path) -> Result<(), GitError> {
        let operation = Operation::new(
            timeout_from_env("KF_GIT_UPDATE_TIMEOUT_SECS", DEFAULT_GIT_UPDATE_TIMEOUT_SECS),
            self.no_timeouts,
        );
        let result = (|| -> Result<()> {
            let mut repo = gix::open_opts(output_dir, open_options())
                .context("Failed to open clone for update")?;
            scrub_legacy_remote_credentials(&mut repo)?;
            repo.committer_or_set_fallback("Kingfisher", "kingfisher@localhost")?;
            let names = repo.remote_names();
            for name in names {
                operation.check()?;
                let skip = gix::config::KeyRef {
                    section_name: "remote",
                    subsection_name: Some(name.as_bstr()),
                    value_name: "skipDefaultUpdate",
                };
                if repo.config_snapshot().boolean(skip) == Some(true) {
                    continue;
                }
                let remote = repo.find_remote(name.as_bstr())?;
                self.fetch(&repo, &remote, &[], &operation, false)
                    .with_context(|| format!("Failed to fetch remote {name}"))?;
            }
            operation.check()
        })();
        operation.finish(result)
    }

    fn fetch(
        &self,
        repo: &gix::Repository,
        remote: &gix::Remote<'_>,
        extra: &[gix::refspec::RefSpec],
        operation: &Operation,
        initial: bool,
    ) -> Result<RemoteHead> {
        operation.check()?;
        let (mut url, version) = remote.sanitized_url_and_version(Direction::Fetch)?;
        // HTTP credentials never enter URLs, including URL rewrites. An SSH
        // username is routing information and must be retained (e.g. git@host).
        if matches!(url.scheme, gix::url::Scheme::Http | gix::url::Scheme::Https) {
            url.set_user(None);
            url.set_password(None);
        }
        if url.scheme == gix::url::Scheme::Ssh {
            let (transport, process) = ssh::connect(
                repo,
                url,
                version,
                operation.deadline,
                Arc::clone(&operation.interrupt),
            )?;
            return self
                .receive(repo, remote, transport, extra, initial, operation)
                .map_err(|error| process.explain(error));
        }
        if url.scheme == gix::url::Scheme::File {
            let path = gix::path::from_bstr(url.path.as_bstr())?;
            let source = gix::open_opts(path.as_ref(), open_options())
                .context("Failed to open local clone source")?;
            let selected = narrow_clone_ref(remote, initial);
            if let Some(name) = selected
                && let Some(short) = name.strip_prefix(b"refs/heads/")
                && source.try_find_reference(name)?.is_none()
            {
                let mut tag = BString::from("refs/tags/");
                tag.extend_from_slice(short);
                ensure!(
                    source.try_find_reference(tag.as_bstr())?.is_some(),
                    "Remote branch or tag '{short}' was not found",
                    short = short.as_bstr(),
                );
                drop(source);
                return self.fetch_tag_clone(repo, remote, tag.as_bstr(), extra, operation);
            }
            let source_head = source.head()?;
            let head = RemoteHead {
                target: source_head.referent_name().map(|name| name.as_bstr().to_owned()),
                id: source_head.id().map(|id| id.detach()),
            };
            let mut specs = remote.refspecs(Direction::Fetch).to_vec();
            specs.extend_from_slice(extra);
            if initial && selected.is_none() && head.id.is_some() {
                specs.push(parse_refspec("HEAD")?);
            }
            // Follow only new reachable tags on update. Existing local tags must
            // not be rewritten merely because a remote moved one.
            if remote.fetch_tags() != Tags::None {
                specs.extend(local::auto_follow_tag_specs(
                    &source,
                    repo,
                    &specs,
                    remote.fetch_tags() == Tags::All,
                    &operation.interrupt,
                )?);
            }
            drop(source_head);
            drop(source);
            local::fetch(path.as_ref(), repo, &specs, &operation.interrupt)?;
            return Ok(head);
        }
        ensure!(
            matches!(url.scheme, gix::url::Scheme::Http | gix::url::Scheme::Https),
            "Only HTTP(S), SSH and filesystem Git transports are supported"
        );
        let backend = http::Http::new(repo, remote, self.ignore_certs, operation.deadline)?;
        let transport = gix::protocol::transport::client::blocking_io::http::Transport::new_http(
            backend, url, version, false,
        );
        self.receive(repo, remote, transport, extra, initial, operation)
    }

    fn fetch_tag_clone(
        &self,
        repo: &gix::Repository,
        remote: &gix::Remote<'_>,
        tag: &gix::bstr::BStr,
        extra: &[gix::refspec::RefSpec],
        operation: &Operation,
    ) -> Result<RemoteHead> {
        let mut spec = BString::from("+");
        spec.extend_from_slice(tag);
        spec.push(b':');
        spec.extend_from_slice(tag);
        let mut remote = remote.clone();
        remote.replace_refspecs([spec], Direction::Fetch)?;
        let head = self.fetch(repo, &remote, extra, operation, true)?;
        // Updates stay just as narrow as branch clones, retaining the selected
        // tag instead of the nonexistent branch previously written by Git's wrapper.
        let mut config = repo.config_file_mut(repo.common_dir().join("config"))?;
        remote.save_as_to("origin", &mut config)?;
        config.commit()?;
        Ok(head)
    }

    fn receive<T: gix::protocol::transport::client::blocking_io::Transport>(
        &self,
        repo: &gix::Repository,
        remote: &gix::Remote<'_>,
        transport: T,
        extra: &[gix::refspec::RefSpec],
        initial: bool,
        operation: &Operation,
    ) -> Result<RemoteHead> {
        let auth = self.auth.clone();
        let connection = remote
            .to_connection_with_transport(transport)
            .with_credentials(move |action| auth.credentials(action))
            // Suppress gix's default option resolution, which could install proxy helpers.
            .with_transport_options(Box::new(()));
        let selected = narrow_clone_ref(remote, initial);
        let mut fetch_extra = extra.to_vec();
        if initial && selected.is_none() {
            fetch_extra.push(parse_refspec("HEAD")?);
        }
        let prepared = connection.prepare_fetch(
            gix::progress::Discard,
            gix::remote::ref_map::Options {
                prefix_from_spec_as_filter_on_remote: false,
                extra_refspecs: fetch_extra,
                ..Default::default()
            },
        )?;
        if let Some(name) = selected
            && let Some(short) = name.strip_prefix(b"refs/heads/")
            && !prepared.ref_map().remote_refs.iter().any(|reference| reference.unpack().0 == name)
        {
            let mut tag = BString::from("refs/tags/");
            tag.extend_from_slice(short);
            ensure!(
                prepared.ref_map().remote_refs.iter().any(|reference| reference.unpack().0 == tag),
                "Remote branch or tag '{short}' was not found",
                short = short.as_bstr(),
            );
            // Preparation only advertises refs. Reconnect with the exact tag
            // selection before importing any objects or updating references.
            drop(prepared);
            return self.fetch_tag_clone(repo, remote, tag.as_bstr(), extra, operation);
        }
        // Like Git's and gix's clone implementations, store the initial refs in one
        // packed-refs transaction instead of thousands of loose files. Fetches into
        // existing repositories keep the normal loose-ref/reflog behavior.
        let outcome = prepared
            .with_write_packed_refs_only(initial)
            .receive(gix::progress::Discard, &operation.interrupt)?;
        operation.check()?;
        check_fetch_updates(&outcome, remote)?;
        let names = outcome
            .ref_map
            .remote_refs
            .iter()
            .map(|reference| reference.unpack().0.to_owned())
            .collect::<Vec<_>>();
        local::prune(repo, remote.refspecs(Direction::Fetch), &names)?;
        let mut head = RemoteHead::default();
        for reference in outcome.ref_map.remote_refs {
            use gix::protocol::handshake::Ref;
            if reference.unpack().0 != "HEAD" {
                continue;
            }
            head = match reference {
                Ref::Symbolic { target, object, .. } => {
                    RemoteHead { target: Some(target), id: Some(object) }
                }
                Ref::Unborn { target, .. } => RemoteHead { target: Some(target), id: None },
                Ref::Direct { object, .. } | Ref::Peeled { object, .. } => {
                    RemoteHead { target: None, id: Some(object) }
                }
            };
        }
        Ok(head)
    }
}

/// Only initial single-ref clones use an exact source-to-itself mapping. Tags
/// also count after branch-name resolution, so neither selection fetches HEAD.
fn narrow_clone_ref<'a>(remote: &'a gix::Remote<'_>, initial: bool) -> Option<&'a gix::bstr::BStr> {
    if !initial {
        return None;
    }
    let [spec] = remote.refspecs(Direction::Fetch) else {
        return None;
    };
    use gix::refspec::{Instruction, instruction::Fetch};
    match spec.to_ref().instruction() {
        Instruction::Fetch(Fetch::AndUpdate { src, dst, .. })
            if src == dst
                && !src.contains(&b'*')
                && (src.starts_with(b"refs/heads/") || src.starts_with(b"refs/tags/")) =>
        {
            Some(src)
        }
        _ => None,
    }
}

fn check_fetch_updates(
    outcome: &gix::remote::fetch::Outcome,
    remote: &gix::Remote<'_>,
) -> Result<()> {
    use gix::remote::fetch::{Status, refs::update::Mode};
    let updates = match &outcome.status {
        Status::NoPackReceived { update_refs, .. } | Status::Change { update_refs, .. } => {
            update_refs
        }
    };
    for (update, mapping, spec, _) in updates.iter_mapping_updates(
        &outcome.ref_map.mappings,
        &outcome.ref_map.refspecs,
        &outcome.ref_map.extra_refspecs,
    ) {
        match &update.mode {
            Mode::NoChangeNeeded
            | Mode::FastForward
            | Mode::Forced
            | Mode::New
            | Mode::ImplicitTagNotSentByRemote => {}
            // Like Git's auto-follow, retain existing local tags even if the
            // advertised tag moved. Explicit --tags/refspec updates still fail.
            Mode::RejectedTagUpdate
                if remote.fetch_tags() == Tags::Included
                    && mapping.spec_index.implicit_index().is_some()
                    && spec
                        .is_some_and(|spec| Some(spec.to_ref()) == Tags::Included.to_refspec()) => {
            }
            mode => anyhow::bail!("Git fetch rejected reference update: {mode}"),
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub enum CloneMode {
    Bare,
    Mirror,
    Checkout,
}

impl CloneMode {
    /// Historical command-line spelling, retained for callers describing clone modes.
    pub fn arg(&self) -> Option<&str> {
        match self {
            Self::Bare => Some("--bare"),
            Self::Mirror => Some("--mirror"),
            Self::Checkout => None,
        }
    }
}

fn open_options() -> gix::open::Options {
    gix::open::Options::default().permissions(open_permissions())
}

fn open_permissions() -> gix::open::Permissions {
    let mut permissions = gix::open::Permissions::default();
    permissions.config =
        gix::open::permissions::Config { env: true, ..gix::open::permissions::Config::isolated() };
    permissions.attributes = gix::open::permissions::Attributes::isolated();
    // Ignore repository-local GIT_WORK_TREE/GIT_INDEX_FILE/object-store
    // overrides while acquiring repositories; explicit config rewrites still work.
    permissions.env.git_prefix = gix::sec::Permission::Deny;
    permissions.env.objects = gix::sec::Permission::Deny;
    permissions.env.ssh_prefix = gix::sec::Permission::Deny;
    permissions
}

fn parse_refspec(spec: &str) -> Result<gix::refspec::RefSpec> {
    Ok(gix::refspec::parse(spec.as_bytes().as_bstr(), gix::refspec::parse::Operation::Fetch)?
        .to_owned())
}

#[derive(Default)]
struct RemoteHead {
    target: Option<BString>,
    id: Option<ObjectId>,
}

fn set_initial_head(repo: &gix::Repository, head: &RemoteHead, mode: CloneMode) -> Result<()> {
    let Some(target) = head.target.as_ref() else {
        if let Some(id) = head.id {
            edit_refs(
                repo,
                vec![RefEdit::update(
                    "HEAD".try_into()?,
                    Target::Object(id),
                    PreviousValue::Any,
                    "clone: detached HEAD",
                )],
            )?;
        }
        return Ok(());
    };
    let target: gix::refs::FullName = target.as_bstr().try_into()?;
    let mut edits = Vec::new();
    if let Some(id) = head.id {
        edits.push(RefEdit::update(
            target.clone(),
            Target::Object(id),
            PreviousValue::Any,
            "clone: remote HEAD",
        ));
    }
    edits.push(RefEdit::update(
        "HEAD".try_into()?,
        Target::Symbolic(target.clone()),
        PreviousValue::Any,
        "clone: remote HEAD",
    ));
    if matches!(mode, CloneMode::Checkout) && head.id.is_some() {
        let short = target
            .as_bstr()
            .strip_prefix(b"refs/heads/")
            .context("Remote HEAD is not a branch")?
            .as_bstr();
        let tracking: gix::refs::FullName =
            BString::from(format!("refs/remotes/origin/{short}")).try_into()?;
        edits.push(RefEdit::update(
            "refs/remotes/origin/HEAD".try_into()?,
            Target::Symbolic(tracking),
            PreviousValue::Any,
            "clone: remote HEAD",
        ));
        let mut config = repo.config_file_mut(repo.common_dir().join("config"))?;
        config.set_raw_value(&format!("branch.{short}.remote"), "origin")?;
        config.set_raw_value(&format!("branch.{short}.merge"), target.as_bstr())?;
        config.commit()?;
    }
    edit_refs(repo, edits)
}

fn edit_refs(repo: &gix::Repository, edits: Vec<RefEdit>) -> Result<()> {
    let identity = gix::actor::Signature {
        name: "Kingfisher".into(),
        email: "kingfisher@localhost".into(),
        time: gix::date::Time::now_local_or_utc(),
    };
    repo.edit_references_as(
        edits,
        Some(identity.to_ref(&mut gix::date::parse::TimeBuf::default())),
    )?;
    Ok(())
}

fn checkout(repo: &gix::Repository, interrupt: &AtomicBool) -> Result<()> {
    let Some(id) = repo.head()?.try_peel_to_id()? else {
        return Ok(());
    };
    let tree = id.object()?.peel_to_tree()?.id;
    let mut index = repo.index_from_tree(&tree)?;
    let mut options =
        repo.checkout_options(gix::worktree::stack::state::attributes::Source::IdMapping)?;
    options.destination_is_initially_empty = true;
    // Repository attributes may name external smudge/process drivers. Native
    // checkout keeps built-in conversions without executing arbitrary helpers.
    options.filters.options_mut().drivers.clear();
    let outcome = gix::worktree::state::checkout(
        &mut index,
        repo.workdir().context("Clone has no working tree")?,
        repo.objects.clone().into_arc()?,
        &gix::progress::Discard,
        &gix::progress::Discard,
        interrupt,
        options,
    )?;
    ensure!(
        outcome.errors.is_empty(),
        "Git checkout did not complete: {} errors",
        outcome.errors.len()
    );
    // Like `git clone`, keep the checkout when paths differ only by case on a
    // case-insensitive filesystem; one of the colliding paths is still scanned.
    if !outcome.collisions.is_empty() {
        debug!(
            "Git checkout skipped {} path(s) colliding on this filesystem",
            outcome.collisions.len()
        );
    }
    ensure!(!interrupt.load(Ordering::Relaxed), "Git checkout interrupted");
    index.write(Default::default())?;
    Ok(())
}

/// Remove credentials embedded by older Bitbucket clones before opening any remote.
fn scrub_legacy_remote_credentials(repo: &mut gix::Repository) -> Result<()> {
    let mut config = repo.config_file_mut(repo.common_dir().join("config"))?;
    let ids = config
        .sections_and_ids_by_name("remote")
        .map(|sections| sections.map(|(_, id)| id).collect::<Vec<_>>())
        .unwrap_or_default();
    let mut changed = false;
    for id in ids {
        let mut section = config.section_mut_by_id(id).expect("existing remote section");
        for key in ["url", "pushurl"] {
            let values =
                section.values(key).into_iter().map(|value| value.to_owned()).collect::<Vec<_>>();
            let mut clean = Vec::new();
            let mut scrubbed = false;
            for value in values {
                let mut value = value.to_vec();
                if let Ok(text) = std::str::from_utf8(&value)
                    && let Ok(mut url) = Url::parse(text)
                    && matches!(url.scheme(), "http" | "https")
                    && (!url.username().is_empty() || url.password().is_some())
                {
                    url.set_password(None).ok();
                    url.set_username("").ok();
                    value = url.to_string().into_bytes();
                    scrubbed = true;
                }
                clean.push(value);
            }
            if scrubbed {
                while section.remove(key).is_some() {}
                for value in clean {
                    section.push(key, value.as_bstr())?;
                }
                changed = true;
            }
        }
    }
    if changed {
        config.commit()?;
        repo.reload()?;
    }
    Ok(())
}

/// Cancellation is per operation, not global. Dropping the operation wakes and
/// joins its deadline thread, including after successful fast clones.
struct Operation {
    interrupt: Arc<AtomicBool>,
    deadline: Option<Instant>,
    secs: u64,
    cancel: Option<mpsc::Sender<()>>,
    timer: Option<JoinHandle<()>>,
}

impl Operation {
    fn new(timeout: Duration, disabled: bool) -> Self {
        let interrupt = Arc::new(AtomicBool::new(false));
        let deadline = (!disabled && !timeout.is_zero())
            .then(|| Instant::now().checked_add(timeout))
            .flatten();
        let (cancel, timer) = if deadline.is_some() {
            let (sender, receiver) = mpsc::channel();
            let interrupt = Arc::clone(&interrupt);
            let timer = std::thread::spawn(move || {
                if matches!(receiver.recv_timeout(timeout), Err(mpsc::RecvTimeoutError::Timeout)) {
                    interrupt.store(true, Ordering::Relaxed);
                }
            });
            (Some(sender), Some(timer))
        } else {
            (None, None)
        };
        Self { interrupt, deadline, secs: timeout.as_secs(), cancel, timer }
    }

    fn expired(&self) -> bool {
        self.interrupt.load(Ordering::Relaxed)
            || self.deadline.is_some_and(|deadline| Instant::now() >= deadline)
    }

    fn check(&self) -> Result<()> {
        ensure!(!self.expired(), "Git operation deadline exceeded");
        Ok(())
    }

    fn finish(&self, result: Result<()>) -> Result<(), GitError> {
        if self.expired() {
            Err(GitError::Timeout { secs: self.secs })
        } else {
            result.map_err(GitError::Operation)
        }
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        if let Some(sender) = self.cancel.take() {
            let _ = sender.send(());
        }
        if let Some(timer) = self.timer.take() {
            let _ = timer.join();
        }
    }
}

struct CloneDestination {
    path: PathBuf,
    keep: bool,
}
impl CloneDestination {
    fn new(path: &Path) -> Result<Self> {
        let path = path.canonicalize()?;
        ensure!(path.is_absolute() && path.parent().is_some(), "Unsafe clone cleanup path");
        Ok(Self { path, keep: false })
    }
}
impl Drop for CloneDestination {
    fn drop(&mut self) {
        if !self.keep
            && let Err(error) = std::fs::remove_dir_all(&self.path)
        {
            debug!("Failed to clean incomplete clone {}: {error}", self.path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_hosts_are_normalized_and_github_matching_is_exact() {
        let mut hosts = ProviderHosts::default();
        ProviderHosts::add(&mut hosts.github, " GITHUB.EXAMPLE:8443 ");
        ProviderHosts::add(&mut hosts.github, "github.example:8443");
        assert_eq!(hosts.github, ["github.example:8443"]);
        assert!(hosts.is_github_url(&"https://github.example:8443/org/repo".parse().unwrap()));
        for url in ["https://github.example/org/repo", "https://github.example.evil:8443/org/repo"]
        {
            assert!(!hosts.is_github_url(&url.parse().unwrap()));
        }
        // Tokens cannot authenticate SSH, so ssh:// never triggers GitHub token setup.
        let ssh: GitUrl = "ssh://git@github.example:8443/org/repo".parse().unwrap();
        assert!(!hosts.is_github_url(&ssh));
    }

    #[test]
    fn native_options_never_probe_a_git_installation_or_load_global_config() {
        let permissions = open_permissions();
        assert!(!permissions.config.git_binary);
        assert!(!permissions.attributes.git_binary);
        assert!(!permissions.config.system);
        assert!(!permissions.config.user);
        assert!(!permissions.config.git);
        assert!(permissions.config.env);
        assert!(!permissions.env.git_prefix.is_allowed());
        assert!(!permissions.env.objects.is_allowed());
    }

    #[test]
    fn zero_and_disabled_deadlines_do_not_start_timer_threads() {
        let zero = Operation::new(Duration::ZERO, false);
        let disabled = Operation::new(Duration::from_secs(1), true);
        for operation in [zero, disabled] {
            assert!(operation.timer.is_none());
            assert!(operation.deadline.is_none());
            operation.check().unwrap();
        }
    }

    #[test]
    fn dropping_successful_operation_cancels_and_joins_timer_immediately() {
        let start = Instant::now();
        drop(Operation::new(Duration::from_secs(600), false));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}

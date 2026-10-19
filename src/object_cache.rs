//! Provider-independent durable listing checkpoints and object-content cache.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u32,
    source: String,
    policy: serde_json::Value,
    in_progress: bool,
    scopes: BTreeMap<String, Scope>,
    completed_objects: BTreeSet<String>,
    objects: BTreeMap<String, CachedObject>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Scope {
    next_token: Option<String>,
    complete: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ObjectVersion {
    pub identity: Option<String>,
    pub modified: Option<String>,
    pub size: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CachedObject {
    version: ObjectVersion,
    digest: String,
}

/// One durable page contains only that page's objects and its continuation marker.
#[derive(Serialize, Deserialize)]
struct PageCheckpoint {
    prefix: String,
    scope: Scope,
    objects: BTreeMap<String, CachedObject>,
}

pub(crate) struct ObjectCache {
    directory: PathBuf,
    manifest: Manifest,
    pending_objects: BTreeMap<String, CachedObject>,
    // The OS releases this lock after a crash as well as after a clean exit.
    _lock: File,
}

impl ObjectCache {
    pub fn open(directory: &Path, source: &str, policy: &impl Serialize) -> Result<Self> {
        // One cache root can hold independent sources without mixing credentials or content.
        let directory = directory.join(blake3::hash(source.as_bytes()).to_hex().as_str());
        let policy = serde_json::to_value(policy)?;
        std::fs::create_dir_all(directory.join("objects"))
            .context("Cannot create object cache directory")?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("lock"))?;
        lock.try_lock().context("object cache directory is already in use")?;
        let path = directory.join("manifest.json");
        let mut manifest = match std::fs::read(&path) {
            Ok(bytes) => {
                let manifest: Manifest =
                    serde_json::from_slice(&bytes).context("Invalid object cache manifest")?;
                ensure!(
                    manifest.version == 1 && manifest.source == source && manifest.policy == policy,
                    "Object cache policy changed; use a different --object-cache-dir"
                );
                manifest
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Manifest {
                version: 1,
                source: source.into(),
                policy,
                in_progress: false,
                scopes: BTreeMap::new(),
                completed_objects: BTreeSet::new(),
                objects: BTreeMap::new(),
            },
            Err(error) => return Err(error).context("Cannot read object cache manifest"),
        };
        let fresh = !manifest.in_progress;
        if fresh {
            manifest.scopes.clear();
            manifest.completed_objects.clear();
            manifest.in_progress = true;
        }
        let mut state = Self { directory, manifest, pending_objects: BTreeMap::new(), _lock: lock };
        if fresh {
            // A completed manifest supersedes any journal left by a crash during finish().
            // Reset the journal before publishing the new in-progress manifest.
            atomic_write(&state.directory.join("pages.jsonl"), b"")?;
            state.save()?;
        } else {
            state.replay_pages()?;
        }
        Ok(state)
    }

    fn replay_pages(&mut self) -> Result<()> {
        let path = self.directory.join("pages.jsonl");
        let file = match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => file,
            // Version-one manifests written before page journals remain resumable.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Use the same private-file creation as manifests and object contents.
                atomic_write(&path, b"")?;
                return Ok(());
            }
            Err(error) => return Err(error).context("Cannot open object cache checkpoints"),
        };
        let mut reader = BufReader::new(file);
        let mut valid_bytes = 0u64;
        let mut line = Vec::new();
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if line.last() != Some(&b'\n') {
                // A crash may interrupt the final append. Its page was not committed.
                reader.get_ref().set_len(valid_bytes)?;
                reader.get_ref().sync_all()?;
                break;
            }
            let page: PageCheckpoint =
                serde_json::from_slice(&line).context("Invalid object cache page checkpoint")?;
            for (key, object) in page.objects {
                self.manifest.completed_objects.insert(key.clone());
                self.manifest.objects.insert(key, object);
            }
            self.manifest.scopes.insert(page.prefix, page.scope);
            valid_bytes += line.len() as u64;
        }
        Ok(())
    }

    fn object_path(&self, key: &str) -> PathBuf {
        // Keys never become local paths: traversal, separators and Windows names are harmless.
        self.directory.join("objects").join(blake3::hash(key.as_bytes()).to_hex().as_str())
    }

    pub fn completed_objects(&self) -> Vec<String> {
        self.manifest.completed_objects.iter().cloned().collect()
    }

    pub fn read(&self, key: &str) -> Result<Vec<u8>> {
        let bytes = std::fs::read(self.object_path(key)).context(
            "Cannot replay cached object; restore the cache or use a new --object-cache-dir",
        )?;
        self.check_digest(key, &bytes)?;
        Ok(bytes)
    }

    fn check_digest(&self, key: &str, bytes: &[u8]) -> Result<()> {
        ensure!(
            self.manifest
                .objects
                .get(key)
                .is_some_and(|object| object.digest == blake3::hash(bytes).to_hex().as_str()),
            "Cached object failed its checksum; use a new --object-cache-dir"
        );
        Ok(())
    }

    pub fn scope_complete(&self, prefix: &str) -> bool {
        self.manifest.scopes.get(prefix).is_some_and(|scope| scope.complete)
    }

    pub fn continuation_token(&self, prefix: &str) -> Option<String> {
        self.manifest.scopes.get(prefix).and_then(|scope| scope.next_token.clone())
    }

    pub fn cached(&self, key: &str, version: &ObjectVersion) -> Result<Option<Vec<u8>>> {
        if version.identity.as_ref().is_none_or(|identity| identity.is_empty())
            || self.manifest.objects.get(key).is_none_or(|object| &object.version != version)
        {
            return Ok(None);
        }
        match std::fs::read(self.object_path(key)) {
            Ok(bytes) => {
                self.check_digest(key, &bytes)?;
                Ok(Some(bytes))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("Cannot read cached object"),
        }
    }

    pub fn store(&mut self, key: &str, version: ObjectVersion, bytes: &[u8]) -> Result<()> {
        let cached = CachedObject { version, digest: blake3::hash(bytes).to_hex().to_string() };
        if self.manifest.objects.get(key) != Some(&cached) || !self.object_path(key).is_file() {
            atomic_write(&self.object_path(key), bytes)?;
        }
        self.pending_objects.insert(key.to_owned(), cached.clone());
        self.manifest.objects.insert(key.to_owned(), cached);
        self.manifest.completed_objects.insert(key.to_owned());
        Ok(())
    }

    pub fn finish_page(&mut self, prefix: &str, next_token: Option<String>) -> Result<()> {
        let scope = Scope { complete: next_token.is_none(), next_token };
        let page = PageCheckpoint {
            prefix: prefix.into(),
            scope: scope.clone(),
            objects: std::mem::take(&mut self.pending_objects),
        };
        let mut bytes = serde_json::to_vec(&page)?;
        bytes.push(b'\n');
        let mut journal =
            OpenOptions::new().append(true).open(self.directory.join("pages.jsonl"))?;
        journal.write_all(&bytes).context("Cannot write object cache page checkpoint")?;
        journal.sync_all().context("Cannot persist object cache page checkpoint")?;
        self.manifest.scopes.insert(prefix.into(), scope);
        Ok(())
    }

    pub fn finish(&mut self) -> Result<()> {
        // Objects written before a page checkpoint may never have reached the manifest.
        // Sweep the directory, rather than just old manifest entries, to remove those too.
        let object_directory = self.directory.join("objects");
        // Never turn a substituted cache/source directory symlink into a broad deletion target.
        for directory in [&self.directory, &object_directory] {
            ensure!(
                std::fs::symlink_metadata(directory)?.file_type().is_dir(),
                "Object cache directory must be a real directory, not a symlink"
            );
        }
        let referenced: BTreeSet<_> =
            self.manifest.completed_objects.iter().map(|key| self.object_path(key)).collect();
        for entry in std::fs::read_dir(&object_directory)? {
            let entry = entry?;
            let path = entry.path();
            ensure!(
                path.parent() == Some(object_directory.as_path()),
                "Invalid cached object path"
            );
            if !referenced.contains(&path) {
                remove_obsolete_object(entry)?;
            }
        }
        self.manifest.objects.retain(|key, _| self.manifest.completed_objects.contains(key));
        self.manifest.in_progress = false;
        // Compact once per completed scan, rather than rewriting all previous keys per page.
        self.save()?;
        atomic_write(&self.directory.join("pages.jsonl"), b"")
    }

    fn save(&self) -> Result<()> {
        atomic_write(&self.directory.join("manifest.json"), &serde_json::to_vec(&self.manifest)?)
    }
}

fn remove_obsolete_object(entry: std::fs::DirEntry) -> Result<()> {
    let path = entry.path();
    let kind = match entry.file_type() {
        Ok(kind) => kind,
        // External cleanup can remove an entry after read_dir yielded it.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("Cannot inspect obsolete cached object"),
    };
    // Object files are direct children. Never recursively delete an unexpected directory.
    ensure!(!kind.is_dir(), "Unexpected directory in object cache; refusing to remove it");
    // remove_file unlinks a symlink itself, not its target. Windows directory
    // symlinks require remove_dir, which likewise does not recurse into the target.
    #[cfg(windows)]
    let result = {
        use std::os::windows::fs::FileTypeExt;
        // Use link metadata, not path.is_dir(), which follows the target and
        // misclassifies dangling directory symlinks as files.
        if kind.is_symlink_dir() { std::fs::remove_dir(&path) } else { std::fs::remove_file(&path) }
    };
    #[cfg(not(windows))]
    let result = std::fs::remove_file(&path);
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("Cannot remove obsolete cached object"),
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut temporary =
        tempfile::NamedTempFile::new_in(path.parent().context("Object cache path has no parent")?)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .context("Cannot persist object cache manifest")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(value: &str) -> ObjectVersion {
        ObjectVersion { identity: Some(value.into()), ..Default::default() }
    }

    #[test]
    fn sources_are_isolated_locked_and_bound_to_their_selection_policy() {
        let root = tempfile::tempdir().unwrap();
        let mut first = ObjectCache::open(root.path(), "s3://bucket", &()).unwrap();
        assert!(ObjectCache::open(root.path(), "s3://bucket", &()).is_err());
        let mut second = ObjectCache::open(root.path(), "gs://bucket", &()).unwrap();
        for key in ["../../escape", "C:\\Windows\\CON", "/absolute/path"] {
            first.store(key, version("one"), b"first").unwrap();
            second.store(key, version("two"), b"second").unwrap();
            assert_eq!(first.cached(key, &version("one")).unwrap(), Some(b"first".to_vec()));
            assert_eq!(second.cached(key, &version("two")).unwrap(), Some(b"second".to_vec()));
            assert_eq!(
                first.object_path(key).parent(),
                Some(first.directory.join("objects").as_path())
            );
        }
        first.finish_page("", None).unwrap();
        first.finish().unwrap();
        drop(first);
        assert!(ObjectCache::open(root.path(), "s3://bucket", &"changed selection").is_err());
        let mut first = ObjectCache::open(root.path(), "s3://bucket", &()).unwrap();
        assert!(first.completed_objects().is_empty());
        first.finish().unwrap();
        assert_eq!(std::fs::read_dir(first.directory.join("objects")).unwrap().count(), 0);
    }

    #[test]
    fn versionless_objects_are_downloaded_again_and_corruption_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let mut cache = ObjectCache::open(root.path(), "hf://bucket", &()).unwrap();
        cache.store("key", ObjectVersion::default(), b"first").unwrap();
        assert!(cache.cached("key", &ObjectVersion::default()).unwrap().is_none());
        cache.store("key", version("v1"), b"changed").unwrap();
        assert_eq!(cache.read("key").unwrap(), b"changed");
        std::fs::write(cache.object_path("key"), b"corrupt").unwrap();
        assert!(cache.cached("key", &version("v1")).unwrap_err().to_string().contains("checksum"));
        assert!(cache.read("key").is_err());
    }

    #[test]
    fn fresh_listing_prunes_deleted_objects_but_resume_replays_only_current_pages() {
        let root = tempfile::tempdir().unwrap();
        let mut cache = ObjectCache::open(root.path(), "s3://bucket", &()).unwrap();
        for key in ["kept", "deleted"] {
            cache.store(key, version("v1"), key.as_bytes()).unwrap();
        }
        cache.finish_page("", None).unwrap();
        cache.finish().unwrap();
        drop(cache);

        let mut cache = ObjectCache::open(root.path(), "s3://bucket", &()).unwrap();
        assert!(cache.completed_objects().is_empty());
        // Prior objects remain available for reuse, without being counted as seen this run.
        assert_eq!(cache.cached("kept", &version("v1")).unwrap().unwrap(), b"kept");
        cache.store("kept", version("v1"), b"kept").unwrap();
        cache.finish_page("", Some("next".into())).unwrap();
        drop(cache);

        let mut cache = ObjectCache::open(root.path(), "s3://bucket", &()).unwrap();
        assert_eq!(cache.completed_objects(), ["kept"]);
        assert_eq!(cache.continuation_token(""), Some("next".into()));
        assert!(cache.object_path("deleted").exists());
        cache.finish_page("", None).unwrap();
        cache.finish().unwrap();
        assert!(!cache.object_path("deleted").exists());
        assert!(!cache.manifest.objects.contains_key("deleted"));
        assert!(cache.object_path("kept").exists());
    }

    #[test]
    fn finish_removes_uncheckpointed_objects_and_abandoned_temporary_files() {
        let root = tempfile::tempdir().unwrap();
        let mut cache = ObjectCache::open(root.path(), "s3://bucket", &()).unwrap();
        cache.store("orphan", version("v1"), b"uncommitted secret").unwrap();
        let orphan = cache.object_path("orphan");
        // A temporary file can also survive a process exit while atomically writing an object.
        let temporary = cache.directory.join("objects").join("abandoned-temporary");
        std::fs::write(&temporary, b"temporary secret").unwrap();
        drop(cache);

        let mut cache = ObjectCache::open(root.path(), "s3://bucket", &()).unwrap();
        assert!(!cache.manifest.objects.contains_key("orphan"));
        assert!(orphan.exists());
        cache.store("kept", version("v1"), b"kept").unwrap();
        cache.finish_page("", None).unwrap();
        cache.finish().unwrap();
        assert!(!orphan.exists());
        assert!(!temporary.exists());
        assert_eq!(std::fs::read_dir(cache.directory.join("objects")).unwrap().count(), 1);
        assert_eq!(cache.read("kept").unwrap(), b"kept");
    }

    #[test]
    fn orphan_removal_tolerates_an_entry_disappearing_after_enumeration() {
        let root = tempfile::tempdir().unwrap();
        let mut cache = ObjectCache::open(root.path(), "s3://bucket", &()).unwrap();
        let orphan = cache.directory.join("objects").join("orphan");
        std::fs::write(&orphan, b"obsolete").unwrap();
        let entry =
            std::fs::read_dir(cache.directory.join("objects")).unwrap().next().unwrap().unwrap();
        assert_eq!(entry.path(), orphan);
        std::fs::remove_file(&orphan).unwrap();
        remove_obsolete_object(entry).unwrap();
        cache.finish().unwrap();
        assert!(!cache.manifest.in_progress);
    }

    #[test]
    fn orphan_removal_still_refuses_unexpected_directories() {
        let root = tempfile::tempdir().unwrap();
        let unexpected = root.path().join("unexpected");
        std::fs::create_dir(&unexpected).unwrap();
        let entry = std::fs::read_dir(root.path()).unwrap().next().unwrap().unwrap();
        let error = remove_obsolete_object(entry).unwrap_err();
        assert!(error.to_string().contains("Unexpected directory"));
        assert!(unexpected.is_dir());
    }

    #[test]
    fn finish_refuses_to_recursively_remove_unexpected_directories() {
        let root = tempfile::tempdir().unwrap();
        let mut cache = ObjectCache::open(root.path(), "s3://bucket", &()).unwrap();
        let unexpected = cache.directory.join("objects").join("unexpected");
        std::fs::create_dir(&unexpected).unwrap();
        let content = unexpected.join("keep");
        std::fs::write(&content, b"do not delete").unwrap();
        assert!(cache.finish().unwrap_err().to_string().contains("Unexpected directory"));
        assert_eq!(std::fs::read(content).unwrap(), b"do not delete");
        assert!(cache.manifest.in_progress);
    }

    #[cfg(unix)]
    #[test]
    fn finish_unlinks_orphan_symlinks_without_touching_their_targets() {
        let root = tempfile::tempdir().unwrap();
        let mut cache = ObjectCache::open(root.path(), "s3://bucket", &()).unwrap();
        let external = root.path().join("external");
        std::fs::create_dir(&external).unwrap();
        let content = external.join("keep");
        std::fs::write(&content, b"do not delete").unwrap();
        let directory_link = cache.directory.join("objects").join("directory-link");
        let file_link = cache.directory.join("objects").join("file-link");
        std::os::unix::fs::symlink(&external, &directory_link).unwrap();
        std::os::unix::fs::symlink(&content, &file_link).unwrap();
        cache.finish().unwrap();
        assert!(!directory_link.exists());
        assert!(!file_link.exists());
        assert_eq!(std::fs::read(content).unwrap(), b"do not delete");
    }

    #[cfg(unix)]
    #[test]
    fn finish_refuses_to_sweep_a_symlinked_object_directory() {
        let root = tempfile::tempdir().unwrap();
        let source = "s3://bucket";
        let source_directory = root.path().join(blake3::hash(source.as_bytes()).to_hex().as_str());
        std::fs::create_dir(&source_directory).unwrap();
        let external = root.path().join("external");
        std::fs::create_dir(&external).unwrap();
        let content = external.join("keep");
        std::fs::write(&content, b"do not delete").unwrap();
        std::os::unix::fs::symlink(&external, source_directory.join("objects")).unwrap();
        let mut cache = ObjectCache::open(root.path(), source, &()).unwrap();
        assert!(cache.finish().unwrap_err().to_string().contains("real directory"));
        assert_eq!(std::fs::read(content).unwrap(), b"do not delete");
        assert!(cache.manifest.in_progress);
    }

    #[test]
    fn checkpoint_bytes_grow_by_page_instead_of_rewriting_the_manifest() {
        let root = tempfile::tempdir().unwrap();
        let mut cache = ObjectCache::open(root.path(), "gs://bucket", &()).unwrap();
        let initial_manifest = std::fs::read(cache.directory.join("manifest.json")).unwrap();
        let journal = cache.directory.join("pages.jsonl");
        let mut previous_length = 0;
        for i in 0..100 {
            cache.store(&format!("key-{i:03}"), version("v1"), b"content").unwrap();
            cache.finish_page("", Some(format!("page-{i:03}"))).unwrap();
            let length = std::fs::metadata(&journal).unwrap().len();
            assert!(length - previous_length < 400, "each append should contain just one page");
            previous_length = length;
        }
        assert_eq!(std::fs::read(cache.directory.join("manifest.json")).unwrap(), initial_manifest);
        drop(cache);
        let mut cache = ObjectCache::open(root.path(), "gs://bucket", &()).unwrap();
        assert_eq!(cache.completed_objects().len(), 100);
        assert_eq!(cache.continuation_token(""), Some("page-099".into()));
        cache.finish_page("", None).unwrap();
        cache.finish().unwrap();
        assert_eq!(std::fs::metadata(journal).unwrap().len(), 0);
        assert_eq!(cache.manifest.objects.len(), 100);
    }

    #[test]
    fn interrupted_last_append_is_discarded_before_resuming() {
        let root = tempfile::tempdir().unwrap();
        let mut cache = ObjectCache::open(root.path(), "hf://bucket", &()).unwrap();
        cache.store("first", version("v1"), b"first").unwrap();
        cache.finish_page("configs/", Some("next".into())).unwrap();
        let path = cache.directory.join("pages.jsonl");
        let valid_length = std::fs::metadata(&path).unwrap().len();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"incomplete").unwrap();
        file.sync_all().unwrap();
        drop(file);
        drop(cache);

        let mut cache = ObjectCache::open(root.path(), "hf://bucket", &()).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), valid_length);
        assert_eq!(cache.completed_objects(), ["first"]);
        cache.store("second", version("v1"), b"second").unwrap();
        cache.finish_page("configs/", None).unwrap();
        drop(cache);
        let cache = ObjectCache::open(root.path(), "hf://bucket", &()).unwrap();
        assert_eq!(cache.completed_objects(), ["first", "second"]);
        assert!(cache.scope_complete("configs/"));
    }

    #[test]
    fn legacy_in_progress_manifests_without_a_journal_can_resume() {
        let root = tempfile::tempdir().unwrap();
        let mut cache = ObjectCache::open(root.path(), "s3://bucket", &()).unwrap();
        cache.store("first", version("v1"), b"first").unwrap();
        cache
            .manifest
            .scopes
            .insert("".into(), Scope { next_token: Some("next".into()), complete: false });
        cache.save().unwrap();
        std::fs::remove_file(cache.directory.join("pages.jsonl")).unwrap();
        drop(cache);
        let mut cache = ObjectCache::open(root.path(), "s3://bucket", &()).unwrap();
        assert_eq!(cache.completed_objects(), ["first"]);
        assert_eq!(cache.continuation_token(""), Some("next".into()));
        cache.store("second", version("v1"), b"second").unwrap();
        cache.finish_page("", None).unwrap();
        drop(cache);
        let cache = ObjectCache::open(root.path(), "s3://bucket", &()).unwrap();
        assert_eq!(cache.completed_objects(), ["first", "second"]);
    }

    #[test]
    fn completed_manifest_supersedes_an_untrimmed_old_journal() {
        let root = tempfile::tempdir().unwrap();
        let mut cache = ObjectCache::open(root.path(), "s3://bucket", &()).unwrap();
        cache.store("first", version("v1"), b"first").unwrap();
        cache.finish_page("", None).unwrap();
        // Simulate a crash after the finished manifest was published but before journal reset.
        cache.manifest.in_progress = false;
        cache.save().unwrap();
        let journal = cache.directory.join("pages.jsonl");
        assert!(std::fs::metadata(&journal).unwrap().len() > 0);
        drop(cache);
        let cache = ObjectCache::open(root.path(), "s3://bucket", &()).unwrap();
        assert!(cache.completed_objects().is_empty());
        assert!(!cache.scope_complete(""));
        assert_eq!(std::fs::metadata(journal).unwrap().len(), 0);
        assert!(cache.cached("first", &version("v1")).unwrap().is_some());
    }
}

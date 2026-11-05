use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use kingfisher_scanner::{
    ScanControl,
    git::{GitEvent, GitInputs, GitMode, GitOptions, GitScope},
};
use napi::{
    Env, Result,
    bindgen_prelude::{Buffer, PromiseRaw},
};
use napi_derive::napi;
use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::control::{NativeCancellationToken, blocking, control, failure, interrupted, invalid};

enum Cursor {
    Filesystem { walk: Box<ignore::Walk>, roots: Vec<String> },
    Git(Box<GitInputs>),
}

fn walk_error_path(error: &ignore::Error) -> Option<&std::path::Path> {
    match error {
        ignore::Error::WithPath { path, .. } => Some(path),
        ignore::Error::WithDepth { err, .. } | ignore::Error::WithLineNumber { err, .. } => {
            walk_error_path(err)
        }
        ignore::Error::Loop { child, .. } => Some(child),
        ignore::Error::Partial(errors) => errors.iter().find_map(walk_error_path),
        _ => None,
    }
}

fn git_error(error: anyhow::Error) -> napi::Error {
    if let Some(reason) = error.downcast_ref::<kingfisher_scanner::ScanAborted>() {
        interrupted(*reason)
    } else {
        failure("KF_INPUT", "Git input processing failed or exceeded its budget")
    }
}

#[napi(object)]
pub struct NativeInput {
    pub path: String,
    pub file: Option<String>,
    pub data: Option<Buffer>,
    pub metadata: Value,
    pub attributes: BTreeMap<String, String>,
    pub raw_path: Option<Buffer>,
    pub skipped: Option<String>,
}

#[napi]
pub struct NativeInputCursor {
    cursor: Arc<Mutex<Option<Cursor>>>,
    closed: Arc<AtomicBool>,
    control: ScanControl,
}

#[napi]
impl NativeInputCursor {
    #[napi(catch_unwind)]
    pub fn next<'env>(&self, env: &'env Env) -> Result<PromiseRaw<'env, Option<NativeInput>>> {
        let cursor = self.cursor.clone();
        let closed = self.closed.clone();
        env.spawn_future(blocking(self.control.clone(), move |control| {
            let mut cursor = cursor.lock();
            let result = (|| {
                if closed.load(Ordering::Relaxed) { return Ok(None); }
                let Some(cursor) = cursor.as_mut() else { return Ok(None); };
                match cursor {
                    Cursor::Filesystem { walk, roots } => loop {
                        control.check().map_err(interrupted)?;
                        let Some(entry) = walk.next() else { return Ok(None); };
                        let entry = match entry {
                            Ok(entry) => entry,
                            Err(error) => {
                                // A caller-selected root must be readable; otherwise an
                                // empty enumeration could be mistaken for a clean scan.
                                if error.depth() == Some(0) {
                                    return Err(failure("KF_INPUT", "filesystem root could not be read"));
                                }
                                // Nested I/O and depth-less parent-ignore errors are
                                // recoverable; other entries still provide useful coverage.
                                let path = walk_error_path(&error)
                                    .map(|path| path.to_string_lossy().into_owned())
                                    .unwrap_or_else(|| roots.join(", "));
                                return Ok(Some(NativeInput {
                                    path, file: None, data: None, metadata: json!({}),
                                    attributes: BTreeMap::new(), raw_path: None,
                                    skipped: Some("walk_error".into()),
                                }));
                            }
                        };
                        let is_file = entry.file_type().is_some_and(|kind| kind.is_file());
                        let skipped = entry.error().map(|_| "ignore_error".to_owned());
                        if is_file || skipped.is_some() {
                            // Only warning-only paths may be lossy: actual inputs are
                            // reopened later and must roundtrip without aliasing names.
                            let path = if is_file {
                                entry.path().to_str().ok_or_else(|| failure(
                                    "KF_INPUT",
                                    "filesystem paths must contain valid Unicode; rename the file or scan its bytes directly",
                                ))?.to_owned()
                            } else {
                                entry.path().to_string_lossy().into_owned()
                            };
                            return Ok(Some(NativeInput {
                                file: is_file.then(|| path.clone()), path, data: None, metadata: json!({}),
                                attributes: BTreeMap::new(), raw_path: None, skipped,
                            }));
                        }
                    },
                    Cursor::Git(inputs) => {
                        let Some(event) = inputs.next() else { return Ok(None); };
                        match event.map_err(git_error)? {
                            GitEvent::Skipped { path, raw_path, blob_id, reason } => Ok(Some(NativeInput {
                                path, file: None, data: None,
                                metadata: json!({ "blobId": blob_id.to_string() }),
                                attributes: BTreeMap::new(), raw_path: Some(raw_path.into()),
                                skipped: Some(match reason {
                                    kingfisher_scanner::git::GitSkipReason::Oversized => "oversized",
                                    kingfisher_scanner::git::GitSkipReason::Missing => "missing",
                                }.into()),
                            })),
                            GitEvent::Input(input) => {
                                let signature = |value: &kingfisher_scanner::git::GitSignature| json!({
                                    "name": value.name, "email": value.email,
                                    // Untrusted Git timestamps can exceed Number's exact range.
                                    "timestamp": value.timestamp.to_string(), "timezoneOffset": value.timezone_offset,
                                });
                                let origins: Vec<_> = input.origins.iter().map(|origin| json!({
                                    "id": origin.id.to_string(), "author": signature(&origin.author),
                                    "committer": signature(&origin.committer), "message": origin.message,
                                    "parents": origin.parents.iter().map(ToString::to_string).collect::<Vec<_>>(),
                                })).collect();
                                let mut attributes = BTreeMap::new();
                                if let Some(origin) = input.origins.first() {
                                    attributes.insert("git.sha".into(), origin.id.to_string());
                                    attributes.insert("git.author_name".into(), origin.author.name.clone());
                                    attributes.insert("git.author_email".into(), origin.author.email.clone());
                                    attributes.insert("git.committer_name".into(), origin.committer.name.clone());
                                    attributes.insert("git.committer_email".into(), origin.committer.email.clone());
                                }
                                Ok(Some(NativeInput {
                                    path: input.path, file: None, data: Some(input.data.into()),
                                    metadata: json!({ "blobId": input.blob_id.to_string(), "origins": origins,
                                        "staged": input.staged, "unreachable": input.unreachable }),
                                    attributes, raw_path: Some(input.raw_path.into()), skipped: None,
                                }))
                            }
                        }
                    }
                }
            })();
            if closed.load(Ordering::Relaxed) { cursor.take(); }
            result
        }))
    }

    #[napi(catch_unwind)]
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        // Do not block the JS thread behind an in-flight native object read.
        if let Some(mut cursor) = self.cursor.try_lock() {
            cursor.take();
        }
    }
}

#[napi(object)]
pub struct NativeFilesystemOptions {
    pub roots: Vec<String>,
    pub gitignore: bool,
    pub hidden: bool,
    pub max_file_size: Option<u32>,
}

#[napi(catch_unwind)]
pub fn filesystem_inputs<'env>(
    env: &'env Env,
    options: NativeFilesystemOptions,
    timeout_ms: Option<f64>,
    token: Option<&NativeCancellationToken>,
) -> Result<PromiseRaw<'env, NativeInputCursor>> {
    let control = control(timeout_ms, token)?;
    if options.roots.is_empty() {
        return Err(invalid("at least one filesystem root is required"));
    }
    let retained = control.clone();
    env.spawn_future(blocking(control, move |_| {
        let mut builder = ignore::WalkBuilder::new(&options.roots[0]);
        for root in &options.roots[1..] {
            builder.add(root);
        }
        builder
            .hidden(!options.hidden)
            .git_ignore(options.gitignore)
            .git_exclude(options.gitignore)
            .git_global(false)
            .ignore(options.gitignore)
            .follow_links(false)
            .max_filesize(options.max_file_size.map(u64::from))
            .filter_entry(|entry| {
                !entry.file_name().to_str().is_some_and(|name| name.eq_ignore_ascii_case(".git"))
            });
        Ok(NativeInputCursor {
            cursor: Arc::new(Mutex::new(Some(Cursor::Filesystem {
                walk: Box::new(builder.build()),
                roots: options.roots,
            }))),
            closed: Arc::new(AtomicBool::new(false)),
            control: retained,
        })
    }))
}

#[napi(object)]
pub struct NativeGitOptions {
    pub path: String,
    pub mode: String,
    pub refs: Option<Vec<String>>,
    pub since_commit: Option<String>,
    pub since_hours: Option<f64>,
    pub since_time: Option<i64>,
    pub until_time: Option<i64>,
    pub branch_root: Option<String>,
    pub include_unreachable: bool,
    pub discover: bool,
    pub max_blob_size: Option<u32>,
    pub max_commits: Option<u32>,
    pub max_inputs: Option<u32>,
    pub skip_missing_blobs: bool,
}

#[napi(catch_unwind)]
pub fn git_inputs<'env>(
    env: &'env Env,
    options: NativeGitOptions,
    timeout_ms: Option<f64>,
    token: Option<&NativeCancellationToken>,
) -> Result<PromiseRaw<'env, NativeInputCursor>> {
    let control = control(timeout_ms, token)?;
    let mode = match options.mode.as_str() {
        "history" => GitMode::History,
        "snapshot" => GitMode::Snapshot,
        "diff" => GitMode::Diff,
        "staged" => GitMode::Staged,
        _ => return Err(invalid("Git mode must be history, snapshot, diff or staged")),
    };
    let retained = control.clone();
    env.spawn_future(blocking(control, move |control| {
        let path = PathBuf::from(options.path);
        let scope = GitScope {
            mode,
            refs: options.refs,
            since_commit: options.since_commit,
            since_hours: options.since_hours,
            since_time: options.since_time,
            until_time: options.until_time,
            branch_root: options.branch_root,
            include_unreachable: options.include_unreachable,
        };
        let options = GitOptions {
            discover: options.discover,
            max_blob_size: options.max_blob_size.map(u64::from),
            max_commits: options.max_commits.map(|value| value as usize),
            max_inputs: options.max_inputs.map(|value| value as usize),
            skip_missing_blobs: options.skip_missing_blobs,
        };
        let inputs = GitInputs::open(path, scope, options, control.clone()).map_err(git_error)?;
        control.check().map_err(interrupted)?;
        Ok(NativeInputCursor {
            cursor: Arc::new(Mutex::new(Some(Cursor::Git(Box::new(inputs))))),
            closed: Arc::new(AtomicBool::new(false)),
            control: retained,
        })
    }))
}

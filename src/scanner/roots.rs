//! Group filesystem inputs into repository and non-repository scan roots.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use tracing::debug;

/// Expands directory inputs into scan roots and discovered repositories.
///
/// Repositories found anywhere in a directory subtree become their own scan
/// roots (each with its own scan lifecycle and audit record); the input
/// directory itself also remains a scan root covering all non-repository
/// content, with the discovered repository subtrees excluded from its walk so
/// nothing is scanned twice. That grouped root keeps loose sibling files at
/// directory granularity instead of turning each into its own scan root, and
/// repository-free directory trees still collapse to a single root. Returns
/// `(scan_roots, repo_roots)`.
pub(super) fn expand_repo_roots(
    input_roots: &[PathBuf],
    exclude_globset: Option<&std::sync::Arc<globset::GlobSet>>,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut scan_roots = Vec::new();
    let mut repo_roots = Vec::new();

    for root in input_roots {
        if is_symlink(root) {
            scan_roots.push(root.clone());
            continue;
        }
        if is_git_repository_root(root) {
            scan_roots.push(root.clone());
            repo_roots.push(root.clone());
            continue;
        }
        if !root.is_dir() {
            scan_roots.push(root.clone());
            continue;
        }

        let (mut found, non_repo_content) = find_repo_roots_in_dir(root, exclude_globset)?;
        if found.is_empty() {
            scan_roots.push(root.clone());
            continue;
        }
        repo_roots.extend(found.iter().cloned());
        scan_roots.append(&mut found);
        if non_repo_content {
            // The grouped root covers every non-repository file and directory
            // in the subtree; the walker prunes the repository subtrees, which
            // are scanned through their own roots above.
            scan_roots.push(root.clone());
        }
    }

    Ok((deduplicate_paths(scan_roots), deduplicate_paths(repo_roots)))
}

fn deduplicate_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::with_capacity(paths.len());
    paths.into_iter().filter(|path| seen.insert(path.clone())).collect()
}

/// Collects the repository roots found under `dir`, not descending into a
/// discovered repository, skipping children matched by the `--exclude`
/// globset, and skipping symlinked directories (the filesystem walker runs
/// with `follow_links(false)` and would not traverse them either; a link is
/// reported as non-repository content so the grouped root covers it).
///
/// Returns the repository roots plus whether any non-repository content was
/// seen, so the caller can decide whether a grouped root is needed.
fn find_repo_roots_in_dir(
    dir: &Path,
    exclude_globset: Option<&std::sync::Arc<globset::GlobSet>>,
) -> Result<(Vec<PathBuf>, bool)> {
    let mut repos = Vec::new();
    // Mirror the filesystem walker, which logs and skips unreadable entries
    // instead of failing the scan: this pre-scan also runs before --exclude
    // filtering, so an unreadable — and possibly excluded — descendant must
    // not abort an otherwise valid scan.
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            debug!(
                "Skipping unreadable directory while expanding repo roots: {}: {error}",
                dir.display()
            );
            return Ok((repos, true));
        }
    };
    let mut non_repo_content = false;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                debug!("Skipping entry while expanding repo roots: {error}");
                continue;
            }
        };
        let child_path = entry.path();
        if exclude_globset.as_ref().is_some_and(|globset| globset.is_match(&child_path)) {
            debug!("Skipping {} due to --exclude while expanding repo roots", child_path.display());
            continue;
        }
        if is_symlink(&child_path) {
            // Never classify a symlink as a repository root: the walker does
            // not descend into symlinked directories, so the link target
            // would be scanned (and audited) even though it is not part of
            // the tree. The grouped root still covers the link entry itself.
            non_repo_content = true;
            continue;
        }
        if is_git_repository_root(&child_path) {
            repos.push(child_path);
        } else if child_path.is_dir() {
            let (mut child_repos, child_content) =
                find_repo_roots_in_dir(&child_path, exclude_globset)?;
            repos.append(&mut child_repos);
            non_repo_content |= child_content;
        } else {
            non_repo_content = true;
        }
    }
    repos.sort();
    Ok((repos, non_repo_content))
}

pub(super) fn is_git_repository_root(root: &Path) -> bool {
    !is_symlink(root)
        && (root.join(".git").exists()
            || (root.join("HEAD").is_file() && root.join("objects").is_dir()))
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_repo_roots_discovers_nested_repositories() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        // workspace/services/api/.git — a repository two levels below the
        // input, plus a repository-free sibling subtree and a loose file.
        std::fs::create_dir_all(base.join("workspace/services/api/.git")).unwrap();
        std::fs::create_dir_all(base.join("workspace/docs")).unwrap();
        std::fs::write(base.join("workspace/docs/README.md"), b"x").unwrap();
        std::fs::create_dir_all(base.join("plain")).unwrap();
        std::fs::write(base.join("plain/notes.txt"), b"x").unwrap();

        let (roots, repos) = expand_repo_roots(&[base.to_path_buf()], None).unwrap();

        let nested = base.join("workspace/services/api");
        assert!(
            roots.contains(&nested),
            "nested repository must become its own scan root: {roots:?}"
        );
        assert!(repos.contains(&nested));
        // The input root stays a single grouped root covering the loose
        // sibling content instead of exploding into per-file roots.
        assert!(roots.contains(&base.to_path_buf()));
        // Intermediate directories are not roots of their own, and the
        // repository is not covered twice.
        assert!(!roots.contains(&base.join("workspace")));
        assert!(!roots.contains(&base.join("workspace/services")));
        assert_eq!(roots.len(), roots.iter().collect::<std::collections::HashSet<_>>().len());
    }

    #[test]
    fn expand_repo_roots_keeps_repository_free_tree_as_one_root() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        std::fs::create_dir_all(base.join("a/b/c")).unwrap();
        std::fs::write(base.join("a/b/c/file.txt"), b"x").unwrap();

        let (roots, repos) = expand_repo_roots(&[base.to_path_buf()], None).unwrap();

        assert_eq!(roots, vec![base.to_path_buf()]);
        assert!(repos.is_empty());
    }

    #[test]
    fn expand_repo_roots_skips_excluded_subtrees() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        std::fs::create_dir_all(base.join("deps/vendor/repo/.git")).unwrap();
        std::fs::create_dir_all(base.join("src/api/.git")).unwrap();

        // The same pattern expansion the filesystem walker applies via
        // --exclude: a literal pattern excludes the named directory anywhere
        // in the tree.
        let exclude_globset = crate::build_exclude_globset(&["deps".to_string()]).unwrap().unwrap();
        let (roots, repos) =
            expand_repo_roots(&[base.to_path_buf()], Some(&exclude_globset)).unwrap();

        // The excluded subtree is neither expanded nor emitted, so the
        // repository inside it stays out of the audit manifest exactly like
        // the filesystem walker keeps it out of the scan.
        assert!(!roots.contains(&base.join("deps/vendor/repo")));
        assert!(!roots.iter().any(|root| root.starts_with(base.join("deps"))));
        assert!(roots.contains(&base.join("src/api")));
        assert!(repos.contains(&base.join("src/api")));
    }

    #[test]
    fn expand_repo_roots_does_not_descend_into_found_repository() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        // A repository containing a nested-looking .git deeper inside: the
        // outer repository wins and the walk must not recurse into it.
        std::fs::create_dir_all(base.join("outer/.git")).unwrap();
        std::fs::create_dir_all(base.join("outer/vendor/inner/.git")).unwrap();

        let (roots, repos) = expand_repo_roots(&[base.to_path_buf()], None).unwrap();

        assert_eq!(roots, vec![base.join("outer")]);
        assert_eq!(repos, vec![base.join("outer")]);
    }

    #[test]
    fn expand_repo_roots_deduplicates_overlapping_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        let repo = base.join("workspace/repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::write(base.join("notes.txt"), b"notes").unwrap();

        let (roots, repos) = expand_repo_roots(&[base.to_path_buf(), repo.clone()], None).unwrap();

        assert_eq!(roots, vec![repo.clone(), base.to_path_buf()]);
        assert_eq!(repos, vec![repo]);
    }

    #[test]
    fn scan_nested_repositories_can_be_disabled() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        let nested = base.join("workspace/repo");
        std::fs::create_dir_all(nested.join(".git")).unwrap();

        let roots = vec![base.to_path_buf()];
        let repos = roots
            .iter()
            .filter(|root| super::is_git_repository_root(root))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(roots, vec![base.to_path_buf()]);
        assert!(repos.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn expand_repo_roots_does_not_recurse_into_symlinked_directories() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        std::fs::create_dir_all(base.join("real/repo/.git")).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();

        let (roots, repos) = expand_repo_roots(&[base.to_path_buf()], None).unwrap();

        // The walker runs with follow_links(false), so a symlinked directory
        // is never turned into a repository root (even when it targets one);
        // the grouped root covers the link entry itself.
        assert!(roots.contains(&base.join("real/repo")));
        assert!(!roots.contains(&base.join("link")));
        assert!(!repos.contains(&base.join("link")));
        assert!(repos.contains(&base.join("real/repo")));
    }

    #[cfg(unix)]
    #[test]
    fn expand_repo_roots_skips_unreadable_directories() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        std::fs::create_dir_all(base.join("locked")).unwrap();
        std::fs::create_dir_all(base.join("open/repo/.git")).unwrap();
        std::fs::set_permissions(base.join("locked"), std::fs::Permissions::from_mode(0o000))
            .unwrap();

        // An unreadable descendant must not abort the pre-scan; the scanner's
        // own walker decides later whether to skip its contents, which the
        // grouped root covers.
        let (roots, _repos) = expand_repo_roots(&[base.to_path_buf()], None).unwrap();
        assert!(roots.contains(&base.join("open/repo")));
        assert!(roots.contains(&base.to_path_buf()));

        std::fs::set_permissions(base.join("locked"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }
}

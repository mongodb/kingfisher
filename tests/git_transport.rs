//! Behavioral coverage for the Git operations used by repository scans.
//! Fixtures are built by gix; no fixture setup requires the Git executable.
#[path = "../src/git_test_fixture.rs"]
mod fixture;

use std::{path::Path, process::Command};

use anyhow::Result;
use gix::refs::transaction::PreviousValue;
use kingfisher::{
    git_binary::{CloneMode, Git, ProviderHosts},
    git_url::GitUrl,
};
#[path = "support/git_server.rs"]
mod git_server;

fn isolated(test: &str, body: impl FnOnce() -> Result<()>) -> Result<()> {
    if std::env::var_os("KF_TEST_GIT_TRANSPORT_CHILD").is_some() {
        return body();
    }
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--exact", test, "--nocapture"])
        .env("KF_TEST_GIT_TRANSPORT_CHILD", "1")
        .env("PATH", "")
        .env("KF_GIT_BINARY", "kingfisher-no-git-must-be-needed")
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("GIT_CONFIG_PARAMETERS");
    for variable in [
        "KF_GITHUB_TOKEN",
        "KF_GITLAB_TOKEN",
        "KF_GITEA_TOKEN",
        "KF_GITEA_USERNAME",
        "KF_BITBUCKET_TOKEN",
        "KF_BITBUCKET_USERNAME",
        "KF_BITBUCKET_APP_PASSWORD",
        "KF_BITBUCKET_PASSWORD",
        "KF_BITBUCKET_OAUTH_TOKEN",
        "KF_AZURE_TOKEN",
        "KF_AZURE_PAT",
        "KF_AZURE_USERNAME",
        "KF_HUGGINGFACE_TOKEN",
        "KF_HUGGINGFACE_USERNAME",
    ] {
        command.env_remove(variable);
    }
    let output = command.output()?;
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn source(path: &Path) -> Result<(gix::Repository, gix::ObjectId, gix::ObjectId)> {
    let repo = gix::init_bare(path)?;
    fixture::set_head(&repo, "refs/heads/main")?;
    let sig = fixture::signature("fixture", "fixture@example.com");
    let blob = repo.write_blob(b"committed content\n")?.detach();
    let mut tree = repo.empty_tree().edit()?;
    tree.upsert("nested/file with spaces.txt", gix::objs::tree::EntryKind::Blob, blob)?;
    let tree = tree.write()?.detach();
    let first = fixture::commit(&repo, Some("HEAD"), &sig, &sig, "first", &tree, &[])?;
    let second = fixture::commit(&repo, Some("HEAD"), &sig, &sig, "second", &tree, &[&first])?;
    fixture::reference(&repo, "refs/heads/feature", first, PreviousValue::Any, "feature")?;
    fixture::reference(&repo, "refs/custom/audit", first, PreviousValue::Any, "custom")?;
    fixture::tag(&repo, "v1", first, &sig, "annotated release")?;
    Ok((repo, first, second))
}

fn with_rewrite<T>(source: &Path, body: impl FnOnce(GitUrl) -> T) -> T {
    let local = source.to_string_lossy().replace('\\', "/");
    let key = format!("url.{local}.insteadOf");
    temp_env::with_vars(
        [
            ("GIT_CONFIG_COUNT", Some("1")),
            ("GIT_CONFIG_KEY_0", Some(key.as_str())),
            ("GIT_CONFIG_VALUE_0", Some("https://fixture.invalid/repo.git")),
        ],
        || body("https://fixture.invalid/repo.git".parse().unwrap()),
    )
}

fn id(repo: &gix::Repository, reference: &str) -> Result<gix::ObjectId> {
    Ok(repo.find_reference(reference)?.peel_to_id()?.detach())
}

#[test]
fn shallow_local_sources_clone_in_all_modes_and_update_without_git() -> Result<()> {
    isolated("shallow_local_sources_clone_in_all_modes_and_update_without_git", || {
        let temp = tempfile::tempdir()?;
        let source_dir = temp.path().join("shallow source with spaces.git");
        let source = gix::init_bare(&source_dir)?;
        fixture::set_head(&source, "refs/heads/main")?;
        let sig = fixture::signature("fixture", "fixture@example.com");
        let blob = source.write_blob(b"shallow content\n")?.detach();
        let mut tree = source.empty_tree().edit()?;
        tree.upsert("secret.txt", gix::objs::tree::EntryKind::Blob, blob)?;
        let tree = tree.write()?.detach();
        let missing = gix::ObjectId::from_hex(b"1111111111111111111111111111111111111111")?;
        let boundary =
            fixture::commit(&source, Some("HEAD"), &sig, &sig, "boundary", &tree, &[&missing])?;
        fixture::tag(&source, "v1", boundary, &sig, "shallow release")?;
        std::fs::write(source.shallow_file()?, format!("{boundary}\n"))?;
        with_rewrite(&source_dir, |url| -> Result<()> {
            for (name, mode) in [
                ("bare", CloneMode::Bare),
                ("mirror", CloneMode::Mirror),
                ("checkout", CloneMode::Checkout),
            ] {
                let dest = temp.path().join(name);
                let git = Git::default();
                git.create_fresh_clone(&url, &dest, mode)?;
                let repo = gix::open(&dest)?;
                assert_eq!(repo.head_id()?.detach(), boundary);
                assert_eq!(id(&repo, "refs/tags/v1")?, boundary);
                assert!(repo.is_shallow()?);
                assert_eq!(
                    repo.shallow_commits()?.unwrap().iter().copied().collect::<Vec<_>>(),
                    vec![boundary]
                );
                assert_eq!(
                    repo.rev_walk([boundary]).all()?.collect::<Result<Vec<_>, _>>()?.len(),
                    1
                );
                assert!(repo.has_object(blob));
                assert!(!repo.has_object(missing));
                if name == "checkout" {
                    assert_eq!(std::fs::read(dest.join("secret.txt"))?, b"shallow content\n");
                }

                let next =
                    fixture::commit(&source, Some("HEAD"), &sig, &sig, name, &tree, &[&boundary])?;
                git.update_clone(&url, &dest)?;
                let updated = gix::open(&dest)?;
                assert_eq!(id(&updated, "refs/remotes/origin/heads/main")?, next);
                assert_eq!(
                    updated.shallow_commits()?.unwrap().iter().copied().collect::<Vec<_>>(),
                    vec![boundary]
                );
                assert_eq!(
                    updated.rev_walk([next]).all()?.collect::<Result<Vec<_>, _>>()?.len(),
                    2
                );
                fixture::reference(
                    &source,
                    "refs/heads/main",
                    boundary,
                    PreviousValue::Any,
                    "reset fixture",
                )?;
            }
            Ok(())
        })
    })
}

#[test]
fn checkout_keeps_clone_when_paths_differ_only_by_case() -> Result<()> {
    isolated("checkout_keeps_clone_when_paths_differ_only_by_case", || {
        let temp = tempfile::tempdir()?;
        let source_dir = temp.path().join("case.git");
        let repo = gix::init_bare(&source_dir)?;
        fixture::set_head(&repo, "refs/heads/main")?;
        let sig = fixture::signature("fixture", "fixture@example.com");
        let upper = repo.write_blob(b"upper\n")?.detach();
        let lower = repo.write_blob(b"lower\n")?.detach();
        let mut tree = repo.empty_tree().edit()?;
        tree.upsert("README", gix::objs::tree::EntryKind::Blob, upper)?;
        tree.upsert("readme", gix::objs::tree::EntryKind::Blob, lower)?;
        let tree = tree.write()?.detach();
        let head = fixture::commit(&repo, Some("HEAD"), &sig, &sig, "case", &tree, &[])?;
        with_rewrite(&source_dir, |url| -> Result<()> {
            // Case-insensitive filesystems (default macOS and Windows) collide here;
            // like `git clone`, the checkout must still succeed and remain scannable.
            let dest = temp.path().join("checkout");
            Git::default().create_fresh_clone(&url, &dest, CloneMode::Checkout)?;
            assert_eq!(gix::open(&dest)?.head_id()?.detach(), head);
            assert!(dest.join("README").is_file() || dest.join("readme").is_file());
            Ok(())
        })
    })
}

#[test]
fn clone_modes_preserve_history_refs_and_checkout() -> Result<()> {
    isolated("clone_modes_preserve_history_refs_and_checkout", || {
        let temp = tempfile::tempdir()?;
        let source_dir = temp.path().join("source with spaces.git");
        let (_, first, second) = source(&source_dir)?;
        with_rewrite(&source_dir, |url| -> Result<()> {
            for (name, mode) in [
                ("bare", CloneMode::Bare),
                ("mirror", CloneMode::Mirror),
                ("checkout", CloneMode::Checkout),
            ] {
                let dest = temp.path().join("nested clone cache").join(name).join("repository");
                Git::default().create_fresh_clone(&url, &dest, mode)?;
                let repo = gix::open(&dest)?;
                assert_eq!(repo.is_bare(), name != "checkout");
                assert_eq!(repo.head_id()?.detach(), second);
                assert_eq!(id(&repo, "refs/tags/v1")?, first);
                assert!(repo.find_object(first).is_ok(), "history must be retained");
                // Local fetches write one pack, like a network fetch, not loose objects.
                let objects = repo.common_dir().join("objects");
                let loose: Vec<_> = std::fs::read_dir(&objects)?
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name())
                    .filter(|name| name != "pack" && name != "info")
                    .collect();
                assert!(loose.is_empty(), "loose object directories: {loose:?}");
                let packs = std::fs::read_dir(objects.join("pack"))?
                    .filter_map(Result::ok)
                    .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "pack"))
                    .count();
                assert_eq!(packs, 1);
                assert_eq!(id(&repo, "refs/remotes/origin/custom/audit")?, first);
                assert_eq!(id(&repo, "refs/remotes/origin/heads/feature")?, first);
                if name != "checkout" {
                    assert_eq!(id(&repo, "refs/heads/feature")?, first);
                }
                if name == "mirror" {
                    assert_eq!(id(&repo, "refs/custom/audit")?, first);
                    assert_eq!(repo.config_snapshot().boolean("remote.origin.mirror"), Some(true));
                }
                if name == "checkout" {
                    assert_eq!(
                        std::fs::read(dest.join("nested/file with spaces.txt"))?,
                        b"committed content\n"
                    );
                    assert!(repo.index().is_ok());
                }
                assert_eq!(
                    repo.config_snapshot().string("remote.origin.url").unwrap().to_string(),
                    url.as_str()
                );
            }
            Ok(())
        })
    })
}

#[test]
fn branch_clone_is_narrow_complete_and_updates_with_pruning() -> Result<()> {
    isolated("branch_clone_is_narrow_complete_and_updates_with_pruning", || {
        let temp = tempfile::tempdir()?;
        let source_dir = temp.path().join("source.git");
        let (source, first, second) = source(&source_dir)?;
        with_rewrite(&source_dir, |url| -> Result<()> {
            let dest = temp.path().join("new cache").join(".branch-clones").join("branch.git");
            Git::default().create_branch_clone(&url, &dest, "main")?;
            let repo = gix::open(&dest)?;
            assert!(repo.is_bare());
            assert_eq!(repo.head_id()?.detach(), second);
            assert!(repo.find_object(first).is_ok());
            assert!(repo.try_find_reference("refs/heads/feature")?.is_none());
            assert!(repo.try_find_reference("refs/tags/v1")?.is_none());
            let sig = fixture::signature("fixture", "fixture@example.com");
            let tree = source.head_commit()?.tree_id()?.detach();
            let third =
                fixture::commit(&source, Some("HEAD"), &sig, &sig, "third", &tree, &[&second])?;
            Git::default().update_clone(&url, &dest)?;
            assert_eq!(gix::open(&dest)?.head_id()?.detach(), third);
            assert!(
                Git::default()
                    .create_branch_clone(&url, &temp.path().join("missing"), "not-present")
                    .is_err()
            );
            Ok(())
        })
    })
}

#[test]
fn branch_clone_resolves_tags_and_prefers_branches_without_fetching_default_head() -> Result<()> {
    isolated(
        "branch_clone_resolves_tags_and_prefers_branches_without_fetching_default_head",
        || {
            for http in [false, true] {
                let temp = tempfile::tempdir()?;
                let source_dir = temp.path().join("source.git");
                let (source, first, second) = source(&source_dir)?;
                let sig = fixture::signature("fixture", "fixture@example.com");
                let unrelated_blob =
                    source.write_blob(b"unrelated default branch contents")?.detach();
                let mut tree = source.empty_tree().edit()?;
                tree.upsert("unrelated.txt", gix::objs::tree::EntryKind::Blob, unrelated_blob)?;
                let tree = tree.write()?.detach();
                let unrelated = fixture::commit(
                    &source,
                    Some("HEAD"),
                    &sig,
                    &sig,
                    "unrelated root",
                    &tree,
                    &[],
                )?;
                fixture::reference(&source, "refs/tags/light", first, PreviousValue::Any, "light")?;
                fixture::reference(
                    &source,
                    "refs/heads/collision",
                    first,
                    PreviousValue::Any,
                    "branch",
                )?;
                fixture::reference(
                    &source,
                    "refs/tags/collision",
                    second,
                    PreviousValue::Any,
                    "tag",
                )?;
                let server = git_server::Server::new(
                    git_server::Snapshot::from_repo(&source)?,
                    false,
                    None,
                )?;
                let run = |url: GitUrl| -> Result<()> {
                    let git = Git::default();
                    for (name, tag) in
                        [("feature", false), ("v1", true), ("light", true), ("collision", false)]
                    {
                        server.state.lock().unwrap().requests.clear();
                        let dest = temp.path().join(name);
                        git.create_branch_clone(&url, &dest, name)?;
                        let repo = gix::open(&dest)?;
                        assert!(repo.is_bare());
                        assert_eq!(repo.head()?.is_detached(), tag);
                        assert_eq!(repo.head()?.id().unwrap().detach(), first);
                        let selected =
                            format!("refs/{}/{name}", if tag { "tags" } else { "heads" });
                        assert_eq!(
                            repo.find_reference(selected.as_str())?.id().detach(),
                            source.find_reference(selected.as_str())?.id().detach(),
                            "annotated tags must retain their tag object: http={http}, name={name}",
                        );
                        assert_eq!(repo.references()?.all()?.count(), 1, "only the selected ref");
                        assert_eq!(
                            repo.config_snapshot()
                                .string("remote.origin.fetch")
                                .unwrap()
                                .to_string(),
                            format!("+{selected}:{selected}"),
                        );
                        assert_eq!(
                            repo.config_snapshot()
                                .string("remote.origin.tagOpt")
                                .unwrap()
                                .to_string(),
                            "--no-tags",
                        );
                        if http {
                            // The fixture legally overdelivers all objects. Verify what
                            // the client requested instead of asserting pack contents.
                            let state = server.state.lock().unwrap();
                            let wants = state
                                .requests
                                .iter()
                                .flat_map(|request| &request.wants)
                                .collect::<Vec<_>>();
                            assert!(!wants.is_empty(), "HTTP want capture must be exercised");
                            assert!(!wants.contains(&&unrelated), "must not request default HEAD");
                        } else {
                            assert!(!repo.has_object(unrelated));
                            assert!(!repo.has_object(unrelated_blob));
                        }
                        drop(repo);
                        if tag {
                            if name == "v1" {
                                source.find_reference(selected.as_str())?.delete()?;
                                fixture::tag(&source, name, second, &sig, "moved selected tag")?;
                            } else {
                                fixture::reference(
                                    &source,
                                    selected.as_str(),
                                    second,
                                    PreviousValue::Any,
                                    "move",
                                )?;
                            }
                            server.state.lock().unwrap().snapshot =
                                git_server::Snapshot::from_repo(&source)?;
                            git.update_clone(&url, &dest)?;
                            let repo = gix::open(&dest)?;
                            assert_eq!(id(&repo, selected.as_str())?, second);
                            assert!(repo.head()?.is_detached());
                            assert_eq!(
                                repo.head()?.id().unwrap().detach(),
                                first,
                                "updates leave HEAD untouched"
                            );
                        }
                    }
                    server.state.lock().unwrap().requests.clear();
                    let missing = temp.path().join("missing");
                    assert!(git.create_branch_clone(&url, &missing, "not-present").is_err());
                    assert!(!missing.exists(), "failed selection must remove its new clone");
                    assert!(
                        server
                            .state
                            .lock()
                            .unwrap()
                            .requests
                            .iter()
                            .all(|request| request.wants.is_empty())
                    );
                    Ok(())
                };
                if http {
                    run(server.url().parse().map_err(anyhow::Error::msg)?)?;
                } else {
                    with_rewrite(&source_dir, run)?;
                }
            }
            Ok(())
        },
    )
}

#[test]
fn mirror_update_fetches_new_refs_and_prunes_deleted_refs() -> Result<()> {
    isolated("mirror_update_fetches_new_refs_and_prunes_deleted_refs", || {
        let temp = tempfile::tempdir()?;
        let source_dir = temp.path().join("source.git");
        let (source, first, second) = source(&source_dir)?;
        with_rewrite(&source_dir, |url| -> Result<()> {
            let dest = temp.path().join("mirror.git");
            let git = Git::default();
            git.create_fresh_clone(&url, &dest, CloneMode::Mirror)?;
            source.find_reference("refs/heads/feature")?.delete()?;
            source.find_reference("refs/tags/v1")?.delete()?;
            fixture::reference(&source, "refs/heads/new", second, PreviousValue::Any, "new")?;
            fixture::reference(
                &source,
                "refs/custom/audit",
                second,
                PreviousValue::Any,
                "advance",
            )?;
            git.update_clone(&url, &dest)?;
            let repo = gix::open(&dest)?;
            assert_eq!(id(&repo, "refs/heads/new")?, second);
            assert_eq!(id(&repo, "refs/custom/audit")?, second);
            assert!(repo.try_find_reference("refs/heads/feature")?.is_none());
            assert!(repo.try_find_reference("refs/remotes/origin/heads/feature")?.is_none());
            assert!(repo.try_find_reference("refs/tags/v1")?.is_none());
            assert!(repo.find_object(first).is_ok(), "pruning refs must not discard objects");
            Ok(())
        })
    })
}

#[test]
fn updates_preserve_checkout_and_existing_tags_but_follow_new_tags() -> Result<()> {
    isolated("updates_preserve_checkout_and_existing_tags_but_follow_new_tags", || {
        for http in [false, true] {
            let temp = tempfile::tempdir()?;
            let source_dir = temp.path().join("source.git");
            let (source, first, second) = source(&source_dir)?;
            let server =
                git_server::Server::new(git_server::Snapshot::from_repo(&source)?, false, None)?;
            let run = |url: GitUrl| -> Result<()> {
                let git = Git::default();
                let bare = temp.path().join("bare");
                let checkout = temp.path().join("checkout");
                git.create_fresh_clone(&url, &bare, CloneMode::Bare)?;
                git.create_fresh_clone(&url, &checkout, CloneMode::Checkout)?;
                let work_file = checkout.join("nested/file with spaces.txt");
                std::fs::write(&work_file, "local uncommitted edit\n")?;
                let index_before = std::fs::read(checkout.join(".git/index"))?;
                let sig = fixture::signature("fixture", "fixture@example.com");
                let tree = source.head_commit()?.tree_id()?.detach();
                let third =
                    fixture::commit(&source, Some("HEAD"), &sig, &sig, "third", &tree, &[&second])?;
                source.find_reference("refs/tags/v1")?.delete()?;
                fixture::tag(&source, "v1", third, &sig, "moved upstream tag")?;
                fixture::tag(&source, "v2", third, &sig, "new reachable tag")?;
                source.find_reference("refs/heads/feature")?.delete()?;
                server.state.lock().unwrap().snapshot = git_server::Snapshot::from_repo(&source)?;
                for destination in [&bare, &checkout] {
                    git.update_clone(&url, destination)?;
                    let repo = gix::open(destination)?;
                    assert_eq!(
                        repo.head_id()?.detach(),
                        second,
                        "updates must not reset local HEAD"
                    );
                    assert_eq!(
                        id(&repo, "refs/tags/v1")?,
                        first,
                        "auto-follow must retain moved local tags"
                    );
                    assert_eq!(id(&repo, "refs/tags/v2")?, third);
                    assert_eq!(id(&repo, "refs/remotes/origin/heads/main")?, third);
                    assert!(
                        repo.try_find_reference("refs/remotes/origin/heads/feature")?.is_none()
                    );
                }
                assert_eq!(std::fs::read(&work_file)?, b"local uncommitted edit\n");
                assert_eq!(std::fs::read(checkout.join(".git/index"))?, index_before);
                Ok(())
            };
            if http {
                run(server.url().parse().map_err(anyhow::Error::msg)?)?;
            } else {
                with_rewrite(&source_dir, run)?;
            }
        }
        Ok(())
    })
}

#[test]
fn rejected_explicit_tag_updates_fail_instead_of_silently_succeeding() -> Result<()> {
    isolated("rejected_explicit_tag_updates_fail_instead_of_silently_succeeding", || {
        for http in [false, true] {
            let temp = tempfile::tempdir()?;
            let source_dir = temp.path().join("source.git");
            let (source, first, second) = source(&source_dir)?;
            let server =
                git_server::Server::new(git_server::Snapshot::from_repo(&source)?, false, None)?;
            let run = |url: GitUrl| -> Result<()> {
                let dest = temp.path().join("bare");
                let git = Git::default();
                git.create_fresh_clone(&url, &dest, CloneMode::Bare)?;
                fixture::config(&gix::open(&dest)?, "remote.origin.tagOpt", "--tags")?;
                source.find_reference("refs/tags/v1")?.delete()?;
                let sig = fixture::signature("fixture", "fixture@example.com");
                fixture::tag(&source, "v1", second, &sig, "moved tag must reject")?;
                server.state.lock().unwrap().snapshot = git_server::Snapshot::from_repo(&source)?;
                assert!(git.update_clone(&url, &dest).is_err(), "unforced tag update must fail");
                assert_eq!(id(&gix::open(&dest)?, "refs/tags/v1")?, first);
                Ok(())
            };
            if http {
                run(server.url().parse().map_err(anyhow::Error::msg)?)?;
            } else {
                with_rewrite(&source_dir, run)?;
            }
        }
        Ok(())
    })
}

#[test]
fn update_fetches_configured_remotes_and_respects_skip_default_update() -> Result<()> {
    isolated("update_fetches_configured_remotes_and_respects_skip_default_update", || {
        let temp = tempfile::tempdir()?;
        let source_dir = temp.path().join("source.git");
        let (_, _, second) = source(&source_dir)?;
        let backup_dir = temp.path().join("backup source.git");
        let (backup, first, _) = source(&backup_dir)?;
        fixture::reference(&backup, "refs/heads/backup-only", first, PreviousValue::Any, "backup")?;
        with_rewrite(&source_dir, |url| -> Result<()> {
            let destination = temp.path().join("clone.git");
            let git = Git::default();
            git.create_fresh_clone(&url, &destination, CloneMode::Bare)?;
            let repository = gix::open(&destination)?;
            fixture::config(
                &repository,
                "remote.backup.url",
                &backup_dir.to_string_lossy().replace('\\', "/"),
            )?;
            fixture::config(
                &repository,
                "remote.backup.fetch",
                "+refs/heads/*:refs/remotes/backup/*",
            )?;
            fixture::config(&repository, "remote.disabled.url", "ext::must-not-run-any-helper")?;
            fixture::config(
                &repository,
                "remote.disabled.fetch",
                "+refs/heads/*:refs/remotes/disabled/*",
            )?;
            fixture::config(&repository, "remote.disabled.skipDefaultUpdate", "true")?;
            git.update_clone(&url, &destination)?;
            let repository = gix::open(&destination)?;
            assert_eq!(id(&repository, "refs/remotes/backup/backup-only")?, first);
            assert_eq!(id(&repository, "refs/remotes/origin/heads/main")?, second);
            Ok(())
        })
    })
}

#[test]
fn empty_remote_and_existing_destination_are_handled_safely() -> Result<()> {
    isolated("empty_remote_and_existing_destination_are_handled_safely", || {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("empty.git");
        let repo = gix::init_bare(&source)?;
        let server = git_server::Server::new(git_server::Snapshot::from_repo(&repo)?, false, None)?;
        let run = |url: GitUrl, transport: &str| -> Result<()> {
            for mode in [CloneMode::Bare, CloneMode::Mirror, CloneMode::Checkout] {
                let dest = temp.path().join(format!("{transport}-{mode:?}"));
                Git::default().create_fresh_clone(&url, &dest, mode)?;
                let repo = gix::open(&dest)?;
                assert!(repo.head()?.is_unborn());
                assert_eq!(repo.references()?.all()?.count(), 0);
            }
            let occupied = temp.path().join(format!("{transport}-occupied"));
            std::fs::create_dir(&occupied)?;
            std::fs::write(occupied.join("keep.txt"), "must survive")?;
            assert!(Git::default().create_fresh_clone(&url, &occupied, CloneMode::Bare).is_err());
            assert_eq!(std::fs::read_to_string(occupied.join("keep.txt"))?, "must survive");
            Ok(())
        };
        with_rewrite(&source, |url| run(url, "local"))?;
        run(server.url().parse().map_err(anyhow::Error::msg)?, "http")
    })
}

#[test]
fn smart_http_clone_and_incremental_update() -> Result<()> {
    isolated("smart_http_clone_and_incremental_update", || {
        let temp = tempfile::tempdir()?;
        let (source, first, second) = source(&temp.path().join("source.git"))?;
        let server =
            git_server::Server::new(git_server::Snapshot::from_repo(&source)?, false, None)?;
        let url = server.url().parse::<GitUrl>().map_err(anyhow::Error::msg)?;
        let dest = temp.path().join("clone.git");
        let git = Git::default();
        git.create_fresh_clone(&url, &dest, CloneMode::Mirror)?;
        assert!(dest.join("packed-refs").is_file(), "initial network refs must be packed");
        assert_eq!(gix::open(&dest)?.head_id()?.detach(), second);
        let sig = fixture::signature("fixture", "fixture@example.com");
        let tree = source.head_commit()?.tree_id()?.detach();
        let third = fixture::commit(&source, Some("HEAD"), &sig, &sig, "third", &tree, &[&second])?;
        source.find_reference("refs/heads/feature")?.delete()?;
        server.state.lock().unwrap().snapshot = git_server::Snapshot::from_repo(&source)?;
        git.update_clone(&url, &dest)?;
        let repo = gix::open(&dest)?;
        assert_eq!(repo.head_id()?.detach(), third);
        assert!(repo.try_find_reference("refs/heads/feature")?.is_none());
        assert!(repo.find_object(first).is_ok());
        assert!(
            server
                .state
                .lock()
                .unwrap()
                .requests
                .iter()
                .any(|request| request.path.ends_with("/git-upload-pack"))
        );
        Ok(())
    })
}

#[test]
fn network_clone_packs_many_refs_and_updates_them_incrementally() -> Result<()> {
    isolated("network_clone_packs_many_refs_and_updates_them_incrementally", || {
        let temp = tempfile::tempdir()?;
        let (source, first, second) = source(&temp.path().join("source.git"))?;
        for number in 0..64 {
            fixture::reference(
                &source,
                &format!("refs/heads/topic-{number:03}"),
                first,
                PreviousValue::Any,
                "fixture",
            )?;
        }
        let server =
            git_server::Server::new(git_server::Snapshot::from_repo(&source)?, false, None)?;
        let url = server.url().parse::<GitUrl>().map_err(anyhow::Error::msg)?;
        let destination = temp.path().join("clone.git");
        let git = Git::default();
        git.create_fresh_clone(&url, &destination, CloneMode::Mirror)?;
        let repo = gix::open(&destination)?;
        assert!(destination.join("packed-refs").is_file());
        for number in 0..64 {
            for prefix in ["refs/heads/", "refs/remotes/origin/heads/"] {
                let name = format!("{prefix}topic-{number:03}");
                assert_eq!(id(&repo, &name)?, first);
                assert!(!destination.join(&name).exists(), "initial ref must be packed: {name}");
            }
        }
        drop(repo);
        fixture::reference(&source, "refs/heads/topic-000", second, PreviousValue::Any, "move")?;
        source.find_reference("refs/heads/topic-001")?.delete()?;
        fixture::reference(&source, "refs/heads/topic-new", second, PreviousValue::Any, "new")?;
        server.state.lock().unwrap().snapshot = git_server::Snapshot::from_repo(&source)?;
        git.update_clone(&url, &destination)?;
        let repo = gix::open(&destination)?;
        for prefix in ["refs/heads/", "refs/remotes/origin/heads/"] {
            assert_eq!(id(&repo, &format!("{prefix}topic-000"))?, second);
            assert_eq!(id(&repo, &format!("{prefix}topic-new"))?, second);
            assert!(repo.try_find_reference(format!("{prefix}topic-001").as_str())?.is_none());
            for number in 2..64 {
                assert_eq!(id(&repo, &format!("{prefix}topic-{number:03}"))?, first);
            }
        }
        assert!(repo.has_object(first), "pruning packed refs must not discard objects");
        Ok(())
    })
}

#[test]
fn network_clone_rejects_object_checksum_corruption_with_valid_pack_digest() -> Result<()> {
    isolated("network_clone_rejects_object_checksum_corruption_with_valid_pack_digest", || {
        let temp = tempfile::tempdir()?;
        let (source, _, _) = source(&temp.path().join("source.git"))?;
        let snapshot = git_server::Snapshot::from_repo(&source)?.with_corrupt_object_checksum();
        let server = git_server::Server::new(snapshot, false, None)?;
        let url = server.url().parse::<GitUrl>().map_err(anyhow::Error::msg)?;
        let destination = temp.path().join("corrupt.git");
        assert!(Git::default().create_fresh_clone(&url, &destination, CloneMode::Mirror).is_err());
        assert!(!destination.exists(), "failed clone must be cleaned up");
        Ok(())
    })
}

#[test]
fn custom_ca_and_network_checkout_work_without_git_or_global_identity() -> Result<()> {
    isolated("custom_ca_and_network_checkout_work_without_git_or_global_identity", || {
        let temp = tempfile::tempdir()?;
        let (source, _, second) = source(&temp.path().join("source.git"))?;
        let server =
            git_server::Server::new(git_server::Snapshot::from_repo(&source)?, true, None)?;
        let ca = temp.path().join("fixture CA.pem");
        std::fs::write(&ca, server.certificate_pem.as_ref().unwrap())?;
        let url = server.url().parse::<GitUrl>().map_err(anyhow::Error::msg)?;
        temp_env::with_vars(
            [
                ("GIT_SSL_CAINFO", Some(ca.as_os_str())),
                ("GIT_SSL_NO_VERIFY", None),
                ("GIT_SSL_CAPATH", None),
                ("SSL_CERT_DIR", None),
            ],
            || -> Result<()> {
                let destination = temp.path().join("checkout");
                let git = Git::default();
                git.create_fresh_clone(&url, &destination, CloneMode::Checkout)?;
                git.update_clone(&url, &destination)?;
                let repository = gix::open(&destination)?;
                assert_eq!(repository.head_id()?.detach(), second);
                assert_eq!(
                    std::fs::read(destination.join("nested/file with spaces.txt"))?,
                    b"committed content\n"
                );
                let config = std::fs::read_to_string(repository.common_dir().join("config"))?;
                assert!(
                    !config.contains("kingfisher@localhost"),
                    "fallback identity is memory-only"
                );
                // Stale generic OpenSSL locations are skipped rather than breaking clones.
                let missing = temp.path().join("missing-ca");
                let stale_dirs =
                    std::env::join_paths([temp.path().to_path_buf(), missing.clone()])?;
                temp_env::with_vars(
                    [
                        ("SSL_CERT_FILE", Some(missing.as_os_str())),
                        ("SSL_CERT_DIR", Some(stale_dirs.as_os_str())),
                    ],
                    || -> Result<()> {
                        let stale = temp.path().join("stale-openssl-env");
                        git.create_fresh_clone(&url, &stale, CloneMode::Bare)?;
                        Ok(())
                    },
                )?;
                // Invalid explicit trust configuration must fail closed, not silently
                // fall back to unverified TLS or leave a partial successful clone.
                // Assert the configuration error itself: the self-signed fixture is
                // untrusted anyway, so a bare is_err() would pass on a TLS failure.
                std::fs::write(&ca, "not a certificate")?;
                let failed = temp.path().join("invalid-ca");
                let error = git.create_fresh_clone(&url, &failed, CloneMode::Bare).unwrap_err();
                assert!(format!("{error:#}").contains("Invalid Git TLS CA file"), "{error:#}");
                assert!(!failed.exists());
                // A required CA directory with no certificates fails closed too.
                std::fs::write(&ca, server.certificate_pem.as_ref().unwrap())?;
                let empty_dir = temp.path().join("empty-ca-dir");
                std::fs::create_dir(&empty_dir)?;
                temp_env::with_var("GIT_SSL_CAPATH", Some(empty_dir.as_os_str()), || {
                    let error = git.create_fresh_clone(&url, &failed, CloneMode::Bare).unwrap_err();
                    assert!(
                        format!("{error:#}").contains("Invalid Git TLS CA directory"),
                        "{error:#}"
                    );
                });
                assert!(!failed.exists());
                Ok(())
            },
        )
    })
}

#[test]
fn provider_authentication_is_https_scoped_and_never_persisted() -> Result<()> {
    isolated("provider_authentication_is_https_scoped_and_never_persisted", || {
        use base64::Engine;
        let temp = tempfile::tempdir()?;
        let (source, _, _) = source(&temp.path().join("source.git"))?;
        let snapshot = git_server::Snapshot::from_repo(&source)?;
        for (provider, variable, username) in [
            ("github", "KF_GITHUB_TOKEN", "x-access-token"),
            ("gitlab", "KF_GITLAB_TOKEN", "oauth2"),
            ("gitea", "KF_GITEA_TOKEN", "gitea"),
            ("bitbucket", "KF_BITBUCKET_OAUTH_TOKEN", "x-token-auth"),
            ("azure", "KF_AZURE_TOKEN", "pat"),
            ("huggingface", "KF_HUGGINGFACE_TOKEN", "hf_user"),
        ] {
            let secret = "wire-secret+/=do-not-persist";
            let authorization = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{secret}"))
            );
            let server = git_server::Server::new(snapshot.clone(), true, Some(authorization))?;
            let host = server.address.to_string();
            let mut hosts = ProviderHosts::default();
            match provider {
                "github" => hosts.github.push(host),
                "gitlab" => hosts.gitlab.push(host),
                "gitea" => hosts.gitea.push(host),
                "bitbucket" => hosts.bitbucket.push(host),
                "azure" => hosts.azure.push(host),
                "huggingface" => hosts.huggingface.push(host),
                _ => unreachable!(),
            }
            temp_env::with_vars([(variable, Some(secret))], || -> Result<()> {
                let url = server.url().parse::<GitUrl>().map_err(anyhow::Error::msg)?;
                let dest = temp.path().join(provider);
                // A self-signed certificate must fail without explicit opt-out.
                assert!(
                    Git::with_provider_hosts(false, &hosts)
                        .create_fresh_clone(
                            &url,
                            &temp.path().join(format!("{provider}-untrusted")),
                            CloneMode::Bare
                        )
                        .is_err()
                );
                let git = Git::with_provider_hosts(true, &hosts);
                git.create_fresh_clone(&url, &dest, CloneMode::Bare)?;
                git.update_clone(&url, &dest)?;
                let config = std::fs::read_to_string(dest.join("config"))?;
                assert!(!config.contains(secret), "{provider}: credential persisted");
                assert!(!config.contains("credential"), "{provider}: helper persisted");
                assert!(
                    server
                        .state
                        .lock()
                        .unwrap()
                        .requests
                        .iter()
                        .any(|request| request.authorization.is_some()),
                    "{provider}: no authenticated request"
                );
                // A trusted hostname without the explicit non-default port must not match.
                assert!(
                    Git::new(true)
                        .create_fresh_clone(
                            &url,
                            &temp.path().join(format!("{provider}-wrong-host")),
                            CloneMode::Bare
                        )
                        .is_err()
                );
                let plaintext = git_server::Server::new(
                    snapshot.clone(),
                    false,
                    Some("Basic never-match".into()),
                )?;
                let mut plaintext_hosts = ProviderHosts::default();
                plaintext_hosts.github.push(plaintext.address.to_string());
                let http_url = plaintext.url().parse::<GitUrl>().map_err(anyhow::Error::msg)?;
                assert!(
                    Git::with_provider_hosts(true, &plaintext_hosts)
                        .create_fresh_clone(
                            &http_url,
                            &temp.path().join(format!("{provider}-http")),
                            CloneMode::Bare
                        )
                        .is_err()
                );
                assert!(
                    plaintext
                        .state
                        .lock()
                        .unwrap()
                        .requests
                        .iter()
                        .all(|request| request.authorization.is_none())
                );
                Ok(())
            })?;
        }
        Ok(())
    })
}

#[test]
fn authenticated_redirect_does_not_leak_credentials() -> Result<()> {
    isolated("authenticated_redirect_does_not_leak_credentials", || {
        use base64::Engine;
        let temp = tempfile::tempdir()?;
        let (source, _, _) = source(&temp.path().join("source.git"))?;
        let snapshot = git_server::Snapshot::from_repo(&source)?;
        let secret = "never-forward-this-secret";
        let authorization = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{secret}"))
        );
        let attacker = git_server::Server::new(
            snapshot.clone(),
            true,
            Some("Basic attacker-challenge".into()),
        )?;
        // The trusted host challenges first and only redirects an authenticated
        // request, so the client holds an identity when it is sent elsewhere.
        let trusted = git_server::Server::new(snapshot, true, Some(authorization.clone()))?;
        trusted.state.lock().unwrap().redirect = Some(attacker.url());
        let mut hosts = ProviderHosts::default();
        hosts.github.push(trusted.address.to_string());
        temp_env::with_var("KF_GITHUB_TOKEN", Some(secret), || -> Result<()> {
            let url = trusted.url().parse::<GitUrl>().map_err(anyhow::Error::msg)?;
            assert!(
                Git::with_provider_hosts(true, &hosts)
                    .create_fresh_clone(&url, &temp.path().join("clone"), CloneMode::Bare)
                    .is_err()
            );
            assert!(
                trusted
                    .state
                    .lock()
                    .unwrap()
                    .requests
                    .iter()
                    .any(|request| request.authorization.as_deref() == Some(&*authorization)),
                "the trusted host never received credentials, so the redirect was not tested"
            );
            let attacker_requests = attacker.state.lock().unwrap().requests.clone();
            assert!(!attacker_requests.is_empty(), "the redirect was never followed");
            assert!(
                attacker_requests.iter().all(|request| request.authorization.is_none()),
                "{attacker_requests:?}"
            );
            Ok(())
        })
    })
}

#[test]
fn clone_and_update_timeouts_are_bounded() -> Result<()> {
    isolated("clone_and_update_timeouts_are_bounded", || {
        let temp = tempfile::tempdir()?;
        let (source, _, _) = source(&temp.path().join("source.git"))?;
        let server =
            git_server::Server::new(git_server::Snapshot::from_repo(&source)?, false, None)?;
        let url = server.url().parse::<GitUrl>().map_err(anyhow::Error::msg)?;
        let dest = temp.path().join("clone.git");
        Git::default().create_fresh_clone(&url, &dest, CloneMode::Mirror)?;
        // Keep the server delay well above the 1s timeout so slow CI runners
        // (notably Windows arm64) still distinguish a bounded timeout from a response.
        server.state.lock().unwrap().delay = std::time::Duration::from_secs(6);
        for (variable, update) in
            [("KF_GIT_CLONE_TIMEOUT_SECS", false), ("KF_GIT_UPDATE_TIMEOUT_SECS", true)]
        {
            temp_env::with_var(variable, Some("1"), || {
                let start = std::time::Instant::now();
                let result = if update {
                    Git::default().update_clone(&url, &dest)
                } else {
                    Git::default().create_fresh_clone(
                        &url,
                        &temp.path().join("timeout"),
                        CloneMode::Bare,
                    )
                };
                let error = result.unwrap_err();
                assert!(error.to_string().contains("timed out"), "{error:?}");
                assert!(start.elapsed() < std::time::Duration::from_secs(5));
            });
        }
        Ok(())
    })
}

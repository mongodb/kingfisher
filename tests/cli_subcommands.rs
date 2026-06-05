// tests/cli_subcommands.rs
//
// Extensive CLI tests for the new subcommand syntax (kingfisher scan <platform>)
// These tests validate that all platform-specific scan subcommands are properly wired up
// and can be invoked with various argument combinations.

use assert_cmd::Command;
use predicates::{
    prelude::PredicateBooleanExt,
    str::{contains, is_match},
};

// =============================================================================
// GitHub Scan Subcommand Tests
// =============================================================================

mod github {
    use super::*;

    #[test]
    fn scan_github_help() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "github", "--help"])
            .assert()
            .success()
            .stdout(contains("Enumerate and scan GitHub repositories"));
    }

    #[test]
    fn scan_github_list_only_help() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "github", "--help"])
            .assert()
            .success()
            .stdout(
                contains("--list-only")
                    .and(contains("List matching repositories without scanning")),
            );
    }

    #[test]
    fn scan_github_requires_specifier() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "github", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("must specify").or(contains("required")).or(contains("provide")));
    }

    #[test]
    fn scan_github_with_user() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "github", "--user", "testuser", "--list-only", "--no-update-check"])
            .assert()
            .code(predicates::function::function(|code: &i32| {
                // May succeed (exit 0) or fail with network/auth error (exit 1)
                *code == 0 || *code == 1
            }));
    }

    #[test]
    fn scan_github_with_organization() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "github",
                "--organization",
                "testorg",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_github_multiple_users() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "github",
                "--user",
                "user1",
                "--user",
                "user2",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_github_with_exclude() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "github",
                "--user",
                "testuser",
                "--github-exclude",
                "testuser/excluded-repo",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_github_with_repo_type_fork() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "github",
                "--user",
                "testuser",
                "--repo-type",
                "fork",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_github_with_repo_type_source() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "github",
                "--user",
                "testuser",
                "--repo-type",
                "source",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_github_custom_api_url() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "github",
                "--api-url",
                "https://github.enterprise.example.com/api/v3/",
                "--user",
                "testuser",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_github_all_organizations() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "github",
                "--api-url",
                "https://github.enterprise.example.com/api/v3/",
                "--all-organizations",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_github_invalid_repo_type() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "github",
                "--user",
                "testuser",
                "--repo-type",
                "invalid-type",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(contains("invalid value").or(contains("isn't a valid value")));
    }

    #[test]
    fn scan_github_mixed_user_and_org() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "github",
                "--user",
                "testuser",
                "--organization",
                "testorg",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }
}

// =============================================================================
// GitLab Scan Subcommand Tests
// =============================================================================

mod gitlab {
    use super::*;

    #[test]
    fn scan_gitlab_help() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "gitlab", "--help"])
            .assert()
            .success()
            .stdout(contains("Enumerate and scan GitLab"));
    }

    #[test]
    fn scan_gitlab_list_only_flag() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "gitlab", "--help"])
            .assert()
            .success()
            .stdout(contains("--list-only"));
    }

    #[test]
    fn scan_gitlab_requires_specifier() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "gitlab", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("must specify").or(contains("required")).or(contains("provide")));
    }

    #[test]
    fn scan_gitlab_with_user() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "gitlab", "--user", "testuser", "--list-only", "--no-update-check"])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_gitlab_with_group() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "gitlab", "--group", "testgroup", "--list-only", "--no-update-check"])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_gitlab_with_include_subgroups() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "gitlab",
                "--group",
                "testgroup",
                "--include-subgroups",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_gitlab_with_repo_type() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "gitlab",
                "--user",
                "testuser",
                "--repo-type",
                "owner",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_gitlab_accepts_global_flags_after_subcommand() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "gitlab",
                "--group",
                "testgroup",
                "--include-subgroups",
                "--list-only",
                "--quiet",
                "--access-map",
                "--no-update-check",
                "--user-agent-suffix",
                "cli-test",
                "--verbose",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code != 2));
    }

    #[test]
    fn scan_gitlab_with_exclude() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "gitlab",
                "--user",
                "testuser",
                "--gitlab-exclude",
                "testuser/excluded-repo",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_gitlab_custom_api_url() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "gitlab",
                "--api-url",
                "https://gitlab.enterprise.example.com/",
                "--user",
                "testuser",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_gitlab_all_groups() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "gitlab",
                "--api-url",
                "https://gitlab.enterprise.example.com/",
                "--all-groups",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }
}

// =============================================================================
// Azure DevOps Scan Subcommand Tests
// =============================================================================

mod azure {
    use super::*;

    #[test]
    fn scan_azure_help() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "azure", "--help"])
            .assert()
            .success()
            .stdout(contains("Enumerate and scan Azure").or(contains("Azure DevOps")));
    }

    #[test]
    fn scan_azure_list_only_flag() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "azure", "--help"])
            .assert()
            .success()
            .stdout(contains("--list-only"));
    }

    #[test]
    fn scan_azure_requires_specifier() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "azure", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("must specify").or(contains("required")).or(contains("provide")));
    }

    #[test]
    fn scan_azure_with_organization() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "azure",
                "--organization",
                "testorg",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_azure_with_project() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "azure",
                "--project",
                "testorg/testproject",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_azure_all_projects() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "azure",
                "--organization",
                "testorg",
                "--all-projects",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_azure_with_exclude() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "azure",
                "--organization",
                "testorg",
                "--azure-exclude",
                "testorg/testproject/testrepo",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_azure_with_repo_type() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "azure",
                "--organization",
                "testorg",
                "--repo-type",
                "fork",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }
}

// =============================================================================
// Bitbucket Scan Subcommand Tests
// =============================================================================

mod bitbucket {
    use super::*;

    #[test]
    fn scan_bitbucket_help() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "bitbucket", "--help"])
            .assert()
            .stdout(is_match(r"kingfisher(\.exe)? scan bitbucket \[OPTIONS\]").unwrap());
    }

    #[test]
    fn scan_bitbucket_list_only_flag() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "bitbucket", "--help"])
            .assert()
            .success()
            .stdout(contains("--list-only"));
    }

    #[test]
    fn scan_bitbucket_requires_specifier() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "bitbucket", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("must specify").or(contains("required")).or(contains("provide")));
    }

    #[test]
    fn scan_bitbucket_with_workspace() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "bitbucket",
                "--workspace",
                "testworkspace",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_bitbucket_with_user() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "bitbucket", "--user", "testuser", "--list-only", "--no-update-check"])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_bitbucket_with_project() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "bitbucket",
                "--project",
                "testproject",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_bitbucket_all_workspaces() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "bitbucket",
                "--api-url",
                "https://bitbucket.enterprise.example.com/",
                "--all-workspaces",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_bitbucket_with_exclude() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "bitbucket",
                "--workspace",
                "testworkspace",
                "--bitbucket-exclude",
                "testworkspace/testrepo",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_bitbucket_with_repo_type() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "bitbucket",
                "--workspace",
                "testworkspace",
                "--repo-type",
                "source",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }
}

// =============================================================================
// Gitea Scan Subcommand Tests
// =============================================================================

mod gitea {
    use super::*;

    #[test]
    fn scan_gitea_help() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "gitea", "--help"])
            .assert()
            .success()
            .stdout(contains("Enumerate and scan Gitea"));
    }

    #[test]
    fn scan_gitea_requires_specifier() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "gitea", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("Specify at least").or(contains("required")).or(contains("provide")));
    }

    #[test]
    fn scan_gitea_with_organization() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "gitea",
                "--gitea-organization",
                "testorg",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_gitea_with_user() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "gitea", "--user", "testuser", "--list-only", "--no-update-check"])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_gitea_all_organizations() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "gitea",
                "--all-gitea-organizations",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_gitea_with_exclude() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "gitea",
                "--user",
                "testuser",
                "--gitea-exclude",
                "testuser/testrepo",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_gitea_with_repo_type() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "gitea",
                "--user",
                "testuser",
                "--repo-type",
                "all",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_gitea_custom_api_url() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "gitea",
                "--api-url",
                "https://gitea.example.com/api/v1/",
                "--user",
                "testuser",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }
}

// =============================================================================
// Hugging Face Scan Subcommand Tests
// =============================================================================

mod huggingface {
    use super::*;

    #[test]
    fn scan_huggingface_help() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "huggingface", "--help"])
            .assert()
            .success()
            .stdout(contains("Hugging Face").or(contains("HuggingFace")));
    }

    #[test]
    fn scan_huggingface_requires_specifier() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "huggingface", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("must specify").or(contains("required")).or(contains("provide")));
    }

    #[test]
    fn scan_huggingface_with_user() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "huggingface",
                "--huggingface-user",
                "testuser",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_huggingface_with_organization() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "huggingface",
                "--huggingface-organization",
                "testorg",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_huggingface_with_model() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "huggingface",
                "--huggingface-model",
                "testorg/testmodel",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_huggingface_with_dataset() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "huggingface",
                "--huggingface-dataset",
                "testorg/testdataset",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_huggingface_with_space() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "huggingface",
                "--huggingface-space",
                "testorg/testspace",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn scan_huggingface_with_exclude() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "huggingface",
                "--huggingface-user",
                "testuser",
                "--huggingface-exclude",
                "testuser/excluded",
                "--list-only",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }
}

// =============================================================================
// Docker Scan Subcommand Tests
// =============================================================================

mod docker {
    use super::*;

    #[test]
    fn scan_docker_help_includes_archive() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "docker", "--help"])
            .assert()
            .success()
            .stdout(contains("Scan Docker or OCI images").and(contains("--archive")));
    }

    #[test]
    fn scan_docker_requires_image_or_archive() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "docker", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("image or --archive"));
    }
}

// =============================================================================
// Cross-Platform Tests
// =============================================================================

mod cross_platform {
    use super::*;

    #[test]
    fn all_platforms_support_list_only() {
        let platforms = vec![
            vec!["scan", "github", "--user", "test"],
            vec!["scan", "gitlab", "--user", "test"],
            vec!["scan", "azure", "--organization", "test"],
            vec!["scan", "bitbucket", "--workspace", "test"],
            vec!["scan", "gitea", "--user", "test"],
            vec!["scan", "huggingface", "--huggingface-user", "test"],
        ];

        for mut platform_args in platforms {
            platform_args.extend_from_slice(&["--list-only", "--no-update-check"]);
            Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
                .args(&platform_args)
                .assert()
                .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
        }
    }

    #[test]
    fn scan_requires_subcommand_or_path() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("required").or(contains("expected")).or(contains("provide")));
    }

    #[test]
    fn scan_invalid_platform_subcommand() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "invalid-platform", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("unrecognized").or(contains("unexpected")));
    }

    #[test]
    fn scan_github_without_scanning_no_paths() {
        // list-only should work without providing actual scan paths
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "github", "--user", "testuser", "--list-only", "--no-update-check"])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }
}

// =============================================================================
// Legacy vs New Syntax Coexistence Tests
// =============================================================================

mod legacy_compatibility {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn scan_path_still_works() {
        // The old syntax of scanning a local path should still work
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        let test_file = root.join("testdata").join("generic_secrets.py");
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                test_file.to_str().expect("REASON"),
                "--no-validate",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| {
                // May succeed or fail depending on rules, but shouldn't error on syntax
                *code == 0 || *code == 1 || *code == 200
            }));
    }

    #[test]
    fn new_subcommand_syntax_coexists() {
        // Verify both old and new work (even if they fail due to network/auth)
        // This just validates the CLI parsing works

        // New syntax
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["scan", "github", "--user", "test", "--list-only", "--no-update-check"])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }
}

use std::{
    borrow::Cow,
    fmt::Display,
    io::{self, Write},
    path::PathBuf,
};

use url::Url;

use crate::cli::commands::{
    inputs::InputSpecifierArgs,
    scan::{ScanArgs, UNLIMITED_RESULTS},
};

pub(super) fn write_inputs_and_filters(
    out: &mut impl Write,
    args: &ScanArgs,
    pre_commit_files: Option<&[PathBuf]>,
    allow_stdin: bool,
) -> anyhow::Result<()> {
    let input = &args.input_specifier_args;
    writeln!(out, "Inputs")?;
    for path in &input.path_inputs {
        if allow_stdin && path.as_os_str() == "-" {
            writeln!(out, "  Standard input (-)")?;
        } else {
            writeln!(out, "  Local path  {:?}", path.as_os_str())?;
        }
    }
    if let Some(paths) = pre_commit_files {
        for path in paths {
            writeln!(out, "    Pre-commit file  {:?}", path.as_os_str())?;
        }
    }
    for url in &input.git_url {
        let target = url.as_str();
        let target = if target.contains("://") {
            safe_identifier(target)
        } else {
            // SCP-style syntax uses an optional account before the host, while the path may
            // itself contain '@'. Strip an account only when it precedes the host separator.
            Cow::Borrowed(
                target
                    .split_once('@')
                    .filter(|(account, _)| !account.contains(':'))
                    .map_or(target, |(_, remote)| remote),
            )
        };
        writeln!(out, "  Git repository  {}", target.escape_debug())?;
    }
    write_repository_sources(out, input)?;
    write_artifact_sources(out, args)?;
    write_git_scope(out, args, allow_stdin)?;
    write_content_filters(out, args)?;
    Ok(())
}

fn write_repository_sources(out: &mut impl Write, input: &InputSpecifierArgs) -> io::Result<()> {
    if write_repo_scope(
        out,
        "GitHub",
        &[("User", &input.github_user), ("Organization", &input.github_organization)],
        input.all_github_organizations.then_some("all organizations"),
        &input.github_api_url,
        input.github_repo_type,
        &input.github_exclude,
    )? && input.github_include_gists
    {
        write_field(out, "Include gists", "yes")?;
    }
    if write_selectors(out, "GitHub public events", &[("User", &input.github_event_user)], None)? {
        write_field(out, "API URL", safe_url(&input.github_api_url))?;
        write_field(out, "Lookback hours", input.github_event_lookback_hours)?;
        write_selectors_list(out, "Exclude repositories", &input.github_exclude)?;
    }
    if write_repo_scope(
        out,
        "GitLab",
        &[("User", &input.gitlab_user), ("Group", &input.gitlab_group)],
        input.all_gitlab_groups.then_some("all groups"),
        &input.gitlab_api_url,
        input.gitlab_repo_type,
        &input.gitlab_exclude,
    )? {
        write_field(out, "Include subgroups", yes_no(input.gitlab_include_subgroups))?;
        write_field(out, "Include snippets", yes_no(input.gitlab_include_snippets))?;
    }
    write_repo_scope(
        out,
        "Gitea",
        &[("User", &input.gitea_user), ("Organization", &input.gitea_organization)],
        input.all_gitea_organizations.then_some("all organizations"),
        &input.gitea_api_url,
        input.gitea_repo_type,
        &input.gitea_exclude,
    )?;
    if write_repo_scope(
        out,
        "Bitbucket",
        &[
            ("User", &input.bitbucket_user),
            ("Workspace", &input.bitbucket_workspace),
            ("Project", &input.bitbucket_project),
        ],
        input.all_bitbucket_workspaces.then_some("all workspaces"),
        &input.bitbucket_api_url,
        input.bitbucket_repo_type,
        &input.bitbucket_exclude,
    )? && input.bitbucket_include_snippets
    {
        write_field(out, "Include snippets", "yes")?;
    }
    write_repo_scope(
        out,
        "Azure DevOps",
        &[("Organization", &input.azure_organization), ("Project", &input.azure_project)],
        input.all_azure_projects.then_some("all projects"),
        &input.azure_base_url,
        input.azure_repo_type,
        &input.azure_exclude,
    )?;
    if write_selectors(
        out,
        "Hugging Face",
        &[
            ("User", &input.huggingface_user),
            ("Organization", &input.huggingface_organization),
            ("Model", &input.huggingface_model),
            ("Dataset", &input.huggingface_dataset),
            ("Space", &input.huggingface_space),
            ("Bucket", &input.huggingface_bucket),
        ],
        None,
    )? {
        write_selectors_list(out, "Exclude resources", &input.huggingface_exclude)?;
    }
    Ok(())
}

fn write_artifact_sources(out: &mut impl Write, args: &ScanArgs) -> io::Result<()> {
    let input = &args.input_specifier_args;
    let max_results =
        if args.content_filtering_args.no_limits { UNLIMITED_RESULTS } else { input.max_results };
    if input.slack_query.is_some() {
        write_search(out, "Slack", &input.slack_api_url, "Search query", max_results)?;
    }
    if input.teams_query.is_some() {
        write_search(out, "Teams", &input.teams_api_url, "Search query", max_results)?;
    }
    if let Some(url) = &input.jira_url {
        write_search(out, "Jira", url, "JQL", max_results)?;
        write_field(out, "Include comments", yes_no(input.jira_include_comments))?;
        write_field(out, "Include changelog", yes_no(input.jira_include_changelog))?;
    }
    if let Some(url) = &input.confluence_url {
        write_search(out, "Confluence", url, "CQL", max_results)?;
    }
    if write_selectors(
        out,
        "Postman",
        &[
            ("Workspace", &input.postman_workspaces),
            ("Collection", &input.postman_collections),
            ("Environment", &input.postman_environments),
        ],
        input.postman_all.then_some("all accessible resources"),
    )? {
        write_field(out, "API URL", safe_url(&input.postman_api_url))?;
        write_field(
            out,
            "Include mocks and monitors",
            yes_no(input.postman_include_mocks_monitors),
        )?;
        write_result_limit(out, max_results)?;
    }
    for (provider, bucket, prefix) in [
        ("Amazon S3", &input.s3_bucket, &input.s3_prefix),
        ("Google Cloud Storage", &input.gcs_bucket, &input.gcs_prefix),
    ] {
        if let Some(bucket) = bucket {
            writeln!(out, "  {provider}")?;
            write_field(out, "Bucket", safe_identifier(bucket))?;
            if let Some(prefix) = prefix {
                write_field(out, "Prefix", prefix)?;
            }
        }
    }
    if let Some(container) = &input.azure_blob {
        writeln!(out, "  Azure Blob Storage")?;
        write_field(out, "Container", safe_url(container))?;
    }
    if !input.docker_image.is_empty() || !input.docker_archive.is_empty() {
        writeln!(out, "  Docker")?;
        write_selectors_list(out, "Image", &input.docker_image)?;
        for archive in &input.docker_archive {
            writeln!(out, "    Archive  {:?}", archive.as_os_str())?;
        }
    }
    Ok(())
}

fn write_git_scope(out: &mut impl Write, args: &ScanArgs, allow_stdin: bool) -> io::Result<()> {
    let input = &args.input_specifier_args;
    let has_git_scope =
        input.path_inputs.iter().any(|path| !allow_stdin || path.as_os_str() != "-")
            || !input.git_url.is_empty()
            || input.has_repository_discovery()
            || !input.github_event_user.is_empty();
    if !has_git_scope {
        return Ok(());
    }
    writeln!(out, "\nGit scope")?;
    write_field(out, "History", input.git_history)?;
    if let Some(branch) = &input.branch {
        write_field(out, "Ref", branch)?;
    }
    if let Some(commit) = &input.since_commit {
        write_field(out, "Since commit", commit)?;
    }
    if let Some((start, end)) = input.history_time_range {
        write_field(
            out,
            "History timestamps",
            format_args!("{start} through {end} (Unix seconds)"),
        )?;
    } else if let Some(hours) = input.since_hours {
        write_field(out, "Recent history", format_args!("last {hours} hours"))?;
    }
    if let Some(commit) =
        input.branch_root_commit.as_ref().or(input.branch.as_ref().filter(|_| input.branch_root))
    {
        write_field(out, "Inclusive root", commit)?;
    }
    if input.staged {
        write_field(out, "Staged changes", "only")?;
    }
    write_field(out, "Nested repositories", yes_no(input.scan_nested_repos))?;
    write_field(out, "Repository artifacts", yes_no(input.repo_artifacts))?;
    if input.include_contributors {
        write_field(out, "Contributor repositories", "included")?;
    }
    if input.has_repository_discovery() || !input.git_url.is_empty() {
        write_field(out, "Clone mode", input.git_clone)?;
    }
    if let Some(limit) = input.repo_clone_limit.filter(|_| !args.content_filtering_args.no_limits) {
        write_field(out, "Repository clone limit", limit)?;
    }
    Ok(())
}

fn write_content_filters(out: &mut impl Write, args: &ScanArgs) -> io::Result<()> {
    let filters = &args.content_filtering_args;
    let paths = &filters.path_selection;
    writeln!(out, "\nFilters")?;
    write_field(out, "Minimum confidence", args.confidence)?;
    if let Some(entropy) = args.min_entropy {
        write_field(out, "Minimum entropy override", entropy)?;
    }
    for (label, values) in [
        ("Include prefixes", &paths.include_prefixes),
        ("Exclude prefixes", &paths.exclude_prefixes),
        ("Include extensions", &paths.include_extensions),
        ("Exclude extensions", &paths.exclude_extensions),
        ("Exclude globs", &filters.exclude),
    ] {
        if !values.is_empty() {
            write_field(out, label, values.join(", "))?;
        }
    }
    if filters.max_file_size_bytes().is_some() {
        write_field(out, "Maximum file size", format_args!("{} MB", filters.max_file_size_mb))?;
    } else {
        write_field(out, "Maximum file size", "unlimited")?;
    }
    write_field(out, "Binary files", if filters.no_binary { "excluded" } else { "included" })?;
    if filters.no_extract_archives {
        write_field(out, "Content extraction", "disabled")?;
    } else if let Some(depth) = filters.archive_depth() {
        write_field(out, "Archive extraction depth", depth)?;
    } else {
        write_field(out, "Archive extraction depth", "unlimited")?;
    }
    write_field(out, "Base64 decoding", yes_no(!args.no_base64 && !args.turbo))?;
    write_field(out, "Inline ignore directives", yes_no(!args.no_inline_ignore))?;
    write_field(out, "Rule-level substring ignores", yes_no(!args.no_ignore_if_contains))?;
    write_field(out, "Report findings", args.effective_validation_filter())?;
    if let Some(path) = &args.baseline_file {
        writeln!(out, "    Baseline  {:?}", path.as_os_str())?;
    } else if args.manage_baseline {
        write_field(out, "Baseline", "baseline-file.yaml")?;
    }
    for (label, len) in [
        ("Skip words", args.skip_word.len()),
        ("Skip regexes", args.skip_regex.len()),
        ("Additional ignore directives", args.extra_ignore_comments.len()),
        ("AWS account skips", args.skip_aws_account.len()),
    ] {
        if len > 0 {
            write_field(out, label, format_args!("{len} configured"))?;
        }
    }
    if args.skip_aws_account_file.is_some() {
        write_field(out, "AWS account skips file", "configured")?;
    }
    Ok(())
}

fn write_repo_scope(
    out: &mut impl Write,
    provider: &str,
    selectors: &[(&str, &[String])],
    all: Option<&str>,
    endpoint: &Url,
    repo_type: impl Display,
    excludes: &[String],
) -> io::Result<bool> {
    if !write_selectors(out, provider, selectors, all)? {
        return Ok(false);
    }
    write_field(out, "API URL", safe_url(endpoint))?;
    write_field(out, "Repository type", repo_type)?;
    write_selectors_list(out, "Exclude repositories", excludes)?;
    Ok(true)
}

fn write_selectors(
    out: &mut impl Write,
    provider: &str,
    selectors: &[(&str, &[String])],
    all: Option<&str>,
) -> io::Result<bool> {
    if all.is_none() && selectors.iter().all(|(_, values)| values.is_empty()) {
        return Ok(false);
    }
    writeln!(out, "  {provider}")?;
    if let Some(scope) = all {
        write_field(out, "Scope", scope)?;
    }
    for (label, values) in selectors {
        write_selectors_list(out, label, values)?;
    }
    Ok(true)
}

fn write_selectors_list(out: &mut impl Write, label: &str, values: &[String]) -> io::Result<()> {
    if !values.is_empty() {
        let selectors: Vec<_> = values.iter().map(|value| safe_identifier(value)).collect();
        write_field(out, label, selectors.join(", "))?;
    }
    Ok(())
}

fn write_search(
    out: &mut impl Write,
    provider: &str,
    endpoint: &Url,
    query_kind: &str,
    max_results: usize,
) -> io::Result<()> {
    writeln!(out, "  {provider}")?;
    write_field(out, "API URL", safe_url(endpoint))?;
    // Free-form provider queries can include the credential being searched for.
    write_field(out, query_kind, "configured")?;
    write_result_limit(out, max_results)
}

fn write_result_limit(out: &mut impl Write, max_results: usize) -> io::Result<()> {
    if max_results == UNLIMITED_RESULTS {
        write_field(out, "Maximum results", "unlimited")
    } else {
        write_field(out, "Maximum results", max_results)
    }
}

fn write_field(out: &mut impl Write, label: &str, value: impl Display) -> io::Result<()> {
    writeln!(out, "    {label}  {}", value.to_string().escape_debug())
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn safe_identifier(raw: &str) -> Cow<'_, str> {
    let trimmed = raw.trim();
    if let Some((kind, target)) = trimmed.split_once(':')
        && matches!(kind, "model" | "dataset" | "space" | "bucket")
        && target.contains("://")
    {
        return Cow::Owned(format!("{kind}:{}", safe_url_text(target.trim())));
    }
    if trimmed.contains("://") { safe_url_text(trimmed) } else { Cow::Borrowed(raw) }
}

fn safe_url_text(raw: &str) -> Cow<'static, str> {
    Url::parse(raw).map_or(Cow::Borrowed("[invalid URL]"), |url| safe_url(&url))
}

fn safe_url(url: &Url) -> Cow<'static, str> {
    let mut url = url.clone();
    if !url.has_host() || url.set_username("").is_err() || url.set_password(None).is_err() {
        return Cow::Borrowed("[unsupported URL]");
    }
    url.set_query(None);
    url.set_fragment(None);
    Cow::Owned(url.into())
}

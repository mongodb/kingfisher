use anyhow::bail;
use clap::{Args, Subcommand, ValueEnum, ValueHint};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
};
use strum::Display;
use tracing::debug;
use url::Url;

use crate::{
    cli::{
        commands::{
            azure::AzureRepoSpecifiers,
            bitbucket::BitbucketRepoSpecifiers,
            gitea::GiteaRepoSpecifiers,
            github::GitHubRepoSpecifiers,
            gitlab::GitLabRepoSpecifiers,
            huggingface::HuggingFaceRepoSpecifiers,
            inputs::{ContentFilteringArgs, InputSpecifierArgs},
            output::{OutputArgs, ReportOutputFormat},
            rules::{RuleCacheArgs, RuleSpecifierArgs},
            view,
        },
        global::RAM_GB,
    },
    git_url::GitUrl,
    rules::rule::Confidence,
};

/// Determine the default number of parallel scan jobs.
///
/// * Target = `available_parallelism * 2`.
/// * Cap by RAM at ≈ 1 GiB per job (so 16 GiB ⇒ max 16 jobs).
/// * Always ≥ 1.
/// * When `-v/--verbose` is passed, the computed value is logged at DEBUG.
fn default_scan_jobs() -> usize {
    // How many logical CPUs do we see? (Falls back to 1 on error.)
    let cpu_count = std::thread::available_parallelism().map(usize::from).unwrap_or(1);

    // Desired parallelism is CPU * 2.
    let desired = cpu_count * 2;

    match *RAM_GB {
        // If we know how much RAM we have, cap by a 1 GiB-per-job heuristic.
        Some(ram_gb) => {
            let max_by_ram = ram_gb.ceil() as usize; // 1 GiB per job
            let jobs = desired.min(max_by_ram).max(1);

            debug!(
                "Using {jobs} parallel scan jobs \
                 (cpus = {cpu_count}, desired = {desired}, \
                 ram = {ram_gb:.1} GiB, cap_by_ram = {max_by_ram})"
            );
            jobs
        }
        // If RAM is unknown, just use the desired value.
        None => {
            debug!("Using {desired} parallel scan jobs (cpus = {cpu_count}, ram unknown)");
            desired
        }
    }
}

/// `kingfisher scan` command and flags
#[derive(Args, Debug, Clone)]
pub struct ScanArgs {
    /// Number of parallel scanning threads
    #[arg(global = true, long = "jobs", short = 'j', default_value_t = default_scan_jobs())]
    pub num_jobs: usize,

    #[command(flatten)]
    pub rules: RuleSpecifierArgs,

    #[command(flatten)]
    pub rule_cache: RuleCacheArgs,

    #[command(flatten)]
    pub input_specifier_args: InputSpecifierArgs,

    #[command(flatten)]
    pub content_filtering_args: ContentFilteringArgs,

    /// Minimum confidence level for reporting findings
    #[arg(global = true, long, short = 'c', default_value = "medium")]
    pub confidence: ConfidenceLevel,

    /// Disable secret validation
    #[arg(global = true, long, short = 'n', default_value_t = false)]
    pub no_validate: bool,

    /// Timeout for validation requests in seconds (1-60)
    #[arg(
        global = true,
        long = "validation-timeout",
        default_value_t = 10,
        value_name = "SECONDS",
        value_parser = clap::value_parser!(u64).range(1..=60)
    )]
    pub validation_timeout: u64,

    /// Number of retries for validation requests (0-5)
    #[arg(
        global = true,
        long = "validation-retries",
        default_value_t = 1,
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(0..=5)
    )]
    pub validation_retries: u32,

    /// Global validation request rate limit in requests per second
    #[arg(global = true, long = "validation-rps", value_name = "RPS")]
    pub validation_rps: Option<f64>,

    /// Rule-scoped validation request rate limit (RULE_SELECTOR=RPS), repeatable
    #[arg(global = true, long = "validation-rps-rule", value_name = "RULE_SELECTOR=RPS")]
    pub validation_rps_rule: Vec<String>,

    /// Include full validation response bodies without truncation
    #[arg(global = true, long, default_value_t = false)]
    pub full_validation_response: bool,

    /// Maximum bytes to store from validation response bodies (0 = unlimited).
    /// Overridden by --full-validation-response which forces unlimited storage.
    #[arg(
        global = true,
        long = "max-validation-response-length",
        default_value_t = 2048,
        value_name = "BYTES"
    )]
    pub max_validation_response_length: usize,

    /// Map validated cloud credentials to their effective identities; use only when
    /// authorized for the target account because this triggers additional network
    /// requests to determine granted access
    #[arg(global = true, long, alias = "blast-radius", default_value_t = false)]
    pub access_map: bool,

    // /// Optional path to write a consolidated access-map HTML report
    // #[arg(long, value_name = "PATH")]
    // pub access_map_html: Option<PathBuf>,
    /// Display only validated findings
    #[arg(global = true, long, default_value_t = false)]
    pub only_valid: bool,

    /// Override the default minimum entropy threshold
    #[arg(global = true, long, short = 'e')]
    pub min_entropy: Option<f32>,

    /// Show performance statistics for each rule
    #[arg(global = true, long, default_value_t = false)]
    pub rule_stats: bool,

    /// Display every occurrence of a finding
    #[arg(global = true, long, default_value_t = false)]
    pub no_dedup: bool,

    /// Serve a JSON report locally and open the browser (http://127.0.0.1:7890)
    #[arg(skip)]
    pub view_report: bool,

    /// Redact findings values using a secure hash
    #[arg(global = true, long, short = 'r', default_value_t = false)]
    pub redact: bool,

    /// Skip decoding Base64 blobs before scanning
    #[arg(global = true, long, default_value_t = false)]
    pub no_base64: bool,

    /// Turbo mode: equivalent to --commit-metadata=false --no-base64 and disables MIME sniffing, language detection, and parser-based context verification
    #[arg(global = true, long = "turbo", default_value_t = false)]
    pub turbo: bool,

    /// Timeout for Git repository scanning in seconds
    #[arg(global = true, long, default_value_t = 1800, value_name = "SECONDS")]
    pub git_repo_timeout: u64,

    #[command(flatten)]
    pub output_args: OutputArgs<ReportOutputFormat>,

    /// Baseline file to filter known secrets
    #[arg(global = true, long, value_name = "FILE")]
    pub baseline_file: Option<std::path::PathBuf>,

    /// Create or update the baseline file with current findings
    #[arg(global = true, long, default_value_t = false)]
    pub manage_baseline: bool,

    /// Regex patterns to allow-list secret matches (repeatable)
    #[arg(global = true, long = "skip-regex", value_name = "PATTERN")]
    pub skip_regex: Vec<String>,

    /// Skipwords to allow-list secret matches (case-insensitive, repeatable)
    #[arg(global = true, long = "skip-word", value_name = "WORD")]
    pub skip_word: Vec<String>,

    /// AWS account IDs whose findings should skip live credential validation (repeatable)
    #[arg(
        global = true,
        long = "skip-aws-account",
        value_name = "ACCOUNT_ID",
        value_delimiter = ','
    )]
    pub skip_aws_account: Vec<String>,

    /// File containing AWS account IDs to skip (one per line, `#` comments ignored)
    #[arg(global = true, long = "skip-aws-account-file", value_name = "FILE")]
    pub skip_aws_account_file: Option<PathBuf>,

    /// Additional inline ignore directives to recognise (repeatable)
    #[arg(global = true, long = "ignore-comment", value_name = "DIRECTIVE")]
    pub extra_ignore_comments: Vec<String>,

    /// Disable inline ignore directives entirely
    #[arg(global = true, long = "no-ignore", default_value_t = false)]
    pub no_inline_ignore: bool,

    /// Disable rule-level `ignore_if_contains` filtering for pattern requirements
    #[arg(global = true, long = "no-ignore-if-contains", default_value_t = false)]
    pub no_ignore_if_contains: bool,

    #[arg(skip)]
    pub view_report_port: u16,
    #[arg(skip)]
    pub view_report_address: String,

    /// POST scan results to a webhook URL when scanning completes (repeatable).
    /// Use multiple `--alert-webhook` flags to fan out to several destinations.
    #[arg(global = true, long = "alert-webhook", value_name = "URL")]
    pub alert_webhook: Vec<String>,

    /// Format for `--alert-webhook` payloads. Default is inferred from the URL
    /// host (slack.com → slack, *.office.com → teams, discord.com → discord,
    /// chat.googleapis.com → googlechat, otherwise generic). Mattermost is
    /// self-hosted and never inferred — pass `--alert-format mattermost`
    /// explicitly.
    #[arg(global = true, long = "alert-format", value_name = "FORMAT")]
    pub alert_format: Option<crate::alerts::AlertFormat>,

    /// When to post alerts: only when there are findings, or always.
    #[arg(global = true, long = "alert-on", value_name = "MODE", default_value = "findings")]
    pub alert_on: crate::alerts::AlertOn,

    /// Minimum confidence required for a finding to be included in alert payloads.
    #[arg(
        global = true,
        long = "alert-min-confidence",
        value_name = "LEVEL",
        default_value = "medium"
    )]
    pub alert_min_confidence: ConfidenceLevel,

    /// Include the (possibly truncated) secret value in alert payloads.
    /// Off by default; on, the snippet is truncated to ~32 chars.
    #[arg(global = true, long = "alert-include-secret", default_value_t = false)]
    pub alert_include_secret: bool,

    /// Pivot link rendered in the payload — typically the URL of the full
    /// scan report (CI run, S3 object, SARIF in Code Scanning, etc.). When
    /// present, every alert payload includes a "Full report" link, which is
    /// the right place to send operators who hit the truncated finding cap.
    /// Falls back to env var `KINGFISHER_ALERT_REPORT_URL` if unset.
    #[arg(
        global = true,
        long = "alert-report-url",
        value_name = "URL",
        env = "KINGFISHER_ALERT_REPORT_URL"
    )]
    pub alert_report_url: Option<String>,

    /// How much per-finding detail to include in alert payloads. `auto`
    /// (default) shows up to 10 findings inline, but switches to a
    /// summary-only payload once the per-sink filtered finding count exceeds
    /// 25 — at that volume, chat detail blocks add noise and the operator
    /// should be pivoting to the full report instead.
    #[arg(global = true, long = "alert-detail", value_name = "MODE", default_value = "auto")]
    pub alert_detail: crate::alerts::AlertDetail,

    /// Per-webhook overrides loaded from `kingfisher.yaml`. Indexed in lockstep
    /// with `alert_webhook` for the trailing config-sourced URLs. Not parsed
    /// from the CLI; populated by `apply_config` in main.rs.
    #[arg(skip)]
    pub config_webhook_overrides: Vec<ConfigWebhookOverride>,
}

/// Override values for a webhook entry that came from the config file.
/// Each field that is `None` falls back to the corresponding `--alert-*` CLI
/// flag's value.
#[derive(Debug, Clone, Default)]
pub struct ConfigWebhookOverride {
    pub format: Option<crate::alerts::AlertFormat>,
    pub on: Option<crate::alerts::AlertOn>,
    pub min_confidence: Option<ConfidenceLevel>,
    pub include_secret: Option<bool>,
    pub report_url: Option<String>,
    pub detail: Option<crate::alerts::AlertDetail>,
}

/// Confidence levels for findings
#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

impl From<ConfidenceLevel> for Confidence {
    fn from(level: ConfidenceLevel) -> Self {
        match level {
            ConfidenceLevel::Low => Confidence::Low,
            ConfidenceLevel::Medium => Confidence::Medium,
            ConfidenceLevel::High => Confidence::High,
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct ScanCommandArgs {
    #[command(flatten)]
    pub scan_args: ScanArgs,

    /// Serve a JSON report locally and open the browser (http://127.0.0.1:7890)
    #[arg(global = true, long = "view-report", default_value_t = false)]
    pub view_report: bool,

    /// Port for the report viewer when using --view-report (default 7890)
    #[arg(
        global = true,
        long = "view-report-port",
        default_value_t = view::DEFAULT_PORT,
        value_name = "PORT"
    )]
    pub view_report_port: u16,

    /// Bind address for the report viewer when using --view-report (default 127.0.0.1). Use 0.0.0.0 to allow access from Docker or other hosts.
    #[arg(
        global = true,
        long = "view-report-address",
        default_value = view::DEFAULT_ADDRESS,
        value_name = "ADDRESS"
    )]
    pub view_report_address: String,

    #[command(subcommand)]
    pub provider: Option<ScanInputCommand>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ScanOperation {
    Scan(ScanArgs),
    ListRepositories(ListRepositoriesCommand),
}

#[derive(Debug)]
pub enum ListRepositoriesCommand {
    Github { api_url: Url, specifiers: GitHubRepoSpecifiers },
    Gitlab { api_url: Url, specifiers: GitLabRepoSpecifiers },
    Gitea { api_url: Url, specifiers: GiteaRepoSpecifiers },
    Bitbucket { api_url: Url, specifiers: BitbucketRepoSpecifiers },
    Azure { base_url: Url, specifiers: AzureRepoSpecifiers },
    Huggingface { specifiers: HuggingFaceRepoSpecifiers },
}

impl ScanCommandArgs {
    fn infer_positional_git_urls(&mut self) {
        let mut inferred_git_urls = Vec::new();
        let mut retained_paths = Vec::new();

        for path in self.scan_args.input_specifier_args.path_inputs.drain(..) {
            if path.as_path() == Path::new("-") || path.exists() {
                retained_paths.push(path);
                continue;
            }

            if let Some(git_url) = parse_git_url_target(&path) {
                inferred_git_urls.push(git_url);
            } else {
                retained_paths.push(path);
            }
        }

        self.scan_args.input_specifier_args.path_inputs = retained_paths;
        self.scan_args.input_specifier_args.git_url.extend(inferred_git_urls);
    }

    /// Convert CLI arguments into a scan or repository-listing operation.
    pub fn into_operation(mut self) -> anyhow::Result<ScanOperation> {
        let mut used_provider_subcommand = false;

        self.scan_args.view_report = self.view_report;
        self.scan_args.view_report_port = self.view_report_port;
        self.scan_args.view_report_address = self.view_report_address.clone();

        if let Some(provider) = self.provider.take() {
            used_provider_subcommand = true;
            let scan_args = &mut self.scan_args;
            let maybe_list = match provider {
                ScanInputCommand::Filesystem(args) => {
                    if args.paths.is_empty() {
                        bail!("Provide at least one path when using the filesystem subcommand");
                    }
                    scan_args.input_specifier_args.path_inputs = args.paths;
                    scan_args.input_specifier_args.git_url = args.git_url;
                    None
                }
                ScanInputCommand::Github(args) => {
                    if args.specifiers.is_empty() {
                        bail!(
                            "You must specify at least one --user, --org, or use --all-orgs when scanning GitHub"
                        );
                    }
                    if args.list_only {
                        Some(ListRepositoriesCommand::Github {
                            api_url: args.api_url,
                            specifiers: args.specifiers,
                        })
                    } else {
                        scan_args.input_specifier_args.github_user = args.specifiers.user;
                        scan_args.input_specifier_args.github_organization =
                            args.specifiers.organization;
                        scan_args.input_specifier_args.github_exclude =
                            args.specifiers.exclude_repos;
                        scan_args.input_specifier_args.all_github_organizations =
                            args.specifiers.all_organizations;
                        scan_args.input_specifier_args.github_repo_type = args.specifiers.repo_type;
                        scan_args.input_specifier_args.github_api_url = args.api_url;
                        scan_args.input_specifier_args.repo_clone_limit = args.repo_clone_limit;
                        scan_args.input_specifier_args.include_contributors =
                            args.include_contributors;
                        None
                    }
                }
                ScanInputCommand::Gitlab(args) => {
                    if args.specifiers.is_empty() {
                        bail!(
                            "You must specify at least one --user, --group, or use --all-groups when scanning GitLab"
                        );
                    }
                    if args.list_only {
                        Some(ListRepositoriesCommand::Gitlab {
                            api_url: args.api_url,
                            specifiers: args.specifiers,
                        })
                    } else {
                        scan_args.input_specifier_args.gitlab_user = args.specifiers.user;
                        scan_args.input_specifier_args.gitlab_group = args.specifiers.group;
                        scan_args.input_specifier_args.gitlab_exclude =
                            args.specifiers.exclude_repos;
                        scan_args.input_specifier_args.all_gitlab_groups =
                            args.specifiers.all_groups;
                        scan_args.input_specifier_args.gitlab_include_subgroups =
                            args.specifiers.include_subgroups;
                        scan_args.input_specifier_args.gitlab_repo_type = args.specifiers.repo_type;
                        scan_args.input_specifier_args.gitlab_api_url = args.api_url;
                        scan_args.input_specifier_args.repo_clone_limit = args.repo_clone_limit;
                        scan_args.input_specifier_args.include_contributors =
                            args.include_contributors;
                        None
                    }
                }
                ScanInputCommand::Gitea(args) => {
                    if args.specifiers.is_empty() {
                        bail!(
                            "Specify at least one --user, --org, or use --all-orgs when scanning Gitea"
                        );
                    }
                    if args.list_only {
                        Some(ListRepositoriesCommand::Gitea {
                            api_url: args.api_url,
                            specifiers: args.specifiers,
                        })
                    } else {
                        scan_args.input_specifier_args.gitea_user = args.specifiers.user;
                        scan_args.input_specifier_args.gitea_organization =
                            args.specifiers.organization;
                        scan_args.input_specifier_args.gitea_exclude =
                            args.specifiers.exclude_repos;
                        scan_args.input_specifier_args.all_gitea_organizations =
                            args.specifiers.all_organizations;
                        scan_args.input_specifier_args.gitea_repo_type = args.specifiers.repo_type;
                        scan_args.input_specifier_args.gitea_api_url = args.api_url;
                        None
                    }
                }
                ScanInputCommand::Bitbucket(args) => {
                    if args.specifiers.is_empty() {
                        bail!(
                            "You must specify at least one --user, --workspace, --project, or use --all-workspaces when scanning Bitbucket"
                        );
                    }
                    if args.list_only {
                        Some(ListRepositoriesCommand::Bitbucket {
                            api_url: args.api_url,
                            specifiers: args.specifiers,
                        })
                    } else {
                        scan_args.input_specifier_args.bitbucket_user = args.specifiers.user;
                        scan_args.input_specifier_args.bitbucket_workspace =
                            args.specifiers.workspace;
                        scan_args.input_specifier_args.bitbucket_project = args.specifiers.project;
                        scan_args.input_specifier_args.bitbucket_exclude =
                            args.specifiers.exclude_repos;
                        scan_args.input_specifier_args.all_bitbucket_workspaces =
                            args.specifiers.all_workspaces;
                        scan_args.input_specifier_args.bitbucket_repo_type =
                            args.specifiers.repo_type;
                        scan_args.input_specifier_args.bitbucket_api_url = args.api_url;
                        None
                    }
                }
                ScanInputCommand::Azure(args) => {
                    if args.specifiers.is_empty() {
                        bail!(
                            "You must specify at least one --organization, --project, or use --all-projects when scanning Azure DevOps"
                        );
                    }
                    if args.list_only {
                        Some(ListRepositoriesCommand::Azure {
                            base_url: args.base_url,
                            specifiers: args.specifiers,
                        })
                    } else {
                        scan_args.input_specifier_args.azure_organization =
                            args.specifiers.organization;
                        scan_args.input_specifier_args.azure_project = args.specifiers.project;
                        scan_args.input_specifier_args.azure_exclude =
                            args.specifiers.exclude_repos;
                        scan_args.input_specifier_args.all_azure_projects =
                            args.specifiers.all_projects;
                        scan_args.input_specifier_args.azure_repo_type = args.specifiers.repo_type;
                        scan_args.input_specifier_args.azure_base_url = args.base_url;
                        None
                    }
                }
                ScanInputCommand::Huggingface(args) => {
                    if args.specifiers.is_empty() {
                        bail!(
                            "You must specify at least one --user, --org, --model, --dataset, or --space when scanning Hugging Face"
                        );
                    }
                    if args.list_only {
                        Some(ListRepositoriesCommand::Huggingface { specifiers: args.specifiers })
                    } else {
                        scan_args.input_specifier_args.huggingface_user = args.specifiers.user;
                        scan_args.input_specifier_args.huggingface_organization =
                            args.specifiers.organization;
                        scan_args.input_specifier_args.huggingface_model = args.specifiers.model;
                        scan_args.input_specifier_args.huggingface_dataset =
                            args.specifiers.dataset;
                        scan_args.input_specifier_args.huggingface_space = args.specifiers.space;
                        scan_args.input_specifier_args.huggingface_exclude =
                            args.specifiers.exclude;
                        None
                    }
                }
                ScanInputCommand::Slack(args) => {
                    scan_args.input_specifier_args.slack_query = Some(args.query);
                    scan_args.input_specifier_args.slack_api_url = args.api_url;
                    scan_args.input_specifier_args.max_results = args.max_results;
                    None
                }
                ScanInputCommand::Teams(args) => {
                    scan_args.input_specifier_args.teams_query = Some(args.query);
                    scan_args.input_specifier_args.teams_api_url = args.api_url;
                    scan_args.input_specifier_args.max_results = args.max_results;
                    None
                }
                ScanInputCommand::Jira(args) => {
                    scan_args.input_specifier_args.jira_url = Some(args.url);
                    scan_args.input_specifier_args.jql = Some(args.jql);
                    scan_args.input_specifier_args.max_results = args.max_results;
                    scan_args.input_specifier_args.jira_include_comments = args.include_comments;
                    scan_args.input_specifier_args.jira_include_changelog = args.include_changelog;
                    None
                }
                ScanInputCommand::Confluence(args) => {
                    scan_args.input_specifier_args.confluence_url = Some(args.url);
                    scan_args.input_specifier_args.cql = Some(args.cql);
                    scan_args.input_specifier_args.max_results = args.max_results;
                    None
                }
                ScanInputCommand::Postman(args) => {
                    if !args.all
                        && args.workspaces.is_empty()
                        && args.collections.is_empty()
                        && args.environments.is_empty()
                    {
                        bail!(
                            "Specify --workspace, --collection, --environment, or --all when using the postman subcommand"
                        );
                    }
                    scan_args.input_specifier_args.postman_workspaces = args.workspaces;
                    scan_args.input_specifier_args.postman_collections = args.collections;
                    scan_args.input_specifier_args.postman_environments = args.environments;
                    scan_args.input_specifier_args.postman_all = args.all;
                    scan_args.input_specifier_args.postman_include_mocks_monitors =
                        args.include_mocks_monitors;
                    scan_args.input_specifier_args.postman_api_url = args.api_url;
                    scan_args.input_specifier_args.max_results = args.max_results;
                    None
                }
                ScanInputCommand::S3(args) => {
                    scan_args.input_specifier_args.s3_bucket = Some(args.bucket);
                    scan_args.input_specifier_args.s3_prefix = args.prefix;
                    scan_args.input_specifier_args.role_arn = args.role_arn;
                    scan_args.input_specifier_args.aws_local_profile = args.profile;
                    None
                }
                ScanInputCommand::Gcs(args) => {
                    scan_args.input_specifier_args.gcs_bucket = Some(args.bucket);
                    scan_args.input_specifier_args.gcs_prefix = args.prefix;
                    scan_args.input_specifier_args.gcs_service_account = args.service_account;
                    None
                }
                ScanInputCommand::Docker(args) => {
                    if args.images.is_empty() && args.archives.is_empty() {
                        bail!(
                            "Provide at least one image or --archive path when using the docker subcommand"
                        );
                    }
                    scan_args.input_specifier_args.docker_image = args.images;
                    scan_args.input_specifier_args.docker_archive = args.archives;
                    None
                }
            };

            if let Some(list_command) = maybe_list {
                return Ok(ScanOperation::ListRepositories(list_command));
            }
        }

        let used_legacy_git_url_flag = !self.scan_args.input_specifier_args.git_url.is_empty();
        self.infer_positional_git_urls();

        if !self.scan_args.input_specifier_args.has_any_input() {
            bail!(
                "Specify a path or Git URL (for example: 'kingfisher scan github.com/org/repo'), or use a provider subcommand such as 'kingfisher scan github'"
            );
        }

        for path in &self.scan_args.input_specifier_args.path_inputs {
            if path.as_path() == Path::new("-") {
                continue;
            }

            if !path.exists() {
                bail!("Error: unrecognized scan target or path does not exist: {}", path.display());
            }
        }

        if !used_provider_subcommand {
            self.scan_args.input_specifier_args.emit_deprecated_warnings(used_legacy_git_url_flag);
        }

        if self.scan_args.manage_baseline {
            self.scan_args.no_dedup = true;
        }

        if self.scan_args.turbo {
            self.scan_args.no_base64 = true;
            self.scan_args.input_specifier_args.commit_metadata = false;
        }

        if self.scan_args.access_map && self.scan_args.no_validate {
            bail!("--access-map cannot be used with --no-validate");
        }

        Ok(ScanOperation::Scan(self.scan_args))
    }
}

fn parse_git_url_target(path: &Path) -> Option<GitUrl> {
    let raw = path.to_str()?.trim();
    if raw.is_empty() || raw == "-" || raw.contains('\\') {
        return None;
    }

    if let Ok(url) = GitUrl::from_str(raw) {
        return Some(url);
    }

    if raw.contains("://")
        || raw.starts_with('/')
        || raw.starts_with("./")
        || raw.starts_with("../")
        || raw.starts_with('~')
    {
        return None;
    }

    let (host, suffix) = raw.split_once('/')?;
    if host.is_empty() || suffix.is_empty() {
        return None;
    }

    let path_segments = suffix.split('/').filter(|segment| !segment.is_empty()).count();
    if path_segments < 2 {
        return None;
    }

    let host_looks_valid =
        host.contains('.') || host == "localhost" || host.parse::<IpAddr>().is_ok();
    if !host_looks_valid {
        return None;
    }

    GitUrl::from_str(&format!("https://{raw}")).ok()
}

#[derive(Subcommand, Debug, Clone)]
pub enum ScanInputCommand {
    /// Scan local files, directories, or Git repositories
    #[command(hide = true)]
    Filesystem(FilesystemScanArgs),

    /// Enumerate and scan GitHub repositories
    Github(GithubScanArgs),

    /// Enumerate and scan GitLab repositories
    Gitlab(GitLabScanArgs),

    /// Enumerate and scan Gitea repositories
    Gitea(GiteaScanArgs),

    /// Enumerate and scan Bitbucket repositories
    Bitbucket(BitbucketScanArgs),

    /// Enumerate and scan Azure DevOps repositories
    Azure(AzureScanArgs),

    /// Enumerate and scan Hugging Face repositories
    Huggingface(HuggingfaceScanArgs),

    /// Scan Slack search results
    Slack(SlackScanArgs),

    /// Scan Microsoft Teams messages via Microsoft Graph
    Teams(TeamsScanArgs),

    /// Scan Jira issues using JQL
    Jira(JiraScanArgs),

    /// Scan Confluence content using CQL
    Confluence(ConfluenceScanArgs),

    /// Scan Postman workspaces, collections, and environments
    Postman(PostmanScanArgs),

    /// Scan an S3 bucket
    S3(S3ScanArgs),

    /// Scan a Google Cloud Storage bucket
    Gcs(GcsScanArgs),

    /// Scan Docker or OCI images
    Docker(DockerScanArgs),
}

#[derive(Args, Debug, Clone, Default)]
pub struct FilesystemScanArgs {
    /// Files, directories, or '-' for stdin
    #[arg(value_name = "PATH", value_hint = ValueHint::AnyPath)]
    pub paths: Vec<PathBuf>,

    /// Deprecated: git repository URLs to clone and scan. Prefer positional targets.
    #[arg(long = "git-url", value_hint = ValueHint::Url)]
    pub git_url: Vec<GitUrl>,
}

#[derive(Args, Debug, Clone)]
pub struct GithubScanArgs {
    #[command(flatten)]
    pub specifiers: GitHubRepoSpecifiers,

    /// Include contributor repositories when scanning git URLs
    #[arg(long = "include-contributors", default_value_t = false)]
    pub include_contributors: bool,

    /// Limit the number of repositories cloned (including contributor repos)
    #[arg(long = "repo-clone-limit", value_name = "COUNT")]
    pub repo_clone_limit: Option<usize>,

    /// List matching repositories without scanning them
    #[arg(long = "list-only")]
    pub list_only: bool,

    /// Override the GitHub API URL (e.g. Enterprise)
    #[arg(
        long = "api-url",
        alias = "github-api-url",
        default_value = "https://api.github.com/",
        value_hint = ValueHint::Url
    )]
    pub api_url: Url,
}

#[derive(Args, Debug, Clone)]
pub struct GitLabScanArgs {
    #[command(flatten)]
    pub specifiers: GitLabRepoSpecifiers,

    /// Include contributor repositories when scanning git URLs
    #[arg(long = "include-contributors", default_value_t = false)]
    pub include_contributors: bool,

    /// Limit the number of repositories cloned (including contributor repos)
    #[arg(long = "repo-clone-limit", value_name = "COUNT")]
    pub repo_clone_limit: Option<usize>,

    /// List matching repositories without scanning them
    #[arg(long = "list-only")]
    pub list_only: bool,

    /// Override the GitLab API URL (e.g. self-hosted)
    #[arg(
        long = "api-url",
        alias = "gitlab-api-url",
        default_value = "https://gitlab.com/",
        value_hint = ValueHint::Url
    )]
    pub api_url: Url,
}

#[derive(Args, Debug, Clone)]
pub struct GiteaScanArgs {
    #[command(flatten)]
    pub specifiers: GiteaRepoSpecifiers,

    /// List matching repositories without scanning them
    #[arg(long = "list-only")]
    pub list_only: bool,

    /// Override the Gitea API URL (e.g. self-hosted)
    #[arg(
        long = "api-url",
        alias = "gitea-api-url",
        default_value = "https://gitea.com/api/v1/",
        value_hint = ValueHint::Url
    )]
    pub api_url: Url,
}

#[derive(Args, Debug, Clone)]
pub struct BitbucketScanArgs {
    #[command(flatten)]
    pub specifiers: BitbucketRepoSpecifiers,

    /// List matching repositories without scanning them
    #[arg(long = "list-only")]
    pub list_only: bool,

    /// Override the Bitbucket API URL (Cloud or self-hosted)
    #[arg(
        long = "api-url",
        alias = "bitbucket-api-url",
        default_value = "https://api.bitbucket.org/2.0/",
        value_hint = ValueHint::Url
    )]
    pub api_url: Url,
}

#[derive(Args, Debug, Clone)]
pub struct AzureScanArgs {
    #[command(flatten)]
    pub specifiers: AzureRepoSpecifiers,

    /// List matching repositories without scanning them
    #[arg(long = "list-only")]
    pub list_only: bool,

    /// Override the Azure DevOps base URL
    #[arg(
        long = "base-url",
        alias = "azure-base-url",
        default_value = "https://dev.azure.com/",
        value_hint = ValueHint::Url
    )]
    pub base_url: Url,
}

#[derive(Args, Debug, Clone, Default)]
pub struct HuggingfaceScanArgs {
    #[command(flatten)]
    pub specifiers: HuggingFaceRepoSpecifiers,

    /// List matching repositories without scanning them
    #[arg(long = "list-only")]
    pub list_only: bool,
}

#[derive(Args, Debug, Clone)]
pub struct SlackScanArgs {
    /// Slack search query
    #[arg(value_name = "QUERY")]
    pub query: String,

    /// Override the Slack API URL
    #[arg(
        long = "api-url",
        alias = "slack-api-url",
        default_value = "https://slack.com/api/",
        value_hint = ValueHint::Url
    )]
    pub api_url: Url,

    /// Maximum number of results to fetch
    #[arg(long = "max-results", default_value_t = 100)]
    pub max_results: usize,
}

#[derive(Args, Debug, Clone)]
pub struct TeamsScanArgs {
    /// Microsoft Teams search query
    #[arg(value_name = "QUERY")]
    pub query: String,

    /// Override the Microsoft Graph API URL
    #[arg(
        long = "api-url",
        alias = "teams-api-url",
        default_value = "https://graph.microsoft.com/",
        value_hint = ValueHint::Url
    )]
    pub api_url: Url,

    /// Maximum number of results to fetch
    #[arg(long = "max-results", default_value_t = 100)]
    pub max_results: usize,
}

#[derive(Args, Debug, Clone)]
pub struct JiraScanArgs {
    /// Jira base URL
    #[arg(long = "url", alias = "jira-url", value_hint = ValueHint::Url)]
    pub url: Url,

    /// JQL query to select Jira issues
    #[arg(long, alias = "jql")]
    pub jql: String,

    /// Maximum number of Jira issues to fetch
    #[arg(long = "max-results", default_value_t = 100)]
    pub max_results: usize,

    /// Include Jira issue comments in the scan
    #[arg(long = "include-comments", default_value_t = false)]
    pub include_comments: bool,

    /// Include Jira issue changelog entries in the scan
    #[arg(long = "include-changelog", default_value_t = false)]
    pub include_changelog: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ConfluenceScanArgs {
    /// Confluence base URL
    #[arg(long = "url", alias = "confluence-url", value_hint = ValueHint::Url)]
    pub url: Url,

    /// CQL query to select Confluence content
    #[arg(long, alias = "cql")]
    pub cql: String,

    /// Maximum number of results to fetch
    #[arg(long = "max-results", default_value_t = 100)]
    pub max_results: usize,
}

#[derive(Args, Debug, Clone)]
pub struct PostmanScanArgs {
    /// Scan a Postman workspace by ID or web URL (repeatable)
    #[arg(long = "workspace", alias = "postman-workspace", value_name = "ID_OR_URL")]
    pub workspaces: Vec<String>,

    /// Scan a single Postman collection by UID or web URL (repeatable)
    #[arg(long = "collection", alias = "postman-collection", value_name = "UID_OR_URL")]
    pub collections: Vec<String>,

    /// Scan a single Postman environment by UID (repeatable)
    #[arg(long = "environment", alias = "postman-environment", value_name = "UID")]
    pub environments: Vec<String>,

    /// Scan every workspace, collection, and environment visible to the API key
    #[arg(
        long = "all",
        alias = "postman-all",
        conflicts_with_all = ["workspaces", "collections", "environments"],
    )]
    pub all: bool,

    /// Include Postman mocks and monitors when scanning a workspace (off by default)
    #[arg(long = "include-mocks-monitors", alias = "postman-include-mocks-monitors")]
    pub include_mocks_monitors: bool,

    /// Override the Postman API base URL
    #[arg(
        long = "api-url",
        alias = "postman-api-url",
        default_value = "https://api.getpostman.com/",
        value_hint = ValueHint::Url,
    )]
    pub api_url: Url,

    /// Maximum number of resources to fetch
    #[arg(long = "max-results", default_value_t = 100)]
    pub max_results: usize,
}

#[derive(Args, Debug, Clone)]
pub struct S3ScanArgs {
    /// S3 bucket to scan
    #[arg(value_name = "BUCKET")]
    pub bucket: String,

    /// Optional prefix within the bucket
    #[arg(long = "prefix", alias = "s3-prefix")]
    pub prefix: Option<String>,

    /// AWS IAM role ARN to assume
    #[arg(long = "role-arn")]
    pub role_arn: Option<String>,

    /// AWS profile name to use for credentials
    #[arg(long = "profile", alias = "aws-local-profile")]
    pub profile: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct GcsScanArgs {
    /// Google Cloud Storage bucket to scan
    #[arg(value_name = "BUCKET")]
    pub bucket: String,

    /// Optional prefix within the bucket
    #[arg(long = "prefix", alias = "gcs-prefix")]
    pub prefix: Option<String>,

    /// Service account JSON file for authentication
    #[arg(long = "service-account", alias = "gcs-service-account", value_hint = ValueHint::FilePath)]
    pub service_account: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct DockerScanArgs {
    /// Docker or OCI images to scan
    #[arg(value_name = "IMAGE")]
    pub images: Vec<String>,

    /// Docker image archive files to scan, such as files produced by docker save
    #[arg(long = "archive", value_name = "PATH", value_hint = ValueHint::FilePath)]
    pub archives: Vec<PathBuf>,
}

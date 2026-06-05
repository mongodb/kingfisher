# Changelog

All notable changes to this project will be documented in this file.

## [v1.102.0]
- Security: hardened ASAR and in-memory archive extraction to skip traversal or absolute entry paths before writing to the temp extraction directory.
- Security: git clone provider tokens (`KF_GITHUB_TOKEN`, `KF_GITLAB_TOKEN`, `KF_GITEA_TOKEN`, `KF_AZURE_TOKEN`, `KF_HUGGINGFACE_TOKEN`) are now installed as host-scoped, HTTPS-only credential helpers (`credential.https://<host>.helper`) instead of unscoped global ones, so a malicious clone target can no longer capture them via an auth challenge. Trusted hosts derive from each provider's SaaS default plus any configured `--<provider>-api-url`/`--azure-base-url`/`--endpoint`, preserving GitHub Enterprise and other self-hosted flows.
- Security: `--output` report files are opened with `O_NOFOLLOW` (with a symlink pre-check on non-Unix) so a symlink planted at the report path inside a scanned repository can no longer redirect the write to truncate or overwrite an arbitrary file.
- Security: single-stream gzip/bzip2/xz/zlib decompression is now bounded by a 512 MB decompressed-byte cap, preventing a small compression bomb from exhausting disk during a scan.
- Added 3 detection and validation rules for Cognition Devin API credentials: `kingfisher.devin.1` (legacy personal keys, `apk_user_` prefix), `kingfisher.devin.2` (legacy service keys, `apk_` prefix), and `kingfisher.devin.3` (v3 service-user tokens, `cog_` prefix / RFC 4648 base32). Live validation uses `GET /v1/sessions` for `apk_*` keys and `GET /v3/self` for `cog_` tokens.
- Added `kingfisher scan docker --archive <image.tar>` for scanning saved Docker/OCI image archives directly, including OCI-layout `docker save` output and compressed tar archives.

## [v1.101.0]
- Fixed asymmetric JWT validation panics by using a single `jsonwebtoken` crypto backend and adding RS256 regression coverage. Thanks @AgentEnder. [#386](https://github.com/mongodb/kingfisher/pull/386)
- Validator panics now fail that validation result instead of crashing the scan, with panic payloads kept out of cached and user-visible validation responses. Thanks @AgentEnder. [#387](https://github.com/mongodb/kingfisher/pull/387)
- Reduced `failed to spawn thread` errors in validation-heavy scans by capping Tokio blocking pools for the main and artifact-fetcher runtimes and raising the Unix soft `RLIMIT_NPROC` before worker startup.

## [v1.100.0]
- Archive scanning now reaches inside Android/iOS app packages: added `apk`, `aab`, and `ipa` to the recognized ZIP-based archive formats so secrets embedded in APK/AAB/IPA contents (e.g. `classes*.dex`, `res/values/strings.xml`) are extracted and matched.
- Git repository scans now extract archive blobs encountered in the object database, not just on the filesystem. Previously a `.zip`/`.jar`/`.apk`/`.tar.gz` committed to a repo was scanned as raw compressed bytes, so secrets inside it were invisible. The git enumerator fans each archive entry out as a synthetic `<archive>!<entry>` blob with the original commit metadata. Honors `--no-extract-archives` for opt-out.
- Fixed tar-wrapped archive extraction for `.tgz` and `.tar.*` files, and made dependent credential validation deduplication preserve per-occurrence context so repeated secrets validate with the correct nearby companion value.
- Performance: ZIP-based git blobs ≤ 64 MB extract entirely in memory (no temp-file round trip), beating the v1.99.0 baseline by ~15% on a 80 GiB monorepo despite scanning ~300K additional archive-content blobs. Larger archives auto-fall-back to a disk-streaming extractor.
- Memory safety: hard caps on archive extraction — 64 MB compressed pre-flight, 256 MB aggregate decompressed per archive (in-memory and disk paths), 512 MB per entry, plus a `PK\x03\x04` magic-byte gate. Worst-case footprint is bounded at ~`num_jobs * 320 MB`.
- Release binary trimmed from 34 MB to 26 MB (~24% smaller). Switched `jsonwebtoken` to its `rust_crypto` backend (eliminates our scanner's pull on `aws-lc-rs`), bumped workspace `hmac` 0.12→0.13, `sha1` 0.10→0.11, `sha2` 0.10→0.11 to deduplicate our internal crypto code with the AWS sigv4 side, and migrated affected call sites in `kingfisher-core`, `kingfisher-rules`, and `kingfisher-scanner` to the digest-0.11 API (`hex::encode` for hex digests, explicit `KeyInit` import for HMAC).

## [v1.99.0]
- Fixed [#371](https://github.com/mongodb/kingfisher/issues/371): `pip install kingfisher-bin` on glibc Linux distros (Ubuntu, Debian, RHEL, Fedora, …) installed a macOS Mach-O binary and failed with `OSError: [Errno 8] Exec format error`. Linux wheels are now tagged `manylinux_2_17_<arch>.musllinux_1_2_<arch>` (instead of `musllinux_1_2_<arch>` only), so pip accepts them on both glibc-2.17+ and musl distros. The `pypi/hatch_build.py` hook now hard-fails when `KINGFISHER_PYPI_WHEEL_TAG` is unset, and the publish workflow refuses to upload any `py3-none-any.whl`, so the v1.92.0-era pure-Python wheel cannot recur.
- `--self-update` (alias `--update`) on a scan or other command now **re-execs into the freshly installed binary** so the current invocation completes with the new code and the latest detection rules. Previously the on-disk binary was replaced but the running process kept using the old in-memory version, requiring a second invocation to pick up the changes. On Unix this is a true `exec()` (same PID); on Windows the new binary is spawned and the parent exits with its status code. The explicit `kingfisher self-update` subcommand still updates and exits without re-execing. Self-update now also covers Windows arm64 (the asset was already published; the runtime cfg map gained the missing arm). See `docs/ADVANCED.md` → *Update Checks*.
- `--include-contributors` now respects `--github-repo-type` when enumerating contributor-owned repositories: by default contributor forks are excluded (matching the existing `Source` default), previously they were always included regardless of the flag. Added a new `--github-repo-type all` option to opt into the prior behavior of scanning both source and fork repos for contributors, organizations, and users.
- **Access Map:** Pinecone API keys (validated `kingfisher.pinecone.1`): caller resources via `GET /indexes` (with serverless cloud/region or pod environment metadata, deletion-protection state) and `GET /collections`; standalone `kingfisher access-map pinecone` (alias `pinecone.io`).
- Added `--blast-radius` as an alias for `--access-map` on `kingfisher scan`, and `kingfisher blast-radius <provider>` as an alias for the `kingfisher access-map <provider>` subcommand, so the user-facing "blast radius" concept matches the CLI invocation.
- **Webhook alerting — Discord, Mattermost, and Google Chat targets:** `--alert-format` now accepts `discord` (color-coded embeds), `mattermost` (Slack-compatible attachments), and `googlechat` (`cardsV2` cards). Discord and Google Chat URLs are auto-inferred from the webhook host; Mattermost requires `--alert-format mattermost` since it is always self-hosted. All five chat targets (Slack, Teams, Discord, Mattermost, Google Chat) plus the Generic JSON sink can be combined in a single run via repeated `--alert-webhook` flags or `alerts.webhooks` entries in `kingfisher.yaml`.
- **Webhook alerting — `--alert-detail` mode:** new `--alert-detail auto|summary|detail` flag controls per-finding verbosity. `auto` (default) renders inline findings for ≤ 25 filtered results and drops to a summary card for larger scans so high-volume runs do not flood the channel. `summary` always suppresses per-finding blocks; `detail` always renders them. Per-webhook overrides are available via `detail:` in `kingfisher.yaml`.
- **Webhook alerting — `--alert-report-url` pivot link:** pass a CI run URL (or set `KINGFISHER_ALERT_REPORT_URL`) to embed a one-click "Full report →" link in every chat payload. In GitHub Actions, pair with `github.server_url/${{ github.repository }}/actions/runs/${{ github.run_id }}` to land the responder directly in the SARIF view for that run.
- **Webhook alerting — fingerprints in chat payloads:** every finding rendered in detail mode now includes its stable `fingerprint` ID (e.g. `fp:1635470773610661884`), matching the value emitted in JSON/JSONL/SARIF/baseline outputs. SOAR playbooks and SIEM rules can use these IDs to dedupe across runs without a separate correlation step.
- **Webhook alerting — scan target in all alert modes:** the "Target" line in chat payloads now correctly reflects the actual scan target for all input modes (GitHub org/user, GitLab group, Bitbucket workspace, S3/GCS bucket, Docker image, Jira/Confluence, Slack, Teams, Postman, etc.), not just local path scans.
- **`kingfisher.yaml` reaches near-CLI parity:** scalar overrides for `--confidence`, `--redact`, `--format`, `--baseline-file`, `--tls-mode`, validation tuning (timeout / retries / rps / per-rule rps), filters (`--max-file-size`, `--no-binary`, `--extraction-depth`, `--skip-aws-account*`), output (`--output`), git options (`--git-clone-dir`, `--keep-clones`, `--repo-clone-limit`, `--include-contributors`), `alerts.defaults.*`, and global flags (`--allow-internal-ips`, `--no-update-check`, `--user-agent-suffix`, `--endpoint`). Precedence is `CLI > env > config > built-in default` (clap `ValueSource` decides per-flag); list-typed values stay additive. Scan-target inputs (paths, `--git-url`, provider user/org/bucket flags) remain CLI-only by design. The config is loaded **only** when `--config FILE` is passed explicitly — there is no auto-discovery, so scan results never depend on which directory the binary was launched from. See `docs/CONFIG.md`.
- **`kingfisher config init` subcommand:** convert an existing `kingfisher scan ...` invocation into a reusable `kingfisher.yaml` by replacing `scan` with `config init` (e.g. `kingfisher config init --confidence high --redact --exclude vendor/ > kingfisher.yaml`). Only flags the user actually supplied appear in the output — clap defaults are stripped — and scan-target inputs are dropped. Writes to stdout by default, or to `--out FILE` (with `--force` to overwrite).
- **Access Map UI redesign** in the report viewer: identities are now grouped into collapsible per-provider sections (admin-bearing providers first); permissions are classified by severity (admin / privilege escalation / risky / read-only) with color-coded badges and rollup chips on each card header; the expanded card body renders permissions **once per group** with a "These permissions apply to all N resources above" banner instead of repeating the same 50+ badges per resource; duplicate-named identities (e.g., multiple MongoDB `admin` tokens) now display a discriminator subtitle (`identity_id · access_type`) so they're tellable apart; new "Critical only" toolbar toggle (persisted in `localStorage`) hides read-only permissions and zero-risk identities; the stats bar gained an admin-permission count. Imported TruffleHog/Gitleaks reports keep the previous flat rendering as a backwards-compatible fallback. Underlying JSON now includes `permissions_by_severity` and an `identity.context` discriminator on each `AccessMapEntry`.

## [v1.98.0]
- Bounded disk usage for large multi-repo scans (e.g. `--include-contributors --repo-artifacts` against orgs with thousands of repos): cloning, artifact fetching, and scanning now run concurrently through bounded channels, and each cloned repo is removed from the temp directory as soon as its scan completes. On-disk footprint stays roughly `O(num_jobs)` regardless of total repo count instead of growing without bound. `--keep-clones` and `--git-clone-dir` opt out of the per-repo cleanup as before.
- Parallelized `--repo-artifacts` fetching with `buffer_unordered(num_jobs)` so issue/PR/wiki API calls run concurrently and stream into the scan loop, replacing the previous per-repo serial loop that delayed the start of scanning by hours on large fan-outs.
- Streamed `--format json` output as compact one-envelope-per-line so concatenated per-repo emits from the parallel scan path produce valid JSONL that `kingfisher view` can load. Pipe through `jq .` for pretty-printed output.
- Fixed a panic in the lexer when a string literal ends in a trailing backslash (`'... \`); the escape handling now clamps past-EOF so `extract_literal_values` returns instead of slicing out of bounds.
- Added first-class **Postman** scanning target: new `kingfisher scan postman` subcommand (and equivalent `--postman-*` flags) fetches workspaces, collections, and environments via the Postman API and scans them for hard-coded credentials in request `auth` blocks, pre-request/test scripts, saved example responses, and — notably — `secret`-typed environment variables, which the API returns in plaintext despite the UI mask. Selectors: `--workspace`, `--collection`, `--environment`, `--all`, with optional `--include-mocks-monitors` and `--api-url` for self-hosted endpoints. Authenticates via `KF_POSTMAN_TOKEN` (or `POSTMAN_API_KEY`) sent as `X-Api-Key`; honors `X-RateLimit-RetryAfter` on 429s. Findings link back to `https://go.postman.co/...` URLs in reports.
- Fixed [#359](https://github.com/mongodb/kingfisher/issues/359): added `kingfisher.github.9` to detect the new ~520-character stateless GitHub App installation token format (`ghs_<APP_ID>_<JWT>`). The legacy 36-character `ghs_` rule (`kingfisher.github.5`) is retained for older / GHES-issued tokens that are still in circulation. 
- Added provider endpoint overrides for validation and revocation via global `--endpoint PROVIDER=URL` and `--endpoint-config FILE`, with built-in support for self-hosted GitHub, GitLab, Gitea, Jira, Confluence, and Artifactory instances.

## [v1.97.0]
- **Report viewer cross-tool triage:** when a Kingfisher report is loaded alongside a Gitleaks or TruffleHog report, matching imported findings are enriched with Kingfisher's validation verdict, validation response, validate command, and revoke command. Matching is keyed on `commit + file + line` with a `file + line` fallback, and enriched rows show an "Enriched by Kingfisher" callout in the detail panel plus an "Enriched" chip in the findings table. Added a **Source** column to the findings table; a new **Duplicates Removed by Tool** dashboard panel showing per-tool cards for Kingfisher / TruffleHog / Gitleaks; and an upload-time **Deduplicate findings** toggle (on by default) so users can inspect the raw rows before fingerprint dedup when needed.
- Fixed the HTML report viewer dark mode so charts redraw correctly on theme changes and follow the system color scheme until manually overridden.
- Fixed [#344](https://github.com/mongodb/kingfisher/issues/344): baseline fingerprints no longer have to be hexadecimal. The fingerprint value emitted by scan output (JSON, JSONL, pretty, SARIF) can now be copied directly into a baseline file and will match on the next scan. `--manage-baseline` now writes fingerprints in decimal to match scan output, and legacy 16-char hex (and `0x`-prefixed hex) entries continue to be accepted, so existing baseline files keep working unchanged.
- Expanded the bundled ruleset to **942 rules** (820 standalone detectors + 122 dependent rules), with **484 standalone detectors** now including live HTTP / service-specific validation.
- Documentation: expanded coverage of the **Report Viewer & Triager** across `README.md`, `docs/USAGE.md`, and the docs site (`docs-site/docs/features/report-viewer.md`, `docs-site/docs/usage/basic-scanning.md`). The same viewer is available locally via `kingfisher view <report.json>` and as a hosted static upload-based page at [https://mongodb.github.io/kingfisher/viewer/](https://mongodb.github.io/kingfisher/viewer/). Both forms import Kingfisher, Gitleaks, and TruffleHog JSON/JSONL for cross-tool triage with fingerprint-based deduplication and blast-radius rendering.

## [v1.96.0]
- Added archive extraction for three Korean formats: HWPX (Hancom OWPML ZIP container), HWP (Hancom 5.x OLE2/CFBF binary — streams decoded via raw DEFLATE / zlib fallbacks), and EGG (ALZip; registered for enumeration and scanned as raw bytes since no open-source extractor exists).
- Added live HTTP validation for 18 rules across 15 providers: Val Town, Polar, hCaptcha, Thunderstore, Elastic Cloud (2 rules), LlamaCloud, Gemfury (2 rules), Vonage, ThingsBoard, Zapier, Facebook Access Token, GitLab Session Cookie, PostHog Feature Flags, Unkey API Key, and Hop.io (2 rules).
- Added revocation support for 7 rules across 6 providers: Discord webhooks (single-step DELETE), DigitalOcean PATs (self-revoke via OAuth), and multi-step HttpMultiStep revocation for LaunchDarkly, Resend, Linode, and Netlify (2 rules). Built-in revocation coverage is now 34 provider families with 53 revocation-enabled rules.
- Expanded Alibaba Cloud coverage with STS temporary credential detection for STS access key IDs, STS security tokens, and STS access key secrets. Built-in rule coverage is now 923 rules total.
- **Access Map:** Alibaba Cloud long-lived and STS access key pairs (validated `kingfisher.alibabacloud.2` and `kingfisher.alibabacloud.5`): caller identity via STS GetCallerIdentity; standalone `kingfisher access-map alibaba` (alias `aliyun`).
- **Access Map:** monday.com API tokens (validated `kingfisher.monday.1`) and Asana personal access / OAuth tokens (validated `kingfisher.asana.3`, `kingfisher.asana.4`, `kingfisher.asana.5`). Monday maps the caller via the `me { account, teams }` GraphQL query and enumerates accessible workspaces and boards; Asana resolves the caller via `/users/me` and enumerates accessible workspaces, organizations, projects, and team memberships. Standalone `kingfisher access-map monday` and `kingfisher access-map asana`.
- **Report viewer:** Import Gitleaks and TruffleHog JSON into the bundled local viewer with deduplication for repeated imported findings, and publish a static upload-based viewer on the docs site for GitHub Pages hosting. See `docs/USAGE.md`.
- Fixed parser-based context gating so assignment-style contextual secrets still scan in raw text when parser verification is unavailable, instead of being dropped.
- Fixed dependent-variable pairing for HTTP validation so rules use the nearest helper match in-file, and updated Pinata detection/validation to reliably catch API key IDs, API secrets, and JWTs, including key+secret validation.
- Corrected several newly added SaaS rules and validators, including LiveKit (with dependent API secret validation), Tinybird, Inngest, Tolgee, Unkey, Composio, Hex.pm, Trigger.dev, Voiceflow, WorkOS, and Infisical.
- Added 61 new detection rules across 46 providers: Axiom (API token + PAT), Trigger.dev (secret key + PAT), Dub.co, Svix webhook signing secret, Liveblocks, Inngest (signing key + event key), Seam, Courier, Cal.com, Arcjet, WarpStream, Mem0, Mintlify, Pirsch, Tinybird, Tolgee (project key + PAT), Ory (API key + session + OAuth2 tokens), Xendit, Xata, Crossmint (server + client keys), DeepL (Free + Pro), Flagsmith, E2B, Infisical, WooCommerce (consumer key + secret), Nightfall AI, Ramp (client ID + secret), Hex.pm (personal + workspace tokens), Convex deploy key, MiniMax, Mappedin (key + secret), Pollinations (secret + publishable), Fal.ai, Aikido, Hack Club, GuardSquare, Browser Use, Composio, Gamma, Hex.tech, Mastra, redirect.pizza, Upstash, and WorkOS. Also added new prefixed-token rules for Netlify (`nfp_`), Cloudflare (`cfut_`), and Supabase (`sb_publishable_`). Added live HTTP validation for 30 of these rules.
- Added 32 new detection rules across 25 providers: Ghost CMS (admin + content keys), UpCloud (`ucat_`), Voiceflow (`VF.DM.`/`VF.WS.`), Robinhood Crypto (`rh-api-`), ClickUp (`pk_`), Unleash (client/admin + personal tokens), ConfigCat (standard + extended SDK keys), SaladCloud (`salad_cloud_`), Tigris (`tid_`/`tsec_`), Portainer (`ptr_`), Permit.io (`permit_key_`), Builder.io (`bpk-`), LiveKit (API key + secret), Close CRM (`api_`), Hetzner Cloud, Censys (API ID + secret), Wistia, PandaDoc, Pinata (key + secret), ZeroTier, Detectify, ChartMogul, Moralis, ButterCMS, and Loops. Includes HTTP validation for 19 of these rules.
- Removed 17 direct dependencies from the root crate by dropping unused deps (`p256`, `ed25519-dalek`, `jsonwebtoken`, `gitlab`, `lazy_static`, `base32`, `pem`, `byteorder`, `reqwest-middleware`, `sha1`, `time`, `ring`, `num_cpus`, `strum_macros`), replacing `once_cell` with `std::sync::{LazyLock, OnceLock}`, and using `std::thread::available_parallelism()` in place of `num_cpus`. Salt generation now uses `rand` instead of `ring`, and all `strum_macros::Display` imports are consolidated under `strum::Display`.
- Migrated the workspace to Rust Edition 2024 (MSRV 1.94) and refactored nested `if let` chains in core/scanner hot paths (content-type detection, origin parsing, GCP/Harness/Azure DevOps access maps, GitHub/GitLab repo parsing, dependent-variable pairing) to use stable let-chains for flatter control flow.
- Tightened lint hygiene by converting stable `#[allow(...)]` attributes to `#[expect(...)]` across the workspace (e.g. `dead_code`, `clippy::too_many_arguments`, `clippy::large_enum_variant`) so the compiler surfaces stale suppressions as warnings.

## [v1.95.0]
- Fixed scan performance regression: the rule profiler was unconditionally active even without `--rule-stats`, causing RwLock contention across scan threads. Scans are now ~15% faster than v1.94.0.
- Added 80+ built-in rules, bringing the bundled ruleset to 825 total. New coverage includes Amazon OAuth, Asaas, multiple Azure credential families, Bitrise, Canva, CockroachDB, eBay, Elastic, hCaptcha, Highnote, Lichess, MailerSend, Onfido, Paddle, Pangea, Persona, Pinterest, Proof, Rootly, Runpod, Telnyx, Thunderstore, Valtown, Volcengine, and more.
- Replaced tree-sitter with a lighter parser-based context verifier built from handwritten lexers plus `tl`/`cssparser`, preserving context-dependent matching while cutting about 19 MB from the release binary.
- Added a `validation: type: Raw` exception path for provider-specific checks, with new raw validators for Azure Batch, FTP, Kraken, LDAP, RabbitMQ, and Redis. Also added stable request-scoped template values plus new Liquid filters for HMAC-SHA384 hex output and timestamp generation.
- Expanded live validation coverage for several built-in rules, including Agora, Bitfinex, DocuSign, Dwolla, GitLab, KuCoin, RingCentral, Snowflake, Tableau, Trello, and Webex. Also tightened newly added helper regex to avoid high-match scan regressions, and made preflight-blocked raw validations report as skipped/not attempted instead of failed.

## [v1.94.0]
- Updated vendored `vectorscan-rs` from v0.0.5 (Vectorscan 5.4.11) to v0.0.6 (Vectorscan 5.4.12). The upstream crate now ships pre-extracted sources instead of a tarball+patch, and fixes the `cpu_native` feature flag. Local Windows and musl build patches have been re-applied.
- Added more built-in rules

## [v1.93.0]
- **Access Map: added 21 new blast radius providers**, bringing the total to 39. New providers: Airtable, Algolia, Artifactory, Auth0, CircleCI, DigitalOcean, Fastly, HubSpot, IBM Cloud, Jira, MySQL, PayPal, Plaid, SendGrid, Sendinblue/Brevo, Shopify, Square, Stripe, Terraform Cloud, JFrog Xray, and Zendesk. Each provider maps leaked credentials to their effective identity, permissions, and exposed resources.
- **Access Map: expanded provider depth** for existing integrations. AWS now enumerates SQS, SNS, RDS, ECR, and SSM Parameter Store in addition to the earlier core services; Azure Storage now maps Blob containers, File shares, and Queues from account keys; OpenAI now enumerates visible models, files, assistants, and fine-tuning jobs; Hugging Face now includes datasets and Spaces alongside models; Anthropic now surfaces visible organization API keys.
- Folded in a set of safe dependency bumps from open maintenance PRs, including `strum`, `sysinfo`, `hmac`, `sha1`, `sha2`, `gitlab`, and `oci-client`, with small compatibility fixes in runtime hashing, system memory detection, and Azure signing code.
- Added Mermaid architecture documentation in `docs/ARCHITECTURE.md`, covering the main Kingfisher components, command paths, and scan flow at a high level.
- Expanded `docs/LIBRARY.md` with Mermaid diagrams showing the relationships and internal structure of `kingfisher-core`, `kingfisher-rules`, and `kingfisher-scanner`.

## [v1.92.0]
- Added new built-in rules for Etsy, Flutterwave, Freemius, JFrog, Kraken, KuCoin, Trello, Octopus Deploy, OpenShift, Private AI, SettleMint, Sidekiq, and Polymarket.
- Added live HTTP validation for Etsy, JFrog, Octopus Deploy, OpenShift, and Private AI where provider documentation supported reliable token-only checks.
- Added detection + validation rules for Anthropic Admin, Azure Speech, Azure Translator, Databento, DataStax Astra, DevCycle, Fullstory, GC Notify, and Stytch; built-in runtime rule count is now 601 with `--confidence=low`.
- Added Heroku token revocation support for both legacy UUID-format tokens and `HRKU-` platform tokens via the OAuth authorizations API.
- Added `hmac_sha256_b64key` Liquid filter for HMAC-SHA256 signing with base64-encoded keys (decodes key to raw bytes before signing), enabling correct Azure Notification Hub SAS validation.
- Integrated SLSA v3 provenance generation into the release workflow; hash computation now scopes to build artifacts only for idempotent re-runs.
- Removed Zapier webhook live validation (GET to a catch hook triggers the Zap).
- Hardened Heroku revocation regex to prevent crossing JSON object boundaries when extracting authorization IDs.
- Fixed Zendesk subdomain regex to reject trailing hyphens; renamed `ZENDESK_SUBDOMAIN` to `ZENDESK_HOST` for clarity.
- Fixed Stytch and Polymarket trailing `\b` boundaries that prevented matching base64-padded secrets ending with `=`.
- Tightened Kubernetes API Server URL pattern to require kube-specific identifiers, preventing bootstrap tokens from binding to unrelated `server:` entries.

## [v1.91.0]
- Added SSRF protection for credential validation: outbound HTTP requests now block connections to loopback, private, link-local, and other non-public IP addresses. HTTP redirect targets are DNS-resolved and validated against the same SSRF rules. Use `--allow-internal-ips` to opt out when scanning internal infrastructure.
- Consolidated JWT SSRF checks to use the shared `is_ssrf_safe_ip` function, covering additional reserved ranges (CGNAT, documentation, benchmarking, IPv6 unique-local).
- Removed `ipnet` dependency from `kingfisher-scanner` (no longer needed).
- Remediated current RustSec vulnerability findings by upgrading core dependencies including `gix`, `mysql_async`, `axum`, `indicatif`, `quick-xml`, and `console`.
- Added `make audit-deps` to run `cargo audit` locally and report vulnerable dependencies.
- Refreshed pinned GitHub Actions for `swatinem/rust-cache`, `msys2/setup-msys2`, and `ncipollo/release-action`, and configured Dependabot to ignore selected GitHub Action major-version bumps.
- OpenSSF Scorecard hardening: added `SECURITY.md`, `.github/dependabot.yml`, pinned all GitHub Actions by SHA, fixed dangerous workflow expression injection patterns, added top-level `permissions: {}` to `pypi.yml`, and added SLSA provenance generation for releases.
- Added ClusterFuzzLite integration with four fuzz targets (entropy, location mapping, base64 decoding, span deduplication) and a `make fuzz` target for local fuzzing.

## [v1.90.0]
- Added `--max-validation-response-length <BYTES>` for `scan` to control validation response storage truncation (default: `2048`, `0` disables truncation).
- Updated `--full-validation-response` to bypass both validation storage truncation and reporter truncation, preserving complete response bodies end-to-end for parsing/reporting workflows.
- Added Testkube detection/validation coverage with `kingfisher.testkube.*` rules for API keys plus dependent organization/environment IDs used for live API validation.
- Improved TrueNAS rule

## [v1.89.0]
- Added TOON output for `scan`, `validate`, and `revoke`, optimized for LLM/agent workflows; prefer `--format toon` when calling Kingfisher from an LLM.
- Expanded built-in revocation support with new YAML revocation flows for Cloudflare, Confluent, Doppler, Mapbox, Particle.io, Twitch, and additional Vercel token formats.
- Added revocation coverage documentation: new `docs/REVOCATION_PROVIDERS.md` matrix and README links highlighting supported revocation providers/rule IDs.
- Access Map: added Microsoft Teams provider. Parses Incoming Webhook URLs (legacy and workflow-based) to extract tenant and webhook identity, probes for active status, and reports channel-level blast radius. Supports standalone `access-map microsoftteams` (alias `msteams`) and automatic mapping for validated `kingfisher.msteams.*` and `kingfisher.microsoftteamswebhook.*` findings.
- Added Microsoft Teams scan target: `kingfisher scan teams "QUERY"` searches Teams messages via Microsoft Graph Search API and scans them for secrets, mirroring the Slack integration.
- Requires `KF_TEAMS_TOKEN` environment variable (Microsoft Graph access token with `ChannelMessage.Read.All` or `Chat.Read` permissions).
- Findings reference Teams message URLs in reports; see `docs/USAGE.md` and `docs/INTEGRATIONS.md` for authentication setup.

## [v1.88.0]
- Tree-sitter fallback behavior changed to be strictly additive: when parser context is unavailable, findings now fall back to Hyperscan/Vectorscan matches instead of being suppressed.
- Fixed dependent-rule reporting gaps (for example Algolia API keys) by preserving regex findings when tree-sitter is unavailable, while still marking validation as skipped when dependency inputs are missing.
- Expanded parser queries for C, Go, Java, JavaScript, and TypeScript to improve assignment/literal capture coverage (including template/raw string handling in JS/TS/Go).
- Added parser query quality gates: compile-time query validation tests plus fixture-based capture-count regression tests backed by `testdata/parsers/tree_sitter_capture_baseline.json`.
- Added inline-ignore coverage for directives placed on the line immediately before a single-line secret match.
- Updated tree-sitter documentation wording to align with `--turbo` terminology.

## [v1.87.0]
- Tree-sitter verification now runs for blobs from `0` bytes up to `128 KiB` (previously `1 KiB` to `64 KiB`), while remaining a post-regex verification step applied only to context-dependent candidate matches from Hyperscan/Vectorscan.
- False-positive reduction: Hyperscan/Vectorscan still scans everything first, then tree-sitter performs a second-pass verification only on auto-classified context-dependent findings; self-identifying/token-explicit findings stay regex-first.
- Hardened Perplexity API key validation to reject auth failures (`401`/`403`) and avoid false "Active Credential" results from error payloads.
- Fixed Yelp API key validation false positives by switching to an auth-enforcing endpoint (`/v3/businesses/search`) and adding explicit auth error guards.
- Added 37 new provider detection + HTTP validation rules: Ably, AbstractAPI, AbuseIPDB, AviationStack, Better Stack, Brevo, Clearout, Clerk, Cloudinary, Coinlayer, Contentstack, Currencylayer, Daily, Fixer, Geoapify, Hunter.io, Mux, NewsAPI, Numverify, OneSignal, Pinecone, Pingdom, Positionstack, Railway, Render, Rollbar, Salesloft, Sanity, StatusCake, Storyblok, UptimeRobot, urlscan.io, VirusTotal, WeatherAPI, Webflow, and ZeroBounce.
- Tightened regex specificity for newly added rules by replacing broad variable-length token captures with explicit fixed formats/lengths and aligned examples to pass `rules check`.

## [v1.86.0]
- GitLab scanning: honor OS-trusted internal CAs without requiring `SSL_CERT_FILE`, and preserve custom GitLab API ports in repository enumeration and artifact fetching.
- Added detection/validation rules for App Center, Branch.io, BrowserStack, Calendly, Cypress, Delighted, DeviantArt, Instagram, Iterable, Keen.io, Lokalise, Pendo, Razorpay, Spotify, WakaTime, WPEngine.
- Added revocation support for DeviantArt access tokens via the OAuth revoke endpoint and BrowserStack access keys via the key recycle endpoint.
- Windows builds: replaced `buildwin.bat` flow with Makefile-driven MinGW targets for `windows-x64` and `windows-arm64`, producing static `kingfisher.exe` artifacts packaged as `kingfisher-windows-*.zip` with checksums.
- GitHub Actions (`ci.yml`, `release.yml`): Windows jobs now build and test both x64 and arm64 via a matrix using `make windows-x64` / `make windows-arm64`.

## [v1.85.0]
- Report viewer: added `--view-report-port` and `--view-report-address` to `kingfisher scan --view-report`, and `--address` to `kingfisher view`, so the embedded report server can bind to `0.0.0.0` and be reached from the host when running in Docker. Use `--view-report-address 0.0.0.0` with `-p 7890:7890` (or `--view-report-port 7891` with `-p 7891:7891`) to view the HTML report at http://localhost:7890 from your host.
- Updated `kingfisher scan` to accept Git repository URLs as positional targets (for example `kingfisher scan github.com/org/repo` or `kingfisher scan https://gitlab.com/group/project.git`) without requiring `--git-url`.
- Deprecated `--git-url` while preserving backward compatibility; using the flag now emits a migration warning to prefer positional URL targets.
- Updated README/integration/usage/install/demo examples and CLI tests to use positional Git URL scanning syntax.
- Jira scanning: added `kingfisher scan jira --include-comments` and `--include-changelog` to scan per-issue comments and changelog entries, with paginated Jira comment fetching and ADF text normalization preserved for issue/comment content.
- Added `--turbo` mode: sets `--commit-metadata=false`, `--no-base64`, disables language detection, and disables tree-sitter parsing...for maximum scan speed. Findings will omit Git commit context (author, date, commit hash) and will not include Base64-decoded secrets.
- SQLite database scanning: kingfisher now detects and extracts SQLite files (`.db`, `.sqlite`, `.sqlite3`, etc.), dumping each table as SQL text with named columns so secrets stored in database rows are scannable. Extraction is enabled by default and can be disabled with `--no-extract-archives`.
- Python bytecode (.pyc) scanning: extracts string constants from compiled Python (`.pyc`, `.pyo`) files via marshal parsing so secrets embedded in bytecode are scannable. Extraction is enabled by default and can be disabled with `--no-extract-archives`.
- Performance: pipelined ODB enumeration — scanning now begins while blob OIDs are still being discovered, overlapping I/O with pattern matching.
- Performance: skip blobs smaller than 20 bytes during enumeration (too small to contain any secret).
- Performance: preserve pack-ascending blob order in the metadata path for better I/O locality when Rayon splits work.
- Performance: defer Git committer metadata materialization until commits actually introduce scannable blobs, reducing unnecessary string/time parsing work.
- Performance: push `--exclude` filtering into Git tree traversal so excluded paths/subtrees are pruned before blob-introduction bookkeeping.
- Performance: make Git repository object indexing single-pass (removed the extra ODB scan in `RepositoryIndex::new`).

## [v1.84.0]
- Added/updated `pipedrive` and `amplitude` rules
- Access Map: added Buildkite provider. Enumerates token scopes, user identity, organizations, and pipelines with severity classification based on scope risk.
- Access Map: added Harness provider. Uses `x-api-key` authentication to enumerate organizations/projects when permitted (best-effort).
- Access Map: added OpenAI provider. Supports standalone `access-map openai` and automatic mapping for validated `kingfisher.openai.*` findings. Enumerates organizations (from `/v1/me`), projects, and API key permission scopes by probing endpoints for restricted key detection.
- Access Map: added Anthropic provider. Supports standalone `access-map anthropic` and automatic mapping for validated `kingfisher.anthropic.*` findings.
- Access Map: added Salesforce provider. Supports standalone `access-map salesforce` (token + instance) and automatic mapping for validated `kingfisher.salesforce.*` findings.
- Added Weights & Biases support: new `kingfisher.wandb.2` rule for `wandb_v1_...` keys (legacy `kingfisher.wandb.1` retained), plus Access Map provider/CLI support (`weightsandbiases`, alias `wandb`).
- Reports: always emit `validate`/`revoke` command hints when supported by a rule (no suppression for missing template vars).
- Access Map GCP: added resource enumeration for Cloud KMS key rings, Cloud Functions, Firestore databases, Cloud Spanner instances, and project service accounts.
- Access Map GCP: populated `token_details` with service account metadata (display name, unique ID, disabled status).
- Access Map GCP: fixed BigQuery and Secret Manager risk assessment to detect write permissions and `secretmanager.versions.access`.
- Access Map GCP: added risk notes for KMS decrypt, Cloud Functions deploy, instance metadata injection, and secret value read access.
- Access Map GCP: expanded `testIamPermissions` fallback with 11 additional permission candidates.

## [v1.83.0]
- Kingfisher can now generate an auditor-friendly HTML report: `--format html --output kingfisher-audit.html`
- Architecture: split `matcher.rs` into a `src/matcher/` module directory with focused sub-modules (`base64_decode`, `captures`, `conversion`, `dedup`, `filter`, `fingerprint`). Decomposed `filter_match` into smaller validation helpers.
- Architecture: refactored `scanner/runner.rs` god function into phase-based helpers (`enumerate_all_repos`, `fetch_all_artifacts`, `run_sequential_scan`, `run_parallel_scan`, etc.) with a `ValidationDeps` type alias.
- Architecture: consolidated duplicated matching primitives (base64 detection, dedup, fingerprinting, secret capture selection) into `kingfisher-scanner::primitives` as the single source of truth; both the scanner crate and binary now share one implementation.
- Architecture: introduced `TokenAccessMapper` trait for access map providers, implemented for GitHub, GitLab, Slack, HuggingFace, Gitea, and Bitbucket.
- Architecture: moved `content_type` module to `kingfisher-core` crate where it logically belongs (zero binary-crate dependencies).
- Library crates: added an external-consumer integration test (`tests/library_crates_external_project.rs`) and fixed `kingfisher-scanner` manifest wiring by making `serde` a required dependency, ensuring `kingfisher-core`/`kingfisher-rules`/`kingfisher-scanner` compile and run from a non-kingfisher Rust project.
- Improved tree-sitter parsing + structured secret detection in source files. A Vectorscan pre-filter over the combined tree-sitter output avoids the O(results × rules) regex cost.
- Access Map: added Hugging Face, Gitea, Bitbucket, PostgreSQL, and MongoDB providers. All perform read-only enumeration with severity classification.
- Access Map: Hugging Face, Bitbucket, Postgres, and MongoDB credentials from scans are now auto-collected when using `--access-map`.
- Access Map CLI: added providers `huggingface`/`hf`, `gitea`, `bitbucket`, `postgres`, `mongodb`/`mongo`.
- Added `kingfisher.gitea.1` rule for Gitea access tokens with validation; self-revocation not supported (API requires Basic Auth).
- Added revocation for GitHub App Server-to-Server tokens (`ghs_`, `kingfisher.github.5`) via `DELETE /installation/token`. Note: `ghu_` (user-to-server) tokens cannot be self-revoked; they require the GitHub App's client credentials or manual revocation via GitHub Settings.
- Fixed GitHub Access Map failing for all token types due to `GitHubUser` struct field mismatch (`_id` vs API `"id"`).
- Viewer: replaced the Access Map tree view with a card-based layout showing identity, resource count, permission tags, and token details at a glance with expandable inline detail.
- Viewer: added per-finding Blast Radius section linking findings to their access map entries with an auto-generated risk rationale (critical/high/medium/low) based on credential status, resource count, and permission severity.
- Viewer: added two new report types — Risk Report (findings + blast radius per credential, for researchers/bug bounty) and Scan Report (executive summary + scan metadata + findings table, for defenders/tickets). Both support "Active credentials only" filtering.
- Viewer: redesigned the Access Map export report to match the Scan/Risk report quality with summary stats, per-identity cards, token details, and resource/permission grids.
- Viewer: added scan metadata bar (timestamp, target, duration, version) to the Dashboard view.

## [v1.82.0]
- Added Vercel credential rules for new token formats introduced February 2026: `vcp_` (personal access), `vci_` (integration), `vca_` (app access), `vcr_` (app refresh), `vck_` (AI Gateway API key). All use CRC32/Base62 checksum validation. Legacy 24-char format retained as `kingfisher.vercel.1`.
- Added revocation support for Vercel app tokens (`vca_`, `vcr_`) via `https://api.vercel.com/login/oauth/token/revoke`. Requires `VERCEL_APP_CLIENT_ID` (or `NEXT_PUBLIC_VERCEL_APP_CLIENT_ID`) and `VERCEL_APP_CLIENT_SECRET`.
- Fixed validate/revoke command generation to omit regex named captures (e.g., `BODY`, `CHECKSUM`) when they are not used by validation/revocation templates, so rules like Vercel no longer produce unnecessary `--var BODY=...` arguments.
- Fixed HTTP validation incorrectly marking valid credentials as inactive when response bodies exceeded 2048 bytes. Matchers (`JsonValid`, `WordMatch`, etc.) now run against the full response; only the stored preview remains truncated for reporting.
- Fixed validation flakiness under service rate limiting by retrying HTTP validations on 429/408 in addition to transient 5xx failures.
- Added optional validation rate limiting via `--validation-rps` (global) and repeatable `--validation-rps-rule <RULE_SELECTOR=RPS>` (per-rule override) for both `scan` and `validate`. Throttling now applies across built-in validator types (HTTP/gRPC plus AWS, GCP, Coinbase, MongoDB, Postgres, MySQL, JDBC, JWT, and Azure Storage). Rule selectors support the short form (for example, `github=2` matches `kingfisher.github.*`) with longest-prefix precedence when multiple selectors apply.
- Prevented transient HTTP validation failures (429/5xx) from being cached, avoiding cache poisoning that could suppress later successful validations in the same scan.
- Added `kingfisher.temporal.1` rule for Temporal Cloud API keys (namespace-scoped and user-scoped JWT formats) with Temporal-specific pattern matching.
- Added Temporal Cloud active credential validation via `GET https://saas-api.tmprl.cloud/cloud/current-identity` using bearer auth, so Temporal keys validate against provider APIs instead of generic OIDC discovery.
- Fixed JWT issuer normalization to treat bare host issuers (e.g. `iss: "temporal.io"`) as HTTPS URLs during discovery, avoiding low-level URL builder failures.
- Added `crates/kingfisher-rules/build.rs` to ensure embedded rule assets rebuild when files under `crates/kingfisher-rules/data` change.

## [v1.81.0]
- Fixed checksum-template evaluation for prefixed tokens by using explicit checksum/body captures in NPM, GitHub, Confluent, and GitLab rules.
- Updated references sections to rules with API documentation links.
- Updated Google OAuth credentials rule requirements so bundled client-id/client-secret examples pass `rules check` consistently.
- Added gRPC validation support for gRPC-only APIs via `validation: type: Grpc` (e.g., Modal administrative keys).

## [v1.80.0]
- Added `--full-validation-response` flag to include complete validation response bodies without truncation. By default, validation responses are still truncated to 512 characters for readability. When enabled, users can parse and present full validation responses as needed (e.g., for GitHub token validation responses that include user metadata beyond the first 512 characters).
- Improved AWS rule.
- Enhanced HTTP multi-step revocation extraction by allowing Liquid rendering in extractors; updated NPM rules accordingly.

## [v1.79.0]
- Added revocation support for SendGrid, Tailscale, MongoDB Atlas, Twilio, and NPM using multi-step (lookup ID then delete) pattern.
- Added new Sumo Logic rule with direct revocation support.
- Added `docs/TOKEN_REVOCATION_SUPPORT.md` with detailed revocation implementation guide and testing examples.
- Fixed AWS access key validation to support temporary/session keys (ASIA prefix) in addition to long-lived keys (AKIA prefix).
- Consolidated all validator implementations into the `kingfisher-scanner` crate to eliminate code duplication. Validators for AWS, Azure, Coinbase, GCP, JWT, JDBC, MongoDB, MySQL, Postgres, and HTTP are now maintained in a single location with proper feature gating.

## [v1.78.0]
- Added "Skipped Validations" counter to scan summary output to distinguish between validations that failed (HTTP errors, connection failures) and validations that were skipped due to missing preconditions (e.g., missing dependent rules). This provides better visibility into validation coverage for large scans.
- Improved error messages for `kingfisher validate` command when rules require dependent variables from `depends_on` sections. Now clearly explains which variables are needed and from which dependent rules they are normally captured.
- Fixed `validate_command` and `revoke_command` generation in scan output to include all required `--var` arguments for rules with `depends_on` sections (e.g., PubNub, Azure Storage). Commands now include dependent variables like `--var SUBSCRIPTIONTOKEN=<value>` or `--var AZURENAME=<value>`.
- Updated Azure Storage validation to use `AZURENAME` variable (matching the `depends_on_rule` configuration) with `STORAGE_ACCOUNT` maintained as a backward-compatible alias.
- Added internal `dependent_captures` field to match records to preserve variables from dependent rules through the validation pipeline for accurate command generation.
- Added `--tls-mode <strict|lax|off>` global flag to control TLS certificate validation behavior during credential validation:
  - `strict` (default): Full WebPKI certificate validation with trusted CA chains, hostname verification, and expiration checks
  - `lax`: Accept self-signed or unknown CA certificates, useful for database connections (PostgreSQL, MySQL, MongoDB) and services using private CAs (e.g., Amazon RDS)
  - `off`: Disable all TLS validation (equivalent to legacy `--ignore-certs`)
- Added rule-level `tls_mode` field allowing individual rules to opt into relaxed TLS validation when appropriate. Rules for PostgreSQL, MySQL, MongoDB, JDBC, and JWT now include `tls_mode: lax` by default.
- The `--ignore-certs` flag remains supported as a deprecated alias for `--tls-mode=off` for backward compatibility.
- Updated documentation to explain TLS validation modes and their security implications.
- Added comprehensive test coverage for TLS mode functionality including unit tests, integration tests, and rule configuration verification.
- Fixed deprecated `commit` stage name in `.pre-commit-hooks.yaml` to use `pre-commit` stage name, eliminating pre-commit framework warnings.

## [v1.77.0]
- Added `kingfisher revoke` subcommand for revoking leaked credentials directly with the provider.
- Added optional `revocation` section to rules to support credential revocation (currently supporting AWS, GCP, GitHub, GitLab, Slack, and Buildkite).
- Added `kingfisher validate` subcommand to validate credentials without running a full scan.
- Added `validate_command` and `revoke_command` fields to scan output (pretty, JSON, JSONL, BSON, SARIF formats) showing the exact `kingfisher validate` or `kingfisher revoke` command to run for each finding. The `validate_command` is included for all findings with validation support; `revoke_command` is included only for active credentials with revocation support. These fields are omitted when `--redact` is used since they contain the secret value.
- Updated the HTML report viewer to display validate and revoke commands in the Finding Details panel with copy-to-clipboard functionality.
- Refactored project into multiple crates for better modularity and maintainability.
- Ensured more CLI arguments are global and available across all subcommands.
- Added `kingfisher-auto` pre-commit hook that automatically downloads and caches the appropriate binary for your platform (no Docker or manual installation required).
- Added Husky integration support with `install-husky.sh` helper script and documentation fclearor Node.js projects.
- Added `kingfisher-pre-commit-auto.sh` and `kingfisher-pre-commit-auto.ps1` scripts for automatic binary download in Git hooks (Linux, macOS, Windows support).

## [v1.76.0]
- Fixed validation deduplication for rules with nested unnamed captures (e.g. `(?<REGEX>...(ABC|DEF)...)`) to use the primary capture for grouping, ensuring each unique match triggers a separate validation request.
- Added trace-level (`-vv`) logging for internal validation dedup keys and grouping to aid debugging.
- Switched compression dependencies to pure-Rust bzip2/lzma implementations and pared zip features to avoid C-based codecs for bz2/xz handling.

## [v1.75.0]
- Enhanced Access Map View: added fingerprint display, enabled searching by fingerprint, and implemented bidirectional navigation between Findings and Access Map nodes.
- Added Slack Access Map support with granular permissions in the tree view.
- Improved HTML report
- Improved several rules
- Added new rules for Apollo, Clay, CodeRabbit, Customer.io, Instantly, Vast.ai
- Skipped per-repository report writes when an output file is specified and emit a single aggregated report after multi-repository scans to preserve full output content in files.

## [v1.74.0]
- Added new rules: cursor, definednetworking, filezilla, harness, intra42, klingai, lark, mergify, naver, plaid, resend, retellai

## [v1.73.0]
- Will now prefer git history findings when identical secrets appear in both current files and git history (dedup only).
- Fixed report viewer to add support for opening JSONL.
- Add opt-in contributor repository enumeration for GitHub/GitLab `--git-url` scans with `--include-contributors`, plus `--repo-clone-limit` to cap repo cloning.
- Add `--git-clone-dir` to set the parent clone directory and `--keep-clones` to preserve cloned repos after scans.
- Added several new rules.
- Added configurable validation timeout and retry settings for `kingfisher scan`.

## [v1.72.0]
- Fixed deduplication for dependency-provider rules so dependent validations run per blob
- Updated Artifactory rule entropy and added new artifactory rule
- Aliased "kingfisher self-update" as "kingfisher update"
- Map SARIF result levels from rule confidence
- Added tag selection support to the bash and PowerShell install scripts.

## [v1.71.0]
- Improved Report Viewer layout
- Improved Salesforce rule

## [v1.70.0]
- Added `--staged` argument to support new `pre-commit` behavior and added integration coverage to ensure validated secrets block commits when used as pre-commit hook
- Added new rules for AWS Bedrock, Voyage.ai, Posthog, Atlassian
- Added an embedded web-based report and access-map viewer via `kingfisher view` subcommand that can load JSON or JSONL reports passed on the CLI (or upload them in the browser) 
- Updated Jira create to gouqi, which supports Jira api v2 and v3

## [v1.69.0]
- Reduced per-match memory usage by compacting stored source locations and interning repeated capture names.
- Stored optional validation response bodies as boxed strings to avoid allocating empty payloads and to streamline validator caches.
- Parallelized git cloning based on the configured job count and begin scanning repositories as soon as each clone finishes to reduce end-to-end scan times.
- Combined per-repository results into a single aggregate summary after scans complete.
- Added initial access-map support and report viewer html file. Currently beta features.

## [v1.68.0]
- Fixed Bitbucket authenticated cloning bug

## [v1.67.0]
- Added checksum to GitLab rule
- Fixed deduplication to consider rule identifiers so overlapping patterns are not merged before validation
- After scan summaries, emit the styled outdated-version notice to stderr when a newer release is available
- Reduced false positives across a number of rules
- Updated Summary to include scan date, kingfisher version ran, and latest kingfisher version available

## [v1.66.0]
- Updating to support Bitbucket App Passwords
- Improved boundaries for several rules
- Added more rules

## [v1.65.0]
- Skip reporting MongoDB and Postgres findings when their connection strings cannot be parsed, even when validation is disabled.
- Improve MySQL detection by broadening URI coverage and adding live validation that skips clearly invalid connection strings.
- Added a helper to truncate validation response bodies only at UTF-8 character boundaries to prevent panics during validation.

## [v1.64.0]
- Fixed a bug when using --redact, that broke validation
- Added JDBC rule with validator
- Filter out empty 'KF_BITBUCKET_*' environment values when constructing the Bitbucket authentication configuration so blank variables no longer override valid credentials

## [v1.63.1]
- Updated allocator

## [v1.63.0]
- Fixed bug when retrieving some finding values and injecting them as TOKENS in the rule templates
- Improved Datadog rule
- Improved AWS rule

## [v1.62.0]
- Added `pattern_requirements` checks to rules, providing lightweight post-regex character-class validation without lookarounds. See docs/RULES.md for detail
- Added an `ignore_if_contains` option to `pattern_requirements` to drop matches containing case-insensitive placeholder words, with tests covering the new behavior.
- Updated rules to adopt the new `pattern_requirements` support.
- Added checksum comparisons to `pattern_requirements`, new `suffix`, `crc32`, and `base62` Liquid filters, and verbose logging so mismatched checksums are skipped with context rather than reported as findings.
- Split GitHub token detections into fine-grained/fixed-format variants and enforce checksum validation for modern GitHub token families (PAT, OAuth, App, refresh) while preserving legacy coverage.
- Added a rule for Zuplo tokens.
- Added checksum calculation for Confluent, GitHub, and Zuplo tokens, which can drastically reduce false positive reports.
- Improved OpsGenie validation.
- Automatically enable `--no-dedup` when `--manage-baseline` is supplied so baseline management keeps every finding.
- This release is focused on further improving detection accuracy, before even attempting to validate findings.
- Updated GitHub Actions CI for Windows and buildwin.bat script

## [v1.61.0]
- Fixed local filesystem scans to keep `open_path_as_is` enabled when opening Git repositories and only disable it for diff-based scans.
- Created Linux and Windows specific installer script
- Updated diff-focused scanning so `--branch-root-commit` can be provided alongside `--branch`, letting you diff from a chosen commit while targeting a specific branch tip (still defaulting back to the `--branch` ref when the commit is omitted).
- Updated rules

## [v1.60.0]
- Removed the `--bitbucket-username`, `--bitbucket-token`, and `--bitbucket-oauth-token` flags in favour of `KF_BITBUCKET_*` environment variables when authenticating to Bitbucket.
- Added provider-specific `kingfisher scan` subcommands (for example `kingfisher scan github …`) that translate into the legacy flags under the hood. The new layout keeps backwards compatibility while removing the wall of provider options from `kingfisher scan --help`.
- Updated the README so every provider example (GitHub, GitLab, Bitbucket, Azure Repos, Gitea, Hugging Face, Slack, Jira, Confluence, S3, GCS, Docker) uses the new subcommand style.
- Legacy provider flags (for example `--github-user`, `--gitlab-group`, `--bitbucket-workspace`, `--s3-bucket`) still work but now emit a deprecation warning to encourage migration to the new `kingfisher scan <provider>` flow.
- Kept the direct `kingfisher scan /path/to/dir` flow for local filesystem / local git repo scans while adding a `--list-only` switch to each provider subcommand so repository enumeration no longer requires the standalone `github repos`, `gitlab repos`, etc. commands.
- Removed the legacy top-level provider commands (`kingfisher github`, `kingfisher gitlab`, `kingfisher gitea`, `kingfisher bitbucket`, `kingfisher azure`, `kingfisher huggingface`) now that enumeration lives under `kingfisher scan <provider> --list-only`.

## [v1.59.0]
- Fixed `kingfisher scan github …` (and other provider-specific subcommands) so they no longer demand placeholder path arguments before the CLI accepts the request.
- Fixed `kingfisher scan` so that providing `--branch` without `--since-commit` now diffs the branch against the empty tree and scans every commit reachable from that branch.
- Added rules for meraki, duffel, finnhub, frameio, freshbooks, gitter, infracost, launchdarkly, lob, maxmind, messagebird, nytimes, prefect, scalingo, sendinblue, sentry, shippo, twitch, typeform

- ## [v1.58.0]
- Added first-class Hugging Face scanning support, including CLI enumeration, token authentication, and integration with remote scans.
- Condensed GitError formatting to report the exit status and the first informative lines from stdout/stderr, producing concise git clone failure logs.
- Added support for scanning Google Cloud Storage buckets via `--gcs-bucket`, including optional prefixes and service-account authentication.
- Added `--skip-aws-account` (now accepting comma-separated values) and `--skip-aws-account-file` to bypass live AWS validation for known canary/honey-token account IDs without triggering alerts. Kingfisher now ships with several canary AWS account IDs pre-seeded in the skip list and now reports matching findings as "Not Attempted" with the "Response" containing "(skip list entry)" so it's clear that validation was intentionally skipped and why.
  
## [v1.57.0]
- Added inline ignore directive detection to treat suppression tokens anywhere on surrounding lines, including multi-line handling
- Added a `--no-ignore` CLI flag to disable inline directives when you need every potential secret reported
- Added: repeatable `--ignore-comment <TOKEN>` flag to reuse inline directives from other scanners (for example `NOSONAR`, `kics-scan ignore`, `gitleaks:allow`, etc)
- Respect user color settings in update messages by using the same color helper as the main reporter, ensuring consistent output and no ANSI codes on update check, when color is disabled

## [v1.56.0]
- Fixed tree-sitter scanning bug where passing --no-base64 caused errors to be printed when the file type couldn’t be determined

## [v1.55.0]
- Added first-class Azure Repos support, including CLI commands, enumeration, and documentation updates
- Improved performance of tree-sitter parsing
- Updated Windows build script to ensure static binary is produced

## [v1.54.0]
- Added first-class Gitea support, including CLI commands, environment-based authentication, documentation, and integration with scans and repository enumeration.
- Populate the finding path from git blob metadata so history-derived secrets display their file location instead of an empty path
- Replaced Match::finding_id’s SHA1-based hashing with a fast xxh3_64 digest that keeps IDs deterministic while eliminating a hot-path SHA1 dependency

## [v1.53.0]
- Added first-class Bitbucket support, including CLI commands, authentication helpers, documentation, and integration testing.

## [v1.52.0]
- Enabled ANSI formatting in the tracing formatter whenever stderr is attached to a terminal so colorized updater messages render correctly instead of showing escape sequences. 
- Added a new CLI flag, `--user-agent-suffix` to allow developers to append additional information to the user-agent
- Removed the unused --rlimit-nofile flag

## [1.51.0]
- Added diff-only Git scanning via `--since-commit` and `--branch`, including remote-aware ref resolution so CI jobs can pair `--git-url` clones with pull request branches

## [1.50.0]
- Added `--github-exclude` and `--gitlab-exclude` options to skip specific repositories when scanning or listing GitHub and GitLab sources, including support for gitignore-style glob patterns

## [1.49.0]
- Enabled MongoDB URI validation
- AWS + GCP validators now respect HTTPS_PROXY and share a consistent user agent across AWS, GCP, and HTTP validation
- Increase max-file-size default to 256 mb (up from 64 mb)
- Improved AWS rule

## [1.48.0]
- Improved error message when self-update cannot find the current binary
- Optimized memory usage via string interning and extensive data sharing
- Replaced quadratic match filtering with a per-rule span map, fixing missed secrets in extremely large files and improving scan performance
- Support scanning extremely large files by chunking input into 1 GiB segments with small overlaps, avoiding vectorscan buffer limits while preserving match offsets
- Always use chunked vectorscan, eliminating the slow regex fallback for blobs over 4 GiB
- Skip Base64 scanning for blobs over 64 MB to avoid a second pass over massive files
- Increased max-file-size default to 64 MB (up from 25 MB)

## [1.47.0]
- MongoDB validator now validates `mongodb+srv://` URIs with a fast timeout instead of skipping them
- Improved rules: github oauth2, diffbot, mailchimp, aws
- Added validation to SauceLabs rule
- Added rules: shodan, bitly, flickr
- Decode Base64 blobs and scan their contents for secrets while skipping short strings for performance. This has a small performance impact and can be disabled with `--no-base64`

## [1.46.0]
- Improved rules: AWS, pem
- Added rule for Ollama, Weights and Biases, Cerebras, Friendli, Fireworks.ai, NVIDIA NIM, together.ai, zhipu
- Added `self-update` command to update the binary independently. Now supports updating over homebrew managed binary
- MongoDB validator now checks `mongodb+srv://` URIs with fast-fail timeouts

## [1.45.0]
- Added `--repo-artifacts` flag to scan repository issues, gists/snippets, and wikis when cloning via `--git-url`
- Added rules for sendbird, mattermost, langchain, notion
- JWT validation hardened to reject alg:none by default (only allowed if explicitly configured), require iss for OIDC/JWKS verification, ensuring "Active Credential" means cryptographically verified and time-valid, not just unexpired
- Updated the Git cloning logic to include all refs and minimize clone output, allowing Kingfisher to analyze pull request and deleted branch history

## [1.44.0]
- Fixed issue with self-update on Linux
- Reverted the change to json and jsonl outputs by rule
- Added `--skip-regex` and `--skip-word` flags to ignore secrets matching custom patterns or skipwords

## [1.43.0]
- Added rules for clearbit, kickbox, azure container registry, improved Azure Storage key
- Grouped JSON and JSONL outputs by rule, restoring `matches` arrays in reports

## [1.42.0]
- Fixed pagination issue when calling gitlab api
- Expanded directory exclusion handling to interpret plain patterns as prefixes, ensuring options like --exclude .git also skip all nested paths
- Updated baseline management to track encountered findings and remove entries that are no longer present, saving the baseline file whenever entries are pruned or new matches are added
- Added rules for authress, clickhouse, codecov, contentful, curl, dropbox, fly.io, hubspot, firecrawl
- Internal refactoring of rule loader, git enumerator, and filetype guesser
- Improved language detection

## [1.41.0]
- Added support for scanning gitlab subgroups, with `kingfisher scan --gitlab-group my-group --gitlab-include-subgroups`
- Added rule for Vercel

## [1.40.0]
- Dropped the “prevalidated” flag from rule definitions and validation logic so every finding now flows through the standard active/inactive/unknown pipeline, simplifying rule configuration and preventing special‑case bypasses
- Improved Tailscale api key detectors

## [1.39.0]
- Added support for scanning Confluence pages via `--confluence-url` and `--cql`

## [1.38.0]
- `--quiet` now suppresses scan summaries and rule statistics unless `--rule-stats` is explicitly provided
- Added X Consumer key detection and validation

## [1.37.0]
- GitLab: Matched GitLab group repository listings to glab by only enumerating projects that belong directly to each group, without automatically traversing subgroups

## [1.36.0]
- Fixed GitHub organization and GitLab group scans when using `--git-history=none`
- JWT tokens without both `iss` and `aud` are no longer reported as active credentials

## [1.35.0]
- Remote scans with `--git-history=none` now clone repositories with a working tree and scan the current files instead of erroring with "No inputs to scan".
- Fixed issue where `--redact` did not function properly
- Fixed validation logic for clarifai rule

## [1.34.0]
- Use system TLS root certificates to support self-hosted GitLab instances with internal CAs
- Added new rule: Coze personal access token
- Updated Supabase rule to detect project url's and validate their corresponding tokens

## [1.33.0]
- Fixed header precedence so custom HTTP validation headers like `Accept` are preserved
- Added new Heroku rule

## [1.32.0]
- Added support for scanning AWS S3 buckets via `--s3-bucket` and optional `--s3-prefix`
- Added `--role-arn` and `--aws-local-profile` flags for S3 authentication alongside `KF_AWS_KEY`/`KF_AWS_SECRET`
- Added progress bar for scanning s3 buckets
- Refactored output reporting and formatting logic

## [1.31.0]
- New rules: Telegram bot token, OpenWeatherMap, Apify, Groq
- New OpenAI detectors added (@joshlarsen)
- Fixed bug that broke validation when using unnamed group captures

## [1.30.0]
- Fixed validation caching for HTTP validators to include rendered headers so inactive secrets no longer appear active.
- Removed pre-commit installation hook, due to bugs

## [1.29.0]
- Fixed issue when more than 1 named capture group is used in a rule variable
- Added a new liquid template filters: `b64dec`
- Added custom validator for Coinbase, and a Coinbase rule that uses it

## [1.28.0]
- Added support for scanning Slack

## [1.27.0]
- Added Buildkite rule
- Added support for scanning Docker images via `--docker-image`

## [1.26.0]
- Added rule for ElevenLabs
- Added support for scanning Jira issues via a given JQL (Jira Query Language)

## [1.25.0]
- Fixed GitLab authentication bug
- Added pre-commit and pre-receive installation hooks
- MongoDB validator now skips `mongodb+srv://` URIs and returns a message that validation was skipped
- Fixed noisy Baseten rule

## [1.24.0]
- Now generating DEB and RPM packages
- Now releasing Docker images, and updated README
- Added rule for Scale, Deepgram, AssemblyAI


## [1.23.0]
- Updating GitHub Action to generate Docker image
- Added rules for Diffbot, ai21, baseten
- Fixed supabase rule
- Added 'alg' to JWT validation output

## [1.22.0]
- Added rules for Google Gemini AI, Cohere, Stability.ai, Replicate, Runway, Clarifai
- Upgraded dependencies

## [1.21.0]
- Improved Azure Storage rule
- Added rule to detect TravisCI encrypted values
- Added baseline feature with `--baseline-file` and `--manage-baseline` flags
- Introduced `--exclude` option for skipping paths
- Added tests covering baseline and exclude workflow
- Added validation for JWT tokens that checks `exp` and `nbf` claims
- JWT validation performs OpenID Connect discovery using the `iss` claim and verifies signatures via JWKS
- Removed `--ignore-tests` argument, because the `--exclude` flag provides more granular functionality
- DigitalOcean rule update
- Adafruit rule update

## [1.20.0]
- Removed confirmation prompt when user provides --self-update flag
- Added support for HTTP request bodies in rule validation 
- Added new liquid-rs filters: HmacSha1, IsoTimestampNoFracFilter, Replace
- Added rules for mistral, perplexity
- Added validation for Alibaba rule
- Set GIT_TERMINAL_PROMPT=0 when cloning git repos

## [1.19.0]
- JSON output was missing committer name and email
- Fixed Gitlab rule which was incorrectly identifying certain tokens as valid

## [1.18.1]
- Restored --version cli argument
- Added test for the argument

## [1.18.0]
- Added rules for DeepSeek, xAI
- Removed branding
- Added NOTICE file

## [1.17.1]
- Fixed broken sourcegraph rule
- Added test to prevent this and similar issues

## [1.17.0]
- Updated README to give proper attribution to Nosey Parker!
- Added rules for sonarcloud, sonarqube, sourcegraph, shopify, truenas, square, sendgrid, nasa, teamcity, truenas, shopify
- Introduced `--ignore-tests` flag – skip files/dirs whose path resembles tests (`test`, `spec`, `fixture`, `example`, `sample`), reducing noise.
## [1.16.0]
- Fix: HTML detection now requires both HTML content-type and "<html" tag, fixing webhook false negatives
- Removed cargo-nextest installation during test running
- Added rules for 1password, droneci

## [1.15.0]
- Ensuring temp files are cleaned up
- Applying visual style to the update check output
- Fixed bug in --self-update where it was looking for the incorrect binary name on GitHub releases
- Rule cleanup

## [1.14.0]
- Fixed several malformed rules
- Now validating that response_matcher is present in validation section of all rules

## [1.13.0]
- Added new rules for Planetscale, Postman, Openweather, opsgenie, pagerduty, pastebin, paypal, netlify, netrc, newrelic, ngrok, npm, nuget, mandrill, mapbox, microsoft teams, stripe, linkedin, mailchimp, mailgun, linear, line, huggingface, ibm cloud, intercom, ipstack, heroku, gradle, grafana
- Added `--rule-stats` command-line flag that will display rule performance statistics during a scan. Useful when creating or debugging rules


## [1.12.0] 
- Added automatic update checks using GitHub releases.
- New `--self-update` flag installs updates when available
- New `--no-update-check` flag disables update checks
- Updated rules

## [1.11.0] 2025-06-21
- Increased default value for number of scanning jobs to improve validation speed
- Fixed issue where some API responses (e.g. GitHub's `/user` endpoint) include required fields like `"name"` beyond the first 512 bytes. Truncating earlier causes `WordMatch` checks to fail even for active credentials. Increased the limit to keep a larger slice of the body while still bounding memory usage.

## [1.10.0] 2025-06-20
- Updated de-dupe fingerprint to include the content of the match
- Updated Makefile
- Adding GitHub Actions

## [1.9.0] 2025-06-16
- Initial public release of Kingfisher

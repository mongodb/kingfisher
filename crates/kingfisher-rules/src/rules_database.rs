use std::{
    env, fs,
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};
use kingfisher_vectorscan::{BlockDatabase, Error as VectorscanError, Flag, Pattern, Scan};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, debug_span, error, warn};
use xxhash_rust::xxh3::xxh3_128;

use crate::{
    betterleaks_filter::{
        BetterleaksFilterContext, BetterleaksFilterEngine, BetterleaksFilterLineCache,
        BetterleaksFilterOutcome, evaluate_filter_with_engine,
        evaluate_filter_with_engine_and_line_cache,
    },
    rule::{BetterleaksExpr, RULE_COMMENTS_PATTERN, Rule},
    rules::Rules,
    scanner_pool::ScannerPool,
};

#[cfg(windows)]
#[path = "rule_cache_security_windows.rs"]
mod cache_security_windows;

#[cfg(target_os = "macos")]
#[path = "rule_cache_security_macos.rs"]
mod cache_security_macos;

/// Compiled detection rules, source-path prefilters, and finding-filter helpers.
///
/// Reuse one database across scans and threads. Compile a loaded [`Rules`]
/// collection with [`Self::from_rule_collection`] to retain its source prefilter.
pub struct RulesDatabase {
    // pub(crate) rules: Vec<Rule,>,
    pub(crate) rules: Vec<Arc<Rule>>,
    pub(crate) anchored_regexes: Vec<Regex>,
    endpoint_regexes: Vec<OnceLock<Option<Regex>>>,
    #[cfg(feature = "__scanner-internals")]
    confirmation_maximum_lengths: Vec<OnceLock<ConfirmationLengths>>,
    pub(crate) self_identifying_flags: Vec<bool>,
    pub(crate) vsdb: BlockDatabase,
    vectorscan_prefilter_flags: Vec<bool>,
    betterleaks_rule_flags: Vec<bool>,
    has_non_betterleaks_rules: bool,
    betterleaks_prefilter: Option<BetterleaksPathPrefilter>,
    betterleaks_filter_engine: BetterleaksFilterEngine,
    cache_status: RuleCacheStatus,
}

/// Whether this database was successfully loaded from or persisted to disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleCacheStatus {
    /// Caching was not requested, was unavailable/unsafe, or its write failed.
    Bypassed,
    /// A valid cache entry supplied the compiled database.
    Loaded,
    /// Compilation succeeded and the resulting entry was persisted successfully.
    Stored,
}

/// The Betterleaks source-path prefilter compiled once into its own Vectorscan database.
///
/// Scanners retain one Vectorscan scratch arena per worker thread. This keeps the prefilter ahead
/// of the main content database without recompiling its regex list for every source path.
struct BetterleaksPathPrefilter {
    expression: BetterleaksExpr,
    scanners: ScannerPool,
}

impl BetterleaksPathPrefilter {
    fn compile(expression: BetterleaksExpr) -> Result<Self> {
        let patterns = extract_path_prefilter_patterns(&expression)?
            .into_iter()
            .enumerate()
            .map(|(id, pattern)| {
                Ok(Pattern::new(pattern.into_bytes(), Flag::default(), Some(id.try_into()?)))
            })
            .collect::<Result<Vec<_>>>()?;
        if patterns.is_empty() {
            bail!("Betterleaks path prefilter contains no patterns");
        }
        let database = Arc::new(
            BlockDatabase::new(patterns)
                .context("compile the Betterleaks path prefilter with Vectorscan")?,
        );
        Ok(Self { expression, scanners: ScannerPool::new(database) })
    }

    #[inline]
    fn is_match(&self, path: &str) -> Result<bool> {
        let mut matched = false;
        self.scanners.try_with(|scanner| {
            scanner.scan(path.as_bytes(), |_id, _from, _to, _flags| {
                matched = true;
                Scan::Terminate
            })
        })??;
        Ok(matched)
    }
}

fn extract_path_prefilter_patterns(expression: &BetterleaksExpr) -> Result<Vec<String>> {
    let expression = match expression {
        BetterleaksExpr::Chain { node } | BetterleaksExpr::Predicate { node } => node.as_ref(),
        expression => expression,
    };
    let BetterleaksExpr::Call { callee, arguments } = expression else {
        bail!("Betterleaks path prefilter must be a matchesAny call");
    };
    let name = betterleaks_expression_name(callee)
        .ok_or_else(|| anyhow!("Betterleaks path prefilter uses a dynamic function call"))?;
    if !matches!(name.as_str(), "matchesAny" | "filter.matchesAny") {
        bail!("unsupported Betterleaks path prefilter function {name:?}");
    }
    let [input, patterns] = arguments.as_slice() else {
        bail!("Betterleaks path prefilter matchesAny call must have two arguments");
    };
    if betterleaks_expression_name(input).as_deref() != Some("attributes.path") {
        bail!("Betterleaks path prefilter must match attributes.path");
    }
    let BetterleaksExpr::Array { nodes } = patterns else {
        bail!("Betterleaks path prefilter patterns must be a literal array");
    };
    nodes
        .iter()
        .map(|node| match node {
            BetterleaksExpr::String { value } => Ok(value.clone()),
            _ => bail!("Betterleaks path prefilter patterns must be string literals"),
        })
        .collect()
}

fn betterleaks_expression_name(expression: &BetterleaksExpr) -> Option<String> {
    match expression {
        BetterleaksExpr::Identifier { value } => Some(value.clone()),
        BetterleaksExpr::Member { node, property, .. } => {
            let parent = betterleaks_expression_name(node)?;
            let BetterleaksExpr::String { value } = property.as_ref() else {
                return None;
            };
            Some(format!("{parent}.{value}"))
        }
        BetterleaksExpr::Chain { node } => betterleaks_expression_name(node),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct RuleCacheConfig {
    cache_dir: PathBuf,
}

impl RuleCacheConfig {
    /// Select a trusted cache directory. Unsafe locations are ignored during construction.
    ///
    /// Entries contain native Vectorscan bytecode. The directory and its ancestors must
    /// prevent modification by other users. An empty path disables caching.
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self { cache_dir: cache_dir.into() }
    }

    /// Use the explicit directory, `KF_RULE_CACHE_DIR`, or a per-user OS cache directory.
    ///
    /// When no user cache directory can be resolved, caching is disabled instead of
    /// falling back to a shared temporary directory.
    pub fn from_dir_or_env(cache_dir: Option<PathBuf>) -> Self {
        Self::new(cache_dir.or_else(default_rule_cache_dir).unwrap_or_default())
    }

    /// The configured path, or an empty path when no per-user directory is available.
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Whether a cache location was configured. Trust and availability are checked on use.
    pub fn is_enabled(&self) -> bool {
        !self.cache_dir.as_os_str().is_empty()
    }
}

const CACHE_MAGIC: &[u8] = b"KFRULEDB";
const CACHE_FORMAT_VERSION: u32 = 6;
const MAX_CACHE_HEADER_BYTES: usize = 1024 * 1024;
const MAX_CACHE_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
pub const DEFAULT_RULE_CACHE_MAX_ENTRIES: usize = 10;
pub const DEFAULT_RULE_CACHE_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CacheHeader {
    format_version: u32,
    cache_key: String,
    rule_count: usize,
    vectorscan_version: String,
    target: String,
    database_kind: String,
    /// Corruption check before passing bytes to the native deserializer; not authentication.
    /// Legacy headers remain readable for pruning; they are never loaded without a digest.
    #[serde(default)]
    database_sha256: String,
    #[serde(default)]
    prefilter_rule_indices: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct RuleCachePruneConfig {
    pub max_entries: usize,
    /// Minimum age for pruning. Recognized temporary files have no entry floor
    /// and use at least a one-day grace period to protect concurrent writers.
    pub max_age: Duration,
    pub protected_cache_key: Option<String>,
    pub dry_run: bool,
}

impl Default for RuleCachePruneConfig {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_RULE_CACHE_MAX_ENTRIES,
            max_age: DEFAULT_RULE_CACHE_MAX_AGE,
            protected_cache_key: None,
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleCachePruneSummary {
    pub scanned_entries: usize,
    pub valid_entries: usize,
    pub invalid_entries: usize,
    pub candidate_entries: usize,
    pub candidate_bytes: u64,
    pub removed_entries: usize,
    pub removed_bytes: u64,
    pub protected_entries: usize,
    pub removal_errors: usize,
}

pub fn format_regex_pattern(pattern: &str) -> String {
    // Remove comments and whitespace while preserving the regex pattern
    let no_comment_pattern = RULE_COMMENTS_PATTERN.replace_all(pattern, "");
    // flattens multi-line regex into a single line
    no_comment_pattern
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<&str>>()
        .join("")
}

pub fn compute_rule_cache_key(rules: &[Rule]) -> String {
    compute_cache_key_from_rules(rules.iter())
}

/// Compile every rule exactly when possible. If one expression exceeds a Vectorscan compiler
/// limit, retry only that expression in candidate-prefilter mode. Confidence is reporting
/// metadata and must not select a slower matching engine.
fn compile_vectorscan_database(rules: &[Arc<Rule>]) -> Result<(BlockDatabase, Vec<bool>)> {
    let mut prefilter_flags = vec![false; rules.len()];

    loop {
        let patterns = rules
            .iter()
            .enumerate()
            .map(|(id, rule)| {
                let flags = if prefilter_flags[id] { Flag::PREFILTER } else { Flag::default() };
                Pattern::new(
                    rule.syntax().pattern.clone().into_bytes(),
                    flags,
                    Some(id.try_into().expect("rule count fits in u32")),
                )
            })
            .collect();

        match BlockDatabase::new(patterns) {
            Ok(database) => return Ok((database, prefilter_flags)),
            Err(VectorscanError::HyperscanCompile(message, expression)) if expression >= 0 => {
                let index = expression as usize;
                let Some(rule) = rules.get(index) else {
                    bail!(
                        "Vectorscan reported an out-of-range failing expression {expression}: \
                         {message}"
                    );
                };
                if prefilter_flags[index] {
                    bail!(
                        "Vectorscan could not compile rule {} even in candidate-prefilter mode: \
                         {message}",
                        rule.id()
                    );
                }
                warn!(
                    rule_id = rule.id(),
                    %message,
                    "Exact Vectorscan compilation exceeded an engine limit; retrying this rule \
                     in candidate-prefilter mode"
                );
                prefilter_flags[index] = true;
            }
            Err(error) => return Err(error).context("compile rules with Vectorscan"),
        }
    }
}

pub fn prune_rule_cache(
    cache: &RuleCacheConfig,
    config: &RuleCachePruneConfig,
) -> RuleCachePruneSummary {
    match prune_rule_cache_at(cache, config, SystemTime::now()) {
        Ok(summary) => summary,
        Err(err) => {
            debug!(
                cache_dir = %cache.cache_dir.display(),
                %err,
                "Failed to inspect Vectorscan rule cache for pruning"
            );
            RuleCachePruneSummary::default()
        }
    }
}

impl RulesDatabase {
    pub fn get_regex_by_rule_id(&self, rule_id: &str) -> Option<&Regex> {
        self.rules
            .iter()
            .position(|r| r.syntax().id == rule_id)
            .and_then(|index| self.anchored_regexes.get(index))
    }

    pub fn get_rule_by_finding_fingerprint(&self, finding_fingerprint: &str) -> Option<Arc<Rule>> {
        self.rules.iter().find(|r| r.finding_sha1_fingerprint() == finding_fingerprint).cloned()
    }

    pub fn get_rule_by_text_id(&self, text_id: &str) -> Option<Arc<Rule>> {
        self.rules.iter().find(|r| r.id() == text_id).cloned()
    }

    pub fn get_rule_by_name(&self, name: &str) -> Option<Arc<Rule>> {
        self.rules.iter().find(|r| r.name() == name).cloned()
    }

    /// Compile explicit rules without a database-level source prefilter.
    ///
    /// # Errors
    ///
    /// Returns an error if rule regexes, source-path prefilters, or finding-filter
    /// expressions cannot be compiled, or the native database cannot be allocated.
    pub fn from_rules(rules: Vec<Rule>) -> Result<Self> {
        Self::from_rules_with_betterleaks_prefilter(rules, None)
    }

    /// Compile a loaded rule collection while preserving its database-level metadata.
    ///
    /// # Errors
    ///
    /// Returns rule compilation or native allocation errors, as documented by
    /// [`Self::from_rules`].
    pub fn from_rule_collection(rules: Rules) -> Result<Self> {
        let Rules { rules, betterleaks_prefilter } = rules;
        Self::from_rules_with_betterleaks_prefilter(
            rules.into_values().map(Rule::new).collect(),
            betterleaks_prefilter,
        )
    }

    /// Compile explicit rules with an optional imported source-path prefilter.
    ///
    /// # Errors
    ///
    /// Returns an error if rule regexes, source-path prefilters, or finding-filter
    /// expressions cannot be compiled, or the native database cannot be allocated.
    pub fn from_rules_with_betterleaks_prefilter(
        rules: Vec<Rule>,
        betterleaks_prefilter: Option<BetterleaksExpr>,
    ) -> Result<Self> {
        let rules: Vec<Arc<Rule>> = rules.into_iter().map(Arc::new).collect();
        let betterleaks_prefilter =
            betterleaks_prefilter.map(BetterleaksPathPrefilter::compile).transpose()?;
        let betterleaks_filter_engine = BetterleaksFilterEngine::compile(
            rules.iter().filter_map(|rule| rule.betterleaks_filter()),
        )?;
        Self::from_arc_rules(rules, betterleaks_prefilter, betterleaks_filter_engine)
    }

    /// Compile explicit rules using a reusable native-database cache.
    ///
    /// # Errors
    ///
    /// Returns an error if rule regexes, source-path prefilters, or finding-filter
    /// expressions cannot be compiled, or the native database cannot be allocated.
    pub fn from_rules_with_cache(rules: Vec<Rule>, cache: &RuleCacheConfig) -> Result<Self> {
        Self::from_rules_with_cache_and_betterleaks_prefilter(rules, cache, None)
    }

    /// Compile and cache a loaded rule collection while preserving database-level metadata.
    ///
    /// Reuse entries from the same native engine build, architecture, pointer width, and
    /// endianness. The exact binding/native crate versions and full engine build version
    /// are keyed; native deserialization additionally checks CPU compatibility. Unsafe,
    /// unavailable, corrupt, or incompatible caches fall back to compilation; writes are
    /// best effort. Only the main content database is persisted, not confirmation regexes
    /// or collection-level path/finding filters. See [`RuleCacheConfig`] for directory trust.
    ///
    /// # Errors
    ///
    /// Returns rule compilation or native allocation errors, as documented by
    /// [`Self::from_rules`].
    pub fn from_rule_collection_with_cache(rules: Rules, cache: &RuleCacheConfig) -> Result<Self> {
        let Rules { rules, betterleaks_prefilter } = rules;
        Self::from_rules_with_cache_and_betterleaks_prefilter(
            rules.into_values().map(Rule::new).collect(),
            cache,
            betterleaks_prefilter,
        )
    }

    /// Compile explicit rules with a cache and an optional source-path prefilter.
    ///
    /// # Errors
    ///
    /// Returns an error if rule regexes, source-path prefilters, or finding-filter
    /// expressions cannot be compiled, or the native database cannot be allocated.
    pub fn from_rules_with_cache_and_betterleaks_prefilter(
        rules: Vec<Rule>,
        cache: &RuleCacheConfig,
        betterleaks_prefilter: Option<BetterleaksExpr>,
    ) -> Result<Self> {
        let rules: Vec<Arc<Rule>> = rules.into_iter().map(Arc::new).collect();
        let betterleaks_prefilter =
            betterleaks_prefilter.map(BetterleaksPathPrefilter::compile).transpose()?;
        let betterleaks_filter_engine = BetterleaksFilterEngine::compile(
            rules.iter().filter_map(|rule| rule.betterleaks_filter()),
        )?;
        Self::from_arc_rules_with_cache(
            rules,
            cache,
            betterleaks_prefilter,
            betterleaks_filter_engine,
        )
    }

    fn from_arc_rules(
        rules: Vec<Arc<Rule>>,
        betterleaks_prefilter: Option<BetterleaksPathPrefilter>,
        betterleaks_filter_engine: BetterleaksFilterEngine,
    ) -> Result<Self> {
        let _span = debug_span!("RulesDatabase::from_rules").entered();
        if rules.is_empty() {
            bail!("No rules to compile");
        }
        let t1 = Instant::now();
        let (vsdb, vectorscan_prefilter_flags) = compile_vectorscan_database(&rules)?;
        let d1 = t1.elapsed().as_secs_f64();
        let (anchored_regexes, d2) = Self::compile_regexes(&rules)?;
        let self_identifying_flags = Self::build_self_identifying_flags(&rules);
        let betterleaks_rule_flags = Self::build_betterleaks_rule_flags(&rules);
        let has_non_betterleaks_rules = betterleaks_rule_flags.contains(&false);
        debug!("Compiled {} rules: vectorscan {}s; regex {}s", rules.len(), d1, d2);
        Ok(RulesDatabase {
            endpoint_regexes: (0..rules.len()).map(|_| OnceLock::new()).collect(),
            #[cfg(feature = "__scanner-internals")]
            confirmation_maximum_lengths: (0..rules.len()).map(|_| OnceLock::new()).collect(),
            rules,
            vsdb,
            anchored_regexes,
            self_identifying_flags,
            vectorscan_prefilter_flags,
            betterleaks_rule_flags,
            has_non_betterleaks_rules,
            betterleaks_prefilter,
            betterleaks_filter_engine,
            cache_status: RuleCacheStatus::Bypassed,
        })
    }

    fn from_arc_rules_with_cache(
        rules: Vec<Arc<Rule>>,
        cache: &RuleCacheConfig,
        betterleaks_prefilter: Option<BetterleaksPathPrefilter>,
        betterleaks_filter_engine: BetterleaksFilterEngine,
    ) -> Result<Self> {
        let _span = debug_span!("RulesDatabase::from_rules_with_cache").entered();
        if rules.is_empty() {
            bail!("No rules to compile");
        }

        if !cache.is_enabled() {
            debug!("No per-user rule cache directory available; compiling without disk caching");
            return Self::from_arc_rules(rules, betterleaks_prefilter, betterleaks_filter_engine);
        }
        if let Err(err) = prepare_rule_cache_dir(&cache.cache_dir) {
            warn!(cache_dir = %cache.cache_dir.display(), %err, "Ignoring unsafe or unavailable rule cache directory");
            return Self::from_arc_rules(rules, betterleaks_prefilter, betterleaks_filter_engine);
        }

        let cache_key = compute_cache_key(&rules);
        let cache_path = cache.cache_dir.join(format!("{cache_key}.vscdb"));
        let mut header = CacheHeader {
            format_version: CACHE_FORMAT_VERSION,
            cache_key,
            rule_count: rules.len(),
            vectorscan_version: cache_vectorscan_version(),
            target: cache_target(),
            database_kind: "block".to_string(),
            database_sha256: String::new(),
            prefilter_rule_indices: Vec::new(),
        };

        debug!(
            cache_dir = %cache.cache_dir.display(),
            cache_path = %cache_path.display(),
            rule_count = rules.len(),
            cache_key = %header.cache_key,
            "Using Vectorscan rule cache"
        );
        let t1 = Instant::now();
        if let Some((vsdb, cached_header)) = load_cached_vectorscan_db(&cache_path, &header) {
            let d1 = t1.elapsed().as_secs_f64();
            let (anchored_regexes, d2) = Self::compile_regexes(&rules)?;
            let self_identifying_flags = Self::build_self_identifying_flags(&rules);
            let betterleaks_rule_flags = Self::build_betterleaks_rule_flags(&rules);
            let has_non_betterleaks_rules = betterleaks_rule_flags.contains(&false);
            let mut vectorscan_prefilter_flags = vec![false; rules.len()];
            for index in cached_header.prefilter_rule_indices {
                let flag = vectorscan_prefilter_flags
                    .get_mut(index)
                    .expect("cache loader checked the prefilter rule index");
                *flag = true;
            }
            debug!(
                "Loaded {} rules from Vectorscan cache: cache {}s; regex {}s",
                rules.len(),
                d1,
                d2
            );
            return Ok(RulesDatabase {
                endpoint_regexes: (0..rules.len()).map(|_| OnceLock::new()).collect(),
                #[cfg(feature = "__scanner-internals")]
                confirmation_maximum_lengths: (0..rules.len()).map(|_| OnceLock::new()).collect(),
                rules,
                vsdb,
                anchored_regexes,
                self_identifying_flags,
                vectorscan_prefilter_flags,
                betterleaks_rule_flags,
                has_non_betterleaks_rules,
                betterleaks_prefilter,
                betterleaks_filter_engine,
                cache_status: RuleCacheStatus::Loaded,
            });
        }

        let mut db = Self::from_arc_rules(rules, betterleaks_prefilter, betterleaks_filter_engine)?;
        header.prefilter_rule_indices = db
            .vectorscan_prefilter_flags
            .iter()
            .enumerate()
            .filter_map(|(index, enabled)| enabled.then_some(index))
            .collect();
        if store_cached_vectorscan_db(&cache_path, &header, db.vectorscan_db()) {
            db.cache_status = RuleCacheStatus::Stored;
        }
        Ok(db)
    }

    fn compile_regexes(rules: &[Arc<Rule>]) -> Result<(Vec<Regex>, f64)> {
        let t2 = Instant::now();
        let mut anchored_regexes = Vec::with_capacity(rules.len());
        for rule in rules {
            match rule.syntax().as_regex() {
                Ok(regex) => anchored_regexes.push(regex),
                Err(e) => {
                    error!(
                        "Failed to compile Regex for rule '{}' (ID: {}): {}",
                        rule.name(),
                        rule.id(),
                        e
                    );
                    return Err(anyhow!(
                        "Failed to compile Regex for rule '{}' (ID: {}): {}",
                        rule.name(),
                        rule.id(),
                        e
                    ));
                }
            }
        }
        let d2 = t2.elapsed().as_secs_f64();
        Ok((anchored_regexes, d2))
    }

    #[inline]
    pub fn num_rules(&self) -> usize {
        self.rules.len()
    }

    /// Report the cache outcome so explicit prewarming can require persistence.
    /// Ordinary scanning still succeeds when the cache is bypassed.
    pub fn cache_status(&self) -> RuleCacheStatus {
        self.cache_status
    }

    #[inline]
    pub fn get_rule(&self, index: usize) -> Option<Arc<Rule>> {
        self.rules.get(index).cloned()
    }

    pub fn rules(&self) -> &[Arc<Rule>] {
        &self.rules
    }

    /// Returns a reference to the Vectorscan database.
    #[inline]
    pub fn vectorscan_db(&self) -> &BlockDatabase {
        &self.vsdb
    }

    /// Return whether Vectorscan uses an approximate candidate expression for this rule.
    ///
    /// Exact Rust-regex confirmation is required for these candidates because their complete
    /// expression exceeds Vectorscan's exact state limit.
    #[inline]
    pub fn uses_vectorscan_prefilter(&self, index: usize) -> bool {
        self.vectorscan_prefilter_flags.get(index).copied().unwrap_or(false)
    }

    /// Lazily compile an endpoint regex for candidate confirmation. If wrapping
    /// exceeds the regex compiler's limit, callers retain the original search.
    pub fn endpoint_regex(&self, index: usize) -> Option<&Regex> {
        let rule = self.rules.get(index)?;
        self.endpoint_regexes
            .get(index)?
            .get_or_init(|| match rule.syntax().as_endpoint_regex() {
                Ok(regex) => Some(regex),
                Err(error) => {
                    debug!(rule_id = rule.id(), %error, "Using original candidate confirmation");
                    None
                }
            })
            .as_ref()
    }

    /// Cached safe tail bound for the rule's byte regex, compiled with Unicode disabled.
    /// `None` retains the original search for unbounded or empty-match expressions.
    #[cfg(feature = "__scanner-internals")]
    #[doc(hidden)]
    pub fn confirmation_maximum_len(&self, index: usize) -> Option<usize> {
        let regex = self.anchored_regexes.get(index)?;
        self.confirmation_maximum_lengths
            .get(index)?
            .get_or_init(|| confirmation_maximum_lengths(regex))
            .safe_tail
    }

    /// Certify positive-width, assertion-free rule expressions for indexed prefix reuse.
    /// Generic regex callers must remain conservative: this follows the rule builder flags.
    #[cfg(feature = "__scanner-internals")]
    #[doc(hidden)]
    pub fn confirmation_prefix_stable(&self, index: usize) -> bool {
        self.anchored_regexes
            .get(index)
            .zip(self.confirmation_maximum_lengths.get(index))
            .is_some_and(|(regex, metadata)| {
                metadata.get_or_init(|| confirmation_maximum_lengths(regex)).prefix_stable
            })
    }

    /// Cached maximum consuming match length for endpoint searches, excluding unbounded runs.
    #[cfg(feature = "__scanner-internals")]
    #[doc(hidden)]
    pub fn confirmation_match_maximum_len(&self, index: usize) -> Option<usize> {
        let regex = self.anchored_regexes.get(index)?;
        self.confirmation_maximum_lengths
            .get(index)?
            .get_or_init(|| confirmation_maximum_lengths(regex))
            .full_match
    }

    /// Original regexes for full-content searches. The historical method name is
    /// retained for compatibility; these regexes are not endpoint-constrained.
    #[inline]
    pub fn anchored_regexes(&self) -> &[Regex] {
        &self.anchored_regexes
    }

    /// Return true when Betterleaks' database-level source prefilter excludes this path.
    ///
    /// # Errors
    ///
    /// Returns native scratch allocation, scanner borrowing, or matching errors.
    #[inline]
    pub fn is_path_prefiltered(&self, path: &str) -> Result<bool> {
        self.betterleaks_prefilter.as_ref().map_or(Ok(false), |prefilter| prefilter.is_match(path))
    }

    /// Return whether the rule at `index` was imported from Betterleaks.
    #[inline]
    pub fn is_betterleaks_rule(&self, index: usize) -> bool {
        self.betterleaks_rule_flags.get(index).copied().unwrap_or(false)
    }

    /// Return whether this database contains rules not governed by the Betterleaks path prefilter.
    #[inline]
    pub fn has_non_betterleaks_rules(&self) -> bool {
        self.has_non_betterleaks_rules
    }

    /// The build-parsed Betterleaks source prefilter, if Betterleaks rules are active.
    pub fn betterleaks_prefilter(&self) -> Option<&BetterleaksExpr> {
        self.betterleaks_prefilter.as_ref().map(|prefilter| &prefilter.expression)
    }

    /// Evaluate an imported Betterleaks finding filter with the database's precompiled
    /// Vectorscan helper patterns.
    ///
    /// # Errors
    ///
    /// Returns expression evaluation errors or native allocation/matching errors.
    pub fn evaluate_betterleaks_filter(
        &self,
        expression: &BetterleaksExpr,
        context: &BetterleaksFilterContext<'_>,
    ) -> Result<BetterleaksFilterOutcome> {
        evaluate_filter_with_engine(expression, context, &self.betterleaks_filter_engine)
    }

    /// Internal scanner reuse of fixed regex results for one immutable source buffer.
    /// `line_range` must identify exactly `context.line` within that buffer; create
    /// a fresh cache for each raw or decoded buffer.
    #[doc(hidden)]
    pub fn evaluate_betterleaks_filter_with_line_cache(
        &self,
        expression: &BetterleaksExpr,
        context: &BetterleaksFilterContext<'_>,
        line_range: std::ops::Range<usize>,
        cache: &mut BetterleaksFilterLineCache,
    ) -> Result<BetterleaksFilterOutcome> {
        evaluate_filter_with_engine_and_line_cache(
            expression,
            context,
            &self.betterleaks_filter_engine,
            line_range,
            Some(cache),
        )
    }

    /// Returns true when the rule at `index` is recognised as
    /// self-identifying by literal pattern shape (e.g. `GHP_`, `AIzaSy`,
    /// `xox[pbarose]`, PEM envelopes, Slack webhook URLs). Self-identifying
    /// rules bypass structural context gating — their regex shape already
    /// provides strong precision.
    #[inline]
    pub fn is_rule_self_identifying(&self, index: usize) -> bool {
        self.self_identifying_flags.get(index).copied().unwrap_or(false)
    }

    fn build_self_identifying_flags(rules: &[Arc<Rule>]) -> Vec<bool> {
        rules
            .iter()
            .map(|rule| {
                has_self_identifying_shape(
                    &format_regex_pattern(&rule.syntax().pattern).to_lowercase(),
                )
            })
            .collect()
    }

    fn build_betterleaks_rule_flags(rules: &[Arc<Rule>]) -> Vec<bool> {
        rules.iter().map(|rule| rule.id().starts_with("betterleaks.")).collect()
    }
}

fn default_rule_cache_dir() -> Option<PathBuf> {
    default_rule_cache_dir_from(non_empty_env_path)
}

fn default_rule_cache_dir_from(get_path: impl Fn(&str) -> Option<PathBuf>) -> Option<PathBuf> {
    if let Some(path) = get_path("KF_RULE_CACHE_DIR") {
        return Some(path);
    }

    if cfg!(windows) {
        if let Some(path) = get_path("LOCALAPPDATA") {
            return Some(path.join("Kingfisher").join("rule-cache"));
        }
        if let Some(path) = get_path("USERPROFILE") {
            return Some(path.join("AppData").join("Local").join("Kingfisher").join("rule-cache"));
        }
    }

    if cfg!(target_os = "macos")
        && let Some(path) = get_path("HOME")
    {
        return Some(path.join("Library").join("Caches").join("kingfisher").join("rule-cache"));
    }

    if let Some(path) = get_path("XDG_CACHE_HOME") {
        return Some(path.join("kingfisher").join("rule-cache"));
    }

    if let Some(path) = get_path("HOME") {
        return Some(path.join(".cache").join("kingfisher").join("rule-cache"));
    }

    None
}

fn non_empty_env_path(name: &str) -> Option<PathBuf> {
    let value = env::var_os(name)?;
    if value.is_empty() { None } else { Some(PathBuf::from(value)) }
}

fn prepare_rule_cache_dir(path: &Path) -> Result<()> {
    // Do not chmod an existing directory: a configured shared location must be rejected,
    // and changing permissions on a caller's directory would hide that configuration error.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    }
    #[cfg(windows)]
    cache_security_windows::create_directory(path)?;
    #[cfg(not(any(unix, windows)))]
    fs::create_dir_all(path)?;
    verify_rule_cache_dir(path)
}

fn verify_rule_cache_dir(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("cache location must be a directory, not a symlink");
    }
    #[cfg(target_os = "macos")]
    cache_security_macos::verify_path(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid() has no arguments or memory-safety preconditions.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
            bail!(
                "cache directory must be owned by the current user and not writable by group or others"
            );
        }
        let absolute =
            if path.is_absolute() { path.to_path_buf() } else { env::current_dir()?.join(path) };
        // Canonicalization alone would hide a replaceable symlink on the supplied
        // route (for example /tmp/someone-elses-link -> a private cache directory).
        let mut route_child_owner = uid;
        for ancestor in absolute.ancestors().skip(1) {
            let metadata = fs::symlink_metadata(ancestor)?;
            if metadata.uid() != uid && metadata.uid() != 0 {
                bail!("cache directory route is owned by another user");
            }
            if !metadata.file_type().is_symlink()
                && metadata.mode() & 0o022 != 0
                && !(metadata.mode() & 0o1000 != 0
                    && (route_child_owner == uid || route_child_owner == 0))
            {
                bail!("cache directory route is writable by group or others");
            }
            route_child_owner = metadata.uid();
            #[cfg(target_os = "macos")]
            cache_security_macos::verify_path(ancestor)?;
        }
        let canonical = fs::canonicalize(path)?;
        let mut child_owner = uid;
        for ancestor in canonical.ancestors().skip(1) {
            let metadata = fs::metadata(ancestor)?;
            if metadata.uid() != uid && metadata.uid() != 0 {
                bail!("cache directory ancestor is owned by another user");
            }
            // A sticky ancestor protects children owned by this user or trusted root. Other
            // writable ancestors could substitute the directory despite its private mode.
            if metadata.mode() & 0o022 != 0
                && !(metadata.mode() & 0o1000 != 0 && (child_owner == uid || child_owner == 0))
            {
                bail!("cache directory ancestor is writable by group or others");
            }
            child_owner = metadata.uid();
            #[cfg(target_os = "macos")]
            cache_security_macos::verify_path(ancestor)?;
        }
    }
    #[cfg(windows)]
    cache_security_windows::verify_directory(path)?;
    #[cfg(not(any(unix, windows)))]
    bail!("cache directory ownership verification is unavailable on this platform");
    Ok(())
}

fn open_cache_file(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Bind validation to the open inode, preventing a symlink substitution between
        // the permission check and read. The trusted parent prevents rename attacks.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).with_context(|| format!("open {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("cache entry must be a regular file");
    }
    if metadata.len() > MAX_CACHE_ENTRY_BYTES {
        bail!("cache entry exceeds the maximum supported size");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid() has no arguments or memory-safety preconditions.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            bail!(
                "cache entry must be owned by the current user and not writable by group or others"
            );
        }
    }
    #[cfg(windows)]
    cache_security_windows::verify_file(path, &metadata)?;
    #[cfg(target_os = "macos")]
    cache_security_macos::verify_file(&file)?;
    Ok(file)
}

fn compute_cache_key(rules: &[Arc<Rule>]) -> String {
    compute_cache_key_from_rules(rules.iter().map(|rule| rule.as_ref()))
}

fn compute_cache_key_from_rules<'a>(rules: impl IntoIterator<Item = &'a Rule>) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(format!("cache-format={CACHE_FORMAT_VERSION}\n").as_bytes());
    input.extend_from_slice(format!("vectorscan={}\n", cache_vectorscan_version()).as_bytes());
    input.extend_from_slice(format!("target={}\n", cache_target()).as_bytes());
    input.extend_from_slice(b"mode=block\n");
    for (index, rule) in rules.into_iter().enumerate() {
        input.extend_from_slice(index.to_string().as_bytes());
        input.push(0);
        input.extend_from_slice(rule.id().as_bytes());
        input.push(0);
        input.extend_from_slice(rule.syntax().pattern.as_bytes());
        input.push(0xff);
    }
    format!("{:032x}", xxh3_128(&input))
}

#[derive(Debug)]
struct CacheEntry {
    path: PathBuf,
    cache_key: String,
    modified: SystemTime,
    size: u64,
}

fn prune_rule_cache_at(
    cache: &RuleCacheConfig,
    config: &RuleCachePruneConfig,
    now: SystemTime,
) -> Result<RuleCachePruneSummary> {
    let mut summary = RuleCachePruneSummary::default();
    if !cache.is_enabled() || !cache.cache_dir.exists() {
        return Ok(summary);
    }
    verify_rule_cache_dir(&cache.cache_dir)?;
    let read_dir = match fs::read_dir(&cache.cache_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(summary),
        Err(err) => {
            return Err(err).with_context(|| format!("read {}", cache.cache_dir.display()));
        }
    };

    let mut entries = Vec::new();
    let mut temporary_entries = Vec::new();
    for entry in read_dir {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                debug!(%err, "Failed to read Vectorscan rule cache directory entry");
                continue;
            }
        };
        let path = entry.path();
        let temporary = is_cache_temp_path(&path);
        if !temporary && path.extension().and_then(|ext| ext.to_str()) != Some("vscdb") {
            continue;
        }
        summary.scanned_entries += 1;

        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => continue,
            Err(err) => {
                debug!(path = %path.display(), %err, "Failed to stat Vectorscan rule cache entry");
                summary.invalid_entries += 1;
                continue;
            }
        };
        if temporary {
            // Never prune recent writers, even with an aggressive configured age.
            // Temporary entries have no retention floor or protected cache key.
            let age = now.duration_since(metadata.modified()?).unwrap_or_default();
            if age > config.max_age.max(Duration::from_secs(24 * 60 * 60)) {
                temporary_entries.push(CacheEntry {
                    path,
                    cache_key: String::new(),
                    modified: metadata.modified()?,
                    size: metadata.len(),
                });
            }
            continue;
        }
        let header = match read_cached_vectorscan_header(&path) {
            Ok(header) => header,
            Err(err) => {
                debug!(
                    path = %path.display(),
                    %err,
                    "Ignoring invalid Vectorscan rule cache entry during pruning"
                );
                summary.invalid_entries += 1;
                continue;
            }
        };
        entries.push(CacheEntry {
            path,
            cache_key: header.cache_key,
            modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            size: metadata.len(),
        });
    }

    summary.valid_entries = entries.len();
    entries.sort_by(|a, b| b.modified.cmp(&a.modified).then_with(|| a.path.cmp(&b.path)));
    for entry in entries.iter().skip(config.max_entries).chain(&temporary_entries) {
        if config.protected_cache_key.as_deref() == Some(entry.cache_key.as_str()) {
            summary.protected_entries += 1;
            continue;
        }
        let age = now.duration_since(entry.modified).unwrap_or_default();
        if age <= config.max_age {
            continue;
        }

        summary.candidate_entries += 1;
        summary.candidate_bytes += entry.size;
        if config.dry_run {
            continue;
        }

        match fs::remove_file(&entry.path) {
            Ok(()) => {
                summary.removed_entries += 1;
                summary.removed_bytes += entry.size;
                debug!(path = %entry.path.display(), "Removed stale Vectorscan rule cache entry");
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => {
                summary.removal_errors += 1;
                debug!(
                    path = %entry.path.display(),
                    %err,
                    "Failed to remove stale Vectorscan rule cache entry"
                );
            }
        }
    }

    Ok(summary)
}

fn is_cache_temp_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else { return false };
    let Some(name) = name.strip_prefix('.').and_then(|name| name.strip_suffix(".tmp")) else {
        return false;
    };
    let Some((name, uuid)) = name.rsplit_once('.') else { return false };
    let Some((name, pid)) = name.rsplit_once('.') else { return false };
    name.ends_with(".vscdb") && pid.parse::<u32>().is_ok() && uuid::Uuid::parse_str(uuid).is_ok()
}

fn cache_target() -> String {
    // Serialized databases contain pattern bytecode, not OS executables. Keep architecture
    // boundaries, but let Vectorscan's deserializer check CPU features on the receiving host.
    format!(
        "{}-{}bit-{}",
        env::consts::ARCH,
        usize::BITS,
        if cfg!(target_endian = "little") { "little" } else { "big" }
    )
}

fn cache_vectorscan_version() -> String {
    // Keep the exact binding/sys pins in Cargo.toml in sync with this identity. The full
    // runtime version includes the build date: release-only keys could admit bytecode
    // from patched or differently configured native builds. Reuse within one deployed
    // build still avoids compilation across processes. CPU compatibility is checked by
    // Vectorscan itself when deserializing; OS labels alone do not establish compatibility.
    format!("binding=0.1.1;sys=0.1.1;runtime={}", kingfisher_vectorscan::version())
}

fn load_cached_vectorscan_db(
    path: &Path,
    expected_header: &CacheHeader,
) -> Option<(BlockDatabase, CacheHeader)> {
    if !path.exists() {
        debug!(path = %path.display(), "No Vectorscan rule cache entry found");
        return None;
    }

    match load_cached_vectorscan_db_inner(path, expected_header) {
        Ok(cached) => {
            debug!(path = %path.display(), "Loaded Vectorscan rule cache entry");
            Some(cached)
        }
        Err(err) => {
            static REJECTION_WARNING: std::sync::Once = std::sync::Once::new();
            REJECTION_WARNING.call_once(|| {
                warn!(path = %path.display(), reason = %format!("{err:#}"),
                    "Ignoring stale or invalid Vectorscan rule cache entry; further rejections logged at debug level");
            });
            debug!(path = %path.display(), reason = %format!("{err:#}"),
                "Ignoring stale or invalid Vectorscan rule cache entry");
            None
        }
    }
}

fn load_cached_vectorscan_db_inner(
    path: &Path,
    expected_header: &CacheHeader,
) -> Result<(BlockDatabase, CacheHeader)> {
    let mut bytes = Vec::new();
    open_cache_file(path)?
        .take(MAX_CACHE_ENTRY_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() as u64 > MAX_CACHE_ENTRY_BYTES {
        bail!("cache entry exceeds the maximum supported size");
    }
    let Some(rest) = bytes.strip_prefix(CACHE_MAGIC) else {
        bail!("invalid cache magic");
    };
    if rest.len() < 4 {
        bail!("truncated cache header length");
    }

    let mut len_bytes = [0_u8; 4];
    len_bytes.copy_from_slice(&rest[..4]);
    let header_len = u32::from_le_bytes(len_bytes) as usize;
    if header_len > MAX_CACHE_HEADER_BYTES {
        bail!("cache header is too large");
    }
    let header_start = 4_usize;
    let Some(header_end) = header_start.checked_add(header_len) else {
        bail!("cache header length overflow");
    };
    if rest.len() < header_end {
        bail!("truncated cache header");
    }

    let header: CacheHeader = serde_json::from_slice(&rest[header_start..header_end])
        .context("parse Vectorscan cache header")?;
    if header.format_version != expected_header.format_version
        || header.cache_key != expected_header.cache_key
        || header.rule_count != expected_header.rule_count
        || header.vectorscan_version != expected_header.vectorscan_version
        || header.target != expected_header.target
        || header.database_kind != expected_header.database_kind
    {
        bail!("cache metadata mismatch");
    }
    if header.prefilter_rule_indices.iter().any(|&index| index >= header.rule_count) {
        bail!("cache contains out-of-range prefilter rule index");
    }

    let database_bytes = &rest[header_end..];
    if hex::encode(Sha256::digest(database_bytes)) != header.database_sha256 {
        bail!("cache database SHA-256 mismatch");
    }
    let database =
        BlockDatabase::deserialize(database_bytes).context("deserialize Vectorscan database")?;
    Ok((database, header))
}

fn read_cached_vectorscan_header(path: &Path) -> Result<CacheHeader> {
    let mut file = open_cache_file(path)?;
    let mut magic = [0_u8; 8];
    file.read_exact(&mut magic).with_context(|| format!("read magic from {}", path.display()))?;
    if magic.as_slice() != CACHE_MAGIC {
        bail!("invalid cache magic");
    }

    let mut len_bytes = [0_u8; 4];
    file.read_exact(&mut len_bytes)
        .with_context(|| format!("read header length from {}", path.display()))?;
    let header_len = u32::from_le_bytes(len_bytes) as usize;
    if header_len > MAX_CACHE_HEADER_BYTES {
        bail!("cache header is too large");
    }
    let mut header_bytes = vec![0_u8; header_len];
    file.read_exact(&mut header_bytes)
        .with_context(|| format!("read header from {}", path.display()))?;
    serde_json::from_slice(&header_bytes).context("parse Vectorscan cache header")
}

fn store_cached_vectorscan_db(path: &Path, header: &CacheHeader, vsdb: &BlockDatabase) -> bool {
    match store_cached_vectorscan_db_inner(path, header, vsdb) {
        Ok(()) => {
            debug!(path = %path.display(), "Wrote Vectorscan rule cache entry");
            true
        }
        Err(err) => {
            debug!(path = %path.display(), %err, "Failed to write Vectorscan rule cache entry");
            false
        }
    }
}

fn store_cached_vectorscan_db_inner(
    path: &Path,
    header: &CacheHeader,
    vsdb: &BlockDatabase,
) -> Result<()> {
    store_cached_vectorscan_db_with_limit(path, header, vsdb, MAX_CACHE_ENTRY_BYTES)
}

fn store_cached_vectorscan_db_with_limit(
    path: &Path,
    header: &CacheHeader,
    vsdb: &BlockDatabase,
    max_entry_bytes: u64,
) -> Result<()> {
    let Some(parent) = path.parent() else {
        bail!("cache path has no parent");
    };
    verify_rule_cache_dir(parent)?;

    let db_bytes = vsdb.serialize().context("serialize Vectorscan database")?;
    let mut header = header.clone();
    header.database_sha256 = hex::encode(Sha256::digest(&db_bytes));
    let header_bytes = serde_json::to_vec(&header).context("serialize Vectorscan cache header")?;
    if header_bytes.len() > MAX_CACHE_HEADER_BYTES {
        bail!("cache header is too large");
    }
    let entry_bytes = (CACHE_MAGIC.len() as u64)
        .saturating_add(4)
        .saturating_add(header_bytes.len() as u64)
        .saturating_add(db_bytes.len() as u64);
    if entry_bytes > max_entry_bytes {
        bail!("serialized cache entry exceeds the maximum supported size");
    }

    let tmp_path = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name().and_then(|name| name.to_str()).unwrap_or("rule-cache"),
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let mut created = false;
    let result = (|| -> Result<()> {
        #[cfg(not(windows))]
        let mut file = {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(&tmp_path).with_context(|| format!("create {}", tmp_path.display()))?
        };
        #[cfg(windows)]
        let mut file = cache_security_windows::create_file(&tmp_path)
            .with_context(|| format!("create {}", tmp_path.display()))?;
        created = true;
        // A private directory may have inherit-only ACLs that make new files
        // writable by other accounts. Verify the actual file before publishing
        // bytecode or reporting that an entry is ready for reuse.
        #[cfg(windows)]
        cache_security_windows::verify_file(&tmp_path, &file.metadata()?)?;
        #[cfg(target_os = "macos")]
        cache_security_macos::verify_file(&file)?;
        file.write_all(CACHE_MAGIC)?;
        file.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        file.write_all(&header_bytes)?;
        file.write_all(&db_bytes)?;
        file.sync_all().with_context(|| format!("sync {}", tmp_path.display()))?;
        drop(file);
        replace_cache_file(&tmp_path, path)?;
        Ok(())
    })();
    if result.is_err() && created {
        fs::remove_file(&tmp_path).ok();
    }
    result
}

fn replace_cache_file(tmp_path: &Path, path: &Path) -> Result<()> {
    // std uses replacement semantics on Windows as well. If a destination is
    // locked, leave the previous valid entry intact and discard our temporary.
    fs::rename(tmp_path, path)
        .with_context(|| format!("rename {} to {}", tmp_path.display(), path.display()))
}

fn has_self_identifying_shape(normalized_pattern: &str) -> bool {
    const LITERAL_MARKERS: &[&str] = &[
        "ccipat_",
        "xapp-",
        "ghp_",
        "github_pat_",
        "sk_live_",
        "sk_test_",
        "ltai",
        "akia",
        "aizasy",
        "pypi-ageichlwas5vcmc",
        "https://hooks\\.slack\\.com/services/",
        "$ansible_vault",
        "<input",
    ];

    if LITERAL_MARKERS.iter().any(|needle| normalized_pattern.contains(needle)) {
        return true;
    }

    if normalized_pattern.contains("xox[pbarose]") || normalized_pattern.contains("xoxe-\\d-") {
        return true;
    }

    let has_pem_escaped_space = normalized_pattern.contains("-----begin\\s")
        && normalized_pattern.contains("private\\skey")
        && normalized_pattern.contains("-----end\\s");
    let has_pem_literal_space = normalized_pattern.contains("-----begin\\ ")
        && normalized_pattern.contains("private\\ key")
        && normalized_pattern.contains("-----end\\ ");
    has_pem_escaped_space || has_pem_literal_space
}

#[cfg(any(feature = "__scanner-internals", test))]
#[derive(Clone, Copy, Default)]
struct ConfirmationLengths {
    prefix_stable: bool,
    safe_tail: Option<usize>,
    full_match: Option<usize>,
}

#[cfg(any(feature = "__scanner-internals", test))]
fn confirmation_maximum_lengths(regex: &Regex) -> ConfirmationLengths {
    fn compute(regex: &Regex) -> Option<ConfirmationLengths> {
        let hir = regex_syntax::ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(regex.as_str())
            .ok()?;
        // SearchFrom only handles consuming matches; empty-match iteration keeps the
        // regex crate's own handling of UTF-8 boundaries and repeated empty matches.
        if !hir.properties().minimum_len().is_some_and(|length| length > 0) {
            return None;
        }
        // With no assertions, removing bytes after an indexed consuming match
        // cannot introduce a new accepting path or invalidate that match. Parse
        // with the same Unicode default as RuleSyntax::build_regex; inline flags
        // remain in regex.as_str() and are interpreted by this parser.
        let prefix_stable = hir.properties().look_set().is_empty();
        if let Some(maximum_len) = hir.properties().maximum_len() {
            return Some(ConfirmationLengths {
                prefix_stable,
                safe_tail: Some(maximum_len),
                full_match: Some(maximum_len),
            });
        }
        // A delimiter-terminated character run cannot grow across its literal
        // suffix. This covers unbounded hostname labels while excluding greedy
        // wildcards and alternatives that can change earlier matches at EOF.
        fn flatten<'a>(
            hir: &'a regex_syntax::hir::Hir,
            nodes: &mut Vec<&'a regex_syntax::hir::Hir>,
        ) {
            use regex_syntax::hir::HirKind;
            match hir.kind() {
                HirKind::Capture(capture) => flatten(&capture.sub, nodes),
                HirKind::Concat(parts) => parts.iter().for_each(|part| flatten(part, nodes)),
                _ => nodes.push(hir),
            }
        }
        use regex_syntax::hir::{Class, HirKind, Look};
        let mut nodes = Vec::new();
        flatten(&hir, &mut nodes);
        let consuming: Vec<_> =
            nodes.iter().filter(|node| !matches!(node.kind(), HirKind::Look(_))).collect();
        if let [run, suffix, rest @ ..] = consuming.as_slice()
            && let HirKind::Repetition(repetition) = run.kind()
            && repetition.min > 0
            && repetition.max.is_none()
            && let HirKind::Class(class) = repetition.sub.kind()
            && let HirKind::Literal(literal) = suffix.kind()
            && let Some(&delimiter) = literal.0.first()
            && delimiter.is_ascii()
            && !nodes.iter().any(|node| {
                matches!(node.kind(), HirKind::Look(Look::End | Look::EndLF | Look::EndCRLF))
            })
        {
            let consumes_delimiter = match class {
                Class::Bytes(class) => {
                    class.iter().any(|range| range.start() <= delimiter && delimiter <= range.end())
                }
                Class::Unicode(class) => class.iter().any(|range| {
                    range.start() <= char::from(delimiter) && char::from(delimiter) <= range.end()
                }),
            };
            if !consumes_delimiter {
                let mut maximum_len = suffix.properties().maximum_len()?;
                for node in rest {
                    maximum_len = maximum_len.checked_add(node.properties().maximum_len()?)?;
                }
                return Some(ConfirmationLengths {
                    prefix_stable,
                    safe_tail: Some(maximum_len),
                    full_match: None,
                });
            }
        }
        Some(ConfirmationLengths { prefix_stable, ..Default::default() })
    }
    compute(regex).unwrap_or_default()
}

#[cfg(test)]
mod test_vectorscan {
    use std::{
        fs,
        path::Path,
        time::{Duration, SystemTime},
    };

    use pretty_assertions::assert_eq;

    use super::*;
    use crate::{Confidence, rules::Rules};

    #[test]
    pub fn test_vectorscan_sanity() -> Result<()> {
        use kingfisher_vectorscan::{BlockDatabase, BlockScanner, Pattern, Scan};
        let input = b"some test data for vectorscan";
        let pattern = Pattern::new(b"test".to_vec(), Flag::CASELESS | Flag::SOM_LEFTMOST, None);
        let db: BlockDatabase = BlockDatabase::new(vec![pattern])?;
        let mut scanner = BlockScanner::new(&db)?;
        let mut matches: Vec<(u64, u64)> = vec![];
        scanner.scan(input, |id: u32, from: u64, to: u64, _flags: u32| {
            println!("found pattern #{} @ [{}, {})", id, from, to);
            matches.push((from, to));
            Scan::Continue
        })?;
        assert_eq!(matches, vec![(5, 9)]);
        Ok(())
    }

    #[test]
    fn cached_vectorscan_database_round_trips() -> Result<()> {
        use kingfisher_vectorscan::{BlockScanner, Scan};

        let yaml = br#"
rules:
  - id: demo.secret
    name: Demo Secret
    pattern: "demo_[0-9]{4}"
    confidence: low
"#;
        let rules = Rules::from_paths_and_contents(
            [(Path::new("demo.yml"), yaml.as_slice())],
            Confidence::Low,
        )?;
        let rule_vec: Vec<Rule> = rules.into_iter().map(Rule::new).collect();
        let cache_dir =
            env::temp_dir().join(format!("kingfisher-rule-cache-test-{}", uuid::Uuid::new_v4()));
        let cache = RuleCacheConfig::new(&cache_dir);

        let db = RulesDatabase::from_rules_with_cache(rule_vec.clone(), &cache)?;
        assert_eq!(db.num_rules(), 1);
        assert_eq!(db.cache_status(), RuleCacheStatus::Stored);
        assert!(!db.uses_vectorscan_prefilter(0));
        let entries = fs::read_dir(&cache_dir)?.count();
        assert_eq!(entries, 1);
        let cache_path = cache_dir.join(format!("{}.vscdb", compute_rule_cache_key(&rule_vec)));
        let old_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        fs::File::options()
            .write(true)
            .open(&cache_path)?
            .set_times(fs::FileTimes::new().set_modified(old_time))?;
        let before = fs::metadata(&cache_path)?.modified()?;

        let cached_db = RulesDatabase::from_rules_with_cache(rule_vec, &cache)?;
        assert_eq!(cached_db.cache_status(), RuleCacheStatus::Loaded);
        assert_eq!(fs::metadata(&cache_path)?.modified()?, before, "cache hit must not rewrite");
        assert!(!cached_db.uses_vectorscan_prefilter(0));
        let mut scanner = BlockScanner::new(cached_db.vectorscan_db())?;
        let mut matches = Vec::new();
        scanner.scan(b"token demo_1234", |id, _from, to, _flags| {
            matches.push((id, to));
            Scan::Continue
        })?;

        fs::remove_dir_all(cache_dir).ok();
        assert_eq!(matches, vec![(0, 15)]);
        Ok(())
    }

    #[test]
    fn cache_compatibility_keeps_the_exact_engine_build() {
        let target = cache_target();
        assert!(!target.contains(env::consts::OS));
        assert!(!target.contains(env::consts::FAMILY));
        let identity = cache_vectorscan_version();
        assert!(identity.starts_with("binding=0.1.1;sys=0.1.1;runtime="));
        assert!(identity.ends_with(&kingfisher_vectorscan::version()));
    }

    #[test]
    fn cache_is_disabled_without_a_per_user_location() -> Result<()> {
        assert_eq!(default_rule_cache_dir_from(|_| None), None);
        let cache = RuleCacheConfig::new(PathBuf::new());
        assert!(!cache.is_enabled());
        assert_eq!(
            prune_rule_cache_at(&cache, &RuleCachePruneConfig::default(), SystemTime::now())?,
            RuleCachePruneSummary::default()
        );
        Ok(())
    }

    #[test]
    fn cache_header_length_is_bounded_before_allocation() -> Result<()> {
        let cache_dir =
            env::temp_dir().join(format!("kingfisher-rule-cache-test-{}", uuid::Uuid::new_v4()));
        prepare_rule_cache_dir(&cache_dir)?;
        let path = cache_dir.join("oversized.vscdb");
        let mut bytes = CACHE_MAGIC.to_vec();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&path, bytes)?;
        assert!(
            read_cached_vectorscan_header(&path).unwrap_err().to_string().contains("too large")
        );
        fs::remove_dir_all(cache_dir)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_cache_directory_compiles_without_reading_or_writing() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let cache_dir =
            env::temp_dir().join(format!("kingfisher-rule-cache-test-{}", uuid::Uuid::new_v4()));
        prepare_rule_cache_dir(&cache_dir)?;
        fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o777))?;
        let rule =
            Rule::new(crate::rule::RuleSyntax::new("demo.secret", "Demo Secret", "demo_[0-9]{4}"));
        let database =
            RulesDatabase::from_rules_with_cache(vec![rule], &RuleCacheConfig::new(&cache_dir))?;
        assert_eq!(database.num_rules(), 1);
        assert_eq!(database.cache_status(), RuleCacheStatus::Bypassed);
        assert_eq!(
            fs::read_dir(&cache_dir)?.count(),
            0,
            "unsafe directory must receive no compiled bytecode"
        );
        fs::remove_dir_all(cache_dir)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn cache_rejects_symlinks_and_writable_entries() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let cache_dir =
            env::temp_dir().join(format!("kingfisher-rule-cache-test-{}", uuid::Uuid::new_v4()));
        prepare_rule_cache_dir(&cache_dir)?;
        assert_eq!(fs::metadata(&cache_dir)?.permissions().mode() & 0o777, 0o700);
        let target = cache_dir.join("target.vscdb");
        fs::write(&target, b"untrusted database")?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o666))?;
        assert!(open_cache_file(&target).is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        let link = cache_dir.join("link.vscdb");
        symlink(&target, &link)?;
        assert!(open_cache_file(&link).is_err());
        let directory_link = cache_dir.with_extension("link");
        symlink(&cache_dir, &directory_link)?;
        assert!(verify_rule_cache_dir(&directory_link).is_err());
        fs::remove_file(directory_link)?;
        fs::remove_dir_all(cache_dir)?;
        Ok(())
    }

    #[test]
    fn cache_checks_database_sha256_before_native_deserialization() -> Result<()> {
        let cache_dir =
            env::temp_dir().join(format!("kingfisher-rule-cache-test-{}", uuid::Uuid::new_v4()));
        let rule =
            Rule::new(crate::rule::RuleSyntax::new("demo.secret", "Demo Secret", "demo_[0-9]{4}"));
        let rules = vec![rule];
        RulesDatabase::from_rules_with_cache(rules.clone(), &RuleCacheConfig::new(&cache_dir))?;
        let path = cache_dir.join(format!("{}.vscdb", compute_rule_cache_key(&rules)));
        let header = read_cached_vectorscan_header(&path)?;
        let mut bytes = fs::read(&path)?;
        *bytes.last_mut().expect("serialized database is not empty") ^= 1;
        fs::write(&path, bytes)?;
        assert!(
            load_cached_vectorscan_db_inner(&path, &header)
                .expect_err("corruption must be rejected")
                .to_string()
                .contains("SHA-256 mismatch")
        );
        RulesDatabase::from_rules_with_cache(rules, &RuleCacheConfig::new(&cache_dir))?;
        assert!(load_cached_vectorscan_db_inner(&path, &header).is_ok());
        fs::remove_dir_all(cache_dir)?;
        Ok(())
    }

    #[test]
    fn failed_cache_write_is_observable_without_preventing_compilation() -> Result<()> {
        let cache_dir =
            env::temp_dir().join(format!("kingfisher-rule-cache-test-{}", uuid::Uuid::new_v4()));
        prepare_rule_cache_dir(&cache_dir)?;
        let rule =
            Rule::new(crate::rule::RuleSyntax::new("demo.secret", "Demo Secret", "demo_[0-9]{4}"));
        let rules = vec![rule];
        let cache_path = cache_dir.join(format!("{}.vscdb", compute_rule_cache_key(&rules)));
        // A directory at the destination causes atomic publication to fail on every OS.
        fs::create_dir(&cache_path)?;
        let database =
            RulesDatabase::from_rules_with_cache(rules, &RuleCacheConfig::new(&cache_dir))?;
        assert_eq!(database.num_rules(), 1);
        assert_eq!(database.cache_status(), RuleCacheStatus::Bypassed);
        assert_eq!(
            fs::read_dir(&cache_dir)?.count(),
            1,
            "failed writes must remove their temporary file"
        );
        fs::remove_dir_all(cache_dir)?;
        Ok(())
    }

    #[test]
    fn oversized_database_is_rejected_before_cache_publication() -> Result<()> {
        let cache_dir =
            env::temp_dir().join(format!("kingfisher-rule-cache-test-{}", uuid::Uuid::new_v4()));
        prepare_rule_cache_dir(&cache_dir)?;
        let rule =
            Rule::new(crate::rule::RuleSyntax::new("demo.secret", "Demo Secret", "demo_[0-9]{4}"));
        let database = RulesDatabase::from_rules(vec![rule])?;
        let header = CacheHeader {
            format_version: CACHE_FORMAT_VERSION,
            cache_key: "size-test".to_owned(),
            rule_count: 1,
            vectorscan_version: cache_vectorscan_version(),
            target: cache_target(),
            database_kind: "block".to_owned(),
            database_sha256: String::new(),
            prefilter_rule_indices: Vec::new(),
        };
        // Exercise the real serializer and atomic publication path with a small
        // injected cap, avoiding a half-gigabyte test fixture on every platform.
        let error = store_cached_vectorscan_db_with_limit(
            &cache_dir.join("size-test.vscdb"),
            &header,
            database.vectorscan_db(),
            64,
        )
        .expect_err("oversized database must not be published");
        assert!(error.to_string().contains("exceeds the maximum supported size"));
        assert_eq!(fs::read_dir(&cache_dir)?.count(), 0);
        fs::remove_dir_all(cache_dir)?;
        Ok(())
    }

    #[test]
    fn cached_vectorscan_database_recompiles_rejected_entries() -> Result<()> {
        use kingfisher_vectorscan::{BlockScanner, HyperscanErrorCode};

        let yaml = br#"
rules:
  - id: demo.secret
    name: Demo Secret
    pattern: "demo_[0-9]{4}"
    confidence: low
"#;
        let rules = Rules::from_paths_and_contents(
            [(Path::new("demo.yml"), yaml.as_slice())],
            Confidence::Low,
        )?;
        let rule_vec: Vec<Rule> = rules.into_iter().map(Rule::new).collect();
        let cache_dir =
            env::temp_dir().join(format!("kingfisher-rule-cache-test-{}", uuid::Uuid::new_v4()));
        let cache = RuleCacheConfig::new(&cache_dir);
        let original = RulesDatabase::from_rules_with_cache(rule_vec.clone(), &cache)?;
        let cache_path = cache_dir.join(format!("{}.vscdb", compute_rule_cache_key(&rule_vec)));
        let header = read_cached_vectorscan_header(&cache_path)?;
        let native_bytes = original.vectorscan_db().serialize()?;

        for rejection in ["cpu", "native-version", "architecture", "metadata", "prefilter"] {
            let mut bad_header = header.clone();
            let mut bad_native = native_bytes.clone();
            // Vectorscan 5.x serialization starts with u32 magic/version/length followed by
            // u64 platform. Alter only compatibility fields, leaving valid bytecode and CRC.
            // Assert the actual native rejection so this exercises CPU/version fallback.
            let expected_code = match rejection {
                "cpu" => {
                    bad_native[12..20].copy_from_slice(&u64::MAX.to_ne_bytes());
                    Some(HyperscanErrorCode::DbPlatformError)
                }
                "native-version" => {
                    bad_native[4..8].fill(0);
                    Some(HyperscanErrorCode::DbVersionError)
                }
                "architecture" => {
                    bad_header.target = "incompatible-architecture".to_string();
                    None
                }
                "metadata" => {
                    bad_header.format_version -= 1;
                    None
                }
                "prefilter" => {
                    bad_header.prefilter_rule_indices.push(header.rule_count);
                    None
                }
                _ => unreachable!(),
            };
            if let Some(expected_code) = expected_code {
                assert!(matches!(
                    BlockDatabase::deserialize(&bad_native),
                    Err(VectorscanError::Hyperscan(code, _)) if code == expected_code
                ));
            }
            // Keep the corruption checksum valid to exercise native compatibility checks.
            bad_header.database_sha256 = hex::encode(Sha256::digest(&bad_native));
            let header_bytes = serde_json::to_vec(&bad_header)?;
            let mut entry = CACHE_MAGIC.to_vec();
            entry.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
            entry.extend_from_slice(&header_bytes);
            entry.extend_from_slice(&bad_native);
            fs::write(&cache_path, entry)?;
            assert!(load_cached_vectorscan_db(&cache_path, &header).is_none(), "{rejection}");

            let rebuilt = RulesDatabase::from_rules_with_cache(rule_vec.clone(), &cache)?;
            let mut scanner = BlockScanner::new(rebuilt.vectorscan_db())?;
            let mut matches = Vec::new();
            scanner.scan(b"token demo_1234", |id, _from, to, _flags| {
                matches.push((id, to));
                Scan::Continue
            })?;
            assert_eq!(matches, vec![(0, 15)], "{rejection}");
            assert!(load_cached_vectorscan_db(&cache_path, &header).is_some(), "{rejection}");
        }
        fs::remove_dir_all(cache_dir)?;
        Ok(())
    }

    #[test]
    fn low_confidence_does_not_force_vectorscan_prefilter_mode() -> Result<()> {
        let yaml = br#"
rules:
  - id: demo.generic
    name: Generic rule
    pattern: "(?i)(?:key|secret|token)[ \\t]{0,8}[:=][ \\t]{0,4}([a-z0-9]{10,150})"
    confidence: low
"#;
        let rules = Rules::from_paths_and_contents(
            [(Path::new("generic.yml"), yaml.as_slice())],
            Confidence::Low,
        )?;
        let database = RulesDatabase::from_rules(rules.into_iter().map(Rule::new).collect())?;

        assert!(!database.uses_vectorscan_prefilter(0));
        Ok(())
    }

    #[test]
    fn cached_database_preserves_betterleaks_path_prefilter() -> Result<()> {
        let expression = BetterleaksExpr::Call {
            callee: Box::new(BetterleaksExpr::Identifier { value: "matchesAny".to_string() }),
            arguments: vec![
                BetterleaksExpr::Member {
                    node: Box::new(BetterleaksExpr::Identifier { value: "attributes".to_string() }),
                    property: Box::new(BetterleaksExpr::String { value: "path".to_string() }),
                    optional: false,
                    method: false,
                },
                BetterleaksExpr::Array {
                    nodes: vec![BetterleaksExpr::String {
                        value: r"(?:^|/)node_modules(?:/.*)?$".to_string(),
                    }],
                },
            ],
        };
        let yaml = br#"
rules:
  - id: demo.secret
    name: Demo Secret
    pattern: "demo_[0-9]{4}"
    confidence: medium
"#;
        let rules = Rules::from_paths_and_contents(
            [(Path::new("demo.yml"), yaml.as_slice())],
            Confidence::Medium,
        )?;
        let rule_vec: Vec<Rule> = rules.into_iter().map(Rule::new).collect();
        let cache_dir =
            env::temp_dir().join(format!("kingfisher-rule-cache-test-{}", uuid::Uuid::new_v4()));
        let cache = RuleCacheConfig::new(&cache_dir);

        let db = RulesDatabase::from_rules_with_cache_and_betterleaks_prefilter(
            rule_vec.clone(),
            &cache,
            Some(expression.clone()),
        )?;
        assert!(db.is_path_prefiltered("repo/node_modules/package.js")?);
        assert!(!db.is_path_prefiltered("src/main.rs")?);

        let cached_db = RulesDatabase::from_rules_with_cache_and_betterleaks_prefilter(
            rule_vec,
            &cache,
            Some(expression),
        )?;
        assert!(cached_db.is_path_prefiltered("repo/node_modules/package.js")?);
        assert!(!cached_db.is_path_prefiltered("src/main.rs")?);

        fs::remove_dir_all(cache_dir).ok();
        Ok(())
    }

    #[test]
    fn cached_vectorscan_database_refreshes_corrupt_entry() -> Result<()> {
        use kingfisher_vectorscan::{BlockScanner, Scan};

        let yaml = br#"
rules:
  - id: demo.secret
    name: Demo Secret
    pattern: "demo_[0-9]{4}"
    confidence: low
"#;
        let rules = Rules::from_paths_and_contents(
            [(Path::new("demo.yml"), yaml.as_slice())],
            Confidence::Low,
        )?;
        let rule_vec: Vec<Rule> = rules.into_iter().map(Rule::new).collect();
        let cache_dir =
            env::temp_dir().join(format!("kingfisher-rule-cache-test-{}", uuid::Uuid::new_v4()));
        let cache = RuleCacheConfig::new(&cache_dir);

        RulesDatabase::from_rules_with_cache(rule_vec.clone(), &cache)?;
        let cache_path =
            fs::read_dir(&cache_dir)?.next().expect("cache entry should exist")?.path();
        let mut corrupt = Vec::new();
        corrupt.extend_from_slice(CACHE_MAGIC);
        corrupt.extend_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&cache_path, corrupt)?;

        let refreshed_db = RulesDatabase::from_rules_with_cache(rule_vec, &cache)?;
        let mut scanner = BlockScanner::new(refreshed_db.vectorscan_db())?;
        let mut matches = Vec::new();
        scanner.scan(b"token demo_1234", |id, _from, to, _flags| {
            matches.push((id, to));
            Scan::Continue
        })?;

        assert_eq!(fs::read_dir(&cache_dir)?.count(), 1);
        fs::remove_dir_all(cache_dir).ok();
        assert_eq!(matches, vec![(0, 15)]);
        Ok(())
    }

    #[test]
    fn cached_vectorscan_database_refreshes_when_rule_pattern_changes() -> Result<()> {
        use kingfisher_vectorscan::{BlockScanner, Scan};

        fn rules_for(pattern: &str) -> Result<Vec<Rule>> {
            let yaml = format!(
                r#"
rules:
  - id: demo.secret
    name: Demo Secret
    pattern: "{pattern}"
    confidence: low
"#
            );
            let rules = Rules::from_paths_and_contents(
                [(Path::new("demo.yml"), yaml.as_bytes())],
                Confidence::Low,
            )?;
            Ok(rules.into_iter().map(Rule::new).collect())
        }

        fn scan_matches(db: &RulesDatabase, input: &[u8]) -> Result<Vec<(u32, u64)>> {
            let mut scanner = BlockScanner::new(db.vectorscan_db())?;
            let mut matches = Vec::new();
            scanner.scan(input, |id, _from, to, _flags| {
                matches.push((id, to));
                Scan::Continue
            })?;
            Ok(matches)
        }

        let cache_dir =
            env::temp_dir().join(format!("kingfisher-rule-cache-test-{}", uuid::Uuid::new_v4()));
        let cache = RuleCacheConfig::new(&cache_dir);

        let numeric_db = RulesDatabase::from_rules_with_cache(rules_for("demo_[0-9]{4}")?, &cache)?;
        assert_eq!(scan_matches(&numeric_db, b"token demo_1234")?, vec![(0, 15)]);
        assert_eq!(fs::read_dir(&cache_dir)?.count(), 1);

        let alpha_db = RulesDatabase::from_rules_with_cache(rules_for("demo_[a-z]{4}")?, &cache)?;
        assert_eq!(scan_matches(&alpha_db, b"token demo_1234")?, Vec::<(u32, u64)>::new());
        assert_eq!(scan_matches(&alpha_db, b"token demo_abcd")?, vec![(0, 15)]);
        assert_eq!(fs::read_dir(&cache_dir)?.count(), 2);

        fs::remove_dir_all(cache_dir).ok();
        Ok(())
    }

    #[test]
    fn legacy_matching_engine_hint_does_not_change_cache_key() -> Result<()> {
        fn rule_for(vectorscan_compatible: bool) -> Result<Rule> {
            let yaml = format!(
                r#"
rules:
  - id: demo.secret
    name: Demo Secret
    pattern: "demo_[0-9]{{4}}"
    confidence: low
    vectorscan_compatible: {vectorscan_compatible}
"#
            );
            let rules = Rules::from_paths_and_contents(
                [(Path::new("demo.yml"), yaml.as_bytes())],
                Confidence::Low,
            )?;
            Ok(Rule::new(rules.into_iter().next().expect("test rule should load")))
        }

        let vectorscan = rule_for(true)?;
        let direct_regex = rule_for(false)?;
        assert_eq!(compute_rule_cache_key(&[vectorscan]), compute_rule_cache_key(&[direct_regex]));
        Ok(())
    }

    #[test]
    fn betterleaks_path_prefilter_is_precompiled_with_vectorscan() -> Result<()> {
        let expression = BetterleaksExpr::Call {
            callee: Box::new(BetterleaksExpr::Identifier { value: "matchesAny".to_string() }),
            arguments: vec![
                BetterleaksExpr::Member {
                    node: Box::new(BetterleaksExpr::Identifier { value: "attributes".to_string() }),
                    property: Box::new(BetterleaksExpr::String { value: "path".to_string() }),
                    optional: false,
                    method: false,
                },
                BetterleaksExpr::Array {
                    nodes: vec![
                        BetterleaksExpr::String {
                            value: r"(?:^|/)node_modules(?:/.*)?$".to_string(),
                        },
                        BetterleaksExpr::String { value: r"(?i)\.png$".to_string() },
                    ],
                },
            ],
        };
        let prefilter = BetterleaksPathPrefilter::compile(expression)?;

        assert!(prefilter.is_match("repo/node_modules/package/index.js")?);
        assert!(prefilter.is_match("assets/LOGO.PNG")?);
        assert!(!prefilter.is_match("src/lib.rs")?);
        Ok(())
    }

    fn write_fake_cache_entry(cache_dir: &Path, cache_key: &str) -> Result<PathBuf> {
        let path = cache_dir.join(format!("{cache_key}.vscdb"));
        let header = CacheHeader {
            format_version: CACHE_FORMAT_VERSION,
            cache_key: cache_key.to_string(),
            rule_count: 1,
            vectorscan_version: cache_vectorscan_version(),
            target: cache_target(),
            database_kind: "block".to_string(),
            database_sha256: hex::encode(Sha256::digest(b"not-a-real-vectorscan-db")),
            prefilter_rule_indices: Vec::new(),
        };
        let header_bytes = serde_json::to_vec(&header)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(CACHE_MAGIC);
        bytes.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&header_bytes);
        bytes.extend_from_slice(b"not-a-real-vectorscan-db");
        fs::write(&path, bytes)?;
        Ok(path)
    }

    #[test]
    fn prune_rule_cache_removes_only_stale_owned_temporaries_without_an_entry_floor() -> Result<()>
    {
        let cache_dir =
            env::temp_dir().join(format!("kingfisher-rule-cache-test-{}", uuid::Uuid::new_v4()));
        prepare_rule_cache_dir(&cache_dir)?;
        let cache = RuleCacheConfig::new(&cache_dir);
        let old = cache_dir.join(format!(".old.vscdb.42.{}.tmp", uuid::Uuid::new_v4()));
        let recent = cache_dir.join(format!(".recent.vscdb.42.{}.tmp", uuid::Uuid::new_v4()));
        let unrelated = cache_dir.join(".notes.tmp");
        for path in [&old, &recent, &unrelated] {
            fs::write(path, b"temporary")?;
        }
        let now = SystemTime::now();
        let old_time = now - Duration::from_secs(2 * 24 * 60 * 60);
        fs::File::options()
            .write(true)
            .open(&old)?
            .set_times(fs::FileTimes::new().set_modified(old_time))?;
        let mut config =
            RuleCachePruneConfig { max_age: Duration::ZERO, dry_run: true, ..Default::default() };
        let summary = prune_rule_cache_at(&cache, &config, now)?;
        assert_eq!(summary.candidate_entries, 1);
        assert_eq!(summary.removed_entries, 0);
        assert!(old.exists());
        config.dry_run = false;
        let summary = prune_rule_cache_at(&cache, &config, now)?;
        assert_eq!(summary.removed_entries, 1);
        assert!(!old.exists());
        assert!(recent.exists());
        assert!(unrelated.exists());
        fs::remove_dir_all(cache_dir)?;
        Ok(())
    }

    #[test]
    fn prune_rule_cache_keeps_entry_floor_and_removes_old_excess_entries() -> Result<()> {
        let cache_dir =
            env::temp_dir().join(format!("kingfisher-rule-cache-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&cache_dir)?;
        let cache = RuleCacheConfig::new(&cache_dir);

        for index in 0..12 {
            write_fake_cache_entry(&cache_dir, &format!("entry-{index:02}"))?;
        }

        let config = RuleCachePruneConfig {
            max_entries: 10,
            max_age: Duration::ZERO,
            protected_cache_key: None,
            dry_run: false,
        };
        let summary =
            prune_rule_cache_at(&cache, &config, SystemTime::now() + Duration::from_secs(60 * 60))?;

        assert_eq!(summary.valid_entries, 12);
        assert_eq!(summary.candidate_entries, 2);
        assert_eq!(summary.removed_entries, 2);
        assert_eq!(fs::read_dir(&cache_dir)?.count(), 10);
        fs::remove_dir_all(cache_dir).ok();
        Ok(())
    }

    #[test]
    fn prune_rule_cache_never_removes_protected_cache_key() -> Result<()> {
        let cache_dir =
            env::temp_dir().join(format!("kingfisher-rule-cache-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&cache_dir)?;
        let cache = RuleCacheConfig::new(&cache_dir);

        write_fake_cache_entry(&cache_dir, "delete-me")?;
        let protected = write_fake_cache_entry(&cache_dir, "protected")?;

        let config = RuleCachePruneConfig {
            max_entries: 0,
            max_age: Duration::ZERO,
            protected_cache_key: Some("protected".to_string()),
            dry_run: false,
        };
        let summary =
            prune_rule_cache_at(&cache, &config, SystemTime::now() + Duration::from_secs(60 * 60))?;

        assert_eq!(summary.protected_entries, 1);
        assert_eq!(summary.removed_entries, 1);
        assert!(protected.exists());
        assert_eq!(fs::read_dir(&cache_dir)?.count(), 1);
        fs::remove_dir_all(cache_dir).ok();
        Ok(())
    }

    #[test]
    fn prune_rule_cache_ignores_invalid_cache_entries() -> Result<()> {
        let cache_dir =
            env::temp_dir().join(format!("kingfisher-rule-cache-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&cache_dir)?;
        let cache = RuleCacheConfig::new(&cache_dir);

        write_fake_cache_entry(&cache_dir, "valid")?;
        fs::write(cache_dir.join("corrupt.vscdb"), b"nope")?;
        fs::write(cache_dir.join("notes.txt"), b"not a cache entry")?;

        let config = RuleCachePruneConfig {
            max_entries: 0,
            max_age: Duration::ZERO,
            protected_cache_key: None,
            dry_run: false,
        };
        let summary =
            prune_rule_cache_at(&cache, &config, SystemTime::now() + Duration::from_secs(60 * 60))?;

        assert_eq!(summary.scanned_entries, 2);
        assert_eq!(summary.invalid_entries, 1);
        assert_eq!(summary.removed_entries, 1);
        assert!(cache_dir.join("corrupt.vscdb").exists());
        assert!(cache_dir.join("notes.txt").exists());
        fs::remove_dir_all(cache_dir).ok();
        Ok(())
    }
}
#[cfg(test)]
mod test_regex_cleaning {
    use super::*;
    #[test]
    fn test_format_regex_pattern() {
        let input = r#"(?x)
            (?i)
            (?:
              \\b
              (?:AWS|AMAZON|AMZN|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)
              (?:\\.|[\\n\\r]){0,32}?  (?# THIS IS A COMMENTCOMMENTCOMMENTCOMMENTCOMMENTCOMMENTCOMMENT)
              (?:SECRET|PRIVATE|ACCESS|KEY|TOKEN) # THIS IS A COMMENT THAT SHOULD NOT BE USED BUT MIGHT BE
              (?:\\.|[\\n\\r]){0,32}?
              \\b
              (
                [A-Za-z0-9/+=]{40}
              )
              \\b
            |
              \\b
              (?:SECRET|PRIVATE|ACCESS)
              (?:\\.|[\\n\\r]){0,16}?
              (?:KEY|TOKEN)
              (?:\\.|[\\n\\r]){0,32}?
              \\b
              (
                [A-Za-z0-9/+=]{40}
              )
              \\b
            )"#;
        let data = format_regex_pattern(input);
        println!("{}", data);
    }
}

#[cfg(test)]
mod confirmation_bounds {
    use super::*;
    use crate::RuleSyntax;

    #[test]
    fn prefix_certificates_follow_rule_builder_flags_and_assertions() {
        for (pattern, expected) in [
            (r"(ab)|(bc)", true),
            (r"(?s)BEGIN(.*?)END", true),
            (
                r"(PuTTY-User-Key-File-3:(?:[^\n]|\n){20,10240}?Private-MAC: ?[0-9a-fA-F]{40,64})",
                true,
            ),
            ("(?x)(token_ [a-z]{2}) # ignored $ and \\b\n", true),
            ("(?x)#[\n(z)|(ar)|(bar$)#]\n", false),
            (r"(z)|(ar)|(bar$)", false),
            (r"(?m)^token_[a-z]{2}$", false),
            (r"(token_[a-z]{2})\b", false),
            (r"(?u)(é+)\b", false),
            (r"()|a", false),
            (r"a*", false),
        ] {
            let rule = RuleSyntax::new("acme.prefix", "Prefix certificate", pattern);
            let regex = rule.as_regex().unwrap();
            assert_eq!(confirmation_maximum_lengths(&regex).prefix_stable, expected, "{pattern}");
        }
    }

    #[test]
    fn tail_bounds_follow_rule_builder_flags_and_delimiters() {
        for (pattern, expected) in [
            (r"(.{32})", Some(32)),
            (r"([^z]{32})", Some(32)),
            (r"(?u)(.{32})", Some(128)),
            (r"([a-z]+\.example\.com)", Some(12)),
            (r"([a-z]+z)", None),
            (r"([a-z]+\.example\.com)$", None),
            (r"()|a", None),
        ] {
            let rule = RuleSyntax::new("acme.bound", "Bound", pattern);
            let regex = rule.as_regex().unwrap();
            let bounds = confirmation_maximum_lengths(&regex);
            assert_eq!(bounds.safe_tail, expected, "{pattern}");
            let full = if pattern == r"([a-z]+\.example\.com)" { None } else { expected };
            assert_eq!(bounds.full_match, full, "{pattern}");
        }
    }
}

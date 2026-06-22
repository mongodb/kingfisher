use std::{
    env, fs,
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use tracing::{debug, debug_span, error};
use vectorscan_rs::{BlockDatabase, Flag, Pattern};
use xxhash_rust::xxh3::xxh3_128;

use crate::rule::{RULE_COMMENTS_PATTERN, Rule};

pub struct RulesDatabase {
    // pub(crate) rules: Vec<Rule,>,
    pub(crate) rules: Vec<Arc<Rule>>,
    pub(crate) anchored_regexes: Vec<Regex>,
    pub(crate) self_identifying_flags: Vec<bool>,
    pub(crate) vsdb: BlockDatabase,
}

#[derive(Debug, Clone)]
pub struct RuleCacheConfig {
    cache_dir: PathBuf,
}

impl RuleCacheConfig {
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self { cache_dir: cache_dir.into() }
    }

    pub fn from_dir_or_env(cache_dir: Option<PathBuf>) -> Self {
        Self::new(cache_dir.unwrap_or_else(default_rule_cache_dir))
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}

const CACHE_MAGIC: &[u8] = b"KFRULEDB";
const CACHE_FORMAT_VERSION: u32 = 1;
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
}

#[derive(Debug, Clone)]
pub struct RuleCachePruneConfig {
    pub max_entries: usize,
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

    pub fn from_rules(rules: Vec<Rule>) -> Result<Self> {
        let rules: Vec<Arc<Rule>> = rules.into_iter().map(Arc::new).collect();
        Self::from_arc_rules(rules)
    }

    pub fn from_rules_with_cache(rules: Vec<Rule>, cache: &RuleCacheConfig) -> Result<Self> {
        let rules: Vec<Arc<Rule>> = rules.into_iter().map(Arc::new).collect();
        Self::from_arc_rules_with_cache(rules, cache)
    }

    fn from_arc_rules(rules: Vec<Arc<Rule>>) -> Result<Self> {
        let _span = debug_span!("RulesDatabase::from_rules").entered();
        if rules.is_empty() {
            bail!("No rules to compile");
        }
        let patterns: Vec<Pattern> = rules
            .iter()
            .enumerate()
            .map(|(id, rule)| {
                Pattern::new(
                    rule.syntax().pattern.clone().into_bytes(),
                    Flag::default(),
                    Some(id.try_into().unwrap()),
                )
            })
            .collect();
        let t1 = Instant::now();
        match BlockDatabase::new(patterns) {
            Ok(vsdb) => {
                let d1 = t1.elapsed().as_secs_f64();
                let (anchored_regexes, d2) = Self::compile_regexes(&rules)?;
                let self_identifying_flags = Self::build_self_identifying_flags(&rules);
                debug!("Compiled {} rules: vectorscan {}s; regex {}s", rules.len(), d1, d2);
                Ok(RulesDatabase { rules, vsdb, anchored_regexes, self_identifying_flags })
            }
            Err(e) => {
                error!(
                    "Failed to create BlockDatabase: {}. Attempting to compile rules individually.",
                    e
                );
                Self::compile_rules_individually(rules)
                    .map_err(|err| anyhow!("Failed to compile rules: {}\n{}", e, err))
            }
        }
    }

    fn from_arc_rules_with_cache(rules: Vec<Arc<Rule>>, cache: &RuleCacheConfig) -> Result<Self> {
        let _span = debug_span!("RulesDatabase::from_rules_with_cache").entered();
        if rules.is_empty() {
            bail!("No rules to compile");
        }

        let cache_key = compute_cache_key(&rules);
        let cache_path = cache.cache_dir.join(format!("{cache_key}.vscdb"));
        let header = CacheHeader {
            format_version: CACHE_FORMAT_VERSION,
            cache_key,
            rule_count: rules.len(),
            vectorscan_version: vectorscan_rs::version(),
            target: cache_target(),
            database_kind: "block".to_string(),
        };

        debug!(
            cache_dir = %cache.cache_dir.display(),
            cache_path = %cache_path.display(),
            rule_count = rules.len(),
            cache_key = %header.cache_key,
            "Using Vectorscan rule cache"
        );
        let t1 = Instant::now();
        if let Some(vsdb) = load_cached_vectorscan_db(&cache_path, &header) {
            let d1 = t1.elapsed().as_secs_f64();
            let (anchored_regexes, d2) = Self::compile_regexes(&rules)?;
            let self_identifying_flags = Self::build_self_identifying_flags(&rules);
            debug!(
                "Loaded {} rules from Vectorscan cache: cache {}s; regex {}s",
                rules.len(),
                d1,
                d2
            );
            return Ok(RulesDatabase { rules, vsdb, anchored_regexes, self_identifying_flags });
        }

        let db = Self::from_arc_rules(rules)?;
        store_cached_vectorscan_db(&cache_path, &header, db.vectorscan_db());
        Ok(db)
    }

    fn compile_rules_individually(rules: Vec<Arc<Rule>>) -> Result<Self> {
        // NOTE: This function only used when attempting to determine which rule failed
        // to compile
        let mut compiled_rules = Vec::new();
        let mut compiled_patterns = Vec::new();
        let mut compiled_regexes = Vec::new();
        let mut error_messages = Vec::new();
        for (id, rule) in rules.into_iter().enumerate() {
            let pattern = Pattern::new(
                rule.syntax().pattern.clone().into_bytes(),
                Flag::default(),
                Some(id.try_into().unwrap()),
            );
            match BlockDatabase::new(vec![pattern]) {
                Ok(_) => {
                    // Recreate the pattern for the final compilation
                    let final_pattern = Pattern::new(
                        rule.syntax().pattern.clone().into_bytes(),
                        Flag::default(),
                        Some(id.try_into().unwrap()),
                    );
                    compiled_patterns.push(final_pattern);
                    match rule.syntax().as_regex() {
                        Ok(regex) => {
                            compiled_regexes.push(regex);
                            compiled_rules.push(rule);
                        }
                        Err(e) => {
                            error_messages.push(format!(
                                "Failed to compile Regex for rule '{}' (ID: {}): {}",
                                rule.name(),
                                rule.id(),
                                e
                            ));
                        }
                    }
                }
                Err(e) => {
                    error_messages.push(format!(
                        "Failed to compile vectorscan pattern for rule '{}' (ID: {}): {}",
                        rule.name(),
                        rule.id(),
                        e
                    ));
                }
            }
        }
        if !error_messages.is_empty() {
            error!(
                "Errors occurred while compiling rules individually:\n{}",
                error_messages.join("\n")
            );
            bail!("Failed to compile the following rules:\n{}", error_messages.join("\n"));
        }
        let vsdb = BlockDatabase::new(compiled_patterns)?;
        let self_identifying_flags = Self::build_self_identifying_flags(&compiled_rules);
        Ok(RulesDatabase {
            rules: compiled_rules,
            vsdb,
            anchored_regexes: compiled_regexes,
            self_identifying_flags,
        })
    }

    fn compile_regexes(rules: &[Arc<Rule>]) -> Result<(Vec<Regex>, f64)> {
        // fn compile_regexes(rules: &[Rule],) -> Result<(Vec<Regex,>, f64,),> {
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

    /// Returns a slice of the anchored regexes.
    #[inline]
    pub fn anchored_regexes(&self) -> &[Regex] {
        &self.anchored_regexes
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
}

fn default_rule_cache_dir() -> PathBuf {
    if let Some(path) = non_empty_env_path("KF_RULE_CACHE_DIR") {
        return path;
    }

    if cfg!(windows) {
        if let Some(path) = non_empty_env_path("LOCALAPPDATA") {
            return path.join("Kingfisher").join("rule-cache");
        }
        if let Some(path) = non_empty_env_path("USERPROFILE") {
            return path.join("AppData").join("Local").join("Kingfisher").join("rule-cache");
        }
    }

    if cfg!(target_os = "macos")
        && let Some(path) = non_empty_env_path("HOME")
    {
        return path.join("Library").join("Caches").join("kingfisher").join("rule-cache");
    }

    if let Some(path) = non_empty_env_path("XDG_CACHE_HOME") {
        return path.join("kingfisher").join("rule-cache");
    }

    if let Some(path) = non_empty_env_path("HOME") {
        return path.join(".cache").join("kingfisher").join("rule-cache");
    }

    env::temp_dir().join("kingfisher").join("rule-cache")
}

fn non_empty_env_path(name: &str) -> Option<PathBuf> {
    let value = env::var_os(name)?;
    if value.is_empty() { None } else { Some(PathBuf::from(value)) }
}

fn compute_cache_key(rules: &[Arc<Rule>]) -> String {
    compute_cache_key_from_rules(rules.iter().map(|rule| rule.as_ref()))
}

fn compute_cache_key_from_rules<'a>(rules: impl IntoIterator<Item = &'a Rule>) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(format!("cache-format={CACHE_FORMAT_VERSION}\n").as_bytes());
    input.extend_from_slice(format!("vectorscan={}\n", vectorscan_rs::version()).as_bytes());
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
    let read_dir = match fs::read_dir(&cache.cache_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(summary),
        Err(err) => {
            return Err(err).with_context(|| format!("read {}", cache.cache_dir.display()));
        }
    };

    let mut entries = Vec::new();
    for entry in read_dir {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                debug!(%err, "Failed to read Vectorscan rule cache directory entry");
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("vscdb") {
            continue;
        }
        summary.scanned_entries += 1;

        let metadata = match entry.metadata() {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => continue,
            Err(err) => {
                debug!(path = %path.display(), %err, "Failed to stat Vectorscan rule cache entry");
                summary.invalid_entries += 1;
                continue;
            }
        };
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
    if entries.len() <= config.max_entries {
        return Ok(summary);
    }

    entries.sort_by(|a, b| b.modified.cmp(&a.modified).then_with(|| a.path.cmp(&b.path)));
    for entry in entries.iter().skip(config.max_entries) {
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

fn cache_target() -> String {
    format!(
        "{}-{}-{}-{}bit-{}",
        env::consts::OS,
        env::consts::ARCH,
        env::consts::FAMILY,
        usize::BITS,
        if cfg!(target_endian = "little") { "little" } else { "big" }
    )
}

fn load_cached_vectorscan_db(path: &Path, expected_header: &CacheHeader) -> Option<BlockDatabase> {
    if !path.exists() {
        debug!(path = %path.display(), "No Vectorscan rule cache entry found");
        return None;
    }

    match load_cached_vectorscan_db_inner(path, expected_header) {
        Ok(vsdb) => {
            debug!(path = %path.display(), "Loaded Vectorscan rule cache entry");
            Some(vsdb)
        }
        Err(err) => {
            debug!(
                path = %path.display(),
                %err,
                "Ignoring stale or invalid Vectorscan rule cache entry"
            );
            None
        }
    }
}

fn load_cached_vectorscan_db_inner(
    path: &Path,
    expected_header: &CacheHeader,
) -> Result<BlockDatabase> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let Some(rest) = bytes.strip_prefix(CACHE_MAGIC) else {
        bail!("invalid cache magic");
    };
    if rest.len() < 4 {
        bail!("truncated cache header length");
    }

    let mut len_bytes = [0_u8; 4];
    len_bytes.copy_from_slice(&rest[..4]);
    let header_len = u32::from_le_bytes(len_bytes) as usize;
    let header_start = 4_usize;
    let Some(header_end) = header_start.checked_add(header_len) else {
        bail!("cache header length overflow");
    };
    if rest.len() < header_end {
        bail!("truncated cache header");
    }

    let header: CacheHeader = serde_json::from_slice(&rest[header_start..header_end])
        .context("parse Vectorscan cache header")?;
    if &header != expected_header {
        bail!("cache metadata mismatch");
    }

    BlockDatabase::deserialize(&rest[header_end..]).context("deserialize Vectorscan database")
}

fn read_cached_vectorscan_header(path: &Path) -> Result<CacheHeader> {
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut magic = [0_u8; 8];
    file.read_exact(&mut magic).with_context(|| format!("read magic from {}", path.display()))?;
    if magic.as_slice() != CACHE_MAGIC {
        bail!("invalid cache magic");
    }

    let mut len_bytes = [0_u8; 4];
    file.read_exact(&mut len_bytes)
        .with_context(|| format!("read header length from {}", path.display()))?;
    let header_len = u32::from_le_bytes(len_bytes) as usize;
    let mut header_bytes = vec![0_u8; header_len];
    file.read_exact(&mut header_bytes)
        .with_context(|| format!("read header from {}", path.display()))?;
    serde_json::from_slice(&header_bytes).context("parse Vectorscan cache header")
}

fn store_cached_vectorscan_db(path: &Path, header: &CacheHeader, vsdb: &BlockDatabase) {
    match store_cached_vectorscan_db_inner(path, header, vsdb) {
        Ok(()) => {
            debug!(path = %path.display(), "Wrote Vectorscan rule cache entry");
        }
        Err(err) => {
            debug!(path = %path.display(), %err, "Failed to write Vectorscan rule cache entry");
        }
    }
}

fn store_cached_vectorscan_db_inner(
    path: &Path,
    header: &CacheHeader,
    vsdb: &BlockDatabase,
) -> Result<()> {
    let Some(parent) = path.parent() else {
        bail!("cache path has no parent");
    };
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;

    let header_bytes = serde_json::to_vec(header).context("serialize Vectorscan cache header")?;
    if header_bytes.len() > u32::MAX as usize {
        bail!("cache header is too large");
    }
    let db_bytes = vsdb.serialize().context("serialize Vectorscan database")?;

    let tmp_path = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name().and_then(|name| name.to_str()).unwrap_or("rule-cache"),
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let result = (|| -> Result<()> {
        let mut file = fs::File::create(&tmp_path)
            .with_context(|| format!("create {}", tmp_path.display()))?;
        file.write_all(CACHE_MAGIC)?;
        file.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        file.write_all(&header_bytes)?;
        file.write_all(&db_bytes)?;
        file.sync_all().with_context(|| format!("sync {}", tmp_path.display()))?;
        drop(file);
        replace_cache_file(&tmp_path, path)?;
        Ok(())
    })();
    if result.is_err() {
        fs::remove_file(&tmp_path).ok();
    }
    result
}

fn replace_cache_file(tmp_path: &Path, path: &Path) -> Result<()> {
    match fs::rename(tmp_path, path) {
        Ok(()) => Ok(()),
        Err(_err) if cfg!(windows) && path.exists() => {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(remove_err) if remove_err.kind() == ErrorKind::NotFound => {}
                Err(remove_err) => {
                    return Err(remove_err)
                        .with_context(|| format!("remove existing {}", path.display()));
                }
            }
            fs::rename(tmp_path, path).with_context(|| {
                format!(
                    "rename {} to {} after removing existing cache entry",
                    tmp_path.display(),
                    path.display()
                )
            })
        }
        Err(err) => {
            Err(err).with_context(|| format!("rename {} to {}", tmp_path.display(), path.display()))
        }
    }
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
        use vectorscan_rs::{BlockDatabase, BlockScanner, Pattern, Scan};
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
        use vectorscan_rs::{BlockScanner, Scan};

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
        let entries = fs::read_dir(&cache_dir)?.count();
        assert_eq!(entries, 1);

        let cached_db = RulesDatabase::from_rules_with_cache(rule_vec, &cache)?;
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
    fn cached_vectorscan_database_refreshes_corrupt_entry() -> Result<()> {
        use vectorscan_rs::{BlockScanner, Scan};

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
        use vectorscan_rs::{BlockScanner, Scan};

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

    fn write_fake_cache_entry(cache_dir: &Path, cache_key: &str) -> Result<PathBuf> {
        let path = cache_dir.join(format!("{cache_key}.vscdb"));
        let header = CacheHeader {
            format_version: CACHE_FORMAT_VERSION,
            cache_key: cache_key.to_string(),
            rule_count: 1,
            vectorscan_version: vectorscan_rs::version(),
            target: cache_target(),
            database_kind: "block".to_string(),
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

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use chrono::Local;
use serde::{Deserialize, Serialize};
use smallvec::{SmallVec, smallvec};
use tracing::debug;

type FingerprintForms = SmallVec<[u64; 2]>;

use crate::findings_store::FindingsStore;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BaselineFile {
    #[serde(rename = "ExactFindings", default)]
    pub exact_findings: ExactFindings,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ExactFindings {
    #[serde(default)]
    pub matches: Vec<BaselineFinding>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BaselineFinding {
    pub filepath: String,
    pub fingerprint: String,
    pub linenum: usize,
    pub lastupdated: String,
}

pub fn load_baseline(path: &Path) -> Result<BaselineFile> {
    let data = fs::read_to_string(path).context("read baseline file")?;
    serde_yaml::from_str(&data).context("parse baseline yaml")
}

/// Parse a baseline fingerprint string into its canonical u64 form(s).
///
/// Accepts either the decimal form users see in scan output (JSON/pretty/SARIF)
/// or the 16-char zero-padded hex form previously written by `--manage-baseline`.
/// Returns 0–2 canonical u64 interpretations: ambiguous 16-digit all-digit
/// strings — which could be either a decimal fingerprint or a legacy hex
/// fingerprint whose value happens to contain no `a-f` — yield both so either
/// form matches.
///
/// Detection:
///   1. A `0x`/`0X` prefix is stripped and the rest parsed as hex.
///   2. Exactly 16 hex chars containing at least one `a-f`/`A-F` letter are parsed as hex
///      (unambiguous legacy canonical form).
///   3. Exactly 16 digits: ambiguous — try both decimal and hex and return whichever
///      interpretations parse successfully, so old baselines keep matching.
///   4. Otherwise the string is parsed as decimal u64.
fn parse_fingerprint(s: &str) -> FingerprintForms {
    let trimmed = s.trim();
    if let Some(rest) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        return match u64::from_str_radix(rest, 16) {
            Ok(v) => smallvec![v],
            Err(_) => SmallVec::new(),
        };
    }
    if trimmed.len() == 16 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        if trimmed.chars().any(|c| c.is_ascii_alphabetic()) {
            return match u64::from_str_radix(trimmed, 16) {
                Ok(v) => smallvec![v],
                Err(_) => SmallVec::new(),
            };
        }
        let mut out: FingerprintForms = SmallVec::new();
        if let Ok(v) = trimmed.parse::<u64>() {
            out.push(v);
        }
        if let Ok(v) = u64::from_str_radix(trimmed, 16)
            && !out.contains(&v)
        {
            out.push(v);
        }
        return out;
    }
    match trimmed.parse::<u64>() {
        Ok(v) => smallvec![v],
        Err(_) => SmallVec::new(),
    }
}

pub fn save_baseline(path: &Path, baseline: &BaselineFile) -> Result<()> {
    let data = serde_yaml::to_string(baseline).context("serialize baseline")?;
    fs::write(path, data).context("write baseline file")
}

fn normalize_path(p: &Path, roots: &[PathBuf]) -> String {
    for root in roots {
        if let Ok(stripped) = p.strip_prefix(root)
            && let Some(name) = root.file_name()
        {
            return PathBuf::from(name).join(stripped).to_string_lossy().replace('\\', "/");
        }
    }
    p.to_string_lossy().replace('\\', "/")
}

pub fn apply_baseline(
    store: &mut FindingsStore,
    baseline_path: &Path,
    manage: bool,
    roots: &[PathBuf],
) -> Result<()> {
    let mut baseline = if baseline_path.exists() {
        load_baseline(baseline_path)?
    } else {
        BaselineFile::default()
    };

    let mut known: HashSet<u64> = HashSet::new();
    for m in &baseline.exact_findings.matches {
        let parsed = parse_fingerprint(&m.fingerprint);
        if parsed.is_empty() {
            debug!("Ignoring unparseable baseline fingerprint {:?}", m.fingerprint);
            continue;
        }
        known.extend(parsed);
    }

    let mut encountered: HashSet<u64> = HashSet::new();
    let mut new_entries = Vec::new();
    for arc_msg in store.get_matches_mut() {
        let (origin, _blob, m) = Arc::make_mut(arc_msg);
        let file_path = origin.iter().filter_map(|o| o.full_path()).next();
        let fp_value = m.finding_fingerprint;

        if let Some(fp) = file_path {
            let normalized = normalize_path(&fp, roots);
            if known.contains(&fp_value) {
                debug!("Skipping {} due to baseline (fingerprint {})", normalized, fp_value);
                m.visible = false;
                if manage {
                    encountered.insert(fp_value);
                }
            } else if manage {
                known.insert(fp_value);
                encountered.insert(fp_value);
                let entry = BaselineFinding {
                    filepath: normalized,
                    fingerprint: fp_value.to_string(),
                    linenum: m.location.resolved_source_span().start.line,
                    lastupdated: Local::now().to_rfc2822(),
                };
                new_entries.push(entry);
            }
        } else if known.contains(&fp_value) {
            m.visible = false;
            if manage {
                encountered.insert(fp_value);
            }
        }
    }
    if manage {
        let original_len = baseline.exact_findings.matches.len();
        baseline
            .exact_findings
            .matches
            .retain(|m| parse_fingerprint(&m.fingerprint).iter().any(|v| encountered.contains(v)));
        let mut changed = baseline.exact_findings.matches.len() != original_len;

        if !new_entries.is_empty() {
            baseline.exact_findings.matches.extend(new_entries);
            changed = true;
        }

        if changed {
            save_baseline(baseline_path, &baseline)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blob::{BlobId, BlobMetadata},
        location::{Location, OffsetSpan, SourcePoint, SourceSpan},
        matcher::{Match, SerializableCapture, SerializableCaptures},
        origin::{Origin, OriginSet},
        rules::rule::{Confidence, Rule, RuleSyntax},
    };
    use anyhow::Result;
    use smallvec::SmallVec;
    use std::{path::Path, sync::Arc};
    use tempfile::TempDir;

    fn test_rule() -> Arc<Rule> {
        Arc::new(Rule::new(RuleSyntax {
            name: "test".to_string(),
            id: "test.rule".to_string(),
            pattern: "test".to_string(),
            min_entropy: 0.0,
            confidence: Confidence::Low,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
        }))
    }

    fn empty_captures() -> SerializableCaptures {
        SerializableCaptures { captures: SmallVec::<[SerializableCapture; 2]>::new() }
    }

    fn make_store_with_match(fingerprint: u64, file_path: &Path) -> FindingsStore {
        let mut store = FindingsStore::new(PathBuf::from("."));
        let rule = test_rule();
        let match_item = Match {
            location: Location::with_source_span(
                OffsetSpan { start: 0, end: 1 },
                Some(SourceSpan {
                    start: SourcePoint { line: 1, column: 0 },
                    end: SourcePoint { line: 1, column: 1 },
                }),
            ),
            groups: empty_captures(),
            blob_id: BlobId::default(),
            finding_fingerprint: fingerprint,
            rule: Arc::clone(&rule),
            validation_response_body: None,
            validation_response_status: 0,
            validation_success: false,
            calculated_entropy: 0.0,
            visible: true,
            is_base64: false,
            dependent_captures: std::collections::BTreeMap::new(),
        };

        let origin = OriginSet::from(Origin::from_file(file_path.to_path_buf()));
        let blob_meta = Arc::new(BlobMetadata {
            id: BlobId::default(),
            num_bytes: 0,
            mime_essence: None,
            language: None,
        });

        let entry = Arc::new((Arc::new(origin), blob_meta, match_item));
        store.get_matches_mut().push(entry);
        store
    }

    fn expected_relative_path(root: &Path, file: &Path) -> String {
        let mut expected = PathBuf::from(root.file_name().unwrap());
        if let Ok(stripped) = file.strip_prefix(root) {
            expected = expected.join(stripped);
        }
        expected.to_string_lossy().replace('\\', "/")
    }

    #[test]
    fn apply_baseline_filters_existing_fingerprints() -> Result<()> {
        let tmp = TempDir::new()?;
        let roots = [tmp.path().to_path_buf()];
        let secret_file = tmp.path().join("secret.txt");
        fs::write(&secret_file, "dummy")?;
        let baseline_path = tmp.path().join("baseline.yaml");
        let fingerprint = 0x1234_u64;

        let mut store = make_store_with_match(fingerprint, &secret_file);
        apply_baseline(&mut store, &baseline_path, true, &roots)?;

        let baseline = load_baseline(&baseline_path)?;
        assert_eq!(baseline.exact_findings.matches.len(), 1);
        let entry = &baseline.exact_findings.matches[0];
        assert_eq!(entry.fingerprint, fingerprint.to_string());
        assert_eq!(entry.filepath, expected_relative_path(roots[0].as_path(), &secret_file));

        let (_, _, recorded) = store.get_matches()[0].as_ref();
        assert!(recorded.visible);

        let mut follow_up = make_store_with_match(fingerprint, &secret_file);
        apply_baseline(&mut follow_up, &baseline_path, false, &roots)?;
        let (_, _, filtered) = follow_up.get_matches()[0].as_ref();
        assert!(!filtered.visible);

        Ok(())
    }

    #[test]
    fn managing_baseline_is_idempotent() -> Result<()> {
        let tmp = TempDir::new()?;
        let roots = [tmp.path().to_path_buf()];
        let secret_file = tmp.path().join("secret.txt");
        fs::write(&secret_file, "dummy")?;
        let baseline_path = tmp.path().join("baseline.yaml");
        let fingerprint = 0xfeed_beef_dade_f00d_u64;

        let mut initial = make_store_with_match(fingerprint, &secret_file);
        apply_baseline(&mut initial, &baseline_path, true, &roots)?;
        let baseline_before = fs::read_to_string(&baseline_path)?;

        let mut rerun = make_store_with_match(fingerprint, &secret_file);
        apply_baseline(&mut rerun, &baseline_path, true, &roots)?;
        let baseline_after = fs::read_to_string(&baseline_path)?;
        assert_eq!(baseline_before, baseline_after);

        let (_, _, suppressed) = rerun.get_matches()[0].as_ref();
        assert!(!suppressed.visible);

        Ok(())
    }

    #[test]
    fn parse_fingerprint_accepts_all_forms() {
        let value: u64 = 0xfeed_beef_dade_f00d;
        assert_eq!(parse_fingerprint(&format!("{:016x}", value)).as_slice(), &[value]);
        assert_eq!(parse_fingerprint(&format!("0x{:016x}", value)).as_slice(), &[value]);
        assert_eq!(parse_fingerprint(&format!("0X{:X}", value)).as_slice(), &[value]);
        assert_eq!(parse_fingerprint(&value.to_string()).as_slice(), &[value]);
        assert_eq!(parse_fingerprint("  42  ").as_slice(), &[42]);
        assert_eq!(parse_fingerprint("0").as_slice(), &[0]);
        assert!(parse_fingerprint("").is_empty());
        assert!(parse_fingerprint("notahex").is_empty());
    }

    #[test]
    fn parse_fingerprint_all_digit_16_chars_is_ambiguous() {
        // A 16-char all-digit string could be either a decimal fingerprint
        // (scan output) or a legacy hex fingerprint whose value contains no
        // a-f. Both interpretations must be returned so old baselines keep
        // matching while new decimal fingerprints round-trip.
        let s = "1234567890123456";
        let parsed = parse_fingerprint(s);
        assert!(parsed.contains(&1234567890123456_u64));
        assert!(parsed.contains(&u64::from_str_radix(s, 16).unwrap()));
    }

    #[test]
    fn decimal_fingerprint_from_output_roundtrips() -> Result<()> {
        // Regression for issue #344: a fingerprint copied (in decimal) from
        // scan output into a hand-written baseline file must suppress the match.
        let tmp = TempDir::new()?;
        let roots = [tmp.path().to_path_buf()];
        let secret_file = tmp.path().join("secret.txt");
        fs::write(&secret_file, "dummy")?;
        let baseline_path = tmp.path().join("baseline.yaml");
        let fingerprint = 0xfeed_beef_dade_f00d_u64;

        let hand_written = BaselineFile {
            exact_findings: ExactFindings {
                matches: vec![BaselineFinding {
                    filepath: expected_relative_path(roots[0].as_path(), &secret_file),
                    fingerprint: fingerprint.to_string(),
                    linenum: 1,
                    lastupdated: "now".to_string(),
                }],
            },
        };
        save_baseline(&baseline_path, &hand_written)?;

        let mut store = make_store_with_match(fingerprint, &secret_file);
        apply_baseline(&mut store, &baseline_path, false, &roots)?;
        let (_, _, m) = store.get_matches()[0].as_ref();
        assert!(!m.visible);

        Ok(())
    }

    #[test]
    fn legacy_hex_baseline_still_matches() -> Result<()> {
        // A baseline file written by an older kingfisher (hex-padded) must
        // still suppress matches after the decimal switchover.
        let tmp = TempDir::new()?;
        let roots = [tmp.path().to_path_buf()];
        let secret_file = tmp.path().join("secret.txt");
        fs::write(&secret_file, "dummy")?;
        let baseline_path = tmp.path().join("baseline.yaml");
        let fingerprint = 0xfeed_beef_dade_f00d_u64;

        let legacy = BaselineFile {
            exact_findings: ExactFindings {
                matches: vec![BaselineFinding {
                    filepath: expected_relative_path(roots[0].as_path(), &secret_file),
                    fingerprint: format!("{:016x}", fingerprint),
                    linenum: 1,
                    lastupdated: "then".to_string(),
                }],
            },
        };
        save_baseline(&baseline_path, &legacy)?;

        let mut store = make_store_with_match(fingerprint, &secret_file);
        apply_baseline(&mut store, &baseline_path, false, &roots)?;
        let (_, _, m) = store.get_matches()[0].as_ref();
        assert!(!m.visible);

        Ok(())
    }

    #[test]
    fn mixed_format_baseline_matches_both_entries() -> Result<()> {
        let tmp = TempDir::new()?;
        let roots = [tmp.path().to_path_buf()];
        let file_hex = tmp.path().join("hex.txt");
        let file_dec = tmp.path().join("dec.txt");
        fs::write(&file_hex, "dummy")?;
        fs::write(&file_dec, "dummy")?;
        let baseline_path = tmp.path().join("baseline.yaml");
        // fp_hex must contain at least one hex letter so its 16-char hex form is
        // unambiguously hex (an all-digit 16-char string is treated as decimal to
        // satisfy the roundtrip contract for fingerprints copied from scan output).
        let fp_hex = 0x1a2b_3c4d_5e6f_7890_u64;
        let fp_dec = 0xaaaa_bbbb_cccc_dddd_u64;

        let mixed = BaselineFile {
            exact_findings: ExactFindings {
                matches: vec![
                    BaselineFinding {
                        filepath: expected_relative_path(roots[0].as_path(), &file_hex),
                        fingerprint: format!("{:016x}", fp_hex),
                        linenum: 1,
                        lastupdated: "then".to_string(),
                    },
                    BaselineFinding {
                        filepath: expected_relative_path(roots[0].as_path(), &file_dec),
                        fingerprint: fp_dec.to_string(),
                        linenum: 1,
                        lastupdated: "now".to_string(),
                    },
                ],
            },
        };
        save_baseline(&baseline_path, &mixed)?;

        let mut store_hex = make_store_with_match(fp_hex, &file_hex);
        apply_baseline(&mut store_hex, &baseline_path, false, &roots)?;
        assert!(!store_hex.get_matches()[0].as_ref().2.visible);

        let mut store_dec = make_store_with_match(fp_dec, &file_dec);
        apply_baseline(&mut store_dec, &baseline_path, false, &roots)?;
        assert!(!store_dec.get_matches()[0].as_ref().2.visible);

        Ok(())
    }
}

//! Shared literal path selection for objects, files and repository contents.
use anyhow::{Result, ensure};
use clap::Args;

#[derive(Args, Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PathSelection {
    /// Scan paths starting with this literal prefix (repeatable; end directory prefixes with '/')
    #[arg(global = true, long = "path-prefix", value_name = "PATH", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub include_prefixes: Vec<String>,

    /// Skip paths starting with this literal prefix (repeatable; overrides selection)
    #[arg(global = true, long = "skip-path-prefix", value_name = "PATH", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub exclude_prefixes: Vec<String>,

    /// Scan this filename extension, with or without a leading dot (repeatable)
    #[arg(global = true, long = "file-extension", value_name = "EXT")]
    pub include_extensions: Vec<String>,

    /// Skip this filename extension (repeatable; overrides selection)
    #[arg(global = true, long = "skip-file-extension", value_name = "EXT")]
    pub exclude_extensions: Vec<String>,
}

impl PathSelection {
    pub fn within_prefix(&self, source_prefix: Option<&str>) -> Option<Self> {
        let scopes = self.listing_prefixes(source_prefix);
        (!scopes.is_empty()).then(|| Self {
            // The empty listing scope means universal selection, not a literal
            // user-supplied empty prefix (which check() correctly rejects).
            include_prefixes: if scopes.iter().any(String::is_empty) { Vec::new() } else { scopes },
            ..self.clone()
        })
    }
    /// Intersect selection with an existing source scope, then collapse overlaps.
    pub fn listing_prefixes(&self, source_prefix: Option<&str>) -> Vec<String> {
        let mut prefixes = if self.include_prefixes.is_empty() {
            vec![source_prefix.unwrap_or_default().to_owned()]
        } else {
            self.include_prefixes
                .iter()
                .filter_map(|prefix| match source_prefix {
                    None => Some(prefix.clone()),
                    Some(base) if prefix.starts_with(base) => Some(prefix.clone()),
                    Some(base) if base.starts_with(prefix) => Some(base.to_owned()),
                    _ => None,
                })
                .collect()
        };
        prefixes.sort();
        let mut scopes: Vec<String> = Vec::new();
        for prefix in prefixes {
            if !scopes.last().is_some_and(|parent| prefix.starts_with(parent))
                && !self.exclude_prefixes.iter().any(|excluded| prefix.starts_with(excluded))
            {
                scopes.push(prefix);
            }
        }
        scopes
    }

    pub fn matches(&self, path: &str) -> bool {
        let extension_matches = |extension: &str| {
            let leaf = path.rsplit('/').next().unwrap_or(path);
            leaf.rsplit_once('.').is_some_and(|(_, actual)| {
                actual.eq_ignore_ascii_case(extension.trim_start_matches('.'))
            })
        };
        (self.include_prefixes.is_empty()
            || self.include_prefixes.iter().any(|prefix| path.starts_with(prefix)))
            && !self.exclude_prefixes.iter().any(|prefix| path.starts_with(prefix))
            && (self.include_extensions.is_empty()
                || self.include_extensions.iter().any(|ext| extension_matches(ext)))
            && !self.exclude_extensions.iter().any(|ext| extension_matches(ext))
    }

    pub fn is_empty(&self) -> bool {
        self.include_prefixes.is_empty()
            && self.exclude_prefixes.is_empty()
            && self.include_extensions.is_empty()
            && self.exclude_extensions.is_empty()
    }

    pub fn check(&self) -> Result<()> {
        ensure!(
            self.include_prefixes
                .iter()
                .chain(&self.exclude_prefixes)
                .all(|prefix| !prefix.is_empty()),
            "Path prefixes must not be empty"
        );
        for extension in self.include_extensions.iter().chain(&self.exclude_extensions) {
            ensure!(
                !extension.trim_start_matches('.').is_empty()
                    && !extension.contains(['/', '\\', '*'])
                    && !extension.trim_start_matches('.').contains('.'),
                "File extensions must be a single extension such as json, .yaml, or env"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_prefixes_are_rejected_by_clap_and_programmatic_validation() {
        use clap::Parser;

        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            selection: PathSelection,
        }

        for option in ["--path-prefix", "--skip-path-prefix"] {
            assert!(Cli::try_parse_from(["test", option, ""]).is_err());
        }
        for selection in [
            PathSelection { include_prefixes: vec![String::new()], ..Default::default() },
            PathSelection { exclude_prefixes: vec![String::new()], ..Default::default() },
        ] {
            assert!(selection.check().is_err());
        }
        assert!(PathSelection::default().check().is_ok());
    }

    #[test]
    fn trailing_slashes_are_not_enough_to_identify_directory_markers() {
        assert!(PathSelection::default().matches("nonempty-object/"));
        let selection =
            PathSelection { include_prefixes: vec!["configs/".into()], ..Default::default() };
        assert!(selection.matches("configs/nonempty-object/"));
    }

    #[test]
    fn universal_listing_scopes_remain_valid_selections() {
        for selection in [
            PathSelection::default(),
            PathSelection { include_extensions: vec!["env".into()], ..Default::default() },
            PathSelection { exclude_prefixes: vec!["private/".into()], ..Default::default() },
        ] {
            for source_prefix in [None, Some("")] {
                let scoped = selection.within_prefix(source_prefix).unwrap();
                scoped.check().unwrap();
                assert!(scoped.include_prefixes.is_empty());
                assert_eq!(scoped, selection);
            }
        }
    }

    #[test]
    fn selection_cannot_expand_a_source_prefix() {
        let selected = PathSelection {
            include_prefixes: vec!["configs/prod/".into(), "unrelated/".into()],
            ..Default::default()
        };
        assert_eq!(selected.listing_prefixes(Some("configs/")), ["configs/prod/"]);
        assert!(selected.listing_prefixes(Some("private/")).is_empty());
        assert_eq!(
            selected.listing_prefixes(Some("configs/prod/nested/")),
            ["configs/prod/nested/"]
        );
    }

    #[test]
    fn directory_boundaries_require_a_trailing_slash() {
        let mut selection =
            PathSelection { include_prefixes: vec!["configs".into()], ..Default::default() };
        assert!(selection.matches("configs2/key.env"));
        selection.include_prefixes = vec!["configs/".into()];
        assert!(!selection.matches("configs2/key.env"));
        assert!(selection.matches("configs/key.env"));
    }
}

// Use clap's canonical name for Display as well as parsing and help text.
// Every enum using this macro has only non-skipped ValueEnum variants.
macro_rules! impl_value_enum_display {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl std::fmt::Display for $ty {
                fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    let value = <Self as clap::ValueEnum>::to_possible_value(self)
                        .expect("displayed CLI variants are not skipped");
                    formatter.write_str(value.get_name())
                }
            }
        )+
    };
}

pub(crate) use impl_value_enum_display;

#[cfg(test)]
mod tests {
    use std::fmt::Display;

    use clap::ValueEnum;

    use crate::cli::{
        commands::{access_map, azure, bitbucket, gitea, github, gitlab, output, rules, scan},
        global,
    };

    fn assert_names<V: ValueEnum + Display>(expected: &[&str]) {
        let variants = V::value_variants();
        assert_eq!(variants.len(), expected.len());
        for (variant, expected) in variants.iter().zip(expected) {
            assert_eq!(variant.to_string(), *expected);
            assert_eq!(variant.to_possible_value().unwrap().get_name(), *expected);
            assert_eq!(V::from_str(expected, false).unwrap().to_string(), *expected);
        }
    }

    #[test]
    fn cli_enum_display_preserves_all_existing_names() {
        assert_names::<access_map::AccessMapOutputFormat>(&["json", "html"]);
        assert_names::<azure::AzureRepoType>(&["source", "fork", "all"]);
        assert_names::<azure::AzureOutputFormat>(&["pretty", "json", "jsonl", "bson", "sarif"]);
        assert_names::<bitbucket::BitbucketRepoType>(&["source", "fork", "all"]);
        assert_names::<gitea::GiteaRepoType>(&["source", "fork", "all"]);
        assert_names::<github::GitHubRepoType>(&["source", "fork", "all"]);
        assert_names::<github::GitHubOutputFormat>(&["pretty", "json", "jsonl", "bson", "sarif"]);
        assert_names::<github::GitCloneMode>(&["bare", "mirror"]);
        assert_names::<github::GitHistoryMode>(&["full", "none"]);
        assert_names::<gitlab::GitLabRepoType>(&["all", "owner", "member"]);
        assert_names::<output::ReportOutputFormat>(&[
            "pretty", "json", "jsonl", "bson", "toon", "sarif", "html",
        ]);
        assert_names::<output::GitHubOutputFormat>(&["pretty", "json", "jsonl", "bson", "sarif"]);
        assert_names::<rules::RulesListOutputFormat>(&["pretty", "json"]);
        assert_names::<scan::ConfidenceLevel>(&["low", "medium", "high"]);
        assert_names::<scan::ValidationFilter>(&["all", "active", "actionable"]);
        assert_names::<global::Mode>(&["auto", "never", "always"]);
        assert_names::<global::TlsMode>(&["strict", "lax", "off"]);
    }

    #[test]
    fn display_uses_clap_casing_and_explicit_names_not_aliases() {
        #[derive(Clone, ValueEnum)]
        enum Naming {
            ReadOnly,
            #[value(name = "custom-name", alias = "old-name")]
            Explicit,
        }
        super::impl_value_enum_display!(Naming);

        assert_names::<Naming>(&["read-only", "custom-name"]);
        assert_eq!(Naming::from_str("old-name", false).unwrap().to_string(), "custom-name");
    }

    #[test]
    fn repository_aliases_display_the_canonical_name() {
        assert_eq!(github::GitHubRepoType::from_str("forks", false).unwrap().to_string(), "fork");
        assert_eq!(gitea::GiteaRepoType::from_str("forks", false).unwrap().to_string(), "fork");
        assert_eq!(
            bitbucket::BitbucketRepoType::from_str("forks", false).unwrap().to_string(),
            "fork"
        );
    }
}

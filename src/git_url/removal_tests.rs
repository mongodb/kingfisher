//! Git URL validation and path compatibility before inherited helper replacement.

use std::fmt::Write;
use std::path::PathBuf;
use std::str::FromStr;

use url::Url;

use super::{GIT_URL_ERROR_MESSAGE, GitUrl};

fn path(parts: &[&str]) -> PathBuf {
    parts.iter().collect()
}

#[test]
fn http_and_https_are_supported_and_keep_distinct_cache_namespaces() {
    for scheme in ["http", "https"] {
        let text = format!("{scheme}://example.com/org/repo.git");
        let git_url = GitUrl::from_str(&text).unwrap();
        assert_eq!(git_url.as_str(), text);
        assert_eq!(git_url.to_path_buf(), path(&[scheme, "example.com", "org", "repo.git"]));
        assert_eq!(git_url.to_string(), text);
    }
    assert_ne!(
        "http://example.com/org/repo.git".parse::<GitUrl>().unwrap().to_path_buf(),
        "https://example.com/org/repo.git".parse::<GitUrl>().unwrap().to_path_buf(),
    );
}

#[test]
fn unsupported_or_malformed_urls_have_the_same_public_error() {
    for text in [
        "",
        "relative/repo.git",
        "git@example.com:org/repo.git",
        "https://",
        "file:///repo.git",
        "ssh://example.com/repo.git",
        "git://example.com/repo.git",
        "ftp://example.com/repo.git",
        "mailto:repo@example.com",
        "https://[invalid]/repo",
    ] {
        assert_eq!(GitUrl::from_str(text).unwrap_err(), GIT_URL_ERROR_MESSAGE, "{text}");
    }
}

#[test]
fn credentials_and_even_empty_query_or_fragment_are_rejected() {
    for text in [
        "https://user@example.com/repo",
        "https://user:pass@example.com/repo",
        "https://:pass@example.com/repo",
        "https://u%73er@example.com/repo",
        "http://user@example.com/repo",
        "https://example.com/repo?",
        "https://example.com/repo?value=1",
        "https://example.com/repo#",
        "https://example.com/repo#branch",
        "http://example.com/repo?value=1",
    ] {
        let parsed = Url::parse(text).unwrap();
        assert_eq!(GitUrl::try_from(parsed).unwrap_err(), GIT_URL_ERROR_MESSAGE, "{text}");
        assert_eq!(text.parse::<GitUrl>().unwrap_err(), GIT_URL_ERROR_MESSAGE, "{text}");
    }
}

#[test]
fn canonical_hosts_and_default_ports_preserve_equality_and_ordering() {
    let canonical: GitUrl = "https://example.com/Org/Repo.git".parse().unwrap();
    let uppercase: GitUrl = "HTTPS://EXAMPLE.COM:443/Org/Repo.git".parse().unwrap();
    assert_eq!(canonical, uppercase);
    assert_eq!(canonical.cmp(&uppercase), std::cmp::Ordering::Equal);
    assert_eq!(canonical.as_str(), "https://example.com/Org/Repo.git");
    assert_eq!(canonical.to_path_buf(), path(&["https", "example.com", "Org", "Repo.git"]));
    let distinct: GitUrl = "https://example.com/org/repo.git".parse().unwrap();
    assert_ne!(canonical, distinct);
    assert_ne!(canonical.to_path_buf(), distinct.to_path_buf());
}

#[test]
fn domain_ipv4_ipv6_and_nondefault_ports_keep_current_components() {
    for (text, expected) in [
        ("https://example.com:8443/repo.git", path(&["https", "example.com:8443", "repo.git"])),
        ("http://127.0.0.1:8080/repo.git", path(&["http", "127.0.0.1:8080", "repo.git"])),
        ("https://[::1]/repo.git", path(&["https", "::1", "repo.git"])),
        ("https://[2001:db8::1]:8443/repo.git", path(&["https", "2001:db8::1:8443", "repo.git"])),
        ("https://bücher.example/repo.git", path(&["https", "xn--bcher-kva.example", "repo.git"])),
    ] {
        assert_eq!(text.parse::<GitUrl>().unwrap().to_path_buf(), expected, "{text}");
    }
}

#[test]
fn dot_segments_are_normalized_by_the_url_parser_before_mapping() {
    for text in [
        "https://example.com/../repo.git",
        "https://example.com/base/../repo.git",
        "https://example.com/base/%2e%2e/repo.git",
        "https://example.com/./repo.git",
    ] {
        let git_url: GitUrl = text.parse().unwrap();
        assert_eq!(git_url.as_str(), "https://example.com/repo.git", "{text}");
        assert_eq!(git_url.to_path_buf(), path(&["https", "example.com", "repo.git"]));
    }
}

#[test]
fn encoded_separators_and_unicode_stay_url_encoded_in_cache_paths() {
    let url: GitUrl =
        "https://example.com/org%2Frepo/a%5Cb/spaced%20name/路径.git".parse().unwrap();
    assert_eq!(
        url.to_path_buf(),
        path(&[
            "https",
            "example.com",
            "org%2Frepo",
            "a%5Cb",
            "spaced%20name",
            "%E8%B7%AF%E5%BE%84.git",
        ])
    );
}

#[test]
fn display_propagates_output_failure() {
    struct FailingWriter;
    impl std::fmt::Write for FailingWriter {
        fn write_str(&mut self, _: &str) -> std::fmt::Result {
            Err(std::fmt::Error)
        }
    }
    let url: GitUrl = "https://example.com/repo.git".parse().unwrap();
    assert!(write!(FailingWriter, "{url}").is_err());
}

#[test]
fn repeated_empty_and_trailing_segments_keep_url_text_and_path_mapping() {
    for (text, canonical, parts) in [
        ("https://example.com", "https://example.com/", vec!["https", "example.com", ""]),
        ("https://example.com/", "https://example.com/", vec!["https", "example.com", ""]),
        ("https://example.com//", "https://example.com//", vec!["https", "example.com", ""]),
        (
            "https://example.com///org//repo.git",
            "https://example.com///org//repo.git",
            vec!["https", "example.com", "org", "repo.git"],
        ),
        (
            "http://example.com:8080/org//repo.git///",
            "http://example.com:8080/org//repo.git///",
            vec!["http", "example.com:8080", "org", "repo.git", ""],
        ),
        (
            "https://example.com/org/org/repo.git/",
            "https://example.com/org/org/repo.git/",
            vec!["https", "example.com", "org", "org", "repo.git", ""],
        ),
    ] {
        let parsed = Url::parse(text).unwrap();
        let git_url = GitUrl::try_from(parsed).unwrap();
        assert_eq!(git_url.as_str(), canonical, "{text}");
        assert_eq!(text.parse::<GitUrl>().unwrap(), git_url, "{text}");
        assert_eq!(git_url.to_path_buf().as_os_str(), path(&parts).as_os_str(), "{text}");
    }
}

#[test]
fn drive_like_components_preserve_the_platform_pathbuf_contract() {
    for (text, drive, unix_parts) in [
        ("https://example.com/C:/repo.git", "C:", vec!["https", "example.com", "C:", "repo.git"]),
        (
            "https://example.com/org/C:/repo.git",
            "C:",
            vec!["https", "example.com", "org", "C:", "repo.git"],
        ),
        (
            "http://example.com/C:relative/repo.git",
            "C:relative",
            vec!["http", "example.com", "C:relative", "repo.git"],
        ),
    ] {
        let git_url: GitUrl = text.parse().unwrap();
        assert_eq!(git_url.as_str(), text);
        // The compatibility mapping delegates each segment to PathBuf. On Windows,
        // a drive-prefixed segment replaces the earlier scheme and authority.
        let expected =
            if cfg!(windows) { PathBuf::from(drive).join("repo.git") } else { path(&unix_parts) };
        assert_eq!(git_url.to_path_buf().as_os_str(), expected.as_os_str(), "{text}");
    }
    let encoded: GitUrl = "https://example.com/C%3A/repo.git".parse().unwrap();
    assert_eq!(
        encoded.to_path_buf().as_os_str(),
        path(&["https", "example.com", "C%3A", "repo.git"]).as_os_str()
    );
}

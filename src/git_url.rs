use std::path::PathBuf;

use url::{Host, Url};

/// A repository URL using HTTP(S) or SSH, without passwords, query, or fragment.
///
/// SSH usernames are account selectors rather than stored credentials. The optional
/// second field preserves scp-style paths, whose relative semantics must not change
/// when passing the URL to the transport.
#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub struct GitUrl(Url, Option<ScpUrl>);

#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
struct ScpUrl {
    original: String,
    relative: bool,
}

impl GitUrl {
    /// Convert this URL into a `PathBuf`, ensuring no path traversal.
    ///
    /// For example, an HTTPS URL like `https://github.com/user/repo.git` becomes
    /// `PathBuf(["https", "github.com", "user", "repo.git"])`.
    ///
    /// Path segments that are `..` are already disallowed in [`TryFrom<Url>`].
    pub fn to_path_buf(&self) -> PathBuf {
        let mut result = PathBuf::new();
        result.push(self.0.scheme());

        let mut host_str = match self.0.host().expect("host should be non-empty") {
            Host::Domain(h) => h.to_string(),
            Host::Ipv4(addr) => addr.to_string(),
            Host::Ipv6(addr) if self.0.scheme() == "ssh" => format!("[{addr}]"),
            Host::Ipv6(addr) => addr.to_string(),
        };
        if self.0.scheme() == "ssh" && !self.0.username().is_empty() {
            host_str = format!("{}@{host_str}", self.0.username());
        }

        if let Some(port) = self.0.port() {
            host_str = format!("{host_str}:{port}");
        }
        let ssh = self.0.scheme() == "ssh";
        if ssh {
            result.push(ssh_cache_component(&host_str));
        } else {
            // Preserve existing HTTP(S) cache paths exactly.
            result.push(host_str);
        }
        if self.1.as_ref().is_some_and(|scp| scp.relative) {
            // scp's relative repository path is distinct from ssh://host/absolute.
            result.push("~");
        }

        // Safe to unwrap path segments due to checks in `TryFrom<Url>`
        if let Some(segments) = self.0.path_segments() {
            if ssh {
                result.extend(segments.map(ssh_cache_component));
            } else {
                result.extend(segments);
            }
        }

        result
    }

    /// Return the wrapped URL as a string.
    pub fn as_str(&self) -> &str {
        self.1.as_ref().map_or_else(|| self.0.as_str(), |scp| scp.original.as_str())
    }
}

/// Keep SSH cache components portable and injective without migrating HTTP caches.
fn ssh_cache_component(component: &str) -> String {
    let basename = component.split('.').next().unwrap_or_default().trim_end_matches(' ');
    let basename = basename.to_ascii_uppercase();
    let reserved = matches!(basename.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (basename.len() == 4
            && (basename.starts_with("COM") || basename.starts_with("LPT"))
            && matches!(basename.as_bytes()[3], b'1'..=b'9'));
    let trailing = component.trim_end_matches(['.', ' ']).len();
    let mut escaped = String::with_capacity(component.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for (offset, character) in component.char_indices() {
        if (reserved && offset == 0)
            || offset >= trailing
            || character.is_control()
            || matches!(character, '%' | '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*')
        {
            let mut bytes = [0; 4];
            for byte in character.encode_utf8(&mut bytes).bytes() {
                escaped.push('%');
                escaped.push(char::from(HEX[usize::from(byte >> 4)]));
                escaped.push(char::from(HEX[usize::from(byte & 15)]));
            }
        } else {
            escaped.push(character);
        }
    }
    escaped
}

impl std::fmt::Display for GitUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

const GIT_URL_ERROR_MESSAGE: &str = "only HTTP(S) URLs without credentials or SSH URLs without passwords, query parameters, or fragment identifiers are supported";

impl std::str::FromStr for GitUrl {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains("://") {
            return Url::parse(s).map_err(|_| GIT_URL_ERROR_MESSAGE).and_then(Self::try_from);
        }
        // A drive-qualified local path must not become a one-letter SSH host,
        // including when a Windows input is parsed on another platform.
        if s.as_bytes().get(1) == Some(&b':') && matches!(s.as_bytes().get(2), Some(b'/' | b'\\')) {
            return Err(GIT_URL_ERROR_MESSAGE);
        }
        // Preserve scp-style paths verbatim: `host:repo` is relative to the
        // remote account's home, unlike the absolute `ssh://host/repo`.
        use gix::bstr::ByteSlice;
        let parsed = gix::url::parse(s.as_bytes().as_bstr()).map_err(|_| GIT_URL_ERROR_MESSAGE)?;
        if parsed.scheme != gix::url::Scheme::Ssh
            || parsed.password().is_some()
            || s.contains(['?', '#', '\n', '\r', '\0'])
            || parsed.path.is_empty()
            || parsed.path.split(|byte| *byte == b'/').any(|part| part == b"..")
            || matches!(parsed.user_as_argument(), gix::url::ArgumentSafety::Dangerous(_))
            || matches!(parsed.host_as_argument(), gix::url::ArgumentSafety::Dangerous(_))
        {
            return Err(GIT_URL_ERROR_MESSAGE);
        }
        let host = parsed.host().ok_or(GIT_URL_ERROR_MESSAGE)?;
        let mut url = Url::parse("ssh://placeholder.invalid/").expect("constant valid URL");
        url.set_host(Some(host)).map_err(|_| GIT_URL_ERROR_MESSAGE)?;
        // SCP syntax treats percent signs literally, unlike URL syntax. Preserve
        // that distinction in the internal URL so encoded dots cannot normalize
        // away and literal `%20` cannot collide with an actual space.
        let user = parsed.user().unwrap_or_default().replace('%', "%25");
        url.set_username(&user).map_err(|_| GIT_URL_ERROR_MESSAGE)?;
        let path = parsed
            .path
            .to_str()
            .map_err(|_| GIT_URL_ERROR_MESSAGE)?
            .replace('%', "%25")
            .replace('\t', "%09");
        url.set_path(&path);
        let mut result = Self::try_from(url)?;
        result.1 =
            Some(ScpUrl { original: s.to_owned(), relative: !parsed.path.starts_with(b"/") });
        Ok(result)
    }
}

impl TryFrom<Url> for GitUrl {
    type Error = &'static str;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        if !matches!(url.scheme(), "https" | "http" | "ssh")
            || url.host().is_none()
            || (url.scheme() != "ssh" && !url.username().is_empty())
            || url.username().starts_with('-')
            || url.host_str().is_some_and(|host| host.starts_with('-'))
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(GIT_URL_ERROR_MESSAGE);
        }
        match url.path_segments() {
            Some(segs) if segs.clone().any(|s| s == "..") => Err(GIT_URL_ERROR_MESSAGE),
            Some(_) => Ok(GitUrl(url, None)),
            None => Err(GIT_URL_ERROR_MESSAGE),
        }
    }
}

#[cfg(test)]
mod test {
    use std::{path::Path, str::FromStr};

    use super::*;

    #[test]
    fn bad_scheme_01() {
        assert!(GitUrl::from_str("file://rel_repo.git").is_err());
    }

    #[test]
    fn bad_scheme_02() {
        assert!(GitUrl::from_str("file:///abs_repo.git").is_err());
    }

    #[test]
    fn ssh_urls_accept_account_names_and_ports() {
        for (text, path) in [
            ("ssh://example.com/repo.git", "ssh/example.com/repo.git"),
            ("ssh://git@example.com/repo.git", "ssh/git@example.com/repo.git"),
            ("ssh://git@example.com:2222/repo.git", "ssh/git@example.com%3A2222/repo.git"),
            (
                "ssh://git@[2001:db8::1]:2222/repo.git",
                "ssh/git@[2001%3Adb8%3A%3A1]%3A2222/repo.git",
            ),
        ] {
            let url = GitUrl::from_str(text).unwrap();
            assert_eq!(url.as_str(), text);
            assert_eq!(url.to_string(), text);
            assert_eq!(url.to_path_buf(), Path::new(path));
        }
    }

    #[test]
    fn scp_urls_preserve_relative_paths_and_do_not_collide_with_absolute_urls() {
        let scp: GitUrl = "git@example.com:org/repo.git".parse().unwrap();
        let absolute: GitUrl = "ssh://git@example.com/org/repo.git".parse().unwrap();
        assert_eq!(scp.as_str(), "git@example.com:org/repo.git");
        assert_eq!(scp.to_string(), "git@example.com:org/repo.git");
        assert_eq!(scp.to_path_buf(), Path::new("ssh/git@example.com/~/org/repo.git"));
        assert_ne!(scp.to_path_buf(), absolute.to_path_buf());
        let scp_absolute: GitUrl = "git@example.com:/org/repo.git".parse().unwrap();
        assert_eq!(scp_absolute.as_str(), "git@example.com:/org/repo.git");
        assert_eq!(scp_absolute.to_path_buf(), absolute.to_path_buf());
        assert_ne!(scp_absolute.to_path_buf(), scp.to_path_buf());
        assert_ne!(
            scp.to_path_buf(),
            "other@example.com:org/repo.git".parse::<GitUrl>().unwrap().to_path_buf(),
        );
        assert!("example.com:org/repo.git".parse::<GitUrl>().is_ok());
    }

    #[test]
    fn ssh_passwords_and_ambiguous_arguments_are_rejected() {
        for text in [
            "ssh://git:secret@example.com/repo.git",
            "ssh://-option@example.com/repo.git",
            "ssh://-option/repo.git",
            "ssh://git@example.com/repo.git?query",
            "ssh://git@example.com/repo.git#fragment",
            "-option@example.com:repo.git",
            "git@-option:repo.git",
            "git@example.com:../repo.git",
            "git@example.com:repo.git?query",
            "git@example.com:repo.git#fragment",
            "git@example.com:repo.git\n",
            "relative/repo.git",
            "C:\\repo.git",
            "git://example.com/repo.git",
        ] {
            assert!(text.parse::<GitUrl>().is_err(), "{text:?}");
        }
    }

    #[test]
    fn ssh_spaces_quotes_and_unicode_remain_safe_cache_components() {
        let url: GitUrl = "git@example.com:org/spaced '路径'.git".parse().unwrap();
        assert_eq!(url.as_str(), "git@example.com:org/spaced '路径'.git");
        assert_eq!(
            url.to_path_buf(),
            Path::new("ssh/git@example.com/~/org/spaced%2520'%25E8%25B7%25AF%25E5%25BE%2584'.git"),
        );
    }

    #[test]
    fn ssh_cache_components_escape_windows_characters_and_trailing_dots_or_spaces() {
        for (component, expected) in [
            ("git@example.com", "git@example.com"),
            ("路径.git", "路径.git"),
            ("C:repo", "C%3Arepo"),
            ("..\\repo", "..%5Crepo"),
            ("a/b", "a%2Fb"),
            ("a<b>c\"d|e?f*g", "a%3Cb%3Ec%22d%7Ce%3Ff%2Ag"),
            ("a\0\t\r\n\x1f\x7fb", "a%00%09%0D%0A%1F%7Fb"),
            ("a\u{85}b", "a%C2%85b"),
            ("repo. .", "repo%2E%20%2E"),
            (".", "%2E"),
            ("..", "%2E%2E"),
            ("%3A", "%253A"),
        ] {
            assert_eq!(ssh_cache_component(component), expected, "{component:?}");
        }
    }

    #[test]
    fn ssh_cache_components_escape_reserved_device_names_with_extensions() {
        for name in ["CON", "prn", "Aux", "nul", "COM1", "com9", "LPT1", "lpt9"] {
            for suffix in ["", ".git", " .git", ". "] {
                let component = format!("{name}{suffix}");
                let escaped = ssh_cache_component(&component);
                assert!(escaped.starts_with('%'), "{component:?}");
                assert_ne!(escaped, component);
                assert_ne!(escaped, ssh_cache_component(&escaped));
            }
        }
        for name in ["COM0", "COM10", "LPT0", "LPT10", "CONSOLE", "NULLED.git"] {
            assert_eq!(ssh_cache_component(name), name);
        }
    }

    #[test]
    fn ssh_cache_escape_sequences_cannot_alias_literal_percent_sequences() {
        for (unsafe_component, literal) in [
            ("C:repo", "C%3Arepo"),
            ("repo\\name", "repo%5Cname"),
            ("repo.", "repo%2E"),
            ("CON.git", "%43ON.git"),
            ("a\tb", "a%09b"),
        ] {
            assert_ne!(ssh_cache_component(unsafe_component), ssh_cache_component(literal));
        }
        for (first, second) in [
            ("git@example.com:org/a b.git", "git@example.com:org/a%20b.git"),
            ("git@example.com:org/a\tb.git", "git@example.com:org/ab.git"),
        ] {
            let second = second.parse::<GitUrl>().unwrap();
            assert_eq!(second.as_str(), second.to_string());
            let first = first.parse::<GitUrl>().unwrap();
            assert_ne!(first.to_path_buf(), second.to_path_buf());
        }
        let percent_dots: GitUrl = "git@example.com:org/%2e%2e/repo.git".parse().unwrap();
        let root: GitUrl = "git@example.com:repo.git".parse().unwrap();
        assert_ne!(percent_dots.to_path_buf(), root.to_path_buf());
        let ipv6_port: GitUrl = "ssh://git@[::1]:2/repo.git".parse().unwrap();
        let ipv6_no_port: GitUrl = "ssh://git@[::1:2]/repo.git".parse().unwrap();
        assert_ne!(ipv6_port.to_path_buf(), ipv6_no_port.to_path_buf());
        let encoded_user: GitUrl = "git%2540name@example.com:repo.git".parse().unwrap();
        let decoded_user: GitUrl = "git%40name@example.com:repo.git".parse().unwrap();
        assert_ne!(encoded_user.to_path_buf(), decoded_user.to_path_buf());
    }

    #[test]
    fn ssh_cache_paths_cannot_escape_through_drives_backslashes_or_device_names() {
        use std::path::Component;
        for text in [
            "git@example.com:org/C:relative/repo\\nested/CON.git/trailing./percent%3A",
            "ssh://git@example.com:2222/org/C:relative/%5C%5Cserver/PRN/repo%01.git",
            "ssh://git@[2001:db8::1]:2222/org/LPT9.git",
        ] {
            let url: GitUrl = text.parse().unwrap();
            let path = url.to_path_buf();
            assert!(!path.is_absolute(), "{text}");
            assert!(path.starts_with("ssh"), "{text}");
            let mut count = 0;
            for component in path.components() {
                let Component::Normal(component) = component else {
                    panic!("Non-normal SSH cache component: {component:?} in {text}");
                };
                let component = component.to_str().unwrap();
                assert!(!component.contains(['\\', '<', '>', ':', '"', '|', '?', '*']));
                assert!(!component.chars().any(char::is_control));
                assert!(!component.ends_with(['.', ' ']));
                count += 1;
            }
            assert_eq!(
                count,
                2 + usize::from(url.1.as_ref().is_some_and(|scp| scp.relative))
                    + url.0.path_segments().unwrap().count(),
            );
        }
        assert!("git@example.com:../repo.git".parse::<GitUrl>().is_err());
        assert!("C:\\repo.git".parse::<GitUrl>().is_err());
    }

    #[test]
    fn ssh_cache_escaping_does_not_migrate_http_caches() {
        let url: GitUrl = "https://example.com/CON/percent%25/ending./repo.git".parse().unwrap();
        assert_eq!(
            url.to_path_buf(),
            Path::new("https/example.com/CON/percent%25/ending./repo.git"),
        );
    }

    #[test]
    fn bad_query_params() {
        assert!(GitUrl::from_str("https://example.com/repo.git?admin=1").is_err());
    }

    #[test]
    fn ok_empty_path_01() {
        let url = GitUrl::from_str("https://example.com").unwrap();
        assert_eq!(url.to_path_buf(), Path::new("https/example.com"));
    }

    #[test]
    fn ok_empty_path_02() {
        let url = GitUrl::from_str("https://example.com/").unwrap();
        assert_eq!(url.to_path_buf(), Path::new("https/example.com"));
    }

    #[test]
    fn ok_01() {
        let url = GitUrl::from_str("https://github.com/mongodb/mongo.git").unwrap();
        assert_eq!(url.to_path_buf(), Path::new("https/github.com/mongodb/mongo.git"));
    }

    #[test]
    fn ok_relpath_01() {
        let url = GitUrl::from_str("https://example.com/../project.git").unwrap();
        assert_eq!(url.to_path_buf(), Path::new("https/example.com/project.git"));
    }

    #[test]
    fn ok_relpath_02() {
        let url = GitUrl::from_str("https://example.com/root/../project.git").unwrap();
        assert_eq!(url.to_path_buf(), Path::new("https/example.com/project.git"));
    }

    #[test]
    fn ok_relpath_03() {
        let url = GitUrl::from_str("https://example.com/root/..").unwrap();
        assert_eq!(url.to_path_buf(), Path::new("https/example.com/"));
    }
}

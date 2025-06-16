use std::path::PathBuf;

use url::{Host, Url};

/// A wrapper around [`Url`] restricted to HTTPS and without credentials, query, or fragment.
#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub struct GitUrl(Url);

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

        let host_str = match self.0.host().expect("host should be non-empty") {
            Host::Domain(h) => h.to_string(),
            Host::Ipv4(addr) => addr.to_string(),
            Host::Ipv6(addr) => addr.to_string(),
        };

        if let Some(port) = self.0.port() {
            result.push(format!("{host_str}:{port}"));
        } else {
            result.push(host_str);
        }

        // Safe to unwrap path segments due to checks in `TryFrom<Url>`
        if let Some(segments) = self.0.path_segments() {
            result.extend(segments);
        }

        result
    }

    /// Return the wrapped URL as a string.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Display for GitUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

const GIT_URL_ERROR_MESSAGE: &str =
    "only https URLs without credentials, query parameters, or fragment identifiers are supported";

impl std::str::FromStr for GitUrl {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Url::parse(s).map_err(|_| GIT_URL_ERROR_MESSAGE).and_then(Self::try_from)
    }
}

impl TryFrom<Url> for GitUrl {
    type Error = &'static str;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        if url.scheme() != "https"
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(GIT_URL_ERROR_MESSAGE);
        }
        match url.path_segments() {
            Some(segs) if segs.clone().any(|s| s == "..") => Err(GIT_URL_ERROR_MESSAGE),
            Some(_) => Ok(GitUrl(url)),
            None => Err(GIT_URL_ERROR_MESSAGE),
        }
    }
}

#[cfg(test)]
mod test {
    use std::{path::Path, str::FromStr};

    use pretty_assertions::assert_eq;

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
    fn bad_scheme_03() {
        assert!(GitUrl::from_str("ssh://example.com/repo.git").is_err());
    }

    #[test]
    fn bad_scheme_04() {
        assert!(GitUrl::from_str("http://example.com/repo.git").is_err());
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

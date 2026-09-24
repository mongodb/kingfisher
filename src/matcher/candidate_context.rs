use crate::location::OffsetSpan;

/// Recognize direct assignments, retaining the entire application-specific
/// prefix. Never use proximity or a partial prefix to select a credential pair.
pub(super) fn assignment_family(bytes: &[u8], span: OffsetSpan) -> Option<String> {
    let mut prefix = bytes.get(..span.start)?;
    if matches!(prefix.last(), Some(b'\'' | b'"')) {
        prefix = &prefix[..prefix.len() - 1];
    }
    let trim = |b: u8| matches!(b, b' ' | b'\t');
    while prefix.last().is_some_and(|b| trim(*b)) {
        prefix = &prefix[..prefix.len() - 1];
    }
    prefix = prefix.strip_suffix(b"=")?;
    while prefix.last().is_some_and(|b| trim(*b)) {
        prefix = &prefix[..prefix.len() - 1];
    }
    let start = prefix
        .iter()
        .rposition(|b| !b.is_ascii_alphanumeric() && *b != b'_')
        .map_or(0, |index| index + 1);
    // Do not silently discard part of a dotted, hyphenated or Unicode name.
    if start > 0
        && !matches!(
            prefix[start - 1],
            b' ' | b'\t' | b'\r' | b'\n' | b'[' | b'{' | b'(' | b',' | b';' | b'\'' | b'"'
        )
    {
        return None;
    }
    let name = std::str::from_utf8(&prefix[start..]).ok()?.to_ascii_lowercase();
    let suffixes: &[&str] = &[
        "_secret_access_key",
        "_access_key_id",
        "_client_secret",
        "_client_id",
        "_access_key",
        "_secret_key",
        "_key_id",
        "_username",
        "_password",
        "_secret",
        "_token",
        "_user",
        "_key",
        "_id",
    ];
    let family = suffixes.iter().find_map(|suffix| name.strip_suffix(suffix))?;
    (!family.is_empty()).then(|| family.to_owned())
}

/// Best-effort object/section context is only a ranking signal, never proof of
/// association. Record scope IDs only at match offsets, without retaining the blob.
pub(super) fn scopes(
    bytes: &[u8],
    offsets: impl Iterator<Item = usize>,
) -> std::collections::BTreeMap<usize, usize> {
    let mut result: std::collections::BTreeMap<usize, usize> = offsets.map(|o| (o, 0)).collect();
    let mut stack = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    let mut section = 0;
    let mut line_start = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        if index == line_start {
            let end =
                bytes[index..].iter().position(|b| *b == b'\n').map_or(bytes.len(), |n| index + n);
            let line = bytes[index..end].trim_ascii();
            if line.starts_with(b"[")
                && line.ends_with(b"]")
                && !line.contains(&b'=')
                && !line.contains(&b'{')
                && !line.contains(&b'"')
                && !line.contains(&b',')
            {
                section = index + 1;
            }
        }
        if let Some(scope) = result.get_mut(&index) {
            *scope = stack.last().map_or(section, |(_, id)| *id);
        }
        if byte == b'\n' {
            line_start = index + 1;
            quote = None;
            escaped = false;
        }
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == delimiter {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'{' | b'[' => stack.push((byte, index + 1)),
            b'}' | b']'
                if stack.last().is_some_and(|(open, _)| {
                    (*open == b'{' && byte == b'}') || (*open == b'[' && byte == b']')
                }) =>
            {
                stack.pop();
            }
            _ => {}
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_arrays_do_not_replace_ini_section_context() {
        let input = b"[production]\nfirst\n[1,2]\nsecond\n[staging]\nthird";
        let offsets: Vec<_> = [b"first".as_slice(), b"second", b"third"]
            .iter()
            .map(|needle| input.windows(needle.len()).position(|w| w == *needle).unwrap())
            .collect();
        let contexts = scopes(input, offsets.iter().copied());
        assert_eq!(contexts[&offsets[0]], contexts[&offsets[1]]);
        assert_ne!(contexts[&offsets[1]], contexts[&offsets[2]]);
    }

    fn family(input: &str) -> Option<String> {
        let start = input.find("VALUE").unwrap();
        assignment_family(input.as_bytes(), OffsetSpan::from_range(start..start + 5))
    }

    #[test]
    fn retains_full_family_and_normalizes_credential_suffixes() {
        for (key, secret, expected) in [
            ("production_client_id=VALUE", "production_client_secret=VALUE", "production"),
            ("kms_aws_key=VALUE", "kms_aws_secret=VALUE", "kms_aws"),
            ("AWS_ACCESS_KEY_ID = 'VALUE'", "AWS_SECRET_ACCESS_KEY = \"VALUE\"", "aws"),
            ("Env=[KMS_AWS_KEY=VALUE", "kms_aws_secret_key=VALUE", "kms_aws"),
            (
                "mongodb_agent_online_archive_test_aws_access_key=VALUE",
                "mongodb_agent_online_archive_test_aws_secret_key=VALUE",
                "mongodb_agent_online_archive_test_aws",
            ),
            (
                "aws_cdn_origin_dev_access_key=VALUE",
                "aws_cdn_origin_dev_secret_key=VALUE",
                "aws_cdn_origin_dev",
            ),
        ] {
            assert_eq!(family(key).as_deref(), Some(expected));
            assert_eq!(family(secret).as_deref(), Some(expected));
        }
    }

    #[test]
    fn rejects_missing_or_indirect_assignments() {
        for input in [
            "VALUE",
            "aws_key=prefixVALUE",
            "aws_key: VALUE",
            "aws_key=\nVALUE",
            "prod.kms_aws_key=VALUE",
            "prod-kms_aws_key=VALUE",
            "éaws_key=VALUE",
        ] {
            assert_eq!(family(input), None, "{input}");
        }
    }
}

"""Private-key placeholders must not hide a later real private-key encoding."""
import base64

import pytest

from kingfisher_sdk import DetectionPolicy, Rules, ScanInput, Scanner


@pytest.fixture(scope="module")
def builtin_rules():
    return Rules(cache=False)


@pytest.mark.parametrize("policy", [None, DetectionPolicy()], ids=["default", "detection-policy"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("empty_envelope", [False, True], ids=["ini", "ini-and-empty"])
def test_ini_private_key_placeholders_preserve_later_key(
        builtin_rules, tmp_path, policy, newline, empty_envelope):
    short = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "  foo\n  bar\n  foobar\n  barfoo\n"
        "  -----END RSA PRIVATE KEY-----"
    )
    numbered = "-----BEGIN RSA PRIVATE KEY-----\n" + "".join(
        f"   {index}{('foo', 'bar', 'foobar', 'barfoo')[(index - 1) % 4]}\n"
        for index in range(1, 97)
    ) + "   -----END RSA PRIVATE KEY-----"
    # A deterministic, synthetic Ed25519 PKCS#8 key needs no crypto dependency
    # or external process. Its seed is public test data, never a live credential.
    der = bytes.fromhex("302e020100300506032b657004220420") + bytes(range(32))
    valid = (
        "-----BEGIN PRIVATE KEY-----\n"
        + base64.b64encode(der).decode("ascii")
        + "\n-----END PRIVATE KEY-----"
    )
    empty = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n" if empty_envelope else ""
    source = (
        "package ini\n\nconst shortFixture = `\n" + short
        + "\nmultiline_list =\n  first\n  second\n  third\n`\n"
        + "\nconst numberedFixture = `\n" + numbered + "\n`\n"
        + "\nconst actualKey = `\n" + empty + valid + "\n`\n"
    ).replace("\n", newline).encode("ascii")
    expected = valid.replace("\n", newline).encode("ascii")
    path = tmp_path / "ini_test.go"
    path.write_bytes(source)

    findings = [
        finding for finding in Scanner(builtin_rules, policy=policy).scan_file(path)
        if finding.rule_id == "betterleaks.private-key"
    ]
    finding, = findings
    assert finding.secret.encode("ascii") == expected
    start = source.index(expected)
    assert finding.location["start_offset"] == start
    assert finding.location["end_offset"] == start + len(expected)
    assert finding.location["line"] == source[:start].count(b"\n") + 1


@pytest.mark.parametrize("policy", [None, DetectionPolicy()], ids=["default", "detection-policy"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("input_kind", ["file", "source", "base64"])
def test_java_private_key_placeholders_preserve_later_key(
        builtin_rules, tmp_path, policy, newline, input_kind):
    # This public test seed produces a structurally valid Ed25519 PKCS#8 container.
    der = bytes.fromhex("302e020100300506032b657004220420") + bytes(range(32))
    valid = (
        "-----BEGIN PRIVATE KEY-----\n"
        + base64.b64encode(der).decode("ascii")
        + "\n-----END PRIVATE KEY-----"
    )
    identifier = "notEncodedKeyMaterial" * 64
    source = (
        'class PrivateKeyExamples {\n'
        '    static final String REDACTED = "-----BEGIN PRIVATE KEY-----'
        '\\n<redacted>\\n-----END PRIVATE KEY-----";\n'
        '    static final String ABSENT = "-----BEGIN PRIVATE KEY-----'
        '\\n<<payload deliberately unavailable>>\\n-----END PRIVATE KEY-----";\n'
        '    static String removeEnvelope(String pem) {\n'
        '        return pem.replace("-----BEGIN PRIVATE KEY-----", "")\n'
        '            .replace("-----END PRIVATE KEY-----", "");\n'
        '    }\n'
        '    static String removeRsaEnvelope(String pem) {\n'
        '        return pem.replaceAll("-----BEGIN RSA PRIVATE KEY-----", "")\n'
        '            .replaceAll("-----END RSA PRIVATE KEY-----", "");\n'
        '    }\n'
        '    static final String RUNTIME = "-----BEGIN EC PRIVATE KEY-----\\n"'
        ' + loadSomething() + "\\n-----END EC PRIVATE KEY-----";\n'
        '    static final String IDENTIFIER = "-----BEGIN DSA PRIVATE KEY-----\\n"'
        f' + {identifier} + "\\n-----END DSA PRIVATE KEY-----";\n'
        '    static final String GARBAGE = """\n'
        '-----BEGIN ENCRYPTED PRIVATE KEY-----\n'
        'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n'
        '-----END ENCRYPTED PRIVATE KEY-----\n""";\n'
        '    // DER sequence with an integer whose declared length exceeds its value.\n'
        '    static final String MALFORMED = """\n'
        '-----BEGIN PRIVATE KEY-----\nMAMCAgA=\n-----END PRIVATE KEY-----\n""";\n'
        '    static final String ACTUAL = """\n'
        + valid + '\n""";\n}\n'
    ).replace("\n", newline).encode("ascii")
    expected = valid.replace("\n", newline).encode("ascii")
    scanner = Scanner(builtin_rules, policy=policy)
    if input_kind == "file":
        path = tmp_path / "PrivateKeyExamples.java"
        path.write_bytes(source)
        results = scanner.scan_file(path)
    else:
        content = base64.b64encode(source) if input_kind == "base64" else source
        results = scanner.scan_input(ScanInput("PrivateKeyExamples.java", content))

    finding, = (finding for finding in results if finding.rule_id == "betterleaks.private-key")
    assert finding.secret.encode("ascii") == expected
    assert finding.is_base64_encoded == (input_kind == "base64")
    start = 0 if input_kind == "base64" else source.index(expected)
    end = len(content) if input_kind == "base64" else start + len(expected)
    assert finding.location["start_offset"] == start
    assert finding.location["end_offset"] == end
    assert finding.location["line"] == (1 if input_kind == "base64"
                                         else source[:start].count(b"\n") + 1)

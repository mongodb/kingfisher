"""Built-in connection-string rules cover issue #558 without generic detection."""
import base64
import json
from pathlib import Path
import subprocess
import sys

import pytest

from kingfisher_sdk import DetectionScanner, Rules, Scanner


ROOT = Path(__file__).resolve().parents[2]
RULE_PREFIX = "kingfisher.connection-string.password."


@pytest.fixture(scope="module")
def connection_rules():
    return Rules()


@pytest.mark.parametrize("scanner_type", [Scanner, DetectionScanner])
@pytest.mark.parametrize("encoded", [False, True])
def test_issue_passwords_and_quoting(connection_rules, scanner_type, encoded):
    scanner = scanner_type(connection_rules)
    for source, secret, suffix in (
        ("Server=tcp:acme.database.windows.net,1433;Initial Catalog=prod;User ID=sqladmin;"
         "Password=Xk9#mQ2!vL7pR4wZ;Encrypt=True;", "Xk9#mQ2!vL7pR4wZ", "unquoted"),
        ("Driver={ODBC Driver 18 for SQL Server};Server=tcp:acme.database.windows.net,1433;"
         "Uid=sqladmin;Pwd=Xk9mQ2vL7pR4wZ8q;", "Xk9mQ2vL7pR4wZ8q", "unquoted"),
        ("Host=pg.acme.io;Port=5432;Database=app;Username=app;Password=Zq8vN3kL0pW2xR7t",
         "Zq8vN3kL0pW2xR7t", "unquoted"),
        ('Host=db.internal;Password="weak";', "weak", "double-quoted"),
        ("Host=db.internal;Password=$money%<call(me)>;",
         "$money%<call(me)>", "unquoted"),
        ('Host=db.internal;Password="process.env.DB_PASSWORD";',
         "process.env.DB_PASSWORD", "double-quoted"),
        ("Data Source=db.internal;Password='Zq8v;N3kL0pW2xR7t';",
         "Zq8v;N3kL0pW2xR7t", "single-quoted"),
        ("DSN=Production;Pwd={Xk9}}mQ2;vL7pR4wZ8q};",
         "Xk9}}mQ2;vL7pR4wZ8q", "odbc-braced"),
        ("jdbc:postgresql://pg.internal:5432/app?user=app&password=Zq8vN3kL0pW2xR7t&ssl=true",
         "Zq8vN3kL0pW2xR7t", "jdbc-query"),
        ("jdbc:mysql://db.internal/app?password=Xk9%23mQ2%21vL7pR4wZ&user=app",
         "Xk9%23mQ2%21vL7pR4wZ", "jdbc-query"),
        ("jdbc:mariadb://db.internal/app?user=app&password=weak", "weak", "jdbc-query"),
        ("jdbc:postgresql://db.internal/app?ssl&user=app&amp;password=S3cret%23",
         "S3cret%23", "jdbc-query"),
        ("jdbc:mysql:loadbalance://db1.internal,db2.internal/app?password=S3cret!",
         "S3cret!", "jdbc-query"),
        ("jdbc:sqlserver://db.internal:1433;databaseName=app;user=app;password=S3cret!;",
         "S3cret!", "unquoted"),
        ("jdbc:sqlserver://db.internal;password={Xk9}}mQ2;vL7pR4wZ8q};",
         "Xk9}}mQ2;vL7pR4wZ8q", "odbc-braced"),
        (f"jdbc:postgresql://db.internal/app?password={'R3!q' * 32}",
         "R3!q" * 32, "jdbc-query"),
    ):
        content = source.encode()
        if encoded:
            content = base64.b64encode(content)
        finding, = (finding for finding in scanner.scan(content)
                    if finding.rule_id.startswith(RULE_PREFIX))
        assert finding.rule_id == f"{RULE_PREFIX}{suffix}"
        assert finding.secret == secret and finding.confidence == "medium"
        assert finding.is_base64_encoded == encoded
        start = 0 if encoded else source.index(secret)
        end = len(content) if encoded else start + len(secret)
        assert finding.location["start_offset"] == start
        assert finding.location["end_offset"] == end
        assert finding.to_dict(redact=False)["secret"] == secret
        assert secret not in repr(finding)
        assert secret not in json.dumps(finding.to_dict())

    for source in (
        'Host=db.internal;Password="${DB_PASSWORD}";',
        'Host=db.internal;Password=prefixCHANGE_ME123suffix;',
        'Host=db.internal;Password=process.env.DB_PASSWORD;',
        'Host=db.internal;Password=getPassword();',
        'jdbc:postgresql://db.internal/app?user=app&ssl=true',
        'jdbc:mysql://db.internal/app?password=',
        'jdbc:mariadb://db.internal/app?notpassword=S3cret!',
        'jdbc:postgresql://db.internal/app?passwordHint=S3cret!',
        'jdbc:oracle:thin:@db.internal:1521/APP',
        'jdbc:sqlite:file.db?password=S3cret!',
        'jdbc:sqlserver://db.internal;integratedSecurity=true;',
        'jdbc:sqlserver://db.internal;password="S3;cret!";',
        "jdbc:sqlserver://db.internal;password='S3;cret!';",
        'jdbc:postgresql://db.internal/app?password=${DB_PASSWORD}',
        'jdbc:mysql://db.internal/app?password=CHANGE_ME123',
        'jdbc:mariadb://db.internal/app?password=$DB_PASSWORD',
        'jdbc:sqlserver://db.internal;password={${DB_PASSWORD}};',
        'jdbc:postgresql:///?password=S3cret!',
        'jdbc:mysql://db invalid/app?password=S3cret!',
        'jdbc:sqlserver://;password=S3cret!;',
        'https://db.internal/app?password=S3cret!',
        'postgresql://db.internal/app?password=S3cret!',
        f"jdbc:postgresql://db.internal/app?password={'R3!q' * 32}x",
        f"jdbc:mysql://db.internal/app?password={'R3!q' * 32}x&user=app",
        f"jdbc:mariadb://db.internal/app?password={'R3!q' * 32}x",
        f"jdbc:sqlserver://db.internal;password={'R3!q' * 32}x;",
    ):
        content = source.encode()
        if encoded:
            content = base64.b64encode(content)
        assert not [finding for finding in scanner.scan(content)
                    if finding.rule_id.startswith(RULE_PREFIX)]


def test_example_preserves_default_exclusions_and_redacts():
    ids = {rule["id"] for rule in Rules(confidence="low", cache=False).metadata()}
    for name in ("generic-api-key", "generic-password", "generic-username"):
        assert f"betterleaks.{name}" not in ids
    assert {f"{RULE_PREFIX}{suffix}" for suffix in
            ("unquoted", "double-quoted", "single-quoted", "odbc-braced", "jdbc-query")} <= ids
    result = subprocess.run(
        [sys.executable, str(ROOT / "python" / "examples" / "connection_string_password.py")],
        check=True, capture_output=True, text=True, timeout=90,
    )
    assert f"{RULE_PREFIX}unquoted" in result.stdout
    assert "[REDACTED]" in result.stdout and "opensaysme" not in result.stdout

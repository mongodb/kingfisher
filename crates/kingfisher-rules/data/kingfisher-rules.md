# First-party detector exceptions

Generally useful detectors belong in [Betterleaks](https://github.com/betterleaks/betterleaks).
Directly maintained Kingfisher detectors are rare exceptions requiring a specific reason to
ship directly, upstream tracking, tests, attribution, and a condition for removing the exception.
They pass through the same maintainer generator, embedded bundle, readable export, provenance,
and documentation pipeline as imported detectors.

The source [kingfisher-rules.yml](kingfisher-rules.yml) contains five medium-confidence
connection-string password detectors. They restore supported pre-2.x connection-string and JDBC
password coverage lost in the 2.x catalog migration, including
[issue #558](https://github.com/mongodb/kingfisher/issues/558). The pinned upstream catalog
lacks equivalent focused password-property detection; broad generic detectors remain deliberately
omitted for noise and cost. This is a temporary regression-repair exception: replace the definitions
when focused equivalent detectors are available in a reviewed immutable Betterleaks revision.
The rules can be expressed in Betterleaks TOML; their syntax is not a reason to keep them local.

Each exception declares its rule IDs, reason, upstream destination, tracking issue, and removal
condition. Missing or unassigned metadata fails generation. The generated runtime YAML contains
only rule definitions; exception metadata is retained in the provenance manifest. The source
and these notes are hashed as generator inputs.

The CLI loads these rules by default. Rust callers receive them through
`kingfisher_rules::get_builtin_rules(None)`; Python callers through `Rules()`.
Their IDs start with `kingfisher.connection-string.password`. The broad Betterleaks
`generic-api-key`, `generic-password`, and `generic-username` rules remain excluded.

The four semicolon-delimited rules require a nonempty `Server`, `Host`, `Data Source`, or
`DSN` value before `Password` or `Pwd` on the same source line. The unquoted and ODBC-braced
rules also accept the JDBC SQL Server prefix (`jdbc:sqlserver://`). Keys are case-insensitive.
Host values are bounded to 128 bytes, and the optional intervening segment to 200 bytes before its terminating
semicolon; horizontal whitespace around separators is permitted. Passwords contain 4–128 bytes
and may be unquoted, single quoted, double quoted, or ODBC braced. A doubled ODBC closing brace
(`}}`) counts as one unit for this bound; findings retain both source bytes. Each rule captures
only the password, without its enclosing quotes or braces.

The JDBC query rule detects a `password=` property in PostgreSQL, MySQL, and MariaDB JDBC
URLs, including MySQL `loadbalance` and `replication` forms. The authority is bounded to 256
bytes and the optional database path to 200 bytes. Up to 16 preceding query properties may
each have a key of 1–64 bytes and a value of at most 200 bytes. Passwords contain 4–128 bytes
and retain their source percent encoding.
The `password` query key is case-sensitive; preceding options may be bare flags,
and `&amp;` separators are supported. A JDBC prefix or URL without a password is not
sufficient. Other JDBC dialects, including Oracle, are outside this coverage.

The rules use `min_entropy: 0` and no character-complexity minimum, so weak and Unicode
literals remain eligible. Their [documented pattern requirements](../../../docs/RULES.md#character-requirements)
use `ignore_if_contains` to exclude common placeholder, redaction, and template markers. The
unquoted and JDBC query rules also exclude specific environment-variable, configuration-property,
and function markers; quoted code-looking literals such as `"process.env.DB_PASSWORD"` remain eligible.

These exclusions are case-insensitive substring checks, not complete-value checks. A real
password containing a listed marker can be suppressed, and unlisted placeholder or code forms
can remain reportable. Use `kingfisher scan --no-ignore-if-contains` to disable these substring
exclusions when needed. No validation or revocation is attached.

Password-first order, quoted hosts, quoted or braced auxiliary fields, doubled single/double
quote escaping, strings assembled across source literals or lines, and space-delimited libpq
connection strings are outside the supported coverage. This is a bounded content detector.

The Apache-2.0 rule definitions use the documented connection-string syntax:

- [Microsoft ADO.NET connection strings](https://learn.microsoft.com/en-us/dotnet/framework/data/adonet/connection-strings)
- [Microsoft ODBC keywords](https://learn.microsoft.com/en-us/sql/connect/odbc/dsn-connection-string-attribute)
- [Microsoft ODBC connection-string grammar](https://learn.microsoft.com/en-us/openspecs/sql_server_protocols/ms-odbcstr/55953f0e-2d30-4ad4-8e56-b4207e491409)
- [ODBC escaped closing braces](https://learn.microsoft.com/en-us/openspecs/sql_server_protocols/ms-odbcstr/3980af3f-d662-46cf-973a-84bc2442b97a)
- [Npgsql connection-string parameters](https://www.npgsql.org/doc/connection-string-parameters.html)
- [Microsoft JDBC connection URLs](https://learn.microsoft.com/en-us/sql/connect/jdbc/building-the-connection-url)
- [PostgreSQL JDBC connection URLs](https://jdbc.postgresql.org/documentation/use/)
- [MySQL Connector/J connection URLs](https://dev.mysql.com/doc/connector-j/en/connector-j-reference-jdbc-url-format.html)
- [MariaDB Connector/J connection URLs](https://mariadb.com/docs/connectors/mariadb-connector-j/about-mariadb-connector-j)

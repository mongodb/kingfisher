use std::fmt::Write as FmtWrite;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags, config::DbConfig, limits::Limit};

use super::ExtractionLimitExceeded;
use crate::{ScanControl, archive::limits::ResourceLimits};
use tracing::{debug, warn};

const MAX_ROWS_PER_TABLE: usize = 100_000;
const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;

/// Extract all user tables from a SQLite database as SQL text.
///
/// Returns a vec of `(logical_name, sql_text)` pairs, one per table.
/// Each entry contains the CREATE TABLE statement followed by INSERT
/// statements with explicit column names so that keyword-based secret
/// detectors can match column names like "api_key" near their values.
pub fn extract_sqlite_contents_with_limits(
    path: &Path,
    resources: ResourceLimits,
) -> Result<Vec<(String, Vec<u8>)>> {
    extract_sqlite(path, resources, MAX_TOTAL_BYTES, false, &ScanControl::default()).inspect_err(
        |err| {
            // Schema hardening can reject a wide table before listing completes.
            // Surface that coverage gap even when the caller falls back to raw bytes.
            warn!("Failed to extract SQLite database {}: {err:#}", path.display());
        },
    )
}

/// Dump a database with a strict aggregate output budget and cooperative control.
/// Budget exhaustion and interruption return errors, never a partial table set.
/// Connections are read-only, defensive, and distrust stored schema expressions.
pub fn extract_sqlite_contents_with_budget(
    path: &Path,
    max_bytes: usize,
    control: &ScanControl,
) -> Result<Vec<(String, Vec<u8>)>> {
    let result = extract_sqlite(
        path,
        ResourceLimits::default(),
        max_bytes.min(MAX_TOTAL_BYTES),
        true,
        control,
    );
    // SQLite reports SQLITE_INTERRUPT when the progress hook stopped a VM. Map
    // that back to the caller's original deadline/cancellation category.
    control.check()?;
    result.map_err(|err| {
        if matches!(err.downcast_ref::<rusqlite::Error>(), Some(rusqlite::Error::SqliteFailure(error, _)) if error.code == rusqlite::ErrorCode::TooBig) {
            ExtractionLimitExceeded::Bytes.into()
        } else { err }
    })
}

fn extract_sqlite(
    path: &Path,
    resources: ResourceLimits,
    max_bytes: usize,
    strict_budget: bool,
    control: &ScanControl,
) -> Result<Vec<(String, Vec<u8>)>> {
    control.check()?;
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("Failed to open SQLite database: {}", path.display()))?;
    harden_connection(&conn, resources, max_bytes)?;
    let progress_control = control.clone();
    conn.progress_handler(1000, Some(move || progress_control.check().is_err()))?;

    if control.is_limited() {
        // A staged SDK snapshot should never be locked. Do not let SQLite's busy
        // wait outlive a caller deadline; return the locking error immediately.
        conn.busy_timeout(std::time::Duration::ZERO)?;
    } else if resources.unlimited {
        conn.busy_handler(Some(|_| {
            std::thread::sleep(std::time::Duration::from_millis(10));
            true
        }))?;
    } else {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
    }

    let tables =
        list_user_tables_with_control(&conn, resources.limit(max_bytes), strict_budget, control)?;
    let mut results = Vec::new();
    let mut total_bytes = 0usize;
    for (table_name, create_sql) in tables {
        control.check()?;
        if resources.reached(total_bytes, max_bytes) {
            if strict_budget {
                return Err(ExtractionLimitExceeded::Bytes.into());
            }
            debug!(
                "SQLite extraction hit total size limit, skipping remaining tables in {}",
                path.display()
            );
            break;
        }
        match dump_table_with_control(
            &conn,
            &table_name,
            &create_sql,
            max_bytes.saturating_sub(total_bytes),
            resources,
            strict_budget,
            control,
        ) {
            Ok(sql_text) => {
                total_bytes += sql_text.len();
                results.push((format!("{table_name}.sql"), sql_text.into_bytes()));
            }
            Err(err) => {
                control.check()?;
                if strict_budget {
                    if matches!(err.downcast_ref::<rusqlite::Error>(), Some(rusqlite::Error::SqliteFailure(error, _)) if error.code == rusqlite::ErrorCode::TooBig)
                    {
                        return Err(ExtractionLimitExceeded::Bytes.into());
                    }
                    return Err(err);
                }
                warn!("Skipping SQLite table '{}' from {}: {err:#}", table_name, path.display());
            }
        }
    }
    control.check()?;
    Ok(results)
}

fn harden_connection(conn: &Connection, resources: ResourceLimits, max_bytes: usize) -> Result<()> {
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    if !resources.unlimited {
        // SQLite materializes one row before Rust formats it. Bound that native
        // allocation as well as generated SQL; allow a small schema overhead for
        // tiny caller output budgets. Generated SQL itself remains strictly capped.
        let length_cap = max_bytes.clamp(4096, MAX_TOTAL_BYTES) as i32;
        conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, length_cap)?;
        conn.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, length_cap.min(1024 * 1024))?;
        conn.set_limit(Limit::SQLITE_LIMIT_COLUMN, 2000)?;
        conn.set_limit(Limit::SQLITE_LIMIT_EXPR_DEPTH, 100)?;
        conn.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)?;
    }
    Ok(())
}

/// List all user tables (excluding sqlite_* internal tables) along with
/// their CREATE TABLE SQL.
fn list_user_tables_with_control(
    conn: &Connection,
    max_bytes: Option<usize>,
    strict_budget: bool,
    control: &ScanControl,
) -> Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT name, sql FROM sqlite_master \
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         ORDER BY name",
    )?;

    let rows = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let sql: String = row.get(1)?;
        Ok((name, sql))
    })?;

    let mut tables = Vec::new();
    let mut total = 0usize;
    for row in rows {
        control.check()?;
        let row = row?;
        total = total.saturating_add(row.0.len()).saturating_add(row.1.len());
        if max_bytes.is_some_and(|limit| total > limit) {
            if strict_budget {
                return Err(ExtractionLimitExceeded::Bytes.into());
            }
            warn!(
                "SQLite schema listing exceeds max_bytes budget; skipping table '{}' and remaining tables",
                row.0
            );
            break;
        }
        tables.push(row);
    }
    Ok(tables)
}

/// Dump a single table as SQL text: the CREATE statement followed by
/// INSERT INTO statements with named columns.
#[cfg(test)]
fn dump_table(
    conn: &Connection,
    table_name: &str,
    create_sql: &str,
    remaining_budget: usize,
    resources: crate::archive::limits::ResourceLimits,
) -> Result<String> {
    dump_table_with_control(
        conn,
        table_name,
        create_sql,
        remaining_budget,
        resources,
        false,
        &ScanControl::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn dump_table_with_control(
    conn: &Connection,
    table_name: &str,
    create_sql: &str,
    remaining_budget: usize,
    resources: ResourceLimits,
    strict_budget: bool,
    control: &ScanControl,
) -> Result<String> {
    control.check()?;
    let mut out = String::with_capacity(remaining_budget.min(4096));
    let create_statement = format!("{create_sql};\n");
    if !push_with_budget(&mut out, &create_statement, remaining_budget, resources) {
        if strict_budget {
            return Err(ExtractionLimitExceeded::Bytes.into());
        }
        bail!(
            "CREATE TABLE statement for '{table_name}' exceeds remaining size budget ({remaining_budget} bytes)"
        );
    }

    let col_names = column_names(conn, table_name)?;
    if col_names.is_empty() {
        return Ok(out);
    }

    let columns_fragment =
        col_names.iter().map(|c| sqlite_quoted_identifier(c)).collect::<Vec<_>>().join(",");

    let quoted_table_name = sqlite_quoted_identifier(table_name);
    let query = format!("SELECT * FROM {quoted_table_name}");
    let mut stmt = conn.prepare(&query)?;
    let col_count = col_names.len();

    let mut rows_emitted: usize = 0;
    let mut rows = stmt.query([])?;

    while let Some(row) = rows.next()? {
        control.check()?;
        if resources.reached(rows_emitted, MAX_ROWS_PER_TABLE) {
            if strict_budget {
                return Err(ExtractionLimitExceeded::Rows.into());
            }
            let marker = format!("-- (truncated after {MAX_ROWS_PER_TABLE} rows)\n");
            let _ = push_with_budget(&mut out, &marker, remaining_budget, resources);
            break;
        }
        if resources.reached(out.len(), remaining_budget) {
            if strict_budget {
                return Err(ExtractionLimitExceeded::Bytes.into());
            }
            break;
        }

        // Formatting is bounded while values are escaped; a large BLOB cannot
        // build a multi-gigabyte temporary SQL row before the output cap applies.
        let mut row_sql = BoundedSql {
            text: String::new(),
            remaining: resources.limit(remaining_budget.saturating_sub(out.len())),
        };
        let formatted = (|| -> Result<()> {
            write!(row_sql, "INSERT INTO {quoted_table_name} ({columns_fragment}) VALUES (")?;

            for i in 0..col_count {
                if i > 0 {
                    write!(row_sql, ",")?;
                }
                write_value(&mut row_sql, row, i, control)?;
            }

            writeln!(row_sql, ");")?;
            Ok(())
        })();
        if let Err(err) = formatted {
            // A deadline/cancellation has priority over output exhaustion, and
            // even best-effort extraction must preserve interruption errors.
            if err.downcast_ref::<crate::ScanAborted>().is_some() {
                return Err(err);
            }
            control.check()?;
            if strict_budget {
                if err.downcast_ref::<std::fmt::Error>().is_some() {
                    return Err(ExtractionLimitExceeded::Bytes.into());
                }
                return Err(err);
            }
            let _ = push_with_budget(
                &mut out,
                "-- (truncated: size limit reached)\n",
                remaining_budget,
                resources,
            );
            break;
        }
        if !push_with_budget(&mut out, &row_sql.text, remaining_budget, resources) {
            if strict_budget {
                return Err(ExtractionLimitExceeded::Bytes.into());
            }
            let marker = "-- (truncated: size limit reached)\n";
            let _ = push_with_budget(&mut out, marker, remaining_budget, resources);
            break;
        }
        rows_emitted += 1;
    }

    Ok(out)
}

fn push_with_budget(
    out: &mut String,
    fragment: &str,
    remaining_budget: usize,
    resources: crate::archive::limits::ResourceLimits,
) -> bool {
    if resources.exceeds(out.len().saturating_add(fragment.len()), remaining_budget) {
        return false;
    }
    out.push_str(fragment);
    true
}

fn column_names(conn: &Connection, table_name: &str) -> Result<Vec<String>> {
    let query = format!("PRAGMA table_info({})", sqlite_quoted_identifier(table_name));
    let mut stmt = conn.prepare(&query)?;
    let names = stmt
        .query_map([], |row| {
            let name: String = row.get(1)?;
            Ok(name)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names)
}

fn sqlite_quoted_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

struct BoundedSql {
    text: String,
    remaining: Option<usize>,
}

impl FmtWrite for BoundedSql {
    fn write_str(&mut self, fragment: &str) -> std::fmt::Result {
        if let Some(remaining) = &mut self.remaining {
            if fragment.len() > *remaining {
                return Err(std::fmt::Error);
            }
            *remaining -= fragment.len();
        }
        self.text.push_str(fragment);
        Ok(())
    }
}

fn write_value(
    out: &mut impl FmtWrite,
    row: &rusqlite::Row<'_>,
    idx: usize,
    control: &ScanControl,
) -> Result<()> {
    write_sqlite_value(out, row.get_ref(idx)?, control)
}

fn write_sqlite_value(
    out: &mut impl FmtWrite,
    value: rusqlite::types::ValueRef<'_>,
    control: &ScanControl,
) -> Result<()> {
    use rusqlite::types::ValueRef;
    const CHUNK_BYTES: usize = 4096;
    control.check()?;
    match value {
        ValueRef::Null => write!(out, "NULL")?,
        ValueRef::Integer(i) => write!(out, "{i}")?,
        ValueRef::Real(f) => write!(out, "{f}")?,
        ValueRef::Text(t) => {
            write!(out, "'")?;
            // Match from_utf8_lossy without allocating the entire converted
            // field; malformed bytes can expand to three-byte replacements.
            for chunk in t.utf8_chunks() {
                let text = chunk.valid();
                let mut start = 0;
                while start < text.len() {
                    control.check()?;
                    let mut end = text.len().min(start + CHUNK_BYTES);
                    // Do not split a UTF-8 codepoint while copying bounded chunks.
                    while !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    for part in text[start..end].split_inclusive('\'') {
                        out.write_str(part)?;
                        if part.ends_with('\'') {
                            out.write_char('\'')?;
                        }
                    }
                    start = end;
                }
                if !chunk.invalid().is_empty() {
                    control.check()?;
                    out.write_char('\u{fffd}')?;
                }
            }
            control.check()?;
            write!(out, "'")?;
        }
        ValueRef::Blob(bytes) => {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            let mut encoded = [0u8; CHUNK_BYTES * 2];
            write!(out, "X'")?;
            for chunk in bytes.chunks(CHUNK_BYTES) {
                control.check()?;
                // Encode a bounded chunk without a formatting call for every
                // byte. The stack buffer never grows with the database value.
                let (pairs, _) = encoded.as_chunks_mut::<2>();
                for (byte, pair) in chunk.iter().zip(pairs.iter_mut()) {
                    pair[0] = HEX[(byte >> 4) as usize];
                    pair[1] = HEX[(byte & 0x0f) as usize];
                }
                out.write_str(
                    std::str::from_utf8(&encoded[..chunk.len() * 2]).expect("hex digits are ASCII"),
                )?;
            }
            control.check()?;
            write!(out, "'")?;
        }
    }
    Ok(())
}

pub fn extract_sqlite_contents(path: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    extract_sqlite_contents_with_limits(path, crate::archive::limits::ResourceLimits::default())
}
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_test_db() -> (NamedTempFile, std::path::PathBuf) {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE user_info (id INTEGER PRIMARY KEY, username TEXT, api_key TEXT);
             INSERT INTO user_info VALUES (1, 'alice', 'ghp_abc123def456ghi789jkl012mno345pqr678');
             INSERT INTO user_info VALUES (2, 'bob', 'AKIAIOSFODNN7EXAMPLE');
             CREATE TABLE config (key TEXT, value TEXT);
             INSERT INTO config VALUES ('db_password', 's3cret!passw0rd');",
        )
        .unwrap();
        (tmp, path)
    }

    #[test]
    fn extracts_all_tables() {
        let (_tmp, path) = create_test_db();
        let results = extract_sqlite_contents(&path).unwrap();
        assert_eq!(results.len(), 2);

        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"config.sql"));
        assert!(names.contains(&"user_info.sql"));
    }

    #[test]
    fn output_contains_column_names_and_values() {
        let (_tmp, path) = create_test_db();
        let results = extract_sqlite_contents(&path).unwrap();

        let user_info = results.iter().find(|(n, _)| n == "user_info.sql").unwrap();
        let sql = String::from_utf8_lossy(&user_info.1);

        assert!(sql.contains("CREATE TABLE"));
        assert!(sql.contains("\"api_key\""));
        assert!(sql.contains("ghp_abc123def456ghi789jkl012mno345pqr678"));
        assert!(sql.contains("INSERT INTO"));
    }

    #[test]
    fn handles_empty_database() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE empty_table (id INTEGER);").unwrap();

        let results = extract_sqlite_contents(&path).unwrap();
        assert_eq!(results.len(), 1);
        let sql = String::from_utf8_lossy(&results[0].1);
        assert!(sql.contains("CREATE TABLE"));
        assert!(!sql.contains("INSERT INTO"));
    }

    #[test]
    fn handles_nonexistent_file() {
        let result = extract_sqlite_contents(Path::new("/nonexistent/database.db"));
        assert!(result.is_err());
    }

    #[test]
    fn handles_special_characters_in_values() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT);
             INSERT INTO t VALUES (1, 'it''s a test');
             INSERT INTO t VALUES (2, NULL);",
        )
        .unwrap();

        let results = extract_sqlite_contents(&path).unwrap();
        let sql = String::from_utf8_lossy(&results[0].1);
        assert!(sql.contains("'it''s a test'"));
        assert!(sql.contains("NULL"));
    }

    #[test]
    fn escapes_quoted_table_names_in_generated_sql() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE \"odd\"\"name\" (id INTEGER PRIMARY KEY, val TEXT);
             INSERT INTO \"odd\"\"name\" VALUES (1, 'secret');",
        )
        .unwrap();

        let results = extract_sqlite_contents(&path).unwrap();
        let sql = String::from_utf8_lossy(&results[0].1);

        assert!(sql.contains("INSERT INTO \"odd\"\"name\""));
        assert!(sql.contains("\"val\""));
        assert!(sql.contains("'secret'"));
    }

    #[test]
    fn respects_remaining_budget_before_writing_create_statement() {
        let (_tmp, path) = create_test_db();
        let conn = Connection::open(&path).unwrap();

        let err = dump_table(
            &conn,
            "user_info",
            "CREATE TABLE user_info (id INTEGER PRIMARY KEY, username TEXT, api_key TEXT)",
            8,
            crate::archive::limits::ResourceLimits::default(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("exceeds remaining size budget"));
    }

    #[test]
    fn does_not_exceed_budget_when_row_is_too_large() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let conn = Connection::open(&path).unwrap();
        let large_value = "x".repeat(512);
        conn.execute_batch(&format!(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT);
             INSERT INTO t VALUES (1, '{large_value}');"
        ))
        .unwrap();

        let sql = dump_table(
            &conn,
            "t",
            "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)",
            96,
            crate::archive::limits::ResourceLimits::default(),
        )
        .unwrap();

        assert!(sql.len() <= 96);
        assert!(!sql.contains(&large_value));
    }
}

#[cfg(test)]
mod unlimited_tests {
    use super::*;

    #[test]
    fn unlimited_sqlite_dump_keeps_rows_beyond_byte_budget() -> Result<()> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("CREATE TABLE secrets (token TEXT); INSERT INTO secrets VALUES ('secret beyond budget');")?;
        let schema = "CREATE TABLE secrets (token TEXT)";
        let bounded = dump_table(
            &conn,
            "secrets",
            schema,
            schema.len() + 2,
            crate::archive::limits::ResourceLimits::default(),
        )?;
        assert!(!bounded.contains("secret beyond budget"));
        let unlimited = dump_table(
            &conn,
            "secrets",
            schema,
            schema.len() + 2,
            crate::archive::limits::ResourceLimits { unlimited: true },
        )?;
        assert!(unlimited.contains("secret beyond budget"));
        Ok(())
    }
}

#[cfg(test)]
mod controlled_tests {
    use super::*;
    use crate::ScanAborted;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn schema_listing_is_bounded_in_both_extraction_modes() -> Result<()> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("CREATE TABLE a (secret TEXT); CREATE TABLE b (secret TEXT);")?;
        let control = ScanControl::default();
        let first_size = "a".len() + "CREATE TABLE a (secret TEXT)".len();
        let tables = list_user_tables_with_control(&conn, Some(first_size), false, &control)?;
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].0, "a");
        let error =
            list_user_tables_with_control(&conn, Some(first_size), true, &control).unwrap_err();
        assert!(error.is::<ExtractionLimitExceeded>());
        Ok(())
    }

    #[test]
    fn hardening_distrusts_schema_and_limits_native_row_allocations() -> Result<()> {
        let conn = Connection::open_in_memory()?;
        harden_connection(&conn, ResourceLimits::default(), 8192)?;
        assert!(conn.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)?);
        assert!(!conn.db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA)?);
        assert_eq!(conn.limit(Limit::SQLITE_LIMIT_LENGTH)?, 8192);
        assert_eq!(conn.limit(Limit::SQLITE_LIMIT_ATTACHED)?, 0);
        Ok(())
    }

    #[test]
    fn strict_budget_stops_before_building_an_oversized_blob_row() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("database.sqlite");
        let conn = Connection::open(&path)?;
        conn.execute_batch("CREATE TABLE t (token BLOB); INSERT INTO t VALUES (zeroblob(4096));")?;
        drop(conn);
        let error =
            extract_sqlite_contents_with_budget(&path, 512, &ScanControl::default()).unwrap_err();
        assert!(error.downcast_ref::<ExtractionLimitExceeded>().is_some());
        Ok(())
    }

    #[test]
    fn interrupted_dump_keeps_control_error_and_returns_no_table_subset() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("database.sqlite");
        let conn = Connection::open(&path)?;
        conn.execute_batch("CREATE TABLE t (token TEXT); WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000) INSERT INTO t SELECT 'synthetic' FROM n;")?;
        drop(conn);
        let checks = Arc::new(AtomicUsize::new(0));
        let observer = Arc::clone(&checks);
        let control = ScanControl::default().with_check_observer(move |_| {
            if observer.fetch_add(1, Ordering::Relaxed) >= 20 {
                Err(ScanAborted::TimedOut)
            } else {
                Ok(())
            }
        });
        let error = extract_sqlite_contents_with_budget(&path, 256 * 1024, &control).unwrap_err();
        assert_eq!(error.downcast_ref::<ScanAborted>(), Some(&ScanAborted::TimedOut));
        assert!(checks.load(Ordering::Relaxed) >= 20);
        Ok(())
    }
    #[test]
    fn value_formatting_preserves_hex_and_utf8_quoting_across_chunks() -> Result<()> {
        use rusqlite::types::ValueRef;
        let control = ScanControl::default();
        let bytes = [0x00, 0x7f, 0x80, 0xff].repeat(4097);
        let mut sql = String::new();
        write_sqlite_value(&mut sql, ValueRef::Blob(&bytes), &control)?;
        assert_eq!(sql, format!("X'{}'", "007F80FF".repeat(4097)));
        let text = format!("{}'quoted'", "🙂€".repeat(4097));
        sql.clear();
        write_sqlite_value(&mut sql, ValueRef::Text(text.as_bytes()), &control)?;
        assert_eq!(sql, format!("'{}'", text.replace('\'', "''")));
        sql.clear();
        let invalid = b"\xff\xed\xa0\x80\xc2'valid";
        write_sqlite_value(&mut sql, ValueRef::Text(invalid), &control)?;
        assert_eq!(sql, format!("'{}'", String::from_utf8_lossy(invalid).replace('\'', "''")));
        Ok(())
    }

    #[test]
    fn long_value_formatting_polls_deadlines_before_output_budget_failure() {
        use rusqlite::types::ValueRef;
        let bytes = vec![b'x'; 32 * 1024];
        for value in [ValueRef::Blob(&bytes), ValueRef::Text(&bytes)] {
            let checks = Arc::new(AtomicUsize::new(0));
            let observer = Arc::clone(&checks);
            let control = ScanControl::default().with_check_observer(move |_| {
                if observer.fetch_add(1, Ordering::Relaxed) >= 2 {
                    Err(ScanAborted::TimedOut)
                } else {
                    Ok(())
                }
            });
            // Fit exactly one chunk and its opening delimiter. The next chunk
            // has both an expired deadline and no output budget: preserve the
            // deadline category and leave the rest of the value unformatted.
            let limit = if matches!(value, ValueRef::Blob(_)) { 8194 } else { 4097 };
            let mut out = BoundedSql { text: String::new(), remaining: Some(limit) };
            let error = write_sqlite_value(&mut out, value, &control).unwrap_err();
            assert_eq!(error.downcast_ref::<ScanAborted>(), Some(&ScanAborted::TimedOut));
            assert_eq!(out.text.len(), limit);
        }
    }

    #[test]
    fn cancelled_value_formatting_checks_control_before_allocating_output() {
        use rusqlite::types::ValueRef;
        let token = crate::CancellationToken::default();
        token.cancel();
        let control = ScanControl::default().with_cancellation(token);
        let mut out = BoundedSql { text: String::new(), remaining: Some(0) };
        let error = write_sqlite_value(&mut out, ValueRef::Blob(b"value"), &control).unwrap_err();
        assert_eq!(error.downcast_ref::<ScanAborted>(), Some(&ScanAborted::Cancelled));
        assert!(out.text.is_empty());
    }
}

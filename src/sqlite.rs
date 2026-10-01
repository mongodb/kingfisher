use std::fmt::Write as FmtWrite;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags};
use tracing::debug;

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
    resources: crate::limits::ResourceLimits,
) -> Result<Vec<(String, Vec<u8>)>> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("Failed to open SQLite database: {}", path.display()))?;

    if resources.unlimited {
        conn.busy_handler(Some(|_| {
            std::thread::sleep(std::time::Duration::from_millis(10));
            true
        }))?;
    } else {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
    }

    let tables = list_user_tables(&conn)?;
    if tables.is_empty() {
        debug!("SQLite database has no user tables: {}", path.display());
        return Ok(Vec::new());
    }

    let mut results = Vec::with_capacity(tables.len());
    let mut total_bytes: usize = 0;

    for (table_name, create_sql) in &tables {
        if resources.reached(total_bytes, MAX_TOTAL_BYTES) {
            debug!(
                "SQLite extraction hit total size limit ({MAX_TOTAL_BYTES} bytes), \
                 skipping remaining tables in {}",
                path.display()
            );
            break;
        }

        match dump_table(
            &conn,
            table_name,
            create_sql,
            MAX_TOTAL_BYTES.saturating_sub(total_bytes),
            resources,
        ) {
            Ok(sql_text) => {
                total_bytes += sql_text.len();
                let logical_name = format!("{}.sql", table_name);
                results.push((logical_name, sql_text.into_bytes()));
            }
            Err(e) => {
                debug!("Failed to dump table '{}' from {}: {e:#}", table_name, path.display());
            }
        }
    }

    Ok(results)
}

/// List all user tables (excluding sqlite_* internal tables) along with
/// their CREATE TABLE SQL.
fn list_user_tables(conn: &Connection) -> Result<Vec<(String, String)>> {
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
    for row in rows {
        tables.push(row?);
    }
    Ok(tables)
}

/// Dump a single table as SQL text: the CREATE statement followed by
/// INSERT INTO statements with named columns.
fn dump_table(
    conn: &Connection,
    table_name: &str,
    create_sql: &str,
    remaining_budget: usize,
    resources: crate::limits::ResourceLimits,
) -> Result<String> {
    let mut out = String::with_capacity(4096);
    let create_statement = format!("{create_sql};\n");
    if !push_with_budget(&mut out, &create_statement, remaining_budget, resources) {
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
        if resources.reached(rows_emitted, MAX_ROWS_PER_TABLE) {
            let marker = format!("-- (truncated after {MAX_ROWS_PER_TABLE} rows)\n");
            let _ = push_with_budget(&mut out, &marker, remaining_budget, resources);
            break;
        }
        if resources.reached(out.len(), remaining_budget) {
            break;
        }

        let mut row_sql = String::new();
        write!(row_sql, "INSERT INTO {quoted_table_name} ({columns_fragment}) VALUES (")?;

        for i in 0..col_count {
            if i > 0 {
                write!(row_sql, ",")?;
            }
            write_value(&mut row_sql, row, i)?;
        }

        writeln!(row_sql, ");")?;
        if !push_with_budget(&mut out, &row_sql, remaining_budget, resources) {
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
    resources: crate::limits::ResourceLimits,
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

fn write_value(out: &mut String, row: &rusqlite::Row<'_>, idx: usize) -> Result<()> {
    use rusqlite::types::ValueRef;
    match row.get_ref(idx)? {
        ValueRef::Null => write!(out, "NULL")?,
        ValueRef::Integer(i) => write!(out, "{i}")?,
        ValueRef::Real(f) => write!(out, "{f}")?,
        ValueRef::Text(t) => {
            let s = String::from_utf8_lossy(t);
            write!(out, "'{}'", s.replace('\'', "''"))?;
        }
        ValueRef::Blob(b) => {
            write!(out, "X'")?;
            for byte in b {
                write!(out, "{byte:02X}")?;
            }
            write!(out, "'")?;
        }
    }
    Ok(())
}

pub fn extract_sqlite_contents(path: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    extract_sqlite_contents_with_limits(path, crate::limits::ResourceLimits::default())
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
            crate::limits::ResourceLimits::default(),
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
            crate::limits::ResourceLimits::default(),
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
            crate::limits::ResourceLimits::default(),
        )?;
        assert!(!bounded.contains("secret beyond budget"));
        let unlimited = dump_table(
            &conn,
            "secrets",
            schema,
            schema.len() + 2,
            crate::limits::ResourceLimits { unlimited: true },
        )?;
        assert!(unlimited.contains("secret beyond budget"));
        Ok(())
    }
}

//! Vectorscan is a fork of [Hyperscan](https://github.com/Intel/hyperscan) that supports additional platforms.
//! To understand how to use this library, it may be helpful to look at the [documentation for the Hyperscan C bindings](https://intel.github.io/hyperscan/dev-reference/).

mod error;
mod native;
mod wrapper;

pub use error::{AsResult, Error, HyperscanErrorCode};
pub use native::*;
pub use wrapper::{Flag, Pattern, ScanMode, Scratch};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_scanning_basic() -> Result<(), Error> {
        let patterns = vec![Pattern::new(b"hello".to_vec(), Flag::default(), None)];
        let db = BlockDatabase::new(patterns)?;
        let mut scanner = BlockScanner::new(&db)?;

        let test_basic = |scanner: &mut BlockScanner| -> Result<(), Error> {
            let mut matches = Vec::new();
            scanner.scan(b"hello hello", |id: u32, from: u64, to: u64, flags: u32| {
                matches.push((id, from, to, flags));
                Scan::Continue
            })?;
            assert_eq!(matches.as_slice(), &[(0, 0, 5, 0), (0, 0, 11, 0)]);
            Ok(())
        };

        test_basic(&mut scanner)?;

        // Check simple use of cloning
        let mut scanner2 = scanner.clone();
        drop(scanner);
        test_basic(&mut scanner2)?;

        assert_eq!(db.size()?, 936); // N.B. this value may change if the vectorscan code changes

        Ok(())
    }

    #[test]
    fn stream_scanning_basic() -> Result<(), Error> {
        let patterns = vec![Pattern::new(b"hello".to_vec(), Flag::default(), None)];
        let db = StreamingDatabase::new(patterns)?;
        let mut scanner = StreamingScanner::new(&db)?;

        let test_basic = |scanner: &mut StreamingScanner| -> Result<(), Error> {
            let mut scanner = scanner.open_stream()?;

            let mut matches = Vec::new();

            scanner.scan(b"hel", |id, from, to, flags| {
                matches.push((id, from, to, flags));
                Scan::Continue
            })?;
            assert_eq!(matches.as_slice(), &[]);

            scanner.scan(b"lo hello", |id, from, to, flags: u32| {
                matches.push((id, from, to, flags));
                Scan::Continue
            })?;

            let expected = &[(0, 0, 5, 0), (0, 0, 11, 0)];
            assert_eq!(matches.as_slice(), expected);

            scanner.close(|id, from, to, flags| {
                matches.push((id, from, to, flags));
                Scan::Continue
            })?;
            assert_eq!(matches.as_slice(), expected);

            assert_eq!(db.size()?, 936); // N.B. this value may change if the vectorscan code changes
            assert_eq!(db.stream_size()?, 22); // N.B. this value may change if the vectorscan code changes

            Ok(())
        };

        test_basic(&mut scanner)?;

        // Check simple use of cloning
        let mut scanner2 = scanner.clone();
        drop(scanner);
        test_basic(&mut scanner2)?;

        Ok(())
    }

    #[should_panic]
    #[test]
    fn empty_database() {
        let _db = wrapper::Database::new(vec![], ScanMode::BLOCK).unwrap();
    }

    #[test]
    fn clone_database() -> Result<(), Error> {
        let patterns = vec![Pattern::new(b"hello".to_vec(), Flag::default(), None)];

        let db = wrapper::Database::new(patterns, ScanMode::BLOCK)?;
        let _dbs: Vec<wrapper::Database> = (0..100).map(|_| db.clone()).collect();
        drop(db);
        Ok(())
    }

    #[test]
    fn database_size() -> Result<(), Error> {
        let patterns = vec![Pattern::new(b"hello".to_vec(), Flag::default(), None)];

        let db = wrapper::Database::new(patterns, ScanMode::BLOCK)?;
        let db_size = db.size()?;
        assert_eq!(db_size, 936); // N.B. this value may change if the vectorscan code changes

        let sdb = db.serialize()?;
        let sdb_size = sdb.deserialized_size()?;
        assert_eq!(db_size, sdb_size);

        let db2 = sdb.deserialize()?;
        let db2_size = db2.size()?;
        assert_eq!(db2_size, db_size);

        Ok(())
    }

    #[test]
    fn stream_size() -> Result<(), Error> {
        let patterns = vec![
            Pattern::new(b"hello".to_vec(), Flag::default(), None),
            Pattern::new(b"world".to_vec(), Flag::default(), None),
            Pattern::new(b"hello.*world".to_vec(), Flag::default(), None),
        ];

        let db = wrapper::Database::new(patterns, ScanMode::STREAM)?;
        let db_size = db.size()?;
        assert_eq!(db_size, 5368); // N.B. this value may change if the vectorscan code changes

        let stream_size = db.stream_size()?;
        assert_eq!(stream_size, 39); // N.B. this value may change if the vectorscan code changes

        Ok(())
    }

    #[test]
    fn test_pattern_with_flags() -> Result<(), Error> {
        let patterns = vec![
            Pattern::new(b"HELLO".to_vec(), Flag::CASELESS, Some(0)),
            Pattern::new(
                b"w[o0]rld".to_vec(),
                Flag::CASELESS | Flag::SOM_LEFTMOST,
                Some(1),
            ),
        ];
        let db = BlockDatabase::new(patterns)?;
        let mut scanner = BlockScanner::new(&db)?;

        let mut matches = Vec::new();
        scanner.scan(b"hello W0RLD", |id, from, to, flags| {
            matches.push((id, from, to, flags));
            Scan::Continue
        })?;

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0], (0, 0, 5, 0)); // matches "hello"
        assert_eq!(matches[1], (1, 6, 11, 0)); // matches "W0RLD"

        Ok(())
    }

    #[test]
    fn test_early_termination() -> Result<(), Error> {
        let patterns = vec![
            Pattern::new(b"test".to_vec(), Flag::default(), None),
            Pattern::new(b"pattern".to_vec(), Flag::default(), None),
        ];
        let db = BlockDatabase::new(patterns)?;
        let mut scanner = BlockScanner::new(&db)?;

        let mut match_count = 0;
        scanner.scan(b"test pattern test pattern", |_id, _from, _to, _flags| {
            match_count += 1;
            Scan::Continue
        })?;
        assert_eq!(match_count, 4);

        let mut match_count = 0;
        scanner.scan(b"test pattern test pattern", |_id, _from, _to, _flags| {
            match_count += 1;
            if match_count >= 2 {
                Scan::Terminate
            } else {
                Scan::Continue
            }
        })?;

        assert_eq!(match_count, 2); // Should stop after 2 matches
        Ok(())
    }

    #[test]
    fn test_pattern_compilation_errors() -> Result<(), Error> {
        // Test invalid regex syntax
        let result = BlockDatabase::new(vec![Pattern::new(b"[".to_vec(), Flag::default(), None)]);
        let err = result.expect_err("Expected error but got success");
        assert!(matches!(err, Error::HyperscanCompile(..)));

        // Test unsupported regex features
        let result = BlockDatabase::new(vec![
            Pattern::new(b"(?R)".to_vec(), Flag::default(), None), // Recursive patterns not supported
        ]);
        let err = result.expect_err("Expected error but got success");
        assert!(matches!(err, Error::HyperscanCompile(..)));

        // Test empty pattern
        let result = BlockDatabase::new(vec![Pattern::new(b"".to_vec(), Flag::default(), None)]);
        let err = result.expect_err("Expected error but got success");
        assert!(matches!(err, Error::HyperscanCompile(..)));

        // Test pattern with null bytes
        let result = BlockDatabase::new(vec![Pattern::new(
            b"test\0pattern".to_vec(),
            Flag::default(),
            None,
        )]);
        let err = result.expect_err("Expected error but got success");
        assert!(matches!(err, Error::Nul(_)));

        Ok(())
    }
}

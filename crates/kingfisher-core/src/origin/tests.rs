//! Characterization of nonempty, ordered OriginSet filtering and public protocols.

use super::*;

fn file(name: &str) -> Origin {
    Origin::from_file(PathBuf::from(name))
}

fn generic_repo(name: &str) -> Origin {
    Origin::from_git_repo(Arc::new(PathBuf::from(name)))
}

fn detailed_repo(name: &str, path: &str, digit: u8) -> Origin {
    let id = [digit; 40];
    let metadata = CommitMetadata {
        commit_id: gix::ObjectId::from_hex(&id).unwrap(),
        author_name: Some("Author".into()),
        author_email: Some("author@example.invalid".into()),
        committer_name: "Committer".into(),
        committer_email: "committer@example.invalid".into(),
        committer_timestamp: gix::date::Time::new(1_700_000_000, 3_600),
    };
    Origin::from_git_repo_with_first_commit(
        Arc::new(PathBuf::from(name)),
        Arc::new(metadata),
        path.to_owned(),
    )
}

fn collected(set: &OriginSet) -> Vec<Origin> {
    set.iter().cloned().collect()
}

fn assert_sequence_contract(set: OriginSet, expected: &[Origin]) {
    assert!(!expected.is_empty());
    assert_eq!(set.len(), expected.len());
    assert_eq!(set.first(), &expected[0]);
    assert_eq!(collected(&set), expected);
    assert_eq!(collected(&set.clone()), expected);
    assert_eq!(serde_json::to_value(&set).unwrap(), serde_json::to_value(expected).unwrap());
    assert_eq!(set.into_iter().collect::<Vec<_>>(), expected);
}

#[test]
fn origin_set_single_and_from_preserve_all_origin_kinds() {
    let variants = [
        file("relative-file.txt"),
        generic_repo("relative-repository"),
        detailed_repo("relative-repository", "src/config.txt", b'a'),
        Origin::from_extended(json!({ "kind": "custom", "path": "relative-export.json" })),
    ];
    for origin in variants {
        let expected = [origin.clone()];
        assert_sequence_contract(OriginSet::single(origin.clone()), &expected);
        assert_sequence_contract(OriginSet::from(origin.clone()), &expected);
        assert_sequence_contract(OriginSet::new(origin.clone(), Vec::new()), &expected);
        assert_sequence_contract(OriginSet::try_from_iter([origin]).unwrap(), &expected);
    }
    assert!(OriginSet::try_from_iter(std::iter::empty()).is_none());
}

#[test]
fn origin_set_filters_only_generic_records_for_the_same_repository() {
    let generic = generic_repo("one");
    let detailed = detailed_repo("one", "src/a.txt", b'a');
    let other_generic = generic_repo("two");
    let other_detailed = detailed_repo("three", "src/c.txt", b'c');
    let first_file = file("local.txt");
    let extended = Origin::from_extended(json!({ "path": "custom.txt" }));
    let input = vec![
        generic.clone(),
        first_file.clone(),
        other_generic.clone(),
        detailed.clone(),
        generic.clone(),
        extended.clone(),
        other_detailed.clone(),
    ];
    let expected = [first_file, other_generic, detailed, extended, other_detailed];
    assert_sequence_contract(OriginSet::try_from_iter(input).unwrap(), &expected);
    // Filtering must look ahead even when the first record itself is discarded.
    assert_sequence_contract(OriginSet::new(generic, vec![expected[2].clone()]), &expected[2..3]);
}

#[test]
fn origin_set_preserves_duplicates_and_distinct_detailed_paths_and_commits() {
    let first = detailed_repo("repo", "src/a.txt", b'a');
    let other_path = detailed_repo("repo", "src/b.txt", b'a');
    let other_commit = detailed_repo("repo", "src/a.txt", b'b');
    let local = file("local.txt");
    let custom = Origin::from_extended(json!({ "source": "custom" }));
    let expected = vec![
        local.clone(),
        local,
        first.clone(),
        first,
        other_path,
        other_commit,
        custom.clone(),
        custom,
    ];
    assert_sequence_contract(OriginSet::try_from_iter(expected.clone()).unwrap(), &expected);
    let generic = generic_repo("generic-only");
    assert_sequence_contract(
        OriginSet::new(generic.clone(), vec![generic.clone(), generic.clone()]),
        &[generic.clone(), generic.clone(), generic],
    );
}

#[test]
fn origin_set_git_filter_uses_path_values_and_keeps_distinct_repositories() {
    let detailed = detailed_repo("repo", "a.txt", b'a');
    let equal_generic = generic_repo("repo");
    let prefixed_generic = generic_repo("repo-other");
    let nested_generic = generic_repo("repo/nested");
    let expected = [prefixed_generic.clone(), nested_generic.clone(), detailed.clone()];
    assert_sequence_contract(
        OriginSet::new(equal_generic, vec![prefixed_generic, nested_generic, detailed]),
        &expected,
    );
}

#[test]
fn origin_set_constructors_match_a_stable_ordered_filter_oracle() {
    let catalog = [
        file("local.txt"),
        Origin::from_extended(json!({ "path": "custom.txt" })),
        generic_repo("a"),
        generic_repo("b"),
        detailed_repo("a", "a.txt", b'a'),
        detailed_repo("a", "other.txt", b'b'),
        detailed_repo("b", "b.txt", b'c'),
    ];
    // All short mixtures exercise discarded first entries, separated matching
    // repositories, duplicate records, and ordering without relying on a hash set.
    for len in 1..=4 {
        for mut code in 0..catalog.len().pow(len as u32) {
            let mut input = Vec::with_capacity(len);
            for _ in 0..len {
                input.push(catalog[code % catalog.len()].clone());
                code /= catalog.len();
            }
            let expected: Vec<_> = input
                .iter()
                .filter(|origin| match origin {
                    Origin::GitRepo(repository) if repository.first_commit.is_none() => {
                        !input.iter().any(|other| {
                            matches!(other, Origin::GitRepo(detailed)
                                if detailed.first_commit.is_some()
                                && detailed.repo_path == repository.repo_path)
                        })
                    }
                    _ => true,
                })
                .cloned()
                .collect();
            assert!(!expected.is_empty());
            let from_iter = OriginSet::try_from_iter(input.clone()).unwrap();
            assert_eq!(collected(&from_iter), expected, "{input:?}");
            let first = input.remove(0);
            let from_new = OriginSet::new(first, input);
            assert_eq!(from_new.first(), &expected[0]);
            assert_eq!(from_new.len(), expected.len());
            assert_eq!(from_new.into_iter().collect::<Vec<_>>(), expected);
        }
    }
}

#[test]
fn origin_set_json_is_an_ordered_nonempty_flat_sequence() {
    let input = [file("file.txt"), Origin::from_extended(json!({ "path": "export.json" }))];
    let set = OriginSet::try_from_iter(input).unwrap();
    assert_eq!(
        serde_json::to_string(&set).unwrap(),
        r#"[{"kind":"file","path":"file.txt"},{"kind":"extended","path":"export.json"}]"#
    );
}

#[test]
fn origin_set_schema_preserves_nonempty_array_and_item_reference() {
    for settings in [
        schemars::generate::SchemaSettings::default(),
        schemars::generate::SchemaSettings::default().for_serialize(),
        schemars::generate::SchemaSettings::draft07(),
        schemars::generate::SchemaSettings::draft07().for_serialize(),
    ] {
        let schema = settings.into_generator().into_root_schema_for::<OriginSet>();
        let value = serde_json::to_value(schema).unwrap();
        assert_eq!(value["title"], "OriginSet");
        assert_eq!(value["type"], "array");
        assert_eq!(value["minItems"], 1);
        assert_eq!(value["description"], "A non-empty set of `Origin` entries");
        assert!(value.get("maxItems").is_none());
        let item_ref = value["items"]["$ref"].as_str().unwrap();
        assert!(item_ref.ends_with("/Origin"));
        let definition = value.pointer(item_ref.strip_prefix('#').unwrap()).unwrap();
        assert_eq!(definition["oneOf"].as_array().unwrap().len(), 3);
    }
}

#[test]
fn origin_set_serialization_propagates_io_failure() {
    struct LimitedWriter {
        remaining: usize,
        bytes: Vec<u8>,
    }
    impl std::io::Write for LimitedWriter {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::Error::other("origin destination unavailable"));
            }
            let written = self.remaining.min(input.len());
            self.bytes.extend_from_slice(&input[..written]);
            self.remaining -= written;
            Ok(written)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let set = OriginSet::new(file("file.txt"), vec![file("other.txt")]);
    let expected = serde_json::to_vec(&set).unwrap();
    // Force failure at every byte boundary, including the sequence's closing
    // delimiter, without depending on the serializer's write chunking.
    for budget in 0..expected.len() {
        let mut writer = LimitedWriter { remaining: budget, bytes: Vec::new() };
        let error = serde_json::to_writer(&mut writer, &set).unwrap_err();
        assert!(error.is_io());
        assert!(error.to_string().contains("origin destination unavailable"));
    }
    let mut writer = LimitedWriter { remaining: expected.len(), bytes: Vec::new() };
    serde_json::to_writer(&mut writer, &set).unwrap();
    assert_eq!(writer.bytes, expected);
}

#[test]
fn origin_set_preserves_the_public_owned_iterator_type() {
    let expected = vec![file("first.txt"), file("second.txt")];
    let set = OriginSet::try_from_iter(expected.clone()).unwrap();
    let iterator: std::iter::Chain<std::iter::Once<Origin>, std::vec::IntoIter<Origin>> =
        set.into_iter();
    assert_eq!(iterator.collect::<Vec<_>>(), expected);
}

struct RecordedSequence {
    declared_len: Option<usize>,
    entries: Vec<serde_json::Value>,
}

struct SequenceProtocol(bool);
struct SequenceRecorder(RecordedSequence);

impl serde::ser::SerializeSeq for SequenceRecorder {
    type Ok = RecordedSequence;
    type Error = serde::de::value::Error;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.0.entries.push(serde_json::to_value(value).map_err(serde::ser::Error::custom)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(self.0)
    }
}

macro_rules! reject_scalar_protocol {
    ($($method:ident($value_type:ty)),* $(,)?) => { $(
        fn $method(self, _value: $value_type) -> Result<Self::Ok, Self::Error> {
            Err(serde::ser::Error::custom("expected a sequence"))
        }
    )* };
}

macro_rules! reject_compound_protocol {
    ($($method:ident($($argument:ident: $argument_type:ty),*) -> $result:ident),* $(,)?) => { $(
        fn $method(self, $($argument: $argument_type),*) -> Result<Self::$result, Self::Error> {
            Err(serde::ser::Error::custom("expected a sequence"))
        }
    )* };
}

impl serde::Serializer for SequenceProtocol {
    type Ok = RecordedSequence;
    type Error = serde::de::value::Error;
    type SerializeSeq = SequenceRecorder;
    type SerializeTuple = serde::ser::Impossible<Self::Ok, Self::Error>;
    type SerializeTupleStruct = serde::ser::Impossible<Self::Ok, Self::Error>;
    type SerializeTupleVariant = serde::ser::Impossible<Self::Ok, Self::Error>;
    type SerializeMap = serde::ser::Impossible<Self::Ok, Self::Error>;
    type SerializeStruct = serde::ser::Impossible<Self::Ok, Self::Error>;
    type SerializeStructVariant = serde::ser::Impossible<Self::Ok, Self::Error>;

    fn serialize_seq(self, declared_len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(SequenceRecorder(RecordedSequence { declared_len, entries: Vec::new() }))
    }

    fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("expected a sequence"))
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("expected a sequence"))
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("expected a sequence"))
    }

    fn collect_str<T: ?Sized + std::fmt::Display>(self, _: &T) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("expected a sequence"))
    }

    reject_scalar_protocol! {
        serialize_bool(bool), serialize_i8(i8), serialize_i16(i16), serialize_i32(i32),
        serialize_i64(i64), serialize_u8(u8), serialize_u16(u16), serialize_u32(u32),
        serialize_u64(u64), serialize_f32(f32), serialize_f64(f64), serialize_char(char),
        serialize_str(&str), serialize_bytes(&[u8]), serialize_unit_struct(&'static str),
    }
    reject_compound_protocol! {
        serialize_none() -> Ok,
        serialize_unit() -> Ok,
        serialize_unit_variant(_name: &'static str, _index: u32, _variant: &'static str) -> Ok,
        serialize_tuple(_length: usize) -> SerializeTuple,
        serialize_tuple_struct(_name: &'static str, _length: usize) -> SerializeTupleStruct,
        serialize_tuple_variant(_name: &'static str, _index: u32, _variant: &'static str, _length: usize) -> SerializeTupleVariant,
        serialize_map(_length: Option<usize>) -> SerializeMap,
        serialize_struct(_name: &'static str, _length: usize) -> SerializeStruct,
        serialize_struct_variant(_name: &'static str, _index: u32, _variant: &'static str, _length: usize) -> SerializeStructVariant,
    }

    fn is_human_readable(&self) -> bool {
        self.0
    }
}

#[test]
fn origin_set_serializes_as_a_sized_sequence_for_both_serde_modes() {
    let first = file("first.txt");
    let second = detailed_repo("repository", "src/config.txt", b'a');
    let expected = vec![first.clone(), second.clone(), first.clone()];
    let set = OriginSet::new(first.clone(), vec![second, first]);
    for human_readable in [true, false] {
        let recorded = set.serialize(SequenceProtocol(human_readable)).unwrap();
        assert_eq!(recorded.declared_len, Some(expected.len()));
        assert_eq!(
            serde_json::Value::Array(recorded.entries),
            serde_json::to_value(&expected).unwrap()
        );
    }
}

#[test]
fn origin_set_filtering_moves_surviving_arcs_and_releases_discarded_generics() {
    let generic_path = Arc::new(PathBuf::from("repository"));
    let generic_weak = Arc::downgrade(&generic_path);
    let detailed = detailed_repo("repository", "src/config.txt", b'a');
    let (detailed_path, metadata) = match &detailed {
        Origin::GitRepo(repository) => (
            Arc::clone(&repository.repo_path),
            Arc::clone(&repository.first_commit.as_ref().unwrap().commit_metadata),
        ),
        _ => unreachable!(),
    };
    assert!(!Arc::ptr_eq(&generic_path, &detailed_path));
    let detailed_weak = Arc::downgrade(&detailed_path);
    let metadata_weak = Arc::downgrade(&metadata);
    let file_path = Arc::new(PathBuf::from("local.txt"));
    let file_weak = Arc::downgrade(&file_path);
    let first = Origin::from_git_repo(Arc::clone(&generic_path));
    let redundant = Origin::from_git_repo(Arc::clone(&generic_path));
    assert_eq!(Arc::strong_count(&generic_path), 3);

    let set = OriginSet::new(
        first,
        vec![Origin::File(FileOrigin { path: Arc::clone(&file_path) }), detailed, redundant],
    );
    assert_eq!(set.len(), 2);
    assert_eq!(Arc::strong_count(&generic_path), 1);
    assert_eq!(Arc::strong_count(&file_path), 2);
    assert_eq!(Arc::strong_count(&detailed_path), 2);
    assert_eq!(Arc::strong_count(&metadata), 2);
    {
        let mut entries = set.iter();
        let Origin::File(file) = entries.next().unwrap() else { panic!("file must be first") };
        assert!(Arc::ptr_eq(&file.path, &file_path));
        let Origin::GitRepo(repository) = entries.next().unwrap() else {
            panic!("detailed repository must survive")
        };
        assert!(Arc::ptr_eq(&repository.repo_path, &detailed_path));
        assert!(
            Arc::ptr_eq(&repository.first_commit.as_ref().unwrap().commit_metadata, &metadata,)
        );
        assert!(entries.next().is_none());
    }
    drop(generic_path);
    assert!(generic_weak.upgrade().is_none());

    drop(set);
    assert_eq!(Arc::strong_count(&file_path), 1);
    assert_eq!(Arc::strong_count(&detailed_path), 1);
    assert_eq!(Arc::strong_count(&metadata), 1);
    drop((file_path, detailed_path, metadata));
    assert!(file_weak.upgrade().is_none());
    assert!(detailed_weak.upgrade().is_none());
    assert!(metadata_weak.upgrade().is_none());
}

#[test]
fn origin_set_clone_and_owned_iteration_preserve_arc_sharing_and_release_each_entry() {
    // One detailed tail entry stays inline; two spill. The public owned iterator
    // must move both forms without retaining or cloning any extra origins.
    for (detailed_count, consume_all) in [(1, false), (1, true), (2, false), (2, true)] {
        let detailed = detailed_repo("repository", "src/config.txt", b'a');
        let (repository_path, metadata) = match &detailed {
            Origin::GitRepo(repository) => (
                Arc::clone(&repository.repo_path),
                Arc::clone(&repository.first_commit.as_ref().unwrap().commit_metadata),
            ),
            _ => unreachable!(),
        };
        let file_path = Arc::new(PathBuf::from("local.txt"));
        let repository_weak = Arc::downgrade(&repository_path);
        let metadata_weak = Arc::downgrade(&metadata);
        let file_weak = Arc::downgrade(&file_path);
        let set = OriginSet::new(
            Origin::File(FileOrigin { path: Arc::clone(&file_path) }),
            vec![detailed; detailed_count],
        );
        assert_eq!(Arc::strong_count(&file_path), 2);
        assert_eq!(Arc::strong_count(&repository_path), detailed_count + 1);
        assert_eq!(Arc::strong_count(&metadata), detailed_count + 1);
        let cloned = set.clone();
        assert_eq!(Arc::strong_count(&file_path), 3);
        assert_eq!(Arc::strong_count(&repository_path), 2 * detailed_count + 1);
        assert_eq!(Arc::strong_count(&metadata), 2 * detailed_count + 1);
        for entry in cloned.iter().skip(1) {
            let Origin::GitRepo(repository) = entry else { panic!("expected detailed entry") };
            assert!(Arc::ptr_eq(&repository.repo_path, &repository_path));
            assert!(Arc::ptr_eq(
                &repository.first_commit.as_ref().unwrap().commit_metadata,
                &metadata,
            ));
        }
        drop(set);
        assert_eq!(Arc::strong_count(&file_path), 2);
        assert_eq!(Arc::strong_count(&repository_path), detailed_count + 1);
        assert_eq!(Arc::strong_count(&metadata), detailed_count + 1);

        let mut iterator: std::iter::Chain<std::iter::Once<Origin>, std::vec::IntoIter<Origin>> =
            cloned.into_iter();
        assert_eq!(Arc::strong_count(&file_path), 2);
        assert_eq!(Arc::strong_count(&repository_path), detailed_count + 1);
        assert_eq!(Arc::strong_count(&metadata), detailed_count + 1);
        let file = iterator.next().unwrap();
        let Origin::File(file_origin) = &file else { panic!("file must be first") };
        assert!(Arc::ptr_eq(&file_origin.path, &file_path));
        drop(file);
        assert_eq!(Arc::strong_count(&file_path), 1);
        if consume_all {
            for remaining in (0..detailed_count).rev() {
                let entry = iterator.next().unwrap();
                let Origin::GitRepo(repository) = &entry else { panic!("expected detailed entry") };
                assert!(Arc::ptr_eq(&repository.repo_path, &repository_path));
                assert!(Arc::ptr_eq(
                    &repository.first_commit.as_ref().unwrap().commit_metadata,
                    &metadata,
                ));
                assert_eq!(Arc::strong_count(&repository_path), remaining + 2);
                assert_eq!(Arc::strong_count(&metadata), remaining + 2);
                drop(entry);
                assert_eq!(Arc::strong_count(&repository_path), remaining + 1);
                assert_eq!(Arc::strong_count(&metadata), remaining + 1);
            }
            assert!(iterator.next().is_none());
        }
        drop(iterator);
        assert_eq!(Arc::strong_count(&repository_path), 1);
        assert_eq!(Arc::strong_count(&metadata), 1);
        drop((file_path, repository_path, metadata));
        assert!(file_weak.upgrade().is_none());
        assert!(repository_weak.upgrade().is_none());
        assert!(metadata_weak.upgrade().is_none());
    }
}

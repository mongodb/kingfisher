
use std::io;
use std::path::PathBuf;

use schemars::generate::SchemaSettings;
use serde::de::Visitor;
use serde::de::value::{
    BoolDeserializer, BorrowedStrDeserializer, Error as ProbeError, SeqDeserializer,
};
use serde::ser::Impossible;
use serde::{Deserializer, Serializer};
use serde_json::{Value, json};

use super::*;
use crate::origin::Origin;

const COMMIT_ID: &str = "0123456789abcdef0123456789abcdef01234567";

fn metadata() -> CommitMetadata {
    CommitMetadata {
        commit_id: ObjectId::from_hex(COMMIT_ID.as_bytes()).unwrap(),
        author_name: None,
        author_email: None,
        committer_name: "Zoë \"Z\"\n".into(),
        committer_email: "committer@example.invalid".into(),
        committer_timestamp: Time::new(1_700_000_000, -19_800),
    }
}

fn metadata_json() -> Value {
    json!({
        "commit_id": COMMIT_ID,
        "committer_name": "Zoë \"Z\"\n",
        "committer_email": "committer@example.invalid",
        "committer_timestamp": "1700000000 -0530",
    })
}

fn with_json_field(name: &str, value: Value) -> Value {
    let mut document = metadata_json();
    document[name] = value;
    document
}

#[test]
fn commit_metadata_json_preserves_field_names_order_and_escaping() {
    let value = metadata();
    assert_eq!(serde_json::to_value(&value).unwrap(), metadata_json());
    assert_eq!(
        serde_json::to_string(&value).unwrap(),
        r#"{"commit_id":"0123456789abcdef0123456789abcdef01234567","committer_name":"Zoë \"Z\"\n","committer_email":"committer@example.invalid","committer_timestamp":"1700000000 -0530"}"#,
    );
    assert_eq!(serde_json::from_value::<CommitMetadata>(metadata_json()).unwrap(), value);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert_eq!(serde_json::from_slice::<CommitMetadata>(&bytes).unwrap(), value);
}

#[test]
fn commit_metadata_optional_authors_preserve_missing_null_and_present_values() {
    for (name, email) in [
        (None, None),
        (Some(""), None),
        (None, Some("author@example.invalid")),
        (Some("作者 \"A\"\n"), Some("a+测试@example.invalid")),
    ] {
        let mut value = metadata();
        value.author_name = name.map(Arc::from);
        value.author_email = email.map(Arc::from);
        let document = serde_json::to_value(&value).unwrap();
        assert_eq!(document.get("author_name"), name.map(|v| json!(v)).as_ref());
        assert_eq!(document.get("author_email"), email.map(|v| json!(v)).as_ref());
        assert_eq!(serde_json::from_value::<CommitMetadata>(document).unwrap(), value);
    }

    let mut document = metadata_json();
    document["author_name"] = Value::Null;
    document["author_email"] = Value::Null;
    assert_eq!(serde_json::from_value::<CommitMetadata>(document).unwrap(), metadata());
}

#[test]
fn commit_metadata_retains_required_fields_and_unknown_field_compatibility() {
    for field in ["commit_id", "committer_name", "committer_email", "committer_timestamp"] {
        let mut document = metadata_json();
        document.as_object_mut().unwrap().remove(field);
        assert_eq!(
            serde_json::from_value::<CommitMetadata>(document).unwrap_err().to_string(),
            format!("missing field `{field}`"),
        );
    }

    let document = with_json_field("future_metadata", json!({"version": 2}));
    assert_eq!(serde_json::from_value::<CommitMetadata>(document).unwrap(), metadata());
}

#[test]
fn commit_metadata_timestamps_preserve_raw_git_encoding_and_round_trips() {
    for (seconds, offset, expected) in [
        (0, 0, "0 +0000"),
        (1_700_000_000, 19_800, "1700000000 +0530"),
        (1_700_000_000, -12_600, "1700000000 -0330"),
        (1_700_000_000, 20_700, "1700000000 +0545"),
        (-1, 0, "-1 +0000"),
        (i64::MIN, 0, "-9223372036854775808 +0000"),
        (i64::MAX, 0, "9223372036854775807 +0000"),
        (0, 50_400, "0 +1400"),
        (0, -50_400, "0 -1400"),
    ] {
        let mut value = metadata();
        value.committer_timestamp = Time::new(seconds, offset);
        let document = serde_json::to_value(&value).unwrap();
        assert_eq!(document["committer_timestamp"], expected);
        assert_eq!(serde_json::from_value::<CommitMetadata>(document).unwrap(), value);
    }
}

#[test]
fn commit_metadata_timestamps_preserve_largest_encodable_values() {
    for (seconds, offset, expected) in [
        (i64::MIN, -359_999, "-9223372036854775808 -9959"),
        (i64::MAX, 359_999, "9223372036854775807 +9959"),
    ] {
        let mut value = metadata();
        value.committer_timestamp = Time::new(seconds, offset);
        let document = serde_json::to_value(&value).unwrap();
        assert_eq!(document["committer_timestamp"], expected);
    }
}

#[test]
fn commit_metadata_timestamps_keep_existing_offset_minute_precision() {
    for (offset, expected, decoded_offset) in [
        (19_859, "1700000000 +0530", 19_800),
        (-19_859, "1700000000 -0530", -19_800),
        (59, "1700000000 +0000", 0),
        (-59, "1700000000 -0000", 0),
    ] {
        let mut value = metadata();
        value.committer_timestamp = Time::new(1_700_000_000, offset);
        let document = serde_json::to_value(&value).unwrap();
        assert_eq!(document["committer_timestamp"], expected);
        let decoded = serde_json::from_value::<CommitMetadata>(document).unwrap();
        assert_eq!(decoded.committer_timestamp, Time::new(1_700_000_000, decoded_offset));
    }
}

#[test]
fn commit_metadata_timestamps_accept_all_existing_absolute_date_forms() {
    for (input, seconds, offset) in [
        ("0", 0, 0),
        ("-1000", -1000, 0),
        ("@1700000000", 1_700_000_000, 0),
        ("1745582210 +0200", 1_745_582_210, 7_200),
        ("1970-01-01 05:30:00 +0530", 0, 19_800),
        ("1970-01-01T05:30:00+05:30", 0, 19_800),
        ("Thu, 01 Jan 1970 00:00:00 +0000", 0, 0),
        ("2018-12-24", 1_545_609_600, 0),
    ] {
        let document = with_json_field("committer_timestamp", json!(input));
        let value = serde_json::from_value::<CommitMetadata>(document).unwrap();
        assert_eq!(value.committer_timestamp, Time::new(seconds, offset), "{input}");
    }
}

#[test]
fn commit_metadata_timestamps_preserve_parser_errors_without_relative_clock_defaults() {
    for input in ["", "not a Git date", "now", "yesterday", "2 hours ago", "1 +1500"] {
        let expected = gix::date::parse(input, None).unwrap_err().to_string();
        let document = with_json_field("committer_timestamp", json!(input));
        assert_eq!(
            serde_json::from_value::<CommitMetadata>(document).unwrap_err().to_string(),
            expected,
            "{input}",
        );
    }
}

#[test]
fn commit_metadata_object_ids_preserve_hex_case_normalization_and_round_trips() {
    for input in
        [COMMIT_ID.to_owned(), COMMIT_ID.to_ascii_uppercase(), "0".repeat(40), "F".repeat(40)]
    {
        let document = with_json_field("commit_id", json!(input));
        let value = serde_json::from_value::<CommitMetadata>(document).unwrap();
        assert_eq!(value.commit_id, ObjectId::from_hex(input.as_bytes()).unwrap());
        let serialized = serde_json::to_value(&value).unwrap();
        assert_eq!(serialized["commit_id"], input.to_ascii_lowercase());
        assert_eq!(serde_json::from_value::<CommitMetadata>(serialized).unwrap(), value);
    }
}

#[test]
fn commit_metadata_object_ids_preserve_invalid_encoding_errors() {
    for input in [
        "".to_owned(),
        "0".repeat(39),
        "0".repeat(41),
        "z".repeat(40),
        "é".repeat(20),
        format!(" {COMMIT_ID}"),
        format!("{COMMIT_ID}\n"),
    ] {
        let expected = ObjectId::from_hex(input.as_bytes()).unwrap_err().to_string();
        let document = with_json_field("commit_id", json!(input));
        assert_eq!(
            serde_json::from_value::<CommitMetadata>(document).unwrap_err().to_string(),
            expected,
            "{input:?}",
        );
    }
}

#[test]
fn commit_metadata_adapters_reject_nonstring_json_with_existing_type_errors() {
    for (input, actual) in [
        (Value::Null, "null"),
        (json!(true), "boolean `true`"),
        (json!(42), "integer `42`"),
        (json!(1.25), "floating point `1.25`"),
        (json!([]), "sequence"),
        (json!({}), "map"),
    ] {
        for (field, expected) in [
            ("commit_id", "a 40-character hex string representing a Git object ID"),
            ("committer_timestamp", "a string representing a Git timestamp"),
        ] {
            let document = with_json_field(field, input.clone());
            assert_eq!(
                serde_json::from_value::<CommitMetadata>(document).unwrap_err().to_string(),
                format!("invalid type: {actual}, expected {expected}"),
            );
        }
    }
}

struct FailingWriter {
    remaining: usize,
}

impl io::Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("metadata output blocked"));
        }
        let written = self.remaining.min(bytes.len());
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn commit_metadata_serialization_propagates_output_errors() {
    let value = metadata();
    let encoded_length = serde_json::to_vec(&value).unwrap().len();
    for remaining in [0, 1, 18, 59, 90, encoded_length - 1] {
        let error = serde_json::to_writer(FailingWriter { remaining }, &value).unwrap_err();
        assert!(error.is_io(), "{error}");
        assert!(error.to_string().contains("metadata output blocked"), "{error}");
    }
}

#[test]
fn commit_metadata_serialization_keeps_unrepresentable_offset_failure() {
    // This replacement must not silently change the underlying Git date formatter's policy.
    for offset in [360_000, -360_000, i32::MIN, i32::MAX] {
        let mut value = metadata();
        value.committer_timestamp = Time::new(0, offset);
        assert!(std::panic::catch_unwind(|| serde_json::to_value(&value)).is_err());
    }
}

fn contains_ref(value: &Value, reference: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.get("$ref").and_then(Value::as_str) == Some(reference)
                || object.values().any(|value| contains_ref(value, reference))
        }
        Value::Array(array) => array.iter().any(|value| contains_ref(value, reference)),
        _ => false,
    }
}

#[test]
fn commit_metadata_schema_preserves_named_definitions_and_field_contracts() {
    for (settings, definitions_key) in [
        (SchemaSettings::default(), "$defs"),
        (SchemaSettings::default().for_serialize(), "$defs"),
        (SchemaSettings::draft07(), "definitions"),
        (SchemaSettings::draft07().for_serialize(), "definitions"),
    ] {
        let schema = settings.into_generator().into_root_schema_for::<CommitMetadata>();
        let document = serde_json::to_value(schema).unwrap();
        assert_eq!(document["title"], "CommitMetadata");
        assert_eq!(document["type"], "object");

        let definitions = document[definitions_key].as_object().unwrap();
        assert_eq!(definitions.len(), 2);
        assert_eq!(definitions["Time"], json!({"type": "string"}));
        assert_eq!(
            definitions["ObjectId"],
            json!({
                "type": "string",
                "pattern": "[0-9a-f]{40}",
                "description": "A hex-encoded object ID as computed by Git",
            }),
        );

        let properties = document["properties"].as_object().unwrap();
        assert_eq!(properties.len(), 6);
        for (field, definition) in [("commit_id", "ObjectId"), ("committer_timestamp", "Time")] {
            assert!(
                contains_ref(&properties[field], &format!("#/{definitions_key}/{definition}"),)
            );
        }
        for field in ["committer_name", "committer_email"] {
            assert_eq!(properties[field]["type"], "string");
        }
        for field in ["author_name", "author_email"] {
            assert_eq!(properties[field]["type"], json!(["string", "null"]));
        }
        let mut required = document["required"].as_array().unwrap().clone();
        required.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        assert_eq!(
            required,
            json!(["commit_id", "committer_email", "committer_name", "committer_timestamp"])
                .as_array()
                .unwrap()
                .clone(),
        );
        assert!(document.get("additionalProperties").is_none());
    }
}

#[test]
fn commit_metadata_nested_git_origin_preserves_report_serialization() {
    let value = Origin::from_git_repo_with_first_commit(
        Arc::new(PathBuf::from("metadata-repository")),
        Arc::new(metadata()),
        "source/config.txt".to_owned(),
    );
    let expected = json!({
        "kind": "git_repo",
        "repo_path": "metadata-repository",
        "first_commit": {
            "commit_metadata": metadata_json(),
            "blob_path": "source/config.txt",
        },
    });
    assert_eq!(serde_json::to_value(&value).unwrap(), expected);
    assert_eq!(serde_json::from_value::<Origin>(expected).unwrap(), value);
}

// These probes check Serde's observable newtype protocol without another dependency.
// JSON alone cannot distinguish a named newtype from a directly serialized string.
struct NamedTextSerializer {
    human_readable: bool,
}

macro_rules! reject_values {
    ($($method:ident($value_type:ty)),* $(,)?) => {
        $(
            fn $method(self, _value: $value_type) -> Result<Self::Ok, Self::Error> {
                Err(serde::ser::Error::custom(concat!("unexpected ", stringify!($method))))
            }
        )*
    };
}

macro_rules! reject_compounds {
    ($($method:ident($($argument:ident: $argument_type:ty),*) -> $result:ident),* $(,)?) => {
        $(
            fn $method(self, $($argument: $argument_type),*) -> Result<Self::$result, Self::Error> {
                Err(serde::ser::Error::custom(concat!("unexpected ", stringify!($method))))
            }
        )*
    };
}

impl Serializer for NamedTextSerializer {
    type Ok = (&'static str, String);
    type Error = ProbeError;
    type SerializeSeq = Impossible<Self::Ok, Self::Error>;
    type SerializeTuple = Impossible<Self::Ok, Self::Error>;
    type SerializeTupleStruct = Impossible<Self::Ok, Self::Error>;
    type SerializeTupleVariant = Impossible<Self::Ok, Self::Error>;
    type SerializeMap = Impossible<Self::Ok, Self::Error>;
    type SerializeStruct = Impossible<Self::Ok, Self::Error>;
    type SerializeStructVariant = Impossible<Self::Ok, Self::Error>;

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        match serde_json::to_value(value).map_err(<ProbeError as serde::ser::Error>::custom)? {
            Value::String(text) => Ok((name, text)),
            _ => Err(serde::ser::Error::custom("expected newtype containing text")),
        }
    }

    fn serialize_some<T: ?Sized + Serialize>(self, _value: &T) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("unexpected serialize_some"))
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("unexpected serialize_newtype_variant"))
    }

    reject_values! {
        serialize_bool(bool), serialize_i8(i8), serialize_i16(i16), serialize_i32(i32),
        serialize_i64(i64), serialize_u8(u8), serialize_u16(u16), serialize_u32(u32),
        serialize_u64(u64), serialize_f32(f32), serialize_f64(f64), serialize_char(char),
        serialize_str(&str), serialize_bytes(&[u8]), serialize_unit_struct(&'static str),
    }

    reject_compounds! {
        serialize_none() -> Ok,
        serialize_unit() -> Ok,
        serialize_unit_variant(_name: &'static str, _index: u32, _variant: &'static str) -> Ok,
        serialize_seq(_length: Option<usize>) -> SerializeSeq,
        serialize_tuple(_length: usize) -> SerializeTuple,
        serialize_tuple_struct(_name: &'static str, _length: usize) -> SerializeTupleStruct,
        serialize_tuple_variant(_name: &'static str, _index: u32, _variant: &'static str, _length: usize) -> SerializeTupleVariant,
        serialize_map(_length: Option<usize>) -> SerializeMap,
        serialize_struct(_name: &'static str, _length: usize) -> SerializeStruct,
        serialize_struct_variant(_name: &'static str, _index: u32, _variant: &'static str, _length: usize) -> SerializeStructVariant,
    }

    fn is_human_readable(&self) -> bool {
        self.human_readable
    }
}

enum NamedInput<'a> {
    Newtype(&'a str),
    Sequence(&'a [&'a str]),
}

struct NamedTextDeserializer<'a> {
    expected_name: &'static str,
    input: NamedInput<'a>,
}

impl<'de> Deserializer<'de> for NamedTextDeserializer<'de> {
    type Error = ProbeError;

    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        Err(serde::de::Error::custom("expected named newtype dispatch"))
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        assert_eq!(name, self.expected_name);
        match self.input {
            NamedInput::Newtype(text) => {
                visitor.visit_newtype_struct(BorrowedStrDeserializer::<ProbeError>::new(text))
            }
            NamedInput::Sequence(values) => {
                let mut sequence = SeqDeserializer::<_, ProbeError>::new(values.iter().copied());
                let value = visitor.visit_seq(&mut sequence)?;
                sequence.end()?;
                Ok(value)
            }
        }
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct seq tuple tuple_struct map struct
        enum identifier ignored_any
    }
}

#[test]
fn git_metadata_adapters_preserve_outer_type_errors() {
    let time_error = TextTime::deserialize(BoolDeserializer::<ProbeError>::new(true)).unwrap_err();
    assert_eq!(time_error.to_string(), "invalid type: boolean `true`, expected tuple struct Time",);
    let id_error = HexObjectId::deserialize(BoolDeserializer::<ProbeError>::new(true)).unwrap_err();
    assert_eq!(
        id_error.to_string(),
        "invalid type: boolean `true`, expected tuple struct ObjectId",
    );
}

#[test]
fn git_metadata_adapters_preserve_named_newtype_serialization() {
    for human_readable in [true, false] {
        assert_eq!(
            TextTime::serialize(
                &metadata().committer_timestamp,
                NamedTextSerializer { human_readable }
            )
            .unwrap(),
            ("TextTime", "1700000000 -0530".to_owned()),
        );
        assert_eq!(
            HexObjectId::serialize(&metadata().commit_id, NamedTextSerializer { human_readable })
                .unwrap(),
            ("HexObjectId", COMMIT_ID.to_owned()),
        );
    }
}

#[test]
fn git_metadata_adapters_preserve_named_newtype_and_sequence_deserialization() {
    for input in
        [NamedInput::Newtype("1700000000 -0530"), NamedInput::Sequence(&["1700000000 -0530"])]
    {
        assert_eq!(
            TextTime::deserialize(NamedTextDeserializer { expected_name: "TextTime", input })
                .unwrap(),
            metadata().committer_timestamp,
        );
    }
    for input in [NamedInput::Newtype(COMMIT_ID), NamedInput::Sequence(&[COMMIT_ID])] {
        assert_eq!(
            HexObjectId::deserialize(NamedTextDeserializer { expected_name: "HexObjectId", input })
                .unwrap(),
            metadata().commit_id,
        );
    }
}

#[test]
fn git_metadata_adapters_preserve_empty_and_extra_sequence_errors() {
    let empty_time = TextTime::deserialize(NamedTextDeserializer {
        expected_name: "TextTime",
        input: NamedInput::Sequence(&[]),
    })
    .unwrap_err();
    assert_eq!(
        empty_time.to_string(),
        "invalid length 0, expected tuple struct Time with 1 element"
    );
    let empty_id = HexObjectId::deserialize(NamedTextDeserializer {
        expected_name: "HexObjectId",
        input: NamedInput::Sequence(&[]),
    })
    .unwrap_err();
    assert_eq!(
        empty_id.to_string(),
        "invalid length 0, expected tuple struct ObjectId with 1 element"
    );

    let extra_time = TextTime::deserialize(NamedTextDeserializer {
        expected_name: "TextTime",
        input: NamedInput::Sequence(&["0 +0000", "1 +0000"]),
    })
    .unwrap_err();
    assert_eq!(extra_time.to_string(), "invalid length 2, expected 1 element in sequence");
    let extra_id = HexObjectId::deserialize(NamedTextDeserializer {
        expected_name: "HexObjectId",
        input: NamedInput::Sequence(&[COMMIT_ID, COMMIT_ID]),
    })
    .unwrap_err();
    assert_eq!(extra_id.to_string(), "invalid length 2, expected 1 element in sequence");
}

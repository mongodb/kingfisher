//! Characterization of persisted BlobId encoding, formatting, and Git adapters.
use super::*;
use schemars::generate::SchemaSettings;
use serde::de::value::{
    BorrowedStrDeserializer, Error as ValueError, StrDeserializer, StringDeserializer,
};
use serde_json::{Value, json};
use std::result::Result;

const HEX: &str = "0123456789abcdef0123456789abcdef01234567";

fn example_id() -> BlobId {
    BlobId::from_hex(HEX).unwrap()
}

#[test]
fn blob_id_hashes_preserve_git_blob_identity() {
    for (bytes, expected) in [
        (&b""[..], "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
        (&b"hello\n"[..], "ce013625030ba8dba906f756967f9e9ca394464a"),
        (&b"hello world"[..], "95d09f2b10159347eece71399a7e2e907ea3df4f"),
        (&[0, 255, 128, 13, 10][..], "f21a905eaf587067e88aadfe3cda06c916e532a6"),
    ] {
        assert_eq!(BlobId::new(bytes).hex(), expected);
        assert_eq!(BlobId::compute_from_bytes(bytes).hex(), expected);
    }
}

#[test]
fn blob_id_sampling_boundaries_and_full_hashes_remain_distinct() {
    // Independent SHA-1 vectors over "blob <length>\\0" plus the documented bytes.
    for (size, sampled, complete) in [
        (
            65_535,
            "a6e1d9acb6b754c0acf2b713530d60e8e0e8b196",
            "a6e1d9acb6b754c0acf2b713530d60e8e0e8b196",
        ),
        (
            65_536,
            "9c1953b934e44444df3f5f0951c27661c158b728",
            "9c1953b934e44444df3f5f0951c27661c158b728",
        ),
        (
            131_071,
            "10cd0c64222c268bf5dd7432bbb52abce33ab5a5",
            "10cd0c64222c268bf5dd7432bbb52abce33ab5a5",
        ),
        (
            131_072,
            "12b64b5654826a9e56c0a3524f91be45e0a6df1e",
            "12b64b5654826a9e56c0a3524f91be45e0a6df1e",
        ),
        (
            131_073,
            "7f2a12189c7a36e0dfe3461311d9d0555f0ab1cb",
            "bea672edbb9ffcfcccb1ff877e0a4b31476f1380",
        ),
        (
            196_609,
            "24cae7551b8eeff955cc0978c46dae670e7d2c2a",
            "d3d94d108be20b06c1d77214bba01171746770c5",
        ),
    ] {
        let bytes =
            (0..size).map(|i: usize| i.wrapping_mul(37).wrapping_add(11) as u8).collect::<Vec<_>>();
        assert_eq!(BlobId::new(&bytes).hex(), sampled, "{size}");
        assert_eq!(BlobId::compute_from_bytes(&bytes).hex(), complete, "{size}");
    }
    let mut first = vec![b'x'; 131_073];
    let original = BlobId::new(&first);
    let complete = BlobId::compute_from_bytes(&first);
    first[65_536] = b'y';
    assert_eq!(BlobId::new(&first), original);
    assert_ne!(BlobId::compute_from_bytes(&first), complete);
    first[0] = b'z';
    assert_ne!(BlobId::new(&first), original);
}

#[test]
fn blob_id_hex_accepts_case_and_preserves_every_byte() {
    for input in [HEX.to_owned(), HEX.to_uppercase(), "fF".repeat(20), "00".repeat(20)] {
        let parsed = BlobId::from_hex(&input).unwrap();
        assert_eq!(parsed.hex(), input.to_ascii_lowercase());
        assert_eq!(parsed.as_bytes(), hex::decode(&input).unwrap());
        assert_eq!(BlobId::try_from(input.as_str()).unwrap(), parsed);
        assert_eq!(String::from(parsed), parsed.hex());
    }
    assert_eq!(BlobId::default().as_bytes(), &[0_u8; 20]);
}

#[test]
fn blob_id_wrong_decoded_lengths_keep_invalid_blob_id_errors() {
    for input in [String::new(), "00".to_owned(), "ab".repeat(19), "ab".repeat(21), "ab".repeat(32)]
    {
        let error = BlobId::from_hex(&input).unwrap_err();
        assert!(matches!(&error, crate::Error::InvalidBlobId(value) if value == &input));
        assert_eq!(error.to_string(), format!("Invalid blob ID: {input}"));
        assert_eq!(BlobId::try_from(input.as_str()).unwrap_err().to_string(), error.to_string());
    }
}

#[test]
fn blob_id_hex_errors_precede_decoded_length_errors() {
    for input in ["f", "g", "ggg", "éa", "💥a", &"0".repeat(39), &"0".repeat(41)] {
        assert!(matches!(
            BlobId::from_hex(input),
            Err(crate::Error::HexDecode(hex::FromHexError::OddLength))
        ));
    }
    for (input, character, index) in [
        ("gg".to_owned(), 'g', 0),
        (format!("{}z0", "00".repeat(20)), 'z', 40),
        (format!("{}0z", "00".repeat(19)), 'z', 39),
        (format!("{}  ", "00".repeat(20)), ' ', 40),
        ("é".to_owned(), 'Ã', 0),
        (format!("{}é", "00".repeat(19)), 'Ã', 38),
        (format!("{}💥", "00".repeat(18)), 'ð', 36),
    ] {
        let error = BlobId::from_hex(&input).unwrap_err();
        assert!(
            matches!(error, crate::Error::HexDecode(hex::FromHexError::InvalidHexCharacter { c, index: actual }) if c == character && actual == index)
        );
        assert_eq!(
            error.to_string(),
            format!("Hex decode error: Invalid character {character:?} at position {index}")
        );
    }
}

#[test]
fn blob_id_invalid_character_positions_preserve_error_categories_and_text() {
    for length in [38, 39, 40, 41, 42] {
        let valid = "a".repeat(length);
        match BlobId::from_hex(&valid) {
            Ok(_) => assert_eq!(length, 40),
            Err(error) if length % 2 == 1 => {
                assert!(matches!(error, crate::Error::HexDecode(hex::FromHexError::OddLength)));
                assert_eq!(error.to_string(), "Hex decode error: Odd number of digits");
            }
            Err(error) => {
                assert!(matches!(&error, crate::Error::InvalidBlobId(input) if input == &valid));
                assert_eq!(error.to_string(), format!("Invalid blob ID: {valid}"));
            }
        }

        for invalid in ["g", "G", " ", "\n", "\0", "é", "💥"] {
            for position in 0..=length - invalid.len() {
                for later_invalid in [false, true] {
                    let mut input = valid.clone();
                    input.replace_range(position..position + invalid.len(), invalid);
                    let next_position = position + invalid.len();
                    if later_invalid && next_position < length {
                        input.replace_range(next_position..next_position + 1, "z");
                    }
                    let error = BlobId::from_hex(&input).unwrap_err();
                    let expected = if length % 2 == 1 {
                        assert!(matches!(
                            error,
                            crate::Error::HexDecode(hex::FromHexError::OddLength)
                        ));
                        "Hex decode error: Odd number of digits".to_owned()
                    } else {
                        // The existing hex decoder reports the first invalid byte as
                        // a char, even when it belongs to a multibyte UTF-8 character.
                        let character = char::from(invalid.as_bytes()[0]);
                        assert!(matches!(
                            &error,
                            crate::Error::HexDecode(hex::FromHexError::InvalidHexCharacter { c, index })
                                if *c == character && *index == position
                        ));
                        format!(
                            "Hex decode error: Invalid character {character:?} at position {position}"
                        )
                    };
                    assert_eq!(error.to_string(), expected, "length={length}, position={position}");
                    assert_eq!(BlobId::try_from(input.as_str()).unwrap_err().to_string(), expected);
                    assert_eq!(
                        serde_json::from_value::<BlobId>(json!(input)).unwrap_err().to_string(),
                        expected
                    );
                }
            }
        }
    }
}

#[test]
fn blob_id_display_debug_and_outer_format_flags_stay_compatible() {
    let value = example_id();
    assert_eq!(value.to_string(), HEX);
    assert_eq!(format!("{value:?}"), format!("BlobId({HEX})"));
    for text in [
        format!("{value:>60}"),
        format!("{value:<60}"),
        format!("{value:^60.7}"),
        format!("{value:+060}"),
    ] {
        assert_eq!(text, HEX);
    }
    assert_eq!(format!("{value:#?}"), format!("BlobId({HEX})"));
    assert_eq!(format!("{value:>60.7?}"), format!("BlobId({HEX})"));
}

#[test]
fn blob_id_formatting_propagates_writer_errors() {
    struct Limit(usize);
    impl std::fmt::Write for Limit {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            if value.len() > self.0 {
                return Err(std::fmt::Error);
            }
            self.0 -= value.len();
            Ok(())
        }
    }
    use std::fmt::Write;
    for capacity in [0, 1, 39] {
        assert!(write!(Limit(capacity), "{}", example_id()).is_err());
    }
    assert!(write!(Limit(40), "{}", example_id()).is_ok());
    assert!(write!(Limit(47), "{:?}", example_id()).is_err());
    assert!(write!(Limit(48), "{:?}", example_id()).is_ok());
}

#[test]
fn blob_id_owned_borrowed_and_git_conversions_preserve_identity() {
    let value = example_id();
    let oid: ObjectId = value.into();
    assert_eq!(oid.as_bytes(), value.as_bytes());
    assert_eq!(ObjectId::from(&value), oid);
    assert_eq!(BlobId::from(&oid), value);
    assert_eq!(oid.to_string(), HEX);
    assert_eq!(BlobId::from(oid), value);
}

#[test]
fn blob_id_serde_remains_a_lowercase_string_in_arrays_and_map_keys() {
    let value = example_id();
    assert_eq!(serde_json::to_string(&value).unwrap(), format!("\"{HEX}\""));
    assert_eq!(
        serde_json::from_str::<BlobId>(&format!("\"{}\"", HEX.to_uppercase())).unwrap(),
        value
    );
    assert_eq!(
        serde_json::from_value::<Vec<BlobId>>(json!([HEX, HEX.to_uppercase()])).unwrap(),
        vec![value, value]
    );
    let map = std::collections::BTreeMap::from([(value, 7_u32)]);
    assert_eq!(serde_json::to_value(&map).unwrap(), json!({(HEX): 7}));
    assert_eq!(
        serde_json::from_value::<std::collections::BTreeMap<BlobId, u32>>(json!({(HEX): 7}))
            .unwrap(),
        map
    );
}

#[test]
fn blob_id_deserialization_accepts_borrowed_transient_and_owned_strings() {
    let expected = example_id();
    assert_eq!(
        BlobId::deserialize(BorrowedStrDeserializer::<ValueError>::new(HEX)).unwrap(),
        expected
    );
    assert_eq!(BlobId::deserialize(StrDeserializer::<ValueError>::new(HEX)).unwrap(), expected);
    assert_eq!(
        BlobId::deserialize(StringDeserializer::<ValueError>::new(HEX.to_owned())).unwrap(),
        expected
    );
}

#[test]
fn blob_id_deserialization_preserves_type_expectations_and_parse_errors() {
    for (input, error) in [
        (Value::Null, "invalid type: null, expected a 40-character hex string"),
        (json!(true), "invalid type: boolean `true`, expected a 40-character hex string"),
        (json!(42), "invalid type: integer `42`, expected a 40-character hex string"),
        (json!(1.5), "invalid type: floating point `1.5`, expected a 40-character hex string"),
        (json!([]), "invalid type: sequence, expected a 40-character hex string"),
        (json!({}), "invalid type: map, expected a 40-character hex string"),
    ] {
        assert_eq!(serde_json::from_value::<BlobId>(input).unwrap_err().to_string(), error);
    }
    for input in ["", "a", "gg", "00", &"F".repeat(41)] {
        let expected = BlobId::from_hex(input).unwrap_err().to_string();
        assert_eq!(
            serde_json::from_value::<BlobId>(json!(input)).unwrap_err().to_string(),
            expected
        );
    }
}

#[test]
fn blob_id_serialization_propagates_io_failures() {
    struct Reject;
    impl std::io::Write for Reject {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("intentional BlobId test failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let error = serde_json::to_writer(Reject, &example_id()).unwrap_err();
    assert!(error.is_io());
    assert!(error.to_string().contains("intentional BlobId test failure"));
}

#[test]
fn blob_id_schema_name_and_shape_stay_compatible() {
    assert_eq!(BlobId::schema_name(), "BlobId");
    for settings in [
        SchemaSettings::default(),
        SchemaSettings::default().for_serialize(),
        SchemaSettings::draft07(),
        SchemaSettings::draft07().for_serialize(),
    ] {
        let mut generator = settings.into_generator();
        assert_eq!(
            serde_json::to_value(BlobId::json_schema(&mut generator)).unwrap(),
            json!({
                "type": "string",
                "pattern": "[0-9a-f]{40}",
                "description": "A hex-encoded blob ID as computed by Git",
            })
        );
    }
}

#[test]
fn blob_metadata_schema_preserves_blob_id_references_and_definitions() {
    for (settings, definitions, reference, draft07) in [
        (SchemaSettings::default(), "$defs", "#/$defs/BlobId", false),
        (SchemaSettings::default().for_serialize(), "$defs", "#/$defs/BlobId", false),
        (SchemaSettings::draft07(), "definitions", "#/definitions/BlobId", true),
        (SchemaSettings::draft07().for_serialize(), "definitions", "#/definitions/BlobId", true),
    ] {
        let mut generator = settings.into_generator();
        let schema = serde_json::to_value(generator.root_schema_for::<BlobMetadata>()).unwrap();
        assert_eq!(schema["title"], "BlobMetadata");
        assert_eq!(schema["type"], "object");
        assert_eq!(
            schema[definitions]["BlobId"],
            json!({
                "type": "string",
                "pattern": "[0-9a-f]{40}",
                "description": "A hex-encoded blob ID as computed by Git",
            })
        );
        let id_schema = if draft07 {
            json!({
                "description": "The blob's content-based ID.",
                "allOf": [{ "$ref": reference }],
            })
        } else {
            json!({
                "description": "The blob's content-based ID.",
                "$ref": reference,
            })
        };
        assert_eq!(schema["properties"]["id"], id_schema);
        assert_eq!(
            schema.pointer(reference.strip_prefix('#').unwrap()),
            Some(&schema[definitions]["BlobId"])
        );
        assert_eq!(schema[definitions].as_object().unwrap().len(), 1);
        assert!(schema["required"].as_array().unwrap().contains(&json!("id")));
        assert!(schema[if draft07 { "$defs" } else { "definitions" }].is_null());
    }
}

#[test]
fn blob_metadata_serialization_preserves_persisted_blob_fields() {
    let metadata = BlobMetadata {
        id: example_id(),
        num_bytes: 42,
        mime_essence: Some("text/plain".to_owned()),
        language: None,
    };
    assert_eq!(
        serde_json::to_value(metadata).unwrap(),
        json!({"id": HEX, "num_bytes": 42, "mime_essence": "text/plain", "language": null})
    );
}

// JSON alone does not distinguish Serde's string, collect_str, or newtype methods.
struct StringProtocol(bool);

macro_rules! reject_values {
    ($($method:ident($value_type:ty)),* $(,)?) => { $(
        fn $method(self, _value: $value_type) -> Result<Self::Ok, Self::Error> {
            Err(serde::ser::Error::custom(concat!("unexpected ", stringify!($method))))
        }
    )* };
}

macro_rules! reject_compounds {
    ($($method:ident($($argument:ident: $argument_type:ty),*) -> $result:ident),* $(,)?) => { $(
        fn $method(self, $($argument: $argument_type),*) -> Result<Self::$result, Self::Error> {
            Err(serde::ser::Error::custom(concat!("unexpected ", stringify!($method))))
        }
    )* };
}

impl serde::Serializer for StringProtocol {
    type Ok = String;
    type Error = ValueError;
    type SerializeSeq = serde::ser::Impossible<Self::Ok, Self::Error>;
    type SerializeTuple = serde::ser::Impossible<Self::Ok, Self::Error>;
    type SerializeTupleStruct = serde::ser::Impossible<Self::Ok, Self::Error>;
    type SerializeTupleVariant = serde::ser::Impossible<Self::Ok, Self::Error>;
    type SerializeMap = serde::ser::Impossible<Self::Ok, Self::Error>;
    type SerializeStruct = serde::ser::Impossible<Self::Ok, Self::Error>;
    type SerializeStructVariant = serde::ser::Impossible<Self::Ok, Self::Error>;

    fn serialize_str(self, value: &str) -> Result<Self::Ok, Self::Error> {
        Ok(value.to_owned())
    }
    fn collect_str<T: ?Sized + std::fmt::Display>(self, _: &T) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("unexpected collect_str"))
    }
    fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("unexpected serialize_some"))
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("unexpected serialize_newtype_struct"))
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Err(serde::ser::Error::custom("unexpected serialize_newtype_variant"))
    }
    reject_values! {
        serialize_bool(bool), serialize_i8(i8), serialize_i16(i16), serialize_i32(i32),
        serialize_i64(i64), serialize_u8(u8), serialize_u16(u16), serialize_u32(u32),
        serialize_u64(u64), serialize_f32(f32), serialize_f64(f64), serialize_char(char),
        serialize_bytes(&[u8]), serialize_unit_struct(&'static str),
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
        self.0
    }
}

#[test]
fn blob_id_serde_string_protocol_is_stable_for_binary_serializers() {
    for human_readable in [true, false] {
        assert_eq!(example_id().serialize(StringProtocol(human_readable)).unwrap(), HEX);
    }
}

struct StrictStringInput(bool);

impl<'de> serde::Deserializer<'de> for StrictStringInput {
    type Error = ValueError;
    fn deserialize_any<V: serde::de::Visitor<'de>>(self, _: V) -> Result<V::Value, Self::Error> {
        Err(serde::de::Error::custom("expected deserialize_str dispatch"))
    }
    fn deserialize_str<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_borrowed_str(HEX)
    }
    fn is_human_readable(&self) -> bool {
        self.0
    }
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct map struct
        enum identifier ignored_any
    }
}

#[test]
fn blob_id_deserialization_requests_string_protocol() {
    for human_readable in [true, false] {
        assert_eq!(BlobId::deserialize(StrictStringInput(human_readable)).unwrap(), example_id());
    }
}

#[test]
fn blob_id_hex_and_serde_cover_every_byte_value_at_every_position() {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for seed in 0_u8..=u8::MAX {
        let bytes: [u8; 20] =
            std::array::from_fn(|index| seed.wrapping_add((index as u8).wrapping_mul(13)));
        let mut expected = String::with_capacity(40);
        for byte in bytes {
            expected.push(char::from(DIGITS[usize::from(byte >> 4)]));
            expected.push(char::from(DIGITS[usize::from(byte & 15)]));
        }
        let parsed = BlobId::from_hex(&expected.to_ascii_uppercase()).unwrap();
        assert_eq!(parsed.as_bytes(), bytes);
        assert_eq!(parsed.hex(), expected);
        assert_eq!(parsed.to_string(), expected);
        assert_eq!(String::from(parsed), expected);
        assert_eq!(serde_json::to_value(parsed).unwrap(), json!(expected));
    }
}

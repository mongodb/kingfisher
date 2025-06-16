use bstr::BString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[derive(Deserialize, Serialize)]
#[serde(remote = "BString")]
pub struct BStringLossyUtf8(
    #[serde(
        getter = "bstring_as_vec",
        serialize_with = "serialize_bytes_string_lossy",
        deserialize_with = "deserialize_bytes_string"
    )]
    pub Vec<u8>,
);
#[inline]
fn bstring_as_vec(b: &BString) -> &Vec<u8> {
    b
}
impl From<BStringLossyUtf8> for BString {
    fn from(b: BStringLossyUtf8) -> BString {
        BString::new(b.0)
    }
}
fn serialize_bytes_string_lossy<S: serde::Serializer>(
    bytes: &[u8],
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(&String::from_utf8_lossy(bytes))
}
fn deserialize_bytes_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    struct Vis;
    impl serde::de::Visitor<'_> for Vis {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string")
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(v.into())
        }
    }
    d.deserialize_str(Vis)
}
impl JsonSchema for BStringLossyUtf8 {
    fn is_referenceable() -> bool {
        false
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        <String as JsonSchema>::schema_id()
    }

    fn schema_name() -> String {
        <String as JsonSchema>::schema_name()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        String::json_schema(gen)
    }
}

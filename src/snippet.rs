use std::{
    fmt,
    fmt::{Display, Formatter},
};

use base64::{engine::general_purpose, Engine as _};
use bstr::{BString, ByteSlice};
use schemars::{gen::SchemaGenerator, schema::Schema, JsonSchema};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Base64BString(#[serde(with = "Base64BString")] pub BString);
impl fmt::Display for Base64BString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl JsonSchema for Base64BString {
    fn schema_name() -> String {
        "Base64String".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        String::json_schema(gen)
    }
}
impl Base64BString {
    pub fn serialize<S>(bstring: &BString, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let base64 = general_purpose::STANDARD.encode(bstring.as_bytes());
        serializer.serialize_str(&base64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BString, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let base64 = String::deserialize(deserializer)?;
        let bytes = general_purpose::STANDARD.decode(base64).map_err(serde::de::Error::custom)?;
        Ok(BString::from(bytes))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Snippet {
    /// A snippet of the input immediately prior to `content`
    pub before: Base64BString,

    /// The matching input
    pub matching: Base64BString,

    /// A snippet of the input immediately after `content`
    pub after: Base64BString,
}
impl Display for Snippet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}",
            escape_bstring(&self.before.0),
            escape_bstring(&self.matching.0),
            escape_bstring(&self.after.0)
        )
    }
}
fn escape_bstring(s: &BString) -> String {
    s.chars()
        .flat_map(|ch| {
            if ch.is_ascii_graphic() || ch.is_ascii_whitespace() {
                vec![ch]
            } else {
                format!("\\u{{{:04X}}}", ch as u32).chars().collect()
            }
        })
        .collect()
}

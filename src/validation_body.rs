use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serializer};
use std::borrow::Cow;

/// Storage for validation response payloads. `None` avoids heap allocation when validation is
/// disabled or produces no body.
pub type ValidationResponseBody = Option<Box<str>>;

#[inline]
pub fn from_string(body: impl Into<String>) -> ValidationResponseBody {
    let body = body.into();
    if body.is_empty() { None } else { Some(body.into_boxed_str()) }
}

#[inline]
pub fn as_str(body: &ValidationResponseBody) -> &str {
    body.as_deref().unwrap_or("")
}

#[inline]
pub fn clone_as_string(body: &ValidationResponseBody) -> String {
    as_str(body).to_string()
}

pub fn serialize<S>(body: &ValidationResponseBody, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(as_str(body))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<ValidationResponseBody, D::Error>
where
    D: Deserializer<'de>,
{
    let body: Cow<'de, str> = Deserialize::deserialize(deserializer)?;
    Ok(from_string(body))
}

pub fn schema(generator: &mut SchemaGenerator) -> Schema {
    String::json_schema(generator)
}

//! Storage and serialization for validation response bodies.

#![allow(dead_code)] // Public API for serde attributes in downstream crates

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serializer};
use std::borrow::Cow;

/// Storage for validation response payloads.
/// `None` avoids heap allocation when validation is disabled or produces no body.
pub type ValidationResponseBody = Option<Box<str>>;

/// Create a ValidationResponseBody from a string.
#[inline]
pub fn from_string(body: impl Into<String>) -> ValidationResponseBody {
    let body = body.into();
    if body.is_empty() { None } else { Some(body.into_boxed_str()) }
}

/// Get the response body as a string slice.
#[inline]
pub fn as_str(body: &ValidationResponseBody) -> &str {
    body.as_deref().unwrap_or("")
}

/// Clone the response body to a String.
#[inline]
pub fn clone_as_string(body: &ValidationResponseBody) -> String {
    as_str(body).to_string()
}

/// Serialize a ValidationResponseBody as a string.
pub fn serialize<S>(body: &ValidationResponseBody, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(as_str(body))
}

/// Deserialize a ValidationResponseBody from a string.
pub fn deserialize<'de, D>(deserializer: D) -> Result<ValidationResponseBody, D::Error>
where
    D: Deserializer<'de>,
{
    let body: Cow<'de, str> = Deserialize::deserialize(deserializer)?;
    Ok(from_string(body))
}

/// Generate a JSON schema for ValidationResponseBody.
pub fn schema(generator: &mut SchemaGenerator) -> Schema {
    String::json_schema(generator)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_returns_none() {
        let body = from_string("");
        assert!(body.is_none());
    }

    #[test]
    fn non_empty_string_returns_some() {
        let body = from_string("test");
        assert!(body.is_some());
        assert_eq!(as_str(&body), "test");
    }

    #[test]
    fn clone_as_string_works() {
        let body = from_string("hello");
        assert_eq!(clone_as_string(&body), "hello");
    }
}

use bstr::BString;
use regex::bytes::Regex;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use serde_json::json;
use smallvec::SmallVec;
use std::borrow::Cow;

use crate::{snippet::Base64BString, util::intern};

// -------------------------------------------------------------------------------------------------
// Group
// -------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct Group(pub Base64BString);
impl Group {
    pub fn new(m: regex::bytes::Match<'_>) -> Self {
        Self(Base64BString(BString::from(m.as_bytes())))
    }
}
// -------------------------------------------------------------------------------------------------
// Groups
// -------------------------------------------------------------------------------------------------
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Groups(pub SmallVec<[Group; 1]>);
impl JsonSchema for Groups {
    fn schema_name() -> Cow<'static, str> {
        "Groups".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let mut schema = Schema::default();
        schema.insert("type".to_owned(), json!("array"));
        schema.insert("items".to_owned(), generator.subschema_for::<Group>().to_value());
        schema
    }
}

#[derive(Debug, Clone, JsonSchema)]
pub struct SerializableCapture {
    pub name: Option<&'static str>,
    pub match_number: i32,
    pub start: usize,
    pub end: usize,
    /// Interned original (unredacted) value.
    #[serde(skip_serializing, skip_deserializing)]
    pub value: &'static str,
}

impl SerializableCapture {
    /// Returns the original captured value.
    pub fn raw_value(&self) -> &'static str {
        self.value
    }

    /// Returns the value that should be shown in user-facing output.
    pub fn display_value(&self) -> std::borrow::Cow<'static, str> {
        crate::util::display_value(self.value)
    }
}

impl serde::Serialize for SerializableCapture {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("SerializableCapture", 5)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("match_number", &self.match_number)?;
        state.serialize_field("start", &self.start)?;
        state.serialize_field("end", &self.end)?;
        let value = self.display_value();
        state.serialize_field("value", &value)?;
        state.end()
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SerializableCaptures {
    #[schemars(with = "Vec<SerializableCapture>")]
    pub captures: SmallVec<[SerializableCapture; 2]>,
}

impl SerializableCaptures {
    pub fn from_captures(captures: &regex::bytes::Captures, _input: &[u8], re: &Regex) -> Self {
        let mut serialized_captures: SmallVec<[SerializableCapture; 2]> = SmallVec::new();

        let capture_names: SmallVec<[Option<&'static str>; 4]> =
            re.capture_names().map(|name| name.map(intern)).collect();

        // If there are explicit capture groups (e.g., group 1, 2, ...),
        // only serialize those.
        if captures.len() > 1 {
            for i in 1..captures.len() {
                // Start from 1
                if let Some(cap) = captures.get(i) {
                    let raw_value = String::from_utf8_lossy(cap.as_bytes());
                    let raw_interned = intern(raw_value.as_ref());
                    let name = capture_names.get(i).and_then(|opt| *opt);

                    serialized_captures.push(SerializableCapture {
                        name,
                        match_number: i32::try_from(i).unwrap_or(0),
                        start: cap.start(),
                        end: cap.end(),
                        value: raw_interned,
                    });
                }
            }
        } else if captures.len() == 1 {
            // ELSE, if there is ONLY the full match (len == 1),
            // serialize just that full match (group 0) as the fallback.
            if let Some(cap) = captures.get(0) {
                let raw_value = String::from_utf8_lossy(cap.as_bytes());
                let raw_interned = intern(raw_value.as_ref());
                let name = capture_names.first().and_then(|opt| *opt);

                serialized_captures.push(SerializableCapture {
                    name,
                    match_number: 0,
                    start: cap.start(),
                    end: cap.end(),
                    value: raw_interned,
                });
            }
        }
        // If len == 0 (no match), loop is skipped, empty vec is returned.

        SerializableCaptures { captures: serialized_captures }
    }
}

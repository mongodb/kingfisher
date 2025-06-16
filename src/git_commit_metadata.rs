use bstr::BString;
use gix::{date::Time, ObjectId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::serde_utils::BStringLossyUtf8;

#[derive(Serialize, Deserialize)]
#[serde(remote = "Time")]
struct TextTime(
    #[serde(
        getter = "text_time::getter",
        serialize_with = "text_time::serialize",
        deserialize_with = "text_time::deserialize"
    )]
    Time,
);
impl From<TextTime> for Time {
    fn from(v: TextTime) -> Self {
        v.0
    }
}
impl From<Time> for TextTime {
    fn from(v: Time) -> Self {
        Self(v)
    }
}
mod text_time {
    use super::*;
    pub fn getter(v: &Time) -> &Time {
        v
    }

    pub fn serialize<S: serde::Serializer>(v: &Time, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(v)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Time, D::Error> {
        struct Vis;
        impl<'a> serde::de::Visitor<'a> for Vis {
            type Value = Time;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string representing a Git timestamp")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                gix::date::parse(v, None).map_err(E::custom)
            }
        }
        d.deserialize_str(Vis)
    }
}
impl JsonSchema for TextTime {
    fn schema_name() -> String {
        "Time".into()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        String::json_schema(gen)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ObjectId")]
struct HexObjectId(
    #[serde(
        getter = "hex_object_id::getter",
        serialize_with = "hex_object_id::serialize",
        deserialize_with = "hex_object_id::deserialize"
    )]
    ObjectId,
);
impl From<ObjectId> for HexObjectId {
    fn from(v: ObjectId) -> Self {
        HexObjectId(v)
    }
}
impl From<HexObjectId> for ObjectId {
    fn from(v: HexObjectId) -> Self {
        v.0
    }
}
mod hex_object_id {
    use super::*;

    pub fn getter(v: &ObjectId) -> &ObjectId {
        v
    }

    // Use `collect_str` to avoid intermediate string allocations:
    pub fn serialize<S: serde::Serializer>(v: &ObjectId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&v.to_hex())
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<ObjectId, D::Error> {
        struct Vis;
        impl<'a> serde::de::Visitor<'a> for Vis {
            type Value = ObjectId;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a 40-character hex string representing a Git object ID")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                ObjectId::from_hex(v.as_bytes()).map_err(E::custom)
            }
        }
        d.deserialize_str(Vis)
    }
}
impl JsonSchema for HexObjectId {
    fn schema_name() -> String {
        "ObjectId".into()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        let s = String::json_schema(gen);
        let mut o = s.into_object();
        o.string().pattern = Some("[0-9a-f]{40}".into());
        let md = o.metadata();
        md.description = Some("A hex-encoded object ID as computed by Git".into());
        schemars::schema::Schema::Object(o)
    }
}

/// Metadata about a Git commit.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CommitMetadata {
    #[serde(with = "HexObjectId")]
    pub commit_id: ObjectId,

    #[serde(with = "BStringLossyUtf8")]
    pub committer_name: BString,

    #[serde(with = "BStringLossyUtf8")]
    pub committer_email: BString,

    #[serde(with = "TextTime")]
    pub committer_timestamp: Time,
    // #[serde(with = "BStringLossyUtf8")]
    // pub author_name: BString,

    // #[serde(with = "BStringLossyUtf8")]
    // pub author_email: BString,

    // #[serde(with = "TextTime")]
    // pub author_timestamp: Time,
    // #[serde(with = "BStringLossyUtf8")]
    // pub message: BString,
}

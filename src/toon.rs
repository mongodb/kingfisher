use anyhow::Result;
use serde::Serialize;
use toon_format::{Delimiter, EncodeOptions, Indent};

fn llm_encode_options() -> EncodeOptions {
    // Keep the 2.x report wire format, including safe dotted-key folding.
    EncodeOptions::new()
        .with_delimiter(Delimiter::Pipe)
        .with_indent(Indent::Spaces(2))
        .with_key_folding(toon_format::types::KeyFoldingMode::Safe)
        .with_flatten_depth(2)
}

pub fn encode_llm_friendly<T: Serialize>(value: &T) -> Result<String> {
    Ok(toon_format::encode(value, &llm_encode_options())?)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn assert_encoding<T: Serialize>(value: &T, expected: &str) {
        let encoded = encode_llm_friendly(value).unwrap();
        assert_eq!(encoded, expected);
        let decoded: Value = toon_format::decode_default(&encoded).unwrap();
        assert_eq!(decoded, serde_json::to_value(value).unwrap());
    }

    #[test]
    fn nested_maps_preserve_legacy_safe_folding_and_depth() {
        let value = json!({"report": {"metadata": {"source": {"name": "fixture"}}}});
        let encoded = encode_llm_friendly(&value).unwrap();
        assert_eq!(encoded, "report.metadata:\n  source:\n    name: fixture");
        let options = toon_format::DecodeOptions::new()
            .with_expand_paths(toon_format::types::PathExpansionMode::Safe);
        assert_eq!(toon_format::decode::<Value>(&encoded, &options).unwrap(), value);
    }

    #[test]
    fn literal_dotted_keys_do_not_expand_or_collide_with_nested_keys() {
        assert_encoding(&json!({"source.name": "fixture"}), "source.name: fixture");
        assert_encoding(
            &json!({
                "source": {"name": {"value": "nested"}},
                "source.name.value": "literal"
            }),
            "source:\n  name:\n    value: nested\nsource.name.value: literal",
        );
    }

    #[test]
    fn empty_arrays_preserve_legacy_length_headers() {
        assert_encoding(&json!({"values": []}), "values[0|]:");
        assert_encoding(&json!([]), "[0|]:");
    }

    #[test]
    fn primitive_and_tabular_arrays_keep_pipe_delimiters_and_two_space_indent() {
        assert_encoding(
            &json!({"report": {
                "values": [1, 2, 3],
                "rows": [{"name": "one", "active": true}, {"name": "two", "active": false}]
            }}),
            "report:\n  values[3|]: 1|2|3\n  rows[2|]{name|active}:\n    one|true\n    two|false",
        );
    }

    #[test]
    fn uniform_nested_rows_preserve_legacy_list_layout() {
        assert_encoding(
            &json!([
                {"name": "one", "metadata": {"kind": "demo"}},
                {"name": "two", "metadata": {"kind": "test"}}
            ]),
            "[2|]:\n  - name: one\n    metadata:\n      kind: demo\n  - name: two\n    metadata:\n      kind: test",
        );
    }

    #[test]
    fn uniform_object_maps_preserve_legacy_folded_keys() {
        let value = json!({"alice": {"role": "reader"}, "bob": {"role": "writer"}});
        let encoded = encode_llm_friendly(&value).unwrap();
        assert_eq!(encoded, "alice.role: reader\nbob.role: writer");
        let options = toon_format::DecodeOptions::new()
            .with_expand_paths(toon_format::types::PathExpansionMode::Safe);
        assert_eq!(toon_format::decode::<Value>(&encoded, &options).unwrap(), value);
    }

    #[test]
    fn pipe_delimiters_and_special_strings_round_trip_without_changing_values() {
        assert_encoding(
            &json!({"values": ["a|b", "a,b", "true", "line\nnext", " a ", ""]}),
            "values[6|]: \"a|b\"|a,b|\"true\"|\"line\\nnext\"|\" a \"|\"\"",
        );
    }

    #[test]
    fn serde_objects_keep_field_names_values_and_order() {
        #[derive(Serialize)]
        struct Profile {
            name: &'static str,
            active: bool,
        }
        #[derive(Serialize)]
        struct Record {
            id: u32,
            profile: Profile,
            tags: Vec<&'static str>,
        }

        assert_encoding(
            &Record {
                id: 7,
                profile: Profile { name: "fixture", active: true },
                tags: vec!["api", "test"],
            },
            "id: 7\nprofile:\n  name: fixture\n  active: true\ntags[2|]: api|test",
        );
    }
}

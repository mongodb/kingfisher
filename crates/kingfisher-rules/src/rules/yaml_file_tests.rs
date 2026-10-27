use super::load_yaml_file;

struct YamlTestFile(std::path::PathBuf);

impl YamlTestFile {
    fn new(content: &[u8]) -> Self {
        use std::io::Write;
        let path = std::env::temp_dir()
            .join(format!("kingfisher-yaml-loader-{}.yml", uuid::Uuid::new_v4()));
        let mut file =
            std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        file.write_all(content).unwrap();
        drop(file);
        Self(path)
    }
}

impl Drop for YamlTestFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).ok();
    }
}

#[test]
fn yaml_file_loader_supports_owned_generic_values() {
    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct Settings {
        name: String,
        bytes: Vec<u16>,
        empty: Option<String>,
    }
    let file = YamlTestFile::new("name: clé\nbytes: [0, 255, 65535]\nempty: null\n".as_bytes());
    assert_eq!(
        load_yaml_file::<Settings, _>(&file.0).unwrap(),
        Settings { name: "clé".into(), bytes: vec![0, 255, 65535], empty: None }
    );
    let file = YamlTestFile::new(b"");
    assert_eq!(load_yaml_file::<Option<String>, _>(&file.0).unwrap(), None);
}

#[test]
fn yaml_file_loader_preserves_open_error_context() {
    let file = YamlTestFile::new(b"{}");
    std::fs::remove_file(&file.0).unwrap();
    let error = load_yaml_file::<serde_json::Value, _>(&file.0).unwrap_err();
    assert_eq!(error.to_string(), format!("Failed to open YAML file: {}", file.0.display()));
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
}

#[test]
fn yaml_file_loader_preserves_parse_error_context_and_sources() {
    for input in [b"name: [\n".as_slice(), b"\xff", b"---\n1\n---\n2\n"] {
        let file = YamlTestFile::new(input);
        let error = load_yaml_file::<serde_json::Value, _>(&file.0).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("Failed to parse YAML from file: {}", file.0.display())
        );
        let cause = error.downcast_ref::<serde_yaml::Error>().unwrap();
        assert!(!cause.to_string().is_empty());
        if input.starts_with(b"---") {
            assert_eq!(
                cause.to_string(),
                "deserializing from YAML containing more than one document is not supported"
            );
        }
    }
    let file = YamlTestFile::new(b"- 999999999999999999999999999999999999999999");
    let error = load_yaml_file::<Vec<u8>, _>(&file.0).unwrap_err();
    assert_eq!(error.to_string(), format!("Failed to parse YAML from file: {}", file.0.display()));
    assert!(error.downcast_ref::<serde_yaml::Error>().is_some());
}

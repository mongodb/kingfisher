use clap::Parser;

use kingfisher::cli::{
    commands::access_map::{AccessMapOutputFormat, AccessMapProvider},
    global::{Command, CommandLineArgs},
};

#[test]
fn access_map_accepts_format_and_output_flags() -> anyhow::Result<()> {
    let args = CommandLineArgs::try_parse_from([
        "kingfisher",
        "access-map",
        "gitlab",
        "./gitlab.token",
        "--format",
        "json",
        "--output",
        "gitlab.access-map.json",
        "--no-update-check",
    ])?;

    let command = match args.command {
        Command::AccessMap(args) => args,
        other => panic!("unexpected command parsed: {:?}", other),
    };

    assert_eq!(command.output_args.format, AccessMapOutputFormat::Json);
    assert_eq!(
        command.output_args.output.as_deref(),
        Some(std::path::Path::new("gitlab.access-map.json"))
    );

    Ok(())
}

#[test]
fn access_map_rejects_legacy_output_flags() {
    for legacy_flag in ["--json-out", "--html-out"] {
        let err = CommandLineArgs::try_parse_from([
            "kingfisher",
            "access-map",
            "gitlab",
            "./gitlab.token",
            legacy_flag,
            "out.json",
            "--no-update-check",
        ])
        .expect_err("legacy access-map output flags should be rejected");

        let rendered = err.to_string();
        assert!(
            rendered.contains(legacy_flag),
            "expected error to mention {legacy_flag}: {rendered}"
        );
    }
}

#[test]
fn access_map_provider_aliases_still_parse() -> anyhow::Result<()> {
    for (raw, expected) in [
        ("mongo", AccessMapProvider::Mongodb),
        ("hf", AccessMapProvider::Huggingface),
        ("wandb", AccessMapProvider::Weightsandbiases),
        ("monday.com", AccessMapProvider::Monday),
        ("pinecone.io", AccessMapProvider::Pinecone),
    ] {
        let args = CommandLineArgs::try_parse_from([
            "kingfisher",
            "access-map",
            raw,
            "--no-update-check",
        ])?;

        let command = match args.command {
            Command::AccessMap(args) => args,
            other => panic!("unexpected command parsed: {:?}", other),
        };

        assert_eq!(command.provider, expected, "alias `{raw}` should map to the expected provider");
    }

    Ok(())
}

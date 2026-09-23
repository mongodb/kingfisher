use clap::{CommandFactory, Parser};

use kingfisher::cli::{
    commands::access_map::AccessMapProvider,
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
        Command::BlastRadius(args) => args,
        other => panic!("unexpected command parsed: {:?}", other),
    };

    assert_eq!(command.input.as_deref(), Some("gitlab"));
    assert_eq!(command.credential_path.as_deref(), Some(std::path::Path::new("./gitlab.token")));
    assert_eq!(command.format, "json");
    assert_eq!(command.output.as_deref(), Some(std::path::Path::new("gitlab.access-map.json")));

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
        ("GCP", AccessMapProvider::Gcp),
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
            Command::BlastRadius(args) => args,
            other => panic!("unexpected command parsed: {:?}", other),
        };

        assert_eq!(
            command.input.as_deref().unwrap().parse::<AccessMapProvider>().unwrap(),
            expected,
            "alias `{raw}` should map to the expected provider"
        );
    }

    Ok(())
}

#[test]
fn access_map_is_an_alias_in_help() -> anyhow::Result<()> {
    let mut command = CommandLineArgs::command();
    assert!(!command.get_subcommands().any(|subcommand| subcommand.get_name() == "access-map"));
    let mut help = Vec::new();
    command.write_long_help(&mut help)?;
    let help = String::from_utf8(help)?;
    assert!(help.contains("blast-radius"));
    assert!(help.split_whitespace().collect::<Vec<_>>().join(" ").contains("[alias: access-map]"));
    Ok(())
}

#[test]
fn all_blast_radius_aliases_accept_direct_mapping() -> anyhow::Result<()> {
    for name in ["blast-radius", "access-map", "blast_radius", "access_map"] {
        let args = CommandLineArgs::try_parse_from([
            "kingfisher",
            name,
            "--rule",
            "betterleaks.github-pat",
            "-",
            "--view-report",
        ])?;
        let Command::BlastRadius(args) = args.command else {
            panic!("{name} should dispatch to blast-radius");
        };
        assert_eq!(args.rule.as_deref(), Some("betterleaks.github-pat"));
        assert_eq!(args.input.as_deref(), Some("-"));
        assert!(args.view_report);
    }
    Ok(())
}

#[test]
fn blast_radius_flag_accepts_access_map_alias() -> anyhow::Result<()> {
    for flag in ["--blast-radius", "--access-map"] {
        let args = CommandLineArgs::try_parse_from(["kingfisher", "scan", ".", flag])?;
        let scan = match args.command {
            Command::Scan(args) => args,
            other => panic!("unexpected command parsed: {:?}", other),
        };

        assert!(scan.scan_args.access_map, "flag `{flag}` should enable blast-radius mapping");
    }

    let mut command = CommandLineArgs::command();
    let scan = command.find_subcommand_mut("scan").expect("scan subcommand should exist");
    let mut help = Vec::new();
    scan.write_long_help(&mut help)?;
    let help = String::from_utf8(help)?;
    assert!(help.contains("--blast-radius"));

    Ok(())
}

use clap::{CommandFactory, Parser};

use kingfisher::cli::{
    commands::access_map::AccessMapProvider,
    global::{Command, CommandLineArgs},
};

#[test]
fn standalone_mapping_rejects_scope_options_for_other_providers() {
    // Exercise main's standalone dispatch, not run_direct_access_map (--rule).
    for (provider, flag, scope) in
        [("aws", "--gcp-project", "example-project"), ("gcp", "--aws-region", "us-east-1")]
    {
        for viewer in [false, true] {
            let mut command = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
            command.args(["blast-radius", provider, flag, scope, "--no-update-check"]);
            if viewer {
                command.arg("--view-report");
            }
            command
                .assert()
                .failure()
                .stderr(predicates::str::contains(format!("{flag} requires")));
        }
    }
}

#[test]
fn standalone_scope_expansion_is_explicit_and_defaults_are_unchanged() {
    let args = CommandLineArgs::try_parse_from(["kingfisher", "blast-radius", "aws"]).unwrap();
    let Command::BlastRadius(args) = args.command else { panic!("expected blast-radius") };
    assert!(!args.analysis.is_requested());
    assert_eq!(args.format, "json");

    let args = CommandLineArgs::try_parse_from([
        "kingfisher",
        "blast-radius",
        "aws",
        "--aws-region",
        "us-east-1",
        "--aws-region",
        "us-west-2",
    ])
    .unwrap();
    let Command::BlastRadius(args) = args.command else { panic!("expected blast-radius") };
    assert!(args.analysis.is_requested());
    assert_eq!(args.analysis.aws_regions, ["us-east-1", "us-west-2"]);
    assert!(args.analysis.gcp_projects.is_empty());
    assert!(args.analysis.validate().is_ok());
}

#[test]
fn scan_scope_expansion_is_explicit_and_defaults_are_unchanged() {
    let args =
        CommandLineArgs::try_parse_from(["kingfisher", "scan", ".", "--blast-radius"]).unwrap();
    let Command::Scan(args) = args.command else { panic!("expected scan") };
    assert!(!args.scan_args.blast_radius_options.is_requested());

    let args = CommandLineArgs::try_parse_from([
        "kingfisher",
        "scan",
        ".",
        "--blast-radius",
        "--gcp-project",
        "additional-project",
    ])
    .unwrap();
    let Command::Scan(args) = args.command else { panic!("expected scan") };
    assert!(args.scan_args.access_map);
    let analysis = args.scan_args.blast_radius_options;
    assert!(analysis.is_requested());
    assert!(analysis.aws_regions.is_empty());
    assert_eq!(analysis.gcp_projects, ["additional-project"]);
    assert!(analysis.validate().is_ok());
}

#[test]
fn automatic_assessment_has_no_opt_in_flags() {
    for flag in ["--blast-radius-assessment", "--blast-radius-details"] {
        for arguments in [
            vec!["kingfisher", "blast-radius", "aws", flag],
            vec!["kingfisher", "scan", ".", "--blast-radius", flag],
        ] {
            let error = CommandLineArgs::try_parse_from(arguments)
                .expect_err("assessment is automatic and has no opt-in flag");
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
            assert!(error.to_string().contains(flag));
        }
    }
}

#[test]
fn blast_radius_help_lists_scope_options_without_assessment_flags() {
    let mut command = CommandLineArgs::command();
    for name in ["blast-radius", "scan"] {
        let subcommand = command.find_subcommand_mut(name).expect("subcommand should exist");
        for help in
            [subcommand.render_help().to_string(), subcommand.render_long_help().to_string()]
        {
            for removed in ["--blast-radius-assessment", "--blast-radius-details"] {
                assert!(!help.contains(removed), "{name} help advertises {removed}: {help}");
            }
            for scope in ["--aws-region", "--gcp-project"] {
                assert!(help.contains(scope), "{name} help is missing {scope}: {help}");
            }
        }
    }
}

#[test]
fn investigation_scope_rejects_urls_paths_and_unbounded_requests() {
    for scope in ["https://example.com", "../project", "project/other", "*", ""] {
        assert!(
            CommandLineArgs::try_parse_from([
                "kingfisher",
                "blast-radius",
                "gcp",
                "--gcp-project",
                scope,
            ])
            .is_err(),
            "{scope}"
        );
    }
    let options = kingfisher::cli::commands::access_map::BlastRadiusOptions {
        aws_regions: vec!["us-east-1".into(); 9],
        ..Default::default()
    };
    assert!(options.validate().is_err());
}

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

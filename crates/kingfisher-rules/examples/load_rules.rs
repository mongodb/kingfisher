//! Load embedded rules, or pass a custom TOML/YAML file as the first argument.
use kingfisher_rules::{Confidence, Rules, RulesDatabase, get_builtin_rules};

fn main() -> anyhow::Result<()> {
    let rules = match std::env::args_os().nth(1) {
        Some(path) => Rules::from_paths([std::path::PathBuf::from(path)], Confidence::Low)?,
        None => get_builtin_rules(None)?,
    };
    // Keep collection-level path filtering metadata when compiling.
    let database = RulesDatabase::from_rule_collection(rules)?;
    println!("Compiled {} rules", database.num_rules());
    Ok(())
}

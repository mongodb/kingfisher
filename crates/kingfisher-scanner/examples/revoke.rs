//! Explicitly revoke a selected credential. This performs a destructive live request.
//! Run: cargo run -p kingfisher-scanner --features validation --example revoke -- RULE_ID
//! Supply TOKEN_TO_REVOKE in the environment and optional NAME=VALUE arguments.
#[cfg(feature = "validation")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    use kingfisher_scanner::{Revoker, Rule, get_builtin_rules};
    use std::collections::BTreeMap;

    let mut args = std::env::args().skip(1);
    let id = args.next().ok_or_else(|| anyhow::anyhow!("Expected exact rule ID"))?;
    let variables = args
        .map(|arg| {
            let (name, value) =
                arg.split_once('=').ok_or_else(|| anyhow::anyhow!("Expected NAME=VALUE"))?;
            Ok((name.to_owned(), value.to_owned()))
        })
        .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
    let rules = get_builtin_rules(None)?;
    let syntax = rules.rules.get(&id).ok_or_else(|| anyhow::anyhow!("Rule not found: {id}"))?;
    let secret = std::env::var("TOKEN_TO_REVOKE")?;
    let result = Revoker::new()?.revoke(&Rule::new(syntax.clone()), &secret, &variables).await?;
    println!("{}: revoked={}", result.rule_id, result.revoked);
    Ok(())
}

#[cfg(not(feature = "validation"))]
fn main() {
    eprintln!("Enable validation to run this example");
}

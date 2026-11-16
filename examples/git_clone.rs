//! Time only Kingfisher's production repository acquisition, without starting a scan.
//! Build with `cargo build --locked --release --example git_clone`.
use std::{path::PathBuf, time::Instant};

use anyhow::{Context, Result, bail};
use kingfisher::{
    git_binary::{CloneMode, Git, ProviderHosts},
    git_url::GitUrl,
};

// Match the application's allocator, rather than benchmarking a different heap.
#[cfg(feature = "use-jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
#[cfg(all(
    not(feature = "use-jemalloc"),
    not(feature = "system-alloc"),
    any(feature = "use-mimalloc", target_os = "linux", target_os = "windows")
))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let mode =
        args.next().context("usage: git_clone <mirror|bare|checkout> <url> <destination>")?;
    let mode = match mode.to_str() {
        Some("mirror") => CloneMode::Mirror,
        Some("bare") => CloneMode::Bare,
        Some("checkout") => CloneMode::Checkout,
        _ => bail!("clone mode must be mirror, bare, or checkout"),
    };
    let url: GitUrl = args
        .next()
        .context("missing URL")?
        .to_str()
        .context("URL must be UTF-8")?
        .parse()
        .map_err(anyhow::Error::msg)?;
    let destination = PathBuf::from(args.next().context("missing destination")?);
    anyhow::ensure!(args.next().is_none(), "unexpected argument");
    // The benchmark uses public repositories and never consults GitHub credentials.
    let git =
        Git::with_provider_hosts_and_github_token(false, &ProviderHosts::saas_defaults(), None)
            .without_timeouts(true);
    let start = Instant::now();
    git.create_fresh_clone(&url, &destination, mode)?;
    println!(
        "{}",
        serde_json::json!({
            "elapsed_seconds": start.elapsed().as_secs_f64(),
            "kingfisher_version": env!("CARGO_PKG_VERSION"),
            "mode": format!("{mode:?}"),
        })
    );
    Ok(())
}

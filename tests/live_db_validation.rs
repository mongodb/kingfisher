//! Live validation smoke tests that exercise the database validators against
//! real MySQL and Postgres instances provisioned with the existing Bollard client.
//!
//! These are ignored by default because they require Docker. Run them with:
//! `cargo test --test live_db_validation -- --ignored`.

use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use kingfisher::validation::{validate_mysql, validate_postgres};
#[path = "support/docker_db.rs"]
mod docker_db;
use docker_db::{DatabaseContainer, MYSQL, POSTGRES};
use tokio::{net::TcpStream, time::sleep};

const HOST_ALIAS: &str = "kingfisherlocal";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(250);

async fn wait_for_port(host: &str, port: u16) -> Result<()> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;

    loop {
        match TcpStream::connect((host, port)).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(anyhow!(
                        "timed out after {:?} waiting for {host}:{port}: {err}",
                        STARTUP_TIMEOUT,
                    ));
                }
                sleep(STARTUP_POLL_INTERVAL).await;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn validates_mysql_secret_against_testcontainer() -> Result<()> {
    let container = DatabaseContainer::start(MYSQL).await?;
    let port = container.port;

    wait_for_port(HOST_ALIAS, port).await?;

    let uri = format!("mysql://root:secret@{HOST_ALIAS}:{port}/app");
    let (is_valid, metadata) = validate_mysql(&uri, false, true).await?;

    assert!(is_valid, "expected MySQL validation to succeed, got {metadata:?}");
    assert!(
        metadata.iter().any(|entry| entry.contains("user=root")),
        "expected user metadata in {metadata:?}"
    );
    assert!(
        metadata.iter().any(|entry| entry.contains("database=app")),
        "expected database metadata in {metadata:?}"
    );

    container.remove().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn validates_postgres_secret_against_testcontainer() -> Result<()> {
    let container = DatabaseContainer::start(POSTGRES).await?;
    let port = container.port;

    wait_for_port(HOST_ALIAS, port).await?;

    let uri = format!("postgres://postgres:secret@{HOST_ALIAS}:{port}/postgres");
    let (is_valid, metadata) = validate_postgres(&uri, false, true).await?;

    assert!(is_valid, "expected Postgres validation to succeed");
    assert!(metadata.is_empty(), "expected no metadata but found {metadata:?}");

    container.remove().await?;
    Ok(())
}

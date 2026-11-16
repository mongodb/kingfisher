//! Portable Docker credential-helper fixture, compiled by docker_db_fixture.

use std::io::{self, Read};

fn main() -> io::Result<()> {
    assert_eq!(std::env::args().nth(1).as_deref(), Some("get"));
    let mut server = String::new();
    io::stdin().read_to_string(&mut server)?;
    assert_eq!(server.trim(), "https://index.docker.io/v1/");
    std::fs::write(std::env::var_os("KINGFISHER_DOCKER_HELPER_MARKER").unwrap(), b"called")?;
    println!(
        r#"{{"ServerURL":"https://index.docker.io/v1/","Username":"fixture-user","Secret":"fixture-password"}}"#
    );
    Ok(())
}

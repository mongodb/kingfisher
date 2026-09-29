//! Loopback-only synthetic provider used by the validation example.
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

pub async fn mock_provider() -> anyhow::Result<(String, tokio::task::JoinHandle<anyhow::Result<()>>)>
{
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let task = start(listener)?;
    Ok((endpoint, task))
}

fn start(listener: TcpListener) -> anyhow::Result<tokio::task::JoinHandle<anyhow::Result<()>>> {
    Ok(tokio::spawn(async move {
        for (status, body) in [
            ("200 OK", r#"{"authenticated":true}"#),
            ("401 Unauthorized", r#"{"error":"invalid token"}"#),
            ("429 Too Many Requests", r#"{"error":"rate limit"}"#),
            ("200 OK", r#"{"message":"welcome"}"#),
        ] {
            let (mut stream, _) = listener.accept().await?;
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                anyhow::ensure!(request.len() < 8192, "mock request too large");
                request.push(stream.read_u8().await?);
            }
            let request = String::from_utf8(request)?.to_ascii_lowercase();
            anyhow::ensure!(
                request.contains("authorization: bearer demo_abcd1234efgh5678\r\n"),
                "missing expected synthetic authorization header"
            );
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await?;
        }
        Ok::<_, anyhow::Error>(())
    }))
}

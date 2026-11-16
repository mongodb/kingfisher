//! Minimal smart-HTTP v0 server: fixtures/pack generation are entirely native.
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

use anyhow::Result;

#[derive(Clone)]
pub struct Snapshot {
    advertisement: Vec<u8>,
    pack: Vec<u8>,
}

fn packet(output: &mut Vec<u8>, data: &[u8]) {
    output.extend_from_slice(format!("{:04x}", data.len() + 4).as_bytes());
    output.extend_from_slice(data);
}

impl Snapshot {
    pub fn from_repo(repo: &gix::Repository) -> Result<Self> {
        use gix_pack::{
            self as pack,
            data::output::{Count, Entry, bytes::FromEntriesIter},
        };
        let ids = repo.objects.iter()?.collect::<Result<Vec<_>, _>>()?;
        let entries = ids
            .iter()
            .map(|id| {
                let object = repo.find_object(*id)?;
                Entry::from_data(
                    &Count::from_data(*id, None),
                    &gix::objs::Data {
                        kind: object.kind,
                        data: &object.data,
                        object_hash: repo.object_hash(),
                    },
                    gix::zlib::Compression::DEFAULT,
                )
            })
            .collect::<gix::Result<Vec<_>>>()?;
        let mut output = FromEntriesIter::new(
            std::iter::once(Ok(entries)),
            Vec::new(),
            ids.len().try_into()?,
            pack::data::Version::V2,
            repo.object_hash(),
        );
        for chunk in output.by_ref() {
            chunk?;
        }
        let pack = output.into_write();
        let mut advertisement = Vec::new();
        packet(&mut advertisement, b"# service=git-upload-pack\n");
        advertisement.extend_from_slice(b"0000");
        let head = repo.head()?;
        let name = match head.id() {
            Some(id) => format!("{id} HEAD"),
            None => format!("{} capabilities^{{}}", repo.object_hash().null()),
        };
        // Protocol v0 advertises no HEAD symref for an unborn repository.
        let symref = head
            .id()
            .and_then(|_| head.referent_name())
            .map(|branch| format!(" symref=HEAD:{branch}"))
            .unwrap_or_default();
        packet(&mut advertisement, format!("{name}\0multi_ack_detailed side-band-64k no-progress ofs-delta include-tag{symref}\n").as_bytes());
        for reference in repo.references()?.all()? {
            let mut reference = reference?;
            let name = reference.name().as_bstr().to_owned();
            // Peeling mutates the in-memory reference target. Preserve the tag
            // object before peeling, as a real upload-pack advertisement does.
            let direct = reference.target().try_id().map(ToOwned::to_owned);
            let oid = reference.peel_to_id()?.detach();
            let direct = direct.unwrap_or(oid);
            packet(&mut advertisement, format!("{direct} {name}\n").as_bytes());
            if direct != oid {
                packet(&mut advertisement, format!("{oid} {name}^{{}}\n").as_bytes());
            }
        }
        advertisement.extend_from_slice(b"0000");
        Ok(Self { advertisement, pack })
    }

    /// Preserve the outer pack digest, but corrupt the last entry's zlib Adler-32.
    /// A valid pack SHA must not mask a corrupt compressed object checksum.
    pub fn with_corrupt_object_checksum(mut self) -> Self {
        use sha1::{Digest, Sha1};
        let trailer = self.pack.len() - 20;
        self.pack[trailer - 1] ^= 1;
        let digest = Sha1::digest(&self.pack[..trailer]);
        self.pack[trailer..].copy_from_slice(&digest);
        self
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub path: String,
    pub authorization: Option<String>,
    pub wants: Vec<gix::ObjectId>,
}

pub struct State {
    pub snapshot: Snapshot,
    pub auth: Option<String>,
    pub redirect: Option<String>,
    pub delay: Duration,
    pub requests: Vec<Request>,
}

pub struct Server {
    pub address: SocketAddr,
    pub state: Arc<Mutex<State>>,
    pub certificate_pem: Option<String>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    tls: bool,
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

impl Server {
    pub fn new(snapshot: Snapshot, tls: bool, auth: Option<String>) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let state = Arc::new(Mutex::new(State {
            snapshot,
            auth,
            redirect: None,
            delay: Duration::ZERO,
            requests: Vec::new(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let mut certificate_pem = None;
        let config = if tls {
            let cert =
                rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])?;
            certificate_pem = Some(cert.cert.pem());
            let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
            Some(Arc::new(
                rustls::ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
                ))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(vec![cert.cert.der().clone()], key.into())?,
            ))
        } else {
            None
        };
        let state_thread = state.clone();
        let stop_thread = stop.clone();
        let thread = std::thread::spawn(move || {
            while let Ok((socket, _)) = listener.accept() {
                if stop_thread.load(Ordering::Relaxed) {
                    break;
                }
                socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut stream: Box<dyn ReadWrite> = match &config {
                    Some(config) => Box::new(rustls::StreamOwned::new(
                        rustls::ServerConnection::new(config.clone()).unwrap(),
                        socket,
                    )),
                    None => Box::new(socket),
                };
                let _ = respond(&mut stream, &state_thread);
            }
        });
        Ok(Self { address, state, certificate_pem, stop, thread: Some(thread), tls })
    }

    pub fn url(&self) -> String {
        format!("{}://{}/repo.git", if self.tls { "https" } else { "http" }, self.address)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn respond(stream: &mut dyn ReadWrite, state: &Arc<Mutex<State>>) -> Result<()> {
    let mut reader = BufReader::new(&mut *stream);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
    let mut authorization = None;
    let mut length = 0;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        if line == "\r\n" {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_owned());
            }
            if key.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse()?;
            }
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    drop(reader);
    let mut wants = Vec::new();
    let mut packets = body.as_slice();
    while !packets.is_empty() {
        anyhow::ensure!(packets.len() >= 4, "Incomplete request packet header");
        let length = usize::from_str_radix(std::str::from_utf8(&packets[..4])?, 16)?;
        if length <= 2 {
            packets = &packets[4..];
            continue;
        }
        anyhow::ensure!(length >= 4 && length <= packets.len(), "Invalid request packet length");
        if let Some(want) = packets[4..length].strip_prefix(b"want ") {
            let id = want.split(|byte| byte.is_ascii_whitespace()).next().unwrap();
            wants.push(gix::ObjectId::from_hex(id)?);
        }
        packets = &packets[length..];
    }
    let (status, headers, response, delay) = {
        let mut state = state.lock().unwrap();
        state.requests.push(Request {
            path: path.clone(),
            authorization: authorization.clone(),
            wants,
        });
        // Authenticate before redirecting, so a redirect test can prove an identity
        // was obtained for this host before the client was sent elsewhere.
        let (status, headers, response) = if state.auth.is_some() && state.auth != authorization {
            ("401 Unauthorized", "WWW-Authenticate: Basic realm=fixture\r\n".to_owned(), Vec::new())
        } else if let Some(redirect) = &state.redirect {
            (
                "302 Found",
                format!("Location: {redirect}/info/refs?service=git-upload-pack\r\n"),
                Vec::new(),
            )
        } else if path.contains("/info/refs") {
            (
                "200 OK",
                "Content-Type: application/x-git-upload-pack-advertisement\r\n".to_owned(),
                state.snapshot.advertisement.clone(),
            )
        } else if path.ends_with("/git-upload-pack") {
            let mut response = Vec::new();
            packet(&mut response, b"NAK\n");
            for chunk in state.snapshot.pack.chunks(65514) {
                let mut data = vec![1];
                data.extend_from_slice(chunk);
                packet(&mut response, &data);
            }
            response.extend_from_slice(b"0000");
            (
                "200 OK",
                "Content-Type: application/x-git-upload-pack-result\r\n".to_owned(),
                response,
            )
        } else {
            ("404 Not Found", String::new(), Vec::new())
        };
        (status, headers, response, state.delay)
    };
    if !delay.is_zero() {
        std::thread::sleep(delay);
    }
    write!(
        stream,
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    )?;
    stream.write_all(&response)?;
    stream.flush()?;
    Ok(())
}

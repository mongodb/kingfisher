//! Minimal database-container fixture using the Docker client already used by Kingfisher.
//! Containers are removed on success, startup failure, unwinding, or runtime shutdown.

use std::{
    env,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use bollard::{
    API_DEFAULT_VERSION, Docker,
    auth::DockerCredentials,
    container::LogOutput,
    errors::Error,
    models::{ContainerCreateBody, HostConfig},
    query_parameters::{
        CreateContainerOptionsBuilder, CreateImageOptionsBuilder, LogsOptionsBuilder,
        RemoveContainerOptionsBuilder,
    },
};
use futures::StreamExt;

#[derive(Clone, Copy)]
pub struct DatabaseImage {
    pub image: &'static str,
    pub port: u16,
    pub ready_message: &'static str,
    pub environment: &'static [&'static str],
}

pub const MYSQL: DatabaseImage = DatabaseImage {
    image: "mysql:8.4",
    port: 3306,
    ready_message: "mysqld: ready for connections",
    environment: &["MYSQL_ROOT_PASSWORD=secret", "MYSQL_DATABASE=app", "MYSQL_ROOT_HOST=%"],
};
pub const POSTGRES: DatabaseImage = DatabaseImage {
    image: "postgres:15",
    port: 5432,
    ready_message: "database system is ready to accept connections",
    environment: &["POSTGRES_PASSWORD=secret"],
};

pub struct Options {
    pub startup_timeout: Duration,
    pub platform: Option<String>,
    pub credentials: Option<DockerCredentials>,
    pub keep: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            startup_timeout: Duration::from_secs(60),
            platform: None,
            credentials: None,
            keep: false,
        }
    }
}

pub fn connect(host: &str, tls_verify: bool, cert_dir: Option<&Path>) -> Result<Docker> {
    let scheme = url::Url::parse(host)?.scheme().to_owned();
    if scheme == "https" || (matches!(scheme.as_str(), "tcp" | "http") && tls_verify) {
        let cert_dir = cert_dir.context("Docker TLS requires DOCKER_CERT_PATH")?;
        // Bollard's TLS constructor strips tcp:// and https://, but not http://.
        let tls_host = host.replacen("http://", "https://", 1);
        return Ok(Docker::connect_with_ssl(
            &tls_host,
            &cert_dir.join("key.pem"),
            &cert_dir.join("cert.pem"),
            &cert_dir.join("ca.pem"),
            120,
            API_DEFAULT_VERSION,
        )?);
    }
    match scheme.as_str() {
        "tcp" | "http" => Ok(Docker::connect_with_http(host, 120, API_DEFAULT_VERSION)?),
        #[cfg(unix)]
        "unix" => Ok(Docker::connect_with_unix(host, 120, API_DEFAULT_VERSION)?),
        #[cfg(windows)]
        "npipe" => Ok(Docker::connect_with_named_pipe(host, 120, API_DEFAULT_VERSION)?),
        _ => bail!("unsupported Docker transport: {scheme}"),
    }
}

fn default_host() -> String {
    #[cfg(unix)]
    {
        let mut sockets = vec![PathBuf::from("/var/run/docker.sock")];
        if let Some(runtime) = env::var_os("XDG_RUNTIME_DIR") {
            sockets.push(PathBuf::from(runtime).join(".docker/run/docker.sock"));
        }
        if let Some(home) = env::home_dir() {
            sockets.push(home.join(".docker/run/docker.sock"));
            sockets.push(home.join(".docker/desktop/docker.sock"));
        }
        if let Some(socket) = sockets.into_iter().find(|socket| socket.exists()) {
            return format!("unix://{}", socket.display());
        }
        "unix:///var/run/docker.sock".into()
    }
    #[cfg(windows)]
    {
        "npipe:////./pipe/docker_engine".into()
    }
}

// Keep Docker Hub login/helper support without the container framework's build,
// archive, network, and container-reuse machinery. Both fixtures use public Hub images.
async fn registry_credentials() -> Option<DockerCredentials> {
    let config = env::var("DOCKER_AUTH_CONFIG").ok().or_else(|| {
        let directory = env::var_os("DOCKER_CONFIG")
            .map(PathBuf::from)
            .or_else(|| env::home_dir().map(|home| home.join(".docker")))?;
        std::fs::read_to_string(directory.join("config.json")).ok()
    })?;
    tokio::task::spawn_blocking(move || {
        let server = "https://index.docker.io/v1/";
        let credential =
            docker_credential::get_credential_from_reader(config.as_bytes(), server).ok()?;
        let mut credentials =
            DockerCredentials { serveraddress: Some(server.into()), ..Default::default() };
        match credential {
            docker_credential::DockerCredential::IdentityToken(token) => {
                credentials.identitytoken = Some(token)
            }
            docker_credential::DockerCredential::UsernamePassword(user, password) => {
                credentials.username = Some(user);
                credentials.password = Some(password);
            }
        }
        Some(credentials)
    })
    .await
    .ok()
    .flatten()
}

/// Retain connection settings, not a runtime-bound connection pool, for Drop.
#[derive(Clone)]
pub struct Connection {
    pub host: String,
    pub tls_verify: bool,
    pub cert_dir: Option<PathBuf>,
}

impl Connection {
    fn connect(&self) -> Result<Docker> {
        connect(&self.host, self.tls_verify, self.cert_dir.as_deref())
    }
}

pub fn tls_verify_enabled(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

pub struct DatabaseContainer {
    docker: Docker,
    connection: Connection,
    id: Option<String>,
    keep: bool,
    pub port: u16,
}

impl DatabaseContainer {
    pub async fn start(image: DatabaseImage) -> Result<Self> {
        let host = env::var("DOCKER_HOST").unwrap_or_else(|_| default_host());
        let certificates = env::var_os("DOCKER_CERT_PATH").map(PathBuf::from);
        let connection = Connection {
            host,
            tls_verify: tls_verify_enabled(env::var_os("DOCKER_TLS_VERIFY").as_deref()),
            cert_dir: certificates,
        };
        let keep = match env::var("TESTCONTAINERS_COMMAND").as_deref() {
            Ok("keep") => true,
            Ok("remove" | "") | Err(_) => false,
            Ok(command) => bail!("unsupported TESTCONTAINERS_COMMAND: {command}"),
        };
        let options = Options {
            platform: env::var("DOCKER_DEFAULT_PLATFORM")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            keep,
            ..Default::default()
        };
        Self::start_with(connection, image, options).await
    }

    pub async fn start_with(
        connection: Connection,
        image: DatabaseImage,
        options: Options,
    ) -> Result<Self> {
        let docker = connection.connect()?;
        let body = ContainerCreateBody {
            image: Some(image.image.into()),
            env: Some(image.environment.iter().map(|value| (*value).into()).collect()),
            exposed_ports: Some(vec![format!("{}/tcp", image.port)]),
            host_config: Some(HostConfig { publish_all_ports: Some(true), ..Default::default() }),
            ..Default::default()
        };
        let mut create_options = CreateContainerOptionsBuilder::default();
        if let Some(platform) = &options.platform {
            create_options = create_options.platform(platform);
        }
        let create_options = create_options.build();
        let created =
            match docker.create_container(Some(create_options.clone()), body.clone()).await {
                Err(Error::DockerResponseServerError { status_code: 404, .. }) => {
                    let mut pull = CreateImageOptionsBuilder::default().from_image(image.image);
                    if let Some(platform) = &options.platform {
                        pull = pull.platform(platform);
                    }
                    // Cached public images need no credentials and must not prompt a helper.
                    let credentials = match options.credentials {
                        Some(credentials) => Some(credentials),
                        None => registry_credentials().await,
                    };
                    let mut progress = docker.create_image(Some(pull.build()), None, credentials);
                    while let Some(event) = progress.next().await {
                        event?;
                    }
                    docker.create_container(Some(create_options), body).await?
                }
                result => result?,
            };
        let mut container =
            Self { docker, connection, id: Some(created.id), keep: options.keep, port: 0 };
        let id = container.id.as_deref().unwrap();
        container.port = tokio::time::timeout(options.startup_timeout, async {
            container.docker.start_container(id, None).await?;
            let logs = LogsOptionsBuilder::default().stdout(true).stderr(true).follow(true).build();
            let mut stream = container.docker.logs(id, Some(logs));
            let mut stdout_tail = Vec::new();
            let mut stderr_tail = Vec::new();
            let needle = image.ready_message.as_bytes();
            let mut occurrences = 0;
            while let Some(output) = stream.next().await {
                let output = output?;
                let (tail, message) = match &output {
                    LogOutput::StdOut { message } | LogOutput::Console { message } => {
                        (&mut stdout_tail, message)
                    }
                    LogOutput::StdErr { message } => (&mut stderr_tail, message),
                    LogOutput::StdIn { .. } => continue,
                };
                tail.extend_from_slice(message);
                occurrences += memchr::memmem::find_iter(tail, needle).count();
                if occurrences >= 2 {
                    break;
                }
                // Retain only a possible partial marker, separately for each stream.
                let discard = tail.len().saturating_sub(needle.len() - 1);
                tail.drain(..discard);
            }
            anyhow::ensure!(
                occurrences >= 2,
                "database logs ended before ready message appeared twice"
            );
            let inspected = container.docker.inspect_container(id, None).await?;
            let bindings =
                inspected.network_settings.and_then(|settings| settings.ports).unwrap_or_default();
            let port = bindings
                .get(&format!("{}/tcp", image.port))
                .and_then(Option::as_ref)
                .and_then(|bindings| {
                    bindings.iter().find(|binding| {
                        binding
                            .host_ip
                            .as_deref()
                            .and_then(|ip| ip.parse::<IpAddr>().ok())
                            .is_some_and(|ip| ip.is_ipv4())
                    })
                })
                .and_then(|binding| binding.host_port.as_deref())
                .context("database container has no published IPv4 port")?
                .parse::<u16>()?;
            anyhow::Ok(port)
        })
        .await
        .map_err(|_| anyhow!("database startup timed out after {:?}", options.startup_timeout))??;
        Ok(container)
    }

    pub async fn remove(mut self) -> Result<()> {
        if !self.keep {
            remove(&self.docker, self.id.as_deref().unwrap()).await?;
        }
        self.id = None;
        Ok(())
    }
}

async fn remove(docker: &Docker, id: &str) -> Result<()> {
    let options = RemoveContainerOptionsBuilder::default().force(true).v(true).build();
    tokio::time::timeout(Duration::from_secs(10), docker.remove_container(id, Some(options)))
        .await??;
    Ok(())
}

impl Drop for DatabaseContainer {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        let Some(id) = self.id.take() else {
            return;
        };
        let connection = self.connection.clone();
        // Both the runtime AND client must be independent: cloning the original
        // pool can reuse sockets driven by the blocked or already stopped runtime.
        // Joining this thread also completes cleanup while unwinding.
        let cleanup = std::thread::spawn(move || -> Result<()> {
            tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
                let docker = connection.connect()?;
                remove(&docker, &id).await
            })
        })
        .join();
        match cleanup {
            Ok(Ok(())) => {}
            Ok(Err(error)) => eprintln!("database container cleanup failed: {error:#}"),
            Err(_) => eprintln!("database container cleanup thread panicked"),
        }
    }
}

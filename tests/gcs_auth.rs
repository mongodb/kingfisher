use gcloud_auth::{
    credentials::CredentialsFile, project::Config, token::DefaultTokenSourceProvider,
};
use rsa::{
    PrivateKey,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use serde_json::json;
use token_source::TokenSourceProvider;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};

fn auth_config() -> Config<'static> {
    Config::default().with_scopes(&[
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/devstorage.full_control",
    ])
}

async fn token_provider(credentials: CredentialsFile) -> DefaultTokenSourceProvider {
    DefaultTokenSourceProvider::new_with_credentials(auth_config(), Box::new(credentials))
        .await
        .unwrap()
}

/// Keep this in its own test binary: GCS must be able to sign its first JWT
/// without GitHub authentication or JWT validation installing a provider first.
#[tokio::test]
async fn service_account_authentication_works_without_prior_jwt_initialization() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("assertion="))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "fixture-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let private_key = PrivateKey::new(&mut rand::rng(), 2048).unwrap();
    let private_pem = private_key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("service account 雪.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "type": "service_account",
            "project_id": "fixture-project",
            "private_key_id": "fixture-key",
            "private_key": private_pem.as_str(),
            "client_email": "scanner@fixture-project.iam.gserviceaccount.com",
            "token_uri": format!("{}/token", server.uri()),
        }))
        .unwrap(),
    )
    .unwrap();
    let credentials =
        CredentialsFile::new_from_file(path.to_string_lossy().into_owned()).await.unwrap();
    let provider = token_provider(credentials).await;
    for _ in 0..3 {
        let token = provider.token_source().token().await.unwrap();
        assert_eq!(token, "Bearer fixture-access-token");
    }
    server.verify().await;
}

#[tokio::test]
async fn application_default_credentials_load_from_environment_and_gcloud_files() {
    const CHILD: &str = "KINGFISHER_GCS_ADC_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let provider = DefaultTokenSourceProvider::new(auth_config()).await.unwrap();
        for _ in 0..3 {
            assert_eq!(provider.token_source().token().await.unwrap(), "Bearer adc-token");
        }
        return;
    }

    // Child-process environment avoids mutating global variables while other
    // tests run. current_exe and Path joins also work on Windows x64/arm64.
    use base64::Engine;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(wiremock::matchers::body_json(json!({
            "client_id": "adc-client",
            "client_secret": "adc-secret",
            "grant_type": "refresh_token",
            "refresh_token": "adc-refresh",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "adc-token", "token_type": "Bearer", "expires_in": 3600,
        })))
        .expect(4)
        .mount(&server)
        .await;
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("ADC home 雪");
    let default_directory =
        if cfg!(windows) { home.join("gcloud") } else { home.join(".config").join("gcloud") };
    std::fs::create_dir_all(&default_directory).unwrap();
    let credentials = json!({
        "type": "authorized_user",
        "client_id": "adc-client",
        "client_secret": "adc-secret",
        "refresh_token": "adc-refresh",
        "token_uri": format!("{}/token", server.uri()),
    })
    .to_string();
    let path = default_directory.join("application_default_credentials.json");
    std::fs::write(&path, &credentials).unwrap();
    for source in ["json", "base64", "path", "default"] {
        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "application_default_credentials_load_from_environment_and_gcloud_files",
                "--nocapture",
            ])
            .env(CHILD, source)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("APPDATA", &home)
            .env_remove("GOOGLE_APPLICATION_CREDENTIALS_JSON")
            .env_remove("GOOGLE_APPLICATION_CREDENTIALS");
        match source {
            "json" => {
                command.env("GOOGLE_APPLICATION_CREDENTIALS_JSON", &credentials);
            }
            "base64" => {
                command.env(
                    "GOOGLE_APPLICATION_CREDENTIALS_JSON",
                    base64::engine::general_purpose::STANDARD.encode(&credentials),
                );
            }
            "path" => {
                command.env("GOOGLE_APPLICATION_CREDENTIALS", &path);
            }
            _ => {}
        }
        let output = command.output().await.unwrap();
        assert!(
            output.status.success(),
            "ADC source {source}:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    server.verify().await;
}

#[tokio::test]
async fn explicit_invalid_credentials_never_fall_back_to_anonymous_storage() {
    let directory = tempfile::tempdir().unwrap();
    for (name, expected) in [
        ("missing.json", "Failed to read GCS service account credentials"),
        ("unsupported.json", "Failed to authenticate with GCS using provided credentials"),
    ] {
        let path = directory.path().join(name);
        if name == "unsupported.json" {
            std::fs::write(&path, r#"{"type":"unsupported"}"#).unwrap();
        }
        let error = kingfisher::gcs::visit_bucket_objects("bucket", None, Some(&path), |_, _| {
            panic!("invalid explicit credentials must not visit public objects")
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
    }
}

#[tokio::test]
async fn authorized_user_credentials_refresh_expired_tokens_and_reuse_fresh_tokens() {
    let server = MockServer::start().await;
    let response_number = std::sync::atomic::AtomicUsize::new(0);
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(wiremock::matchers::body_json(json!({
            "client_id": "fixture-client",
            "client_secret": "fixture-secret",
            "grant_type": "refresh_token",
            "refresh_token": "fixture-refresh-token",
        })))
        .respond_with(move |_: &wiremock::Request| {
            let first = response_number.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
            ResponseTemplate::new(200).set_body_json(json!({
                "access_token": if first { "expired-token" } else { "refreshed-token" },
                "token_type": "Bearer",
                "expires_in": if first { 0 } else { 3600 },
            }))
        })
        .expect(2)
        .mount(&server)
        .await;
    let credentials = CredentialsFile::new_from_str(
        &json!({
            "type": "authorized_user",
            "client_id": "fixture-client",
            "client_secret": "fixture-secret",
            "refresh_token": "fixture-refresh-token",
            "token_uri": format!("{}/token", server.uri()),
        })
        .to_string(),
    )
    .await
    .unwrap();
    let provider = token_provider(credentials).await;
    for _ in 0..3 {
        assert_eq!(provider.token_source().token().await.unwrap(), "Bearer refreshed-token");
    }
    server.verify().await;
}

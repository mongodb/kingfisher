use gcloud_storage::client::{ClientConfig, google_cloud_auth::credentials::CredentialsFile};
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, LineEnding},
    rand_core::OsRng,
};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};

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

    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let private_pem = private_key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let credentials: CredentialsFile = serde_json::from_value(json!({
        "type": "service_account",
        "project_id": "fixture-project",
        "private_key_id": "fixture-key",
        "private_key": private_pem.as_str(),
        "client_email": "scanner@fixture-project.iam.gserviceaccount.com",
        "token_uri": format!("{}/token", server.uri()),
    }))
    .unwrap();
    let config = ClientConfig::default().with_credentials(credentials).await.unwrap();
    let provider = config.token_source_provider.unwrap();
    let token = provider.token_source().token().await.unwrap();
    assert_eq!(token, "Bearer fixture-access-token");
    server.verify().await;
}

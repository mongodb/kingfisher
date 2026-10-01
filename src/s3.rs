use anyhow::{Context, Result};
use aws_config::{BehaviorVersion, defaults, meta::region::RegionProviderChain};
use aws_credential_types::Credentials;
use aws_sdk_s3::{
    Client,
    error::ProvideErrorMetadata,                    // for .code()
    operation::list_objects_v2::ListObjectsV2Error, // modeled service error
};
use aws_types::region::Region;
use reqwest; // HTTP client for HEAD fallback

pub async fn visit_bucket_objects<F>(
    bucket: &str,
    prefix: Option<&str>,
    role_arn: Option<&str>,
    profile: Option<&str>,
    mut visitor: F,
) -> Result<()>
where
    F: FnMut(String, Vec<u8>) -> Result<()>,
{
    // Helper to build ConfigLoader with profile/creds/no_credentials
    let build_loader = || {
        let mut loader = defaults(BehaviorVersion::latest());
        if kingfisher_scanner::validation::limits::NetworkLimits::current().no_timeouts {
            loader = loader
                .timeout_config(aws_sdk_s3::config::timeout::TimeoutConfig::disabled())
                .stalled_stream_protection(
                    aws_sdk_s3::config::StalledStreamProtectionConfig::disabled(),
                );
        }
        if let Some(p) = profile {
            loader = loader.profile_name(p);
        }
        if let (Ok(k), Ok(s)) = (std::env::var("KF_AWS_KEY"), std::env::var("KF_AWS_SECRET")) {
            let session_token = std::env::var("KF_AWS_SESSION_TOKEN").ok();
            loader =
                loader.credentials_provider(Credentials::new(k, s, session_token, None, "kf_env"));
        }
        if profile.is_none() && std::env::var("KF_AWS_KEY").is_err() && role_arn.is_none() {
            loader = loader.no_credentials();
        }
        loader
    };

    // Initial client in default→us-east-1
    let default_region = RegionProviderChain::default_provider().or_else("us-east-1");
    let mut config = build_loader().region(default_region).load().await;
    let mut client = if let Some(role) = role_arn {
        let assume = aws_config::sts::AssumeRoleProvider::builder(role.to_string())
            .session_name("kingfisher")
            .configure(&config)
            .build()
            .await;
        let conf = aws_sdk_s3::config::Builder::from(&config).credentials_provider(assume).build();
        Client::from_conf(conf)
    } else {
        Client::new(&config)
    };

    let mut continuation_token: Option<String> = None;
    loop {
        let mut req = client.list_objects_v2().bucket(bucket);
        if let Some(p) = prefix {
            req = req.prefix(p);
        }
        if let Some(ref token) = continuation_token {
            req = req.continuation_token(token);
        }

        let resp = match req.send().await {
            Ok(r) => r,

            // On error, extract the modeled service error
            Err(err) => {
                let svc_err: ListObjectsV2Error = err.into_service_error(); // from SdkError

                // If the bucket must be addressed at another region...
                if svc_err.code() == Some("PermanentRedirect") {
                    // HEAD request to get x-amz-bucket-region header
                    let url = format!("https://{bucket}.s3.amazonaws.com");
                    let head = reqwest::Client::new()
                        .head(&url)
                        .send()
                        .await
                        .context("Failed to HEAD bucket for region")?;
                    let region_str = head
                        .headers()
                        .get("x-amz-bucket-region")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("us-east-1")
                        .to_string();

                    // Rebuild client in the correct region
                    let override_region = RegionProviderChain::first_try(Region::new(region_str))
                        .or_else("us-east-1");
                    config = build_loader().region(override_region).load().await;
                    client = if let Some(r) = role_arn {
                        let assume = aws_config::sts::AssumeRoleProvider::builder(r.to_string())
                            .session_name("kingfisher")
                            .configure(&config)
                            .build()
                            .await;
                        let conf = aws_sdk_s3::config::Builder::from(&config)
                            .credentials_provider(assume)
                            .build();
                        Client::from_conf(conf)
                    } else {
                        Client::new(&config)
                    };

                    // Reset pagination and retry list
                    continuation_token = None;
                    continue;
                }

                // Any other error is fatal
                return Err(svc_err).context("Failed to list objects in bucket");
            }
        };

        // Process objects
        for obj in resp.contents.unwrap_or_default() {
            if let Some(key) = obj.key {
                let data = client
                    .get_object()
                    .bucket(bucket)
                    .key(&key)
                    .send()
                    .await
                    .with_context(|| format!("Failed to fetch object {}", key))?
                    .body
                    .collect()
                    .await
                    .context("Failed to read S3 object body")?
                    .into_bytes()
                    .to_vec();
                visitor(key, data)?;
            }
        }

        // Continue or finish pagination
        if resp.is_truncated.unwrap_or(false) {
            continuation_token = resp.next_continuation_token;
        } else {
            break;
        }
    }

    Ok(())
}

use std::time::Duration;

use anyhow::{anyhow, Result};
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_sts::Client as StsClient;
use aws_types::region::Region;
use base32::Alphabet;
use byteorder::{BigEndian, ByteOrder};
use http::StatusCode;

use crate::validation::{Cache, CachedResponse, VALIDATION_CACHE_SECONDS};

/// Generate a standardized cache key for AWS validation attempts
pub fn generate_aws_cache_key(aws_access_key_id: &str, aws_secret_access_key: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(aws_access_key_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(aws_secret_access_key.as_bytes());
    format!("AWS:{:x}", hasher.finalize())
}

// Validate AWS credentials before attempting validation
pub fn validate_aws_credentials_input(access_key_id: &str, secret_key: &str) -> Result<(), String> {
    // Validate access key ID format (typically starts with "AKIA" and is 20 chars)
    if !access_key_id.starts_with("AKIA") || access_key_id.len() != 20 {
        return Err("Invalid AWS access key ID format".to_string());
    }
    // Validate secret key format (should be at least 40 chars)
    if secret_key.len() < 40 {
        return Err("Invalid AWS secret key format".to_string());
    }
    // Check for invalid characters
    if !access_key_id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("AWS access key ID contains invalid characters".to_string());
    }
    if !secret_key.chars().all(|c| c.is_ascii_alphanumeric() || c == '/' || c == '+') {
        return Err("AWS secret key contains invalid characters".to_string());
    }
    Ok(())
}

pub async fn validate_aws_credentials(
    aws_access_key_id: &str,
    aws_secret_access_key: &str,
    cache: &Cache,
) -> Result<(bool, String)> {
    let cache_key = generate_aws_cache_key(aws_access_key_id, aws_secret_access_key);
    // Check cache first
    if let Some(cached) = cache.get(&cache_key) {
        let cached_response = cached.value();
        if cached_response.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            return Ok((cached_response.is_valid, cached_response.body.clone()));
        }
    }
    // Create static credentials
    let credentials = Credentials::new(
        aws_access_key_id,
        aws_secret_access_key,
        None,     // session token
        None,     // expiry
        "static", // provider name
    );
    // Create AWS config
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .credentials_provider(credentials)
        .load()
        .await;
    // Create STS client
    let sts_client = StsClient::new(&config);
    // Call get-caller-identity
    match sts_client.get_caller_identity().send().await {
        Ok(identity) => {
            let arn = identity.arn.unwrap_or_else(|| "Unknown".to_string());
            // let acct = identity.account.unwrap_or_else(|| "Unknown".to_string());
            let response = CachedResponse::new(arn.clone(), StatusCode::OK, true);
            cache.insert(cache_key, response);
            Ok((true, arn))
        }
        Err(e) => {
            let response = CachedResponse::new(e.to_string(), StatusCode::UNAUTHORIZED, false);
            cache.insert(cache_key, response);
            Err(anyhow!("AWS validation failed: {}", e))
        }
    }
}

/// Converts an AWS Key ID to an AWS Account Number.
/// It assumes that the Key ID has a specific format and extracts the account
/// number encoded within it. Reference: https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489
pub fn aws_key_to_account_number(aws_key_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Ensure the AWS Key ID is at least 5 characters long (since we'll access index
    // 4)
    if aws_key_id.len() < 5 {
        return Err("AWSKeyID is too short".into());
    }
    // Check if the 5th character is 'I' or 'J'
    let fifth_char = aws_key_id.as_bytes()[4] as char;
    if fifth_char == 'I' || fifth_char == 'J' {
        let err_msg =
            format!("Not possible to retrieve account number for {} keys", &aws_key_id[..5]);
        return Err(err_msg.into());
    }
    // Remove the Key ID prefix (first 4 characters)
    let trimmed_aws_key_id = &aws_key_id[4..];
    // Decode the trimmed Key ID from base32, ensuring it's in uppercase
    let decoded =
        base32::decode(Alphabet::Rfc4648 { padding: false }, &trimmed_aws_key_id.to_uppercase())
            .ok_or("Error decoding AWSKeyID")?;
    if decoded.len() < 6 {
        return Err("Decoded AWSKeyID is too short".into());
    }
    // Create an 8-byte array initialized to zeros
    let mut data = [0u8; 8];
    // Copy decoded[0..6] into data[2..8]
    data[2..8].copy_from_slice(&decoded[0..6]);
    // Interpret data as a big-endian u64
    let z = BigEndian::read_u64(&data);
    // Define the mask
    const MASK: u64 = 0x7FFFFFFFFF80;
    // Calculate the account number
    let account_num = (z & MASK) >> 7;
    // Return the account number formatted as a 12-digit string
    Ok(format!("{:012}", account_num))
}

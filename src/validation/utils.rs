use reqwest::Url;
use tokio::net::lookup_host;

use crate::validation::SerializableCaptures;
pub fn process_captures(captures: &SerializableCaptures) -> Vec<(String, String, usize, usize)> {
    let has_multiple_captures = captures.captures.len() > 1;
    captures
        .captures
        .iter()
        .enumerate()
        .filter(|(idx, _)| !has_multiple_captures || *idx > 0)
        .map(|(_, capture)| {
            let name = capture.name.as_ref().map_or("TOKEN".to_string(), |n| n.to_uppercase());
            (name, capture.value.clone().into_owned(), capture.start, capture.end)
        })
        .collect()
}
pub fn find_closest_variable(
    captures: &[(String, String, usize, usize)],
    target_value: &String,
    target_variable_name: &str,
    search_variable_name: &str,
) -> Option<String> {
    // Find positions of the target variable with the target value
    let mut target_positions = Vec::new();
    for (name, value, start, end) in captures {
        if name == target_variable_name && value == target_value {
            target_positions.push((*start, *end));
        }
    }
    if target_positions.is_empty() {
        return None;
    }
    // For each target position, find the closest search variable
    let mut closest_distance = usize::MAX;
    let mut closest_value: Option<String> = None;
    for (_target_start, target_end) in target_positions {
        for (name, value, start, _) in captures {
            if name == search_variable_name {
                let distance = (*start as isize - target_end as isize).abs() as usize;
                if distance < closest_distance {
                    closest_distance = distance;
                    closest_value = Some(value.clone());
                }
            }
        }
    }
    closest_value
}
pub async fn check_url_resolvable(url: &Url) -> Result<(), Box<dyn std::error::Error>> {
    let host = url.host_str().ok_or("No host in URL")?;
    let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    let addr = format!("{}:{}", host, port);
    lookup_host(addr).await?.next().ok_or_else(|| "Failed to resolve URL".into()).map(|_| ())
}

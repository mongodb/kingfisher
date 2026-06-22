//! Utility functions for validation.

use crate::finding::SerializableCaptures;

/// Return (NAME, value, start, end) for the captures we care about.
///
/// * Named captures keep their (upper-cased) name
/// * Among unnamed captures, keep **only the first one** and call it "TOKEN"
pub fn process_captures(captures: &SerializableCaptures) -> Vec<(String, String, usize, usize)> {
    let mut saw_unnamed = false;

    captures
        .captures
        .iter()
        .filter_map(|cap| {
            if let Some(name) = &cap.name {
                Some((name.to_uppercase(), cap.raw_value().to_string(), cap.start, cap.end))
            } else if !saw_unnamed {
                saw_unnamed = true;
                Some(("TOKEN".to_string(), cap.raw_value().to_string(), cap.start, cap.end))
            } else {
                // Ignore any additional unnamed captures (e.g., from unintended groups)
                None
            }
        })
        .collect()
}

/// Find the closest variable to a target value.
///
/// This is useful for finding related captures like an AWS access key ID
/// that should be paired with a secret key.
pub fn find_closest_variable(
    captures: &[(String, String, usize, usize)],
    target_value: &str,
    target_variable_name: &str,
    search_variable_name: &str,
) -> Option<String> {
    // Collect the positions of the target variable for the provided value so we can
    // compare relative offsets with candidate variables.
    let mut target_positions = Vec::new();
    for (name, value, start, end) in captures {
        if name == target_variable_name && value.as_str() == target_value {
            target_positions.push((*start, *end));
        }
    }

    if target_positions.is_empty() {
        return None;
    }

    // Prefer candidates that appear before the target value (same logical block), but
    // fall back to overlapping values and then to those that appear after the target
    // value when no better match exists. This avoids pairing with the next block when
    // multiple credentials are close together in the same file.
    let mut best_before: Option<(usize, String)> = None;
    let mut best_overlap: Option<(usize, String)> = None;
    let mut best_after: Option<(usize, String)> = None;

    for (target_start, target_end) in target_positions.iter().copied() {
        for (name, value, start, end) in captures {
            if name != search_variable_name {
                continue;
            }

            if *end <= target_start {
                // Candidate is before the target; choose the one closest to the target start.
                let distance = target_start - *end;
                match &mut best_before {
                    Some((best_distance, best_value)) if distance < *best_distance => {
                        *best_distance = distance;
                        *best_value = value.clone();
                    }
                    None => {
                        best_before = Some((distance, value.clone()));
                    }
                    _ => {}
                }
            } else if *start >= target_end {
                // Candidate is after the target; choose the one closest to the target end.
                let distance = *start - target_end;
                match &mut best_after {
                    Some((best_distance, best_value)) if distance < *best_distance => {
                        *best_distance = distance;
                        *best_value = value.clone();
                    }
                    None => {
                        best_after = Some((distance, value.clone()));
                    }
                    _ => {}
                }
            } else {
                // Candidate overlaps the target – treat as an exact match.
                let distance = 0usize;
                match &mut best_overlap {
                    Some((best_distance, best_value)) if distance < *best_distance => {
                        *best_distance = distance;
                        *best_value = value.clone();
                    }
                    None => {
                        best_overlap = Some((distance, value.clone()));
                    }
                    _ => {}
                }
            }
        }
    }

    best_before.or(best_overlap).or(best_after).map(|(_, value)| value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{SerializableCapture, SerializableCaptures};
    use smallvec::smallvec;

    #[test]
    fn single_unnamed_capture_is_returned() {
        let captures = SerializableCaptures {
            captures: smallvec![SerializableCapture {
                name: None,
                match_number: 0,
                start: 1,
                end: 4,
                value: crate::finding::intern("abc"),
            }],
        };
        let result = process_captures(&captures);
        assert_eq!(result, vec![("TOKEN".to_string(), "abc".to_string(), 1usize, 4usize)]);
    }

    #[test]
    fn prefers_closest_preceding_variable() {
        let captures = vec![
            ("TOKEN".to_string(), "secret".to_string(), 75usize, 115usize),
            ("AKID".to_string(), "preceding".to_string(), 30usize, 50usize),
            ("AKID".to_string(), "following".to_string(), 180usize, 200usize),
        ];

        let result = find_closest_variable(&captures, "secret", "TOKEN", "AKID").unwrap();

        assert_eq!(result, "preceding".to_string());
    }

    #[test]
    fn falls_back_to_following_when_no_preceding() {
        let captures = vec![
            ("TOKEN".to_string(), "secret".to_string(), 10usize, 50usize),
            ("AKID".to_string(), "after".to_string(), 60usize, 80usize),
        ];

        let result = find_closest_variable(&captures, "secret", "TOKEN", "AKID").unwrap();

        assert_eq!(result, "after".to_string());
    }
}

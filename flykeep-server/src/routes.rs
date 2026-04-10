/// Validates a secret path.
/// Rules: must start with /, no trailing slash, at least 2 segments, no empty segments.
pub fn validate_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err("path must start with /".to_string());
    }
    if path.ends_with('/') {
        return Err("path must not end with /".to_string());
    }
    let segments: Vec<&str> = path[1..].split('/').collect();
    if segments.len() < 2 {
        return Err("path must have at least 2 segments".to_string());
    }
    if segments.iter().any(|s| s.is_empty()) {
        return Err("path must not contain empty segments".to_string());
    }
    Ok(())
}

/// Validates a prefix for list queries.
/// Rules: must start with /, must end with /.
pub fn validate_prefix(prefix: &str) -> Result<(), String> {
    if !prefix.starts_with('/') {
        return Err("prefix must start with /".to_string());
    }
    if !prefix.ends_with('/') {
        return Err("prefix must end with /".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_path_two_segments() {
        assert!(validate_path("/ns/KEY").is_ok());
    }

    #[test]
    fn test_valid_path_four_segments() {
        assert!(validate_path("/ns/dev/app/KEY").is_ok());
    }

    #[test]
    fn test_path_no_leading_slash() {
        assert!(validate_path("ns/dev/app/KEY").is_err());
    }

    #[test]
    fn test_path_trailing_slash() {
        assert!(validate_path("/ns/dev/app/KEY/").is_err());
    }

    #[test]
    fn test_path_single_segment() {
        assert!(validate_path("/KEY").is_err());
    }

    #[test]
    fn test_path_empty() {
        assert!(validate_path("").is_err());
    }

    #[test]
    fn test_path_just_slash() {
        assert!(validate_path("/").is_err());
    }

    #[test]
    fn test_valid_prefix() {
        assert!(validate_prefix("/ns/dev/").is_ok());
    }

    #[test]
    fn test_prefix_no_trailing_slash() {
        assert!(validate_prefix("/ns/dev").is_err());
    }

    #[test]
    fn test_prefix_no_leading_slash() {
        assert!(validate_prefix("ns/dev/").is_err());
    }

    #[test]
    fn test_prefix_just_slash() {
        assert!(validate_prefix("/").is_ok());
    }
}

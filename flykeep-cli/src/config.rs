use serde::Deserialize;
use std::path::PathBuf;

pub struct Config {
    pub server_url: String,
    pub token: String,
}

#[derive(Deserialize)]
struct FileConfig {
    server_url: Option<String>,
    token: Option<String>,
}

pub fn load_config() -> Result<Config, String> {
    let _ = dotenvy::dotenv();

    let env_url = std::env::var("FLYKEEP_SERVER_URL").ok();
    let env_token = std::env::var("FLYKEEP_TOKEN").ok();

    if let (Some(url), Some(token)) = (&env_url, &env_token) {
        return Ok(Config {
            server_url: url.clone(),
            token: token.clone(),
        });
    }

    let file_config = config_file_path().and_then(|p| {
        if p.exists() {
            load_from_file(&p).ok()
        } else {
            None
        }
    });

    let server_url = env_url
        .or_else(|| file_config.as_ref().map(|c| c.server_url.clone()))
        .ok_or("FLYKEEP_SERVER_URL not set and not found in config file")?;

    let token = env_token
        .or_else(|| file_config.as_ref().map(|c| c.token.clone()))
        .ok_or("FLYKEEP_TOKEN not set and not found in config file")?;

    Ok(Config { server_url, token })
}

pub(crate) fn config_file_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("flykeep")
            .join("config.toml"),
    )
}

pub(crate) fn load_from_file(path: &std::path::Path) -> Result<Config, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read config file: {e}"))?;
    let file_config: FileConfig = toml::from_str(&content)
        .map_err(|e| format!("failed to parse config file: {e}"))?;
    let server_url = file_config
        .server_url
        .ok_or("server_url missing in config file")?;
    let token = file_config.token.ok_or("token missing in config file")?;
    Ok(Config { server_url, token })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_config_from_env_vars() {
        std::env::set_var("FLYKEEP_SERVER_URL", "http://test:8080");
        std::env::set_var("FLYKEEP_TOKEN", "test-token");
        let config = load_config().expect("test: load config");
        assert_eq!(config.server_url, "http://test:8080");
        assert_eq!(config.token, "test-token");
        std::env::remove_var("FLYKEEP_SERVER_URL");
        std::env::remove_var("FLYKEEP_TOKEN");
    }

    #[test]
    fn test_load_from_file() {
        let dir = tempfile::TempDir::new().expect("test: temp dir");
        let file_path = dir.path().join("config.toml");
        let mut file = std::fs::File::create(&file_path).expect("test: create file");
        file.write_all(b"server_url = \"http://file:8080\"\ntoken = \"file-token\"\n")
            .expect("test: write file");
        let config = load_from_file(&file_path).expect("test: load from file");
        assert_eq!(config.server_url, "http://file:8080");
        assert_eq!(config.token, "file-token");
    }

    #[test]
    fn test_load_from_file_missing_token() {
        let dir = tempfile::TempDir::new().expect("test: temp dir");
        let file_path = dir.path().join("config.toml");
        let mut file = std::fs::File::create(&file_path).expect("test: create file");
        file.write_all(b"server_url = \"http://file:8080\"\n")
            .expect("test: write file");
        let result = load_from_file(&file_path);
        assert!(result.is_err());
    }
}

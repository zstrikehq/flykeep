use serde::Deserialize;
use serde_json::json;

pub struct Client {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

#[derive(Deserialize)]
pub struct SecretResponse {
    pub path: String,
    pub value: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Deserialize)]
pub struct ListEntry {
    pub path: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Deserialize)]
pub struct ListResponse {
    pub secrets: Vec<ListEntry>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

impl Client {
    pub fn new(base_url: &str, token: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn server_version(&self) -> Result<String, String> {
        let res = self
            .http
            .get(format!("{}/alive", self.base_url))
            .send()
            .await
            .map_err(|e| format!("could not reach server: {e}"))?;
        let body: serde_json::Value = res
            .json()
            .await
            .map_err(|e| format!("failed to parse response: {e}"))?;
        let version = body["version"].as_str().unwrap_or("unknown");
        Ok(version.to_string())
    }

    pub async fn verify_auth(&self) -> Result<String, String> {
        let res = self
            .http
            .get(format!("{}/auth/verify", self.base_url))
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| format!("could not reach server: {e}"))?;
        if !res.status().is_success() {
            let err: ErrorResponse = res
                .json()
                .await
                .map_err(|e| format!("failed to read error response: {e}"))?;
            return Err(err.error);
        }
        let body: serde_json::Value = res
            .json()
            .await
            .map_err(|e| format!("failed to parse response: {e}"))?;
        let role = body["role"].as_str().unwrap_or("unknown");
        Ok(role.to_string())
    }

    pub async fn get_secret(&self, path: &str) -> Result<SecretResponse, String> {
        let res = self
            .http
            .get(format!("{}/secrets", self.base_url))
            .query(&[("path", path)])
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        if !res.status().is_success() {
            let err: ErrorResponse = res
                .json()
                .await
                .map_err(|e| format!("failed to read error response: {e}"))?;
            return Err(err.error);
        }
        res.json()
            .await
            .map_err(|e| format!("failed to parse response: {e}"))
    }

    pub async fn set_secret(&self, path: &str, value: &str) -> Result<(), String> {
        let res = self
            .http
            .put(format!("{}/secrets", self.base_url))
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", self.token))
            .json(&json!({"path": path, "value": value}))
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        if !res.status().is_success() {
            let err: ErrorResponse = res
                .json()
                .await
                .map_err(|e| format!("failed to read error response: {e}"))?;
            return Err(err.error);
        }
        Ok(())
    }

    pub async fn list_secrets(&self, prefix: &str) -> Result<ListResponse, String> {
        let res = self
            .http
            .get(format!("{}/secrets", self.base_url))
            .query(&[("prefix", prefix)])
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        if !res.status().is_success() {
            let err: ErrorResponse = res
                .json()
                .await
                .map_err(|e| format!("failed to read error response: {e}"))?;
            return Err(err.error);
        }
        res.json()
            .await
            .map_err(|e| format!("failed to parse response: {e}"))
    }

    pub async fn delete_secret(&self, path: &str) -> Result<(), String> {
        let res = self
            .http
            .delete(format!("{}/secrets", self.base_url))
            .query(&[("path", path)])
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        if !res.status().is_success() {
            let err: ErrorResponse = res
                .json()
                .await
                .map_err(|e| format!("failed to read error response: {e}"))?;
            return Err(err.error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_get_secret() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("path", "/ns/dev/app/KEY"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"path": "/ns/dev/app/KEY", "value": "secret-val", "created_at": 1700000000, "updated_at": 1700000000})),
            )
            .mount(&mock_server)
            .await;
        let client = Client::new(&mock_server.uri(), "test-token");
        let res = client.get_secret("/ns/dev/app/KEY").await.expect("test: get");
        assert_eq!(res.path, "/ns/dev/app/KEY");
        assert_eq!(res.value, "secret-val");
    }

    #[tokio::test]
    async fn test_get_secret_not_found() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({"error": "not found"})),
            )
            .mount(&mock_server)
            .await;
        let client = Client::new(&mock_server.uri(), "test-token");
        let result = client.get_secret("/ns/dev/app/MISSING").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_set_secret() {
        let mock_server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/secrets"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(&mock_server)
            .await;
        let client = Client::new(&mock_server.uri(), "test-token");
        client.set_secret("/ns/dev/app/KEY", "val").await.expect("test: set");
    }

    #[tokio::test]
    async fn test_list_secrets() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("prefix", "/ns/dev/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"secrets": [
                        {"path": "/ns/dev/app/A", "created_at": 1700000000, "updated_at": 1700000000},
                        {"path": "/ns/dev/app/B", "created_at": 1700000000, "updated_at": 1700000000}
                    ]})),
            )
            .mount(&mock_server)
            .await;
        let client = Client::new(&mock_server.uri(), "test-token");
        let res = client.list_secrets("/ns/dev/").await.expect("test: list");
        assert_eq!(res.secrets.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_secret() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/secrets"))
            .and(query_param("path", "/ns/dev/app/KEY"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(&mock_server)
            .await;
        let client = Client::new(&mock_server.uri(), "test-token");
        client.delete_secret("/ns/dev/app/KEY").await.expect("test: delete");
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/secrets"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({"error": "not found"})),
            )
            .mount(&mock_server)
            .await;
        let client = Client::new(&mock_server.uri(), "test-token");
        let result = client.delete_secret("/ns/dev/app/MISSING").await;
        assert!(result.is_err());
    }
}

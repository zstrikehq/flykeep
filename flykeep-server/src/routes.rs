use crate::auth::{AuthLevel, AuthMiddleware};
use crate::crypto;
use crate::AppState;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

pub fn create_router(state: Arc<AppState>) -> Router {
    let auth = AuthMiddleware { state };
    Router::new().hoop(auth).push(
        Router::with_path("secrets")
            .get(get_secrets)
            .put(put_secret)
            .delete(delete_secret),
    )
}

pub(crate) fn json_error(res: &mut Response, status: StatusCode, message: &str) {
    res.status_code(status);
    res.render(salvo::writing::Json(json!({"error": message})));
}

/// Validates a secret path.
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
pub fn validate_prefix(prefix: &str) -> Result<(), String> {
    if !prefix.starts_with('/') {
        return Err("prefix must start with /".to_string());
    }
    if !prefix.ends_with('/') {
        return Err("prefix must end with /".to_string());
    }
    Ok(())
}

#[handler]
async fn get_secrets(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<Arc<AppState>>() {
        Ok(s) => s.clone(),
        Err(_) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
            return;
        }
    };

    if let Some(path) = req.query::<String>("path") {
        get_single_secret(&state, &path, res).await;
    } else if let Some(prefix) = req.query::<String>("prefix") {
        list_secrets_handler(&state, &prefix, res).await;
    } else {
        json_error(res, StatusCode::BAD_REQUEST, "missing path or prefix parameter");
    }
}

async fn get_single_secret(state: &Arc<AppState>, path: &str, res: &mut Response) {
    if let Err(e) = validate_path(path) {
        json_error(res, StatusCode::BAD_REQUEST, &e);
        return;
    }
    let db = state.db.clone();
    let key = state.encryption_key;
    let path_owned = path.to_string();
    let result = tokio::task::spawn_blocking(move || db.get_secret(&path_owned)).await;
    match result {
        Ok(Ok(Some(row))) => match crypto::decrypt(&key, &row.value, &row.nonce) {
            Ok(plaintext) => {
                res.render(salvo::writing::Json(json!({"path": path, "value": plaintext})));
            }
            Err(e) => {
                json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &format!("decryption error: {e}"));
            }
        },
        Ok(Ok(None)) => {
            json_error(res, StatusCode::NOT_FOUND, "not found");
        }
        Ok(Err(e)) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        Err(e) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &format!("task error: {e}"));
        }
    }
}

async fn list_secrets_handler(state: &Arc<AppState>, prefix: &str, res: &mut Response) {
    if let Err(e) = validate_prefix(prefix) {
        json_error(res, StatusCode::BAD_REQUEST, &e);
        return;
    }
    let db = state.db.clone();
    let prefix_owned = prefix.to_string();
    let result = tokio::task::spawn_blocking(move || db.list_secrets(&prefix_owned)).await;
    match result {
        Ok(Ok(paths)) => {
            res.render(salvo::writing::Json(json!({"paths": paths})));
        }
        Ok(Err(e)) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        Err(e) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &format!("task error: {e}"));
        }
    }
}

#[derive(Deserialize)]
struct PutSecretBody {
    path: String,
    value: String,
}

#[handler]
async fn put_secret(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let auth_level = match depot.obtain::<AuthLevel>() {
        Ok(level) => level.clone(),
        Err(_) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
            return;
        }
    };
    if auth_level != AuthLevel::Admin {
        json_error(res, StatusCode::FORBIDDEN, "write operations require admin token");
        return;
    }
    let state = match depot.obtain::<Arc<AppState>>() {
        Ok(s) => s.clone(),
        Err(_) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
            return;
        }
    };
    let body: PutSecretBody = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            json_error(res, StatusCode::BAD_REQUEST, &format!("invalid body: {e}"));
            return;
        }
    };
    if let Err(e) = validate_path(&body.path) {
        json_error(res, StatusCode::BAD_REQUEST, &e);
        return;
    }
    let key = state.encryption_key;
    let (ciphertext, nonce) = match crypto::encrypt(&key, &body.value) {
        Ok(result) => result,
        Err(e) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &format!("encryption error: {e}"));
            return;
        }
    };
    let db = state.db.clone();
    let path = body.path.clone();
    let result = tokio::task::spawn_blocking(move || db.put_secret(&path, &ciphertext, &nonce)).await;
    match result {
        Ok(Ok(())) => {
            res.render(salvo::writing::Json(json!({"ok": true})));
        }
        Ok(Err(e)) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        Err(e) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &format!("task error: {e}"));
        }
    }
}

#[handler]
async fn delete_secret(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let auth_level = match depot.obtain::<AuthLevel>() {
        Ok(level) => level.clone(),
        Err(_) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
            return;
        }
    };
    if auth_level != AuthLevel::Admin {
        json_error(res, StatusCode::FORBIDDEN, "write operations require admin token");
        return;
    }
    let state = match depot.obtain::<Arc<AppState>>() {
        Ok(s) => s.clone(),
        Err(_) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
            return;
        }
    };
    let path = match req.query::<String>("path") {
        Some(p) => p,
        None => {
            json_error(res, StatusCode::BAD_REQUEST, "missing path parameter");
            return;
        }
    };
    if let Err(e) = validate_path(&path) {
        json_error(res, StatusCode::BAD_REQUEST, &e);
        return;
    }
    let db = state.db.clone();
    let path_clone = path.clone();
    let result = tokio::task::spawn_blocking(move || db.delete_secret(&path_clone)).await;
    match result {
        Ok(Ok(true)) => {
            res.render(salvo::writing::Json(json!({"ok": true})));
        }
        Ok(Ok(false)) => {
            json_error(res, StatusCode::NOT_FOUND, "not found");
        }
        Ok(Err(e)) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        Err(e) => {
            json_error(res, StatusCode::INTERNAL_SERVER_ERROR, &format!("task error: {e}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use crate::AppState;
    use salvo::test::{ResponseExt, TestClient};
    use salvo::Service;
    use serde_json::{json, Value};

    fn test_key() -> [u8; 32] {
        [0xAB; 32]
    }

    fn test_token() -> String {
        "test-admin-token".to_string()
    }

    fn setup_service() -> (Service, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("test: create temp dir");
        let db_path = dir.path().join("test.db");
        let db = Database::init(db_path.to_str().expect("test: path"))
            .expect("test: init db");
        let state = Arc::new(AppState {
            db: Arc::new(db),
            encryption_key: test_key(),
            admin_token: test_token(),
        });
        let router = create_router(state);
        (Service::new(router), dir)
    }

    fn auth_header() -> String {
        format!("Bearer {}", test_token())
    }

    #[tokio::test]
    async fn test_put_and_get_roundtrip() {
        let (service, _dir) = setup_service();
        let res = TestClient::put("http://127.0.0.1:5800/secrets")
            .add_header("authorization", auth_header(), true)
            .json(&json!({"path": "/ns/dev/app/DB_URL", "value": "postgres://localhost"}))
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::OK);

        let mut res = TestClient::get("http://127.0.0.1:5800/secrets?path=/ns/dev/app/DB_URL")
            .add_header("authorization", auth_header(), true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::OK);
        let body: Value = res.take_json().await.expect("test: parse json");
        assert_eq!(body["path"], "/ns/dev/app/DB_URL");
        assert_eq!(body["value"], "postgres://localhost");
    }

    #[tokio::test]
    async fn test_get_nonexistent_returns_404() {
        let (service, _dir) = setup_service();
        let res = TestClient::get("http://127.0.0.1:5800/secrets?path=/ns/dev/app/MISSING")
            .add_header("authorization", auth_header(), true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_secrets() {
        let (service, _dir) = setup_service();
        TestClient::put("http://127.0.0.1:5800/secrets")
            .add_header("authorization", auth_header(), true)
            .json(&json!({"path": "/ns/dev/app/A", "value": "val-a"}))
            .send(&service)
            .await;
        TestClient::put("http://127.0.0.1:5800/secrets")
            .add_header("authorization", auth_header(), true)
            .json(&json!({"path": "/ns/dev/app/B", "value": "val-b"}))
            .send(&service)
            .await;
        let mut res = TestClient::get("http://127.0.0.1:5800/secrets?prefix=/ns/dev/")
            .add_header("authorization", auth_header(), true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::OK);
        let body: Value = res.take_json().await.expect("test: parse json");
        let paths = body["paths"].as_array().expect("test: paths array");
        assert_eq!(paths.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_existing() {
        let (service, _dir) = setup_service();
        TestClient::put("http://127.0.0.1:5800/secrets")
            .add_header("authorization", auth_header(), true)
            .json(&json!({"path": "/ns/dev/app/KEY", "value": "val"}))
            .send(&service)
            .await;
        let res = TestClient::delete("http://127.0.0.1:5800/secrets?path=/ns/dev/app/KEY")
            .add_header("authorization", auth_header(), true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_delete_nonexistent_returns_404() {
        let (service, _dir) = setup_service();
        let res = TestClient::delete("http://127.0.0.1:5800/secrets?path=/ns/dev/app/NOPE")
            .add_header("authorization", auth_header(), true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_invalid_path_returns_400() {
        let (service, _dir) = setup_service();
        let res = TestClient::get("http://127.0.0.1:5800/secrets?path=no-slash")
            .add_header("authorization", auth_header(), true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("test: status"), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_no_auth_from_local_ip_returns_403() {
        let (service, _dir) = setup_service();
        let res = TestClient::get("http://127.0.0.1:5800/secrets?path=/ns/dev/app/KEY")
            .send(&service)
            .await;
        // TestClient connects from localhost (not fdaa::/8), so should get 403
        assert_eq!(res.status_code.expect("test: status"), StatusCode::FORBIDDEN);
    }

    // --- Unit tests for validate_path and validate_prefix ---

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

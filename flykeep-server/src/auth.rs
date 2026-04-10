#[derive(Debug, Clone, PartialEq)]
pub enum AuthLevel {
    Admin,
    ReadOnly,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthError {
    Unauthorized,
    Forbidden,
}

/// Pure auth decision — no HTTP dependency, fully testable.
pub fn check_auth(
    auth_header: Option<&str>,
    admin_token: &str,
    read_token: &str,
) -> Result<AuthLevel, AuthError> {
    if let Some(header) = auth_header {
        let token = header.strip_prefix("Bearer ").ok_or(AuthError::Unauthorized)?;
        if token == admin_token {
            return Ok(AuthLevel::Admin);
        }
        if token == read_token {
            return Ok(AuthLevel::ReadOnly);
        }
        return Err(AuthError::Unauthorized);
    }
    Err(AuthError::Forbidden)
}

use salvo::http::StatusCode;
use salvo::prelude::*;
use std::sync::Arc;

pub struct AuthMiddleware {
    pub state: Arc<crate::AppState>,
}

#[handler]
impl AuthMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let auth_header = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok());

        match check_auth(auth_header, &self.state.admin_token, &self.state.read_token) {
            Ok(level) => {
                depot.inject(level);
                depot.inject(self.state.clone());
                ctrl.call_next(req, depot, res).await;
            }
            Err(AuthError::Unauthorized) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(salvo::writing::Json(
                    serde_json::json!({"error": "unauthorized"}),
                ));
                ctrl.skip_rest();
            }
            Err(AuthError::Forbidden) => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(salvo::writing::Json(
                    serde_json::json!({"error": "forbidden"}),
                ));
                ctrl.skip_rest();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_admin_token() {
        let result = check_auth(Some("Bearer admin-tok"), "admin-tok", "read-tok");
        assert_eq!(result, Ok(AuthLevel::Admin));
    }

    #[test]
    fn test_valid_read_token() {
        let result = check_auth(Some("Bearer read-tok"), "admin-tok", "read-tok");
        assert_eq!(result, Ok(AuthLevel::ReadOnly));
    }

    #[test]
    fn test_invalid_token() {
        let result = check_auth(Some("Bearer wrong"), "admin-tok", "read-tok");
        assert_eq!(result, Err(AuthError::Unauthorized));
    }

    #[test]
    fn test_malformed_auth_header() {
        let result = check_auth(Some("Basic abc123"), "admin-tok", "read-tok");
        assert_eq!(result, Err(AuthError::Unauthorized));
    }

    #[test]
    fn test_no_token_returns_forbidden() {
        let result = check_auth(None, "admin-tok", "read-tok");
        assert_eq!(result, Err(AuthError::Forbidden));
    }

    #[test]
    fn test_read_token_is_readonly_not_admin() {
        let result = check_auth(Some("Bearer read-tok"), "admin-tok", "read-tok");
        assert_ne!(result, Ok(AuthLevel::Admin));
        assert_eq!(result, Ok(AuthLevel::ReadOnly));
    }
}

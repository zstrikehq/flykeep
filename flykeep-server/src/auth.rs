use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum AuthLevel {
    Admin,
    NetworkRead,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthError {
    Unauthorized,
    Forbidden,
}

/// Pure auth decision — no HTTP dependency, fully testable.
pub fn check_auth(
    auth_header: Option<&str>,
    remote_ip: Option<&IpAddr>,
    admin_token: &str,
) -> Result<AuthLevel, AuthError> {
    // Check token first — valid token from anywhere allows all ops
    if let Some(header) = auth_header {
        let token = header.strip_prefix("Bearer ").ok_or(AuthError::Unauthorized)?;
        if token == admin_token {
            return Ok(AuthLevel::Admin);
        }
        return Err(AuthError::Unauthorized);
    }

    // No token — check network
    if let Some(ip) = remote_ip {
        if is_fly_private_network(ip) {
            return Ok(AuthLevel::NetworkRead);
        }
    }

    Err(AuthError::Forbidden)
}

/// Returns true if the IP is in the fd00::/8 range (Fly.io private network).
pub fn is_fly_private_network(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => {
            // fdaa::/8 — first 8 bits are 0xFD
            (v6.segments()[0] >> 8) == 0xFD
        }
        _ => false,
    }
}

use salvo::prelude::*;
use salvo::http::StatusCode;

pub struct AuthMiddleware {
    pub state: std::sync::Arc<crate::AppState>,
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

        // Extract remote IP from the connection
        let remote_ip = req.remote_addr().clone().into_std().map(|addr| addr.ip());

        match check_auth(auth_header, remote_ip.as_ref(), &self.state.admin_token) {
            Ok(level) => {
                depot.inject(level);
                depot.inject(self.state.clone());
                ctrl.call_next(req, depot, res).await;
            }
            Err(AuthError::Unauthorized) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(salvo::writing::Json(serde_json::json!({"error": "unauthorized"})));
            }
            Err(AuthError::Forbidden) => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(salvo::writing::Json(serde_json::json!({"error": "forbidden"})));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_admin_token() {
        let result = check_auth(Some("Bearer my-token"), None, "my-token");
        assert_eq!(result, Ok(AuthLevel::Admin));
    }

    #[test]
    fn test_invalid_admin_token() {
        let result = check_auth(Some("Bearer wrong-token"), None, "my-token");
        assert_eq!(result, Err(AuthError::Unauthorized));
    }

    #[test]
    fn test_malformed_auth_header() {
        let result = check_auth(Some("Basic abc123"), None, "my-token");
        assert_eq!(result, Err(AuthError::Unauthorized));
    }

    #[test]
    fn test_no_token_fly_private_ipv6() {
        let ip: IpAddr = "fdaa::1".parse().expect("test: parse ip");
        let result = check_auth(None, Some(&ip), "my-token");
        assert_eq!(result, Ok(AuthLevel::NetworkRead));
    }

    #[test]
    fn test_no_token_public_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().expect("test: parse ip");
        let result = check_auth(None, Some(&ip), "my-token");
        assert_eq!(result, Err(AuthError::Forbidden));
    }

    #[test]
    fn test_no_token_ipv4() {
        let ip: IpAddr = "192.168.1.1".parse().expect("test: parse ip");
        let result = check_auth(None, Some(&ip), "my-token");
        assert_eq!(result, Err(AuthError::Forbidden));
    }

    #[test]
    fn test_no_token_no_ip() {
        let result = check_auth(None, None, "my-token");
        assert_eq!(result, Err(AuthError::Forbidden));
    }

    #[test]
    fn test_admin_token_overrides_private_network() {
        let ip: IpAddr = "fdaa::1".parse().expect("test: parse ip");
        let result = check_auth(Some("Bearer my-token"), Some(&ip), "my-token");
        assert_eq!(result, Ok(AuthLevel::Admin));
    }

    #[test]
    fn test_is_fly_private_fdaa() {
        let ip: IpAddr = "fdaa::1".parse().expect("test: parse ip");
        assert!(is_fly_private_network(&ip));
    }

    #[test]
    fn test_is_fly_private_fd_range() {
        let ip: IpAddr = "fd00::1".parse().expect("test: parse ip");
        assert!(is_fly_private_network(&ip));
    }

    #[test]
    fn test_is_not_fly_private_public_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().expect("test: parse ip");
        assert!(!is_fly_private_network(&ip));
    }

    #[test]
    fn test_is_not_fly_private_ipv4() {
        let ip: IpAddr = "10.0.0.1".parse().expect("test: parse ip");
        assert!(!is_fly_private_network(&ip));
    }
}

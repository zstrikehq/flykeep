mod auth;
mod crypto;
mod db;
mod routes;

use db::Database;
use std::sync::Arc;

pub struct AppState {
    pub db: Arc<Database>,
    pub encryption_key: [u8; 32],
    pub admin_token: String,
    pub read_token: String,
}

fn load_config() -> Result<(String, String, String, String, u16), String> {
    let _ = dotenvy::dotenv();
    let encryption_key_hex = std::env::var("FLYKEEP_ENCRYPTION_KEY")
        .map_err(|_| "FLYKEEP_ENCRYPTION_KEY is required".to_string())?;
    let admin_token = std::env::var("FLYKEEP_ADMIN_TOKEN")
        .map_err(|_| "FLYKEEP_ADMIN_TOKEN is required".to_string())?;
    let read_token = std::env::var("FLYKEEP_READ_TOKEN")
        .map_err(|_| "FLYKEEP_READ_TOKEN is required".to_string())?;
    let db_path = std::env::var("FLYKEEP_DB_PATH")
        .unwrap_or_else(|_| "./vault.db".to_string());
    let port: u16 = std::env::var("FLYKEEP_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .map_err(|e| format!("invalid FLYKEEP_PORT: {e}"))?;
    Ok((encryption_key_hex, admin_token, read_token, db_path, port))
}

pub fn parse_encryption_key(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| format!("invalid FLYKEEP_ENCRYPTION_KEY hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "FLYKEEP_ENCRYPTION_KEY must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[tokio::main]
async fn main() {
    let (encryption_key_hex, admin_token, read_token, db_path, port) =
        load_config().expect("startup: failed to load config");
    let encryption_key = parse_encryption_key(&encryption_key_hex)
        .expect("startup: failed to parse encryption key");
    let database = Database::init(&db_path)
        .expect("startup: failed to initialize database");
    let state = Arc::new(AppState {
        db: Arc::new(database),
        encryption_key,
        admin_token,
        read_token,
    });
    let router = routes::create_router(state);
    let bind_addr = format!("0.0.0.0:{port}");
    eprintln!("flykeep-server listening on {bind_addr}");
    use salvo::Listener;
    let acceptor = salvo::conn::TcpListener::new(&bind_addr).bind().await;
    salvo::Server::new(acceptor).serve(router).await;
}

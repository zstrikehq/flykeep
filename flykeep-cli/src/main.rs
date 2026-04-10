mod client;
mod config;

use clap::{Parser, Subcommand, ValueEnum};
use client::{Client, ListEntry, ListResponse, SecretResponse};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "flykeep", about = "CLI client for flykeep secret store")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format
    #[arg(long, default_value = "table", global = true)]
    format: OutputFormat,
}

#[derive(Subcommand)]
enum Commands {
    /// Configure server URL and token
    Auth,
    /// Fetch and print a single secret
    Get { path: String },
    /// Create or update a secret
    Set { path: String, value: String },
    /// List secret paths under a prefix
    List {
        prefix: String,
        /// Also fetch and display values
        #[arg(long)]
        values: bool,
    },
    /// Delete a secret
    Delete { path: String },
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Table,
    Env,
    Json,
}

fn format_timestamp(epoch: i64) -> String {
    use chrono::{Local, TimeZone};
    Local
        .timestamp_opt(epoch, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "invalid".to_string())
}

fn tz_label() -> String {
    use chrono::Local;
    Local::now().format("%Z").to_string()
}

pub fn format_get_table(resp: &SecretResponse) -> String {
    use comfy_table::{ContentArrangement, Table};
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    let tz = tz_label();
    table.set_header(vec!["PATH", "VALUE", &format!("CREATED ({tz})"), &format!("UPDATED ({tz})")]);
    table.add_row(vec![
        &resp.path,
        &resp.value,
        &format_timestamp(resp.created_at),
        &format_timestamp(resp.updated_at),
    ]);
    table.to_string()
}

pub fn format_list_env(resp: &ListResponse) -> String {
    resp.secrets
        .iter()
        .map(|e| e.path.rsplit('/').next().unwrap_or(&e.path).to_uppercase())
        .collect::<Vec<String>>()
        .join("\n")
}

pub fn format_list_table_with_values(secrets: &[SecretResponse]) -> String {
    use comfy_table::{ContentArrangement, Table};
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    let tz = tz_label();
    table.set_header(vec!["PATH", "VALUE", &format!("CREATED ({tz})"), &format!("UPDATED ({tz})")]);
    for s in secrets {
        table.add_row(vec![
            &s.path,
            &s.value,
            &format_timestamp(s.created_at),
            &format_timestamp(s.updated_at),
        ]);
    }
    table.to_string()
}

pub fn format_get_env(resp: &SecretResponse) -> String {
    let key = resp.path.rsplit('/').next().unwrap_or(&resp.path).to_uppercase();
    format!("{key}={}", resp.value)
}

pub fn format_list_table(resp: &ListResponse) -> String {
    use comfy_table::{ContentArrangement, Table};
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    let tz = tz_label();
    table.set_header(vec!["PATH", &format!("CREATED ({tz})"), &format!("UPDATED ({tz})")]);
    for entry in &resp.secrets {
        table.add_row(vec![
            &entry.path,
            &format_timestamp(entry.created_at),
            &format_timestamp(entry.updated_at),
        ]);
    }
    table.to_string()
}


#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cli = Cli::parse();

    if matches!(cli.command, Commands::Auth) {
        return run_auth().await;
    }

    let config = config::load_config()?;
    let client = Client::new(&config.server_url, &config.token);

    match cli.command {
        Commands::Auth => unreachable!(),
        Commands::Get { path } => {
            let resp = client.get_secret(&path).await?;
            match cli.format {
                OutputFormat::Table => println!("{}", format_get_table(&resp)),
                OutputFormat::Env => println!("{}", format_get_env(&resp)),
                OutputFormat::Json => {
                    let json = serde_json::json!({"path": resp.path, "value": resp.value});
                    println!("{}", serde_json::to_string_pretty(&json).map_err(|e| e.to_string())?);
                }
            }
        }
        Commands::Set { path, value } => {
            client.set_secret(&path, &value).await?;
            println!("ok");
        }
        Commands::List { prefix, values } => {
            let resp = client.list_secrets(&prefix).await?;
            let fetch_values = values || matches!(cli.format, OutputFormat::Env | OutputFormat::Json);
            if fetch_values {
                let mut secrets = Vec::new();
                for entry in &resp.secrets {
                    let secret = client.get_secret(&entry.path).await?;
                    secrets.push(secret);
                }
                match cli.format {
                    OutputFormat::Table => println!("{}", format_list_table_with_values(&secrets)),
                    OutputFormat::Env => {
                        let lines: Vec<String> = secrets
                            .iter()
                            .map(|s| format_get_env(s))
                            .collect();
                        println!("{}", lines.join("\n"));
                    }
                    OutputFormat::Json => {
                        let items: Vec<serde_json::Value> = secrets
                            .iter()
                            .map(|s| serde_json::json!({"path": s.path, "value": s.value}))
                            .collect();
                        println!("{}", serde_json::to_string_pretty(&items).map_err(|e| e.to_string())?);
                    }
                }
            } else {
                println!("{}", format_list_table(&resp));
            }
        }
        Commands::Delete { path } => {
            client.delete_secret(&path).await?;
            println!("ok");
        }
    }

    Ok(())
}

fn prompt(label: &str) -> Result<String, String> {
    print!("{label}: ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;
    let value = input.trim().to_string();
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(value)
}

async fn run_auth() -> Result<(), String> {
    let server_url = prompt("Server URL")?;
    let token = prompt("Token")?;

    let client = Client::new(&server_url, &token);
    let role = client.verify_auth().await?;

    let path = config::config_file_path()
        .ok_or("could not determine config directory")?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create config directory: {e}"))?;
    }

    let content = format!("server_url = \"{server_url}\"\ntoken = \"{token}\"\n");
    std::fs::write(&path, content)
        .map_err(|e| format!("failed to write config file: {e}"))?;

    println!("authenticated as {role}, saved to {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_get_table() {
        let resp = SecretResponse {
            path: "/ns/dev/app/DB_URL".to_string(),
            value: "postgres://localhost".to_string(),
            created_at: 1700000000,
            updated_at: 1700000000,
        };
        let output = format_get_table(&resp);
        assert!(output.contains("PATH"));
        assert!(output.contains("VALUE"));
        assert!(output.contains("CREATED"));
        assert!(output.contains("UPDATED"));
        assert!(output.contains("/ns/dev/app/DB_URL"));
        assert!(output.contains("postgres://localhost"));
    }

    #[test]
    fn test_format_get_env() {
        let resp = SecretResponse {
            path: "/ns/dev/app/DB_URL".to_string(),
            value: "postgres://localhost".to_string(),
            created_at: 1700000000,
            updated_at: 1700000000,
        };
        let output = format_get_env(&resp);
        assert_eq!(output, "DB_URL=postgres://localhost");
    }

    #[test]
    fn test_format_list_table() {
        let resp = ListResponse {
            secrets: vec![
                ListEntry { path: "/ns/dev/app/DB_URL".to_string(), created_at: 1700000000, updated_at: 1700000000 },
                ListEntry { path: "/ns/dev/app/API_KEY".to_string(), created_at: 1700000000, updated_at: 1700000000 },
            ],
        };
        let output = format_list_table(&resp);
        assert!(output.contains("PATH"));
        assert!(output.contains("CREATED"));
        assert!(output.contains("UPDATED"));
        assert!(output.contains("/ns/dev/app/DB_URL"));
        assert!(output.contains("/ns/dev/app/API_KEY"));
    }

    #[test]
    fn test_format_get_env_extracts_last_segment() {
        let resp = SecretResponse {
            path: "/a/b/c/MY_SECRET".to_string(),
            value: "val".to_string(),
            created_at: 0,
            updated_at: 0,
        };
        assert_eq!(format_get_env(&resp), "MY_SECRET=val"); // already uppercase
    }
}

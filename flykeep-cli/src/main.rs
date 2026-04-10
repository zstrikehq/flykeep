mod client;
mod config;

use clap::{Parser, Subcommand, ValueEnum};
use client::{Client, ListResponse, SecretResponse};

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
    /// Fetch and print a single secret
    Get { path: String },
    /// Create or update a secret
    Set { path: String, value: String },
    /// List secret paths under a prefix
    List { prefix: String },
    /// Delete a secret
    Delete { path: String },
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Table,
    Env,
}

pub fn format_get_table(resp: &SecretResponse) -> String {
    use comfy_table::{ContentArrangement, Table};
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["PATH", "VALUE"]);
    table.add_row(vec![&resp.path, &resp.value]);
    table.to_string()
}

pub fn format_get_env(resp: &SecretResponse) -> String {
    let key = resp.path.rsplit('/').next().unwrap_or(&resp.path);
    format!("{key}={}", resp.value)
}

pub fn format_list_table(resp: &ListResponse) -> String {
    use comfy_table::{ContentArrangement, Table};
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["PATH"]);
    for path in &resp.paths {
        table.add_row(vec![path]);
    }
    table.to_string()
}

pub fn format_list_env(resp: &ListResponse) -> String {
    resp.paths
        .iter()
        .map(|p| p.rsplit('/').next().unwrap_or(p))
        .collect::<Vec<&str>>()
        .join("\n")
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
    let config = config::load_config()?;
    let client = Client::new(&config.server_url, &config.token);

    match cli.command {
        Commands::Get { path } => {
            let resp = client.get_secret(&path).await?;
            match cli.format {
                OutputFormat::Table => println!("{}", format_get_table(&resp)),
                OutputFormat::Env => println!("{}", format_get_env(&resp)),
            }
        }
        Commands::Set { path, value } => {
            client.set_secret(&path, &value).await?;
            println!("ok");
        }
        Commands::List { prefix } => {
            let resp = client.list_secrets(&prefix).await?;
            match cli.format {
                OutputFormat::Table => println!("{}", format_list_table(&resp)),
                OutputFormat::Env => println!("{}", format_list_env(&resp)),
            }
        }
        Commands::Delete { path } => {
            client.delete_secret(&path).await?;
            println!("ok");
        }
    }

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
        };
        let output = format_get_table(&resp);
        assert!(output.contains("PATH"));
        assert!(output.contains("VALUE"));
        assert!(output.contains("/ns/dev/app/DB_URL"));
        assert!(output.contains("postgres://localhost"));
    }

    #[test]
    fn test_format_get_env() {
        let resp = SecretResponse {
            path: "/ns/dev/app/DB_URL".to_string(),
            value: "postgres://localhost".to_string(),
        };
        let output = format_get_env(&resp);
        assert_eq!(output, "DB_URL=postgres://localhost");
    }

    #[test]
    fn test_format_list_table() {
        let resp = ListResponse {
            paths: vec![
                "/ns/dev/app/DB_URL".to_string(),
                "/ns/dev/app/API_KEY".to_string(),
            ],
        };
        let output = format_list_table(&resp);
        assert!(output.contains("PATH"));
        assert!(output.contains("/ns/dev/app/DB_URL"));
        assert!(output.contains("/ns/dev/app/API_KEY"));
    }

    #[test]
    fn test_format_list_env() {
        let resp = ListResponse {
            paths: vec![
                "/ns/dev/app/DB_URL".to_string(),
                "/ns/dev/app/API_KEY".to_string(),
            ],
        };
        let output = format_list_env(&resp);
        assert_eq!(output, "DB_URL\nAPI_KEY");
    }

    #[test]
    fn test_format_get_env_extracts_last_segment() {
        let resp = SecretResponse {
            path: "/a/b/c/MY_SECRET".to_string(),
            value: "val".to_string(),
        };
        assert_eq!(format_get_env(&resp), "MY_SECRET=val");
    }
}

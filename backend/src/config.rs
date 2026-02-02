use anyhow::{bail, Context, Result};
use dotenvy::dotenv;

#[derive(Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub data_dir: String,
    pub listen_addr: String,
    pub base_url: String,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub session_secret: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        dotenv().ok();

        let database_url = env_var("DATABASE_URL")?;
        let data_dir = env_var_or("DATA_DIR", "./files".into());
        let listen_addr = env_var_or("LISTEN_ADDR", "0.0.0.0:5222".into());
        let base_url = env_var("BASE_URL")?;
        let github_client_id = env_var("GITHUB_CLIENT_ID")?;
        let github_client_secret = env_var("GITHUB_CLIENT_SECRET")?;
        let session_secret = env_var("SESSION_SECRET")?;

        Ok(Self {
            database_url,
            data_dir,
            listen_addr,
            base_url,
            github_client_id,
            github_client_secret,
            session_secret,
        })
    }
}

fn env_var(key: &str) -> Result<String> {
    let val = std::env::var(key).with_context(|| format!("missing env var {key}"))?;
    if val.trim().is_empty() {
        bail!("env var {key} is empty");
    }
    Ok(val)
}

fn env_var_or(key: &str, default: String) -> String {
    std::env::var(key).unwrap_or(default)
}

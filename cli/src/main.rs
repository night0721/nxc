use anyhow::Result;
use clap::{Parser, Subcommand};
use reqwest::Response;
use std::fs;
use std::path::Path;

#[derive(Parser)]
#[command(name = "nxc", version, about = "NXC paste/file/url CLI")]
struct Cli {
    #[arg(
        long,
        global = true,
        env = "NXC_BACKEND",
        default_value = "https://nxc.night0721.xyz"
    )]
    backend: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Upload a file (image as multipart, file as paste JSON)
    Upload {
        /// Upload as an image (multipart)
        #[arg(short = 'i', long, group = "input")]
        image: Option<String>,

        /// Upload as a general file (JSON paste)
        #[arg(short = 'f', long, group = "input")]
        file: Option<String>,
    },
    /// Shorten a URL
    Url { target_url: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Upload { image, file } => {
            let (path, endpoint) = if let Some(img_path) = image {
                (img_path, "image")
            } else if let Some(file_path) = file {
                (file_path, "file")
            } else {
                unreachable!("Clap group ensures one is present");
            };
            upload_file(&cli.backend, &path, endpoint).await?
        }
        Commands::Url { target_url } => shorten_url(&cli.backend, &target_url).await?,
    }

    Ok(())
}

async fn handle_res(res: Response) -> Result<()> {
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        eprintln!("Operation failed ({}): {}", status, body);
        std::process::exit(1);
    }

    let v: serde_json::Value = res.json().await?;
    if let Some(url) = v.get("url").and_then(|u| u.as_str()) {
        println!("{url}");
    } else if let Some(short) = v.get("short_url").and_then(|u| u.as_str()) {
        println!("{short}");
    } else {
        println!("{v}");
    }
    Ok(())
}

async fn upload_file(backend: &str, path: &str, endpoint: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let base = backend.trim_end_matches('/');

    if endpoint == "file" {
        /* Treat -f as a text paste */
        let content = fs::read_to_string(path)?;
        let url = format!("{}/api/paste", base);
        let body = serde_json::json!({
            "content": content,
            "title": Path::new(path).file_name().and_then(|s| s.to_str()),
            "syntax": None::<String>,
            "temp": false
        });
        let res = client.post(url).json(&body).send().await?;
        handle_res(res).await?;
    } else {
        /* Treat -i as a binary image upload */
        use reqwest::multipart::{Form, Part};
        let data = fs::read(path)?;
        let name = Path::new(path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("upload.bin");

        let form = Form::new().part("file", Part::bytes(data).file_name(name.to_string()));
        let url = format!("{}/api/image", base);
        let res = client.post(url).multipart(form).send().await?;
        handle_res(res).await?;
    }
    Ok(())
}

async fn shorten_url(backend: &str, target_url: &str) -> Result<()> {
    let url = format!("{}/api/url", backend.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let body = serde_json::json!({ "url": target_url });

    let res = client.post(url).json(&body).send().await?;
    handle_res(res).await
}

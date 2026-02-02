use crate::models::WebhookRecord;
use reqwest::Client;
use serde::Serialize;
use tracing::{error, info};

#[derive(Serialize)]
struct DiscordPayload {
    content: String,
}

pub fn dispatch<T: Serialize + Send + 'static>(
    webhooks: Vec<WebhookRecord>,
    event: String,
    data: T,
    display_msg: String, // Add a human-readable string for Discord
) {
    let client = Client::new();

    for hook in webhooks {
        let url = hook.target_url.clone();
        let is_discord = url.contains("discord.com/api/webhooks/");
        let secret = hook.secret.clone();
        let event_name = event.clone();

        // Clone the client for THIS specific task
        let client_clone = client.clone();

        let generic_body = serde_json::json!({ "event": event_name, "data": data });
        let discord_body = DiscordPayload {
            content: format!("**[{}]** {}", event_name.to_uppercase(), display_msg),
        };

        tokio::spawn(async move {
            let builder = client_clone.post(&url);

            let resp = if is_discord {
                builder.json(&discord_body).send().await
            } else {
                builder
                    .header("X-Webhook-Secret", secret)
                    .json(&generic_body)
                    .send()
                    .await
            };

            match resp {
                Ok(r) if r.status().is_success() => info!("Webhook delivered to {}", url),
                Ok(r) => error!("Webhook to {} returned {}", url, r.status()),
                Err(e) => error!("Webhook network error: {}", e),
            }
        });
    }
}

use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct UserRecord {
    pub id: Uuid,
    pub provider: String,
    pub provider_id: String,
    pub username: String,
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct FileRecord {
    pub id: Uuid,
    pub owner_id: Option<Uuid>,
    pub slug: String,
    pub path: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub title: Option<String>,
    pub syntax: Option<String>,
    pub password_hash: Option<String>,
    pub delete_at: Option<NaiveDateTime>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct UrlRecord {
    pub id: Uuid,
    pub owner_id: Option<Uuid>,
    pub slug: String,
    pub target_url: String,
    pub password_hash: Option<String>,
    pub expires_at: Option<NaiveDateTime>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WebhookRecord {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub target_url: String,
    pub secret: String,
    pub events: Vec<String>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
}

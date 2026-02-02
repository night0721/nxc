use crate::models::{FileRecord, PasteRecord, UrlRecord, UserRecord, WebhookRecord};
use anyhow::Result;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;

#[derive(Clone)]
pub struct Db {
    pub pool: PgPool,
}

impl Db {
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(10))
            .connect(database_url)
            .await?;

        Ok(Self { pool })
    }

    // Placeholder helpers for later expansion; keep simple for now
    pub async fn get_user_by_oauth(
        &self,
        provider: &str,
        provider_id: &str,
    ) -> Result<Option<UserRecord>> {
        let user = sqlx::query_as!(
            UserRecord,
            r#"SELECT id, provider, provider_id, username, avatar_url, created_at
               FROM users
               WHERE provider = $1 AND provider_id = $2"#,
            provider,
            provider_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn insert_user(
        &self,
        provider: &str,
        provider_id: &str,
        username: &str,
        avatar_url: Option<&str>,
    ) -> Result<UserRecord> {
        let user = sqlx::query_as!(
            UserRecord,
            r#"INSERT INTO users (provider, provider_id, username, avatar_url)
               VALUES ($1, $2, $3, $4)
               RETURNING id, provider, provider_id, username, avatar_url, created_at"#,
            provider,
            provider_id,
            username,
            avatar_url
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn get_user_by_id(&self, id: uuid::Uuid) -> Result<Option<UserRecord>> {
        let user = sqlx::query_as!(
            UserRecord,
            r#"SELECT id, provider, provider_id, username, avatar_url, created_at
               FROM users
               WHERE id = $1"#,
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn insert_file(&self, file: &FileRecord) -> Result<FileRecord> {
        let rec = sqlx::query_as!(
            FileRecord,
            r#"INSERT INTO files
                (id, owner_id, slug, path, kind, mime_type, size_bytes, is_temp, password_hash, delete_at, created_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
               RETURNING id, owner_id, slug, path, kind, mime_type, size_bytes, is_temp, password_hash, delete_at, created_at"#,
            file.id,
            file.owner_id,
            file.slug,
            file.path,
            file.kind,
            file.mime_type,
            file.size_bytes,
            file.is_temp,
            file.password_hash,
            file.delete_at,
            file.created_at
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(rec)
    }

    pub async fn get_file_by_slug(&self, slug: &str) -> Result<Option<FileRecord>> {
        let rec = sqlx::query_as!(
            FileRecord,
            r#"SELECT id, owner_id, slug, path, kind, mime_type, size_bytes, is_temp, password_hash, delete_at, created_at
               FROM files WHERE slug = $1"#,
            slug
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    pub async fn list_files(&self, owner_id: Option<uuid::Uuid>) -> Result<Vec<FileRecord>> {
        let rows = if let Some(owner_id) = owner_id {
            sqlx::query_as!(
                FileRecord,
                r#"SELECT id, owner_id, slug, path, kind, mime_type, size_bytes, is_temp, password_hash, delete_at, created_at
                   FROM files WHERE owner_id = $1 ORDER BY created_at DESC"#,
                owner_id
            )
            .fetch_all(&self.pool)
            .await?
        } else {
            // nothing as only authenticated users can see files
            vec![]
        };
        Ok(rows)
    }

    pub async fn list_pastes(&self, owner_id: Option<uuid::Uuid>) -> Result<Vec<PasteRecord>> {
        let rows = if let Some(owner_id) = owner_id {
            sqlx::query_as!(
                PasteRecord,
                r#"SELECT id, owner_id, slug, title, content, syntax, password_hash, is_temp, created_at
                   FROM pastes WHERE owner_id = $1 ORDER BY created_at DESC"#,
                owner_id
            )
            .fetch_all(&self.pool)
            .await?
        } else {
            vec![]
        };
        Ok(rows)
    }

    pub async fn list_urls(&self, owner_id: Option<uuid::Uuid>) -> Result<Vec<UrlRecord>> {
        let rows = if let Some(owner_id) = owner_id {
            sqlx::query_as!(
                UrlRecord,
                r#"SELECT id, owner_id, slug, target_url, password_hash, expires_at, created_at
                   FROM urls WHERE owner_id = $1 ORDER BY created_at DESC"#,
                owner_id
            )
            .fetch_all(&self.pool)
            .await?
        } else {
            vec![]
        };
        Ok(rows)
    }
    pub async fn delete_file_by_slug(&self, slug: &str) -> Result<Option<FileRecord>> {
        let rec = sqlx::query_as!(
            FileRecord,
            r#"DELETE FROM files
               WHERE slug = $1
               RETURNING id, owner_id, slug, path, kind, mime_type, size_bytes, is_temp, password_hash, delete_at, created_at"#,
            slug
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    pub async fn insert_paste(
        &self,
        owner_id: Option<uuid::Uuid>,
        slug: &str,
        title: Option<&str>,
        content: &str,
        syntax: Option<&str>,
        password_hash: Option<&str>,
        is_temp: bool,
    ) -> Result<PasteRecord> {
        let rec = sqlx::query_as!(
            PasteRecord,
            r#"INSERT INTO pastes
                (owner_id, slug, title, content, syntax, password_hash, is_temp)
               VALUES ($1,$2,$3,$4,$5,$6,$7)
               RETURNING id, owner_id, slug, title, content, syntax, password_hash, is_temp, created_at"#,
            owner_id,
            slug,
            title,
            content,
            syntax,
            password_hash,
            is_temp
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(rec)
    }

    pub async fn get_paste_by_slug(&self, slug: &str) -> Result<Option<PasteRecord>> {
        let rec = sqlx::query_as!(
            PasteRecord,
            r#"SELECT id, owner_id, slug, title, content, syntax, password_hash, is_temp, created_at
               FROM pastes WHERE slug = $1"#,
            slug
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    pub async fn delete_paste_by_slug(&self, slug: &str) -> Result<Option<PasteRecord>> {
        let rec = sqlx::query_as!(
            PasteRecord,
            r#"DELETE FROM pastes
               WHERE slug = $1
               RETURNING id, owner_id, slug, title, content, syntax, password_hash, is_temp, created_at"#,
            slug
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    pub async fn insert_url(
        &self,
        owner_id: Option<uuid::Uuid>,
        slug: &str,
        target_url: &str,
        password_hash: Option<&str>,
        expires_at: Option<chrono::NaiveDateTime>,
    ) -> Result<UrlRecord> {
        let rec = sqlx::query_as!(
            UrlRecord,
            r#"INSERT INTO urls
                (owner_id, slug, target_url, password_hash, expires_at)
               VALUES ($1,$2,$3,$4,$5)
               RETURNING id, owner_id, slug, target_url, password_hash, expires_at, created_at"#,
            owner_id,
            slug,
            target_url,
            password_hash,
            expires_at
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(rec)
    }

    pub async fn get_url_by_slug(&self, slug: &str) -> Result<Option<UrlRecord>> {
        let rec = sqlx::query_as!(
            UrlRecord,
            r#"SELECT id, owner_id, slug, target_url, password_hash, expires_at, created_at
               FROM urls WHERE slug = $1"#,
            slug
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    pub async fn delete_url_by_slug(&self, slug: &str) -> Result<Option<UrlRecord>> {
        let rec = sqlx::query_as!(
            UrlRecord,
            r#"DELETE FROM urls
               WHERE slug = $1
               RETURNING id, owner_id, slug, target_url, password_hash, expires_at, created_at"#,
            slug
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    pub async fn insert_webhook(&self, webhook: &WebhookRecord) -> Result<WebhookRecord> {
        let rec = sqlx::query_as!(
            WebhookRecord,
            r#"INSERT INTO webhooks
                (id, owner_id, target_url, secret, events, active, created_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7)
               RETURNING id, owner_id, target_url, secret, events, active, created_at"#,
            webhook.id,
            webhook.owner_id,
            webhook.target_url,
            webhook.secret,
            &webhook.events,
            webhook.active,
            webhook.created_at
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(rec)
    }

    pub async fn get_active_webhooks_for_event(
        &self,
        owner_id: Option<uuid::Uuid>,
        event: &str,
    ) -> Result<Vec<WebhookRecord>> {
        let recs = sqlx::query_as!(
            WebhookRecord,
            r#"SELECT id, owner_id, target_url, secret, events, active, created_at
               FROM webhooks
               WHERE owner_id = $1 AND active = true AND $2 = ANY(events)"#,
            owner_id,
            event
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(recs)
    }
}

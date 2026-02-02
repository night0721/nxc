use crate::config::AppConfig;
use crate::db::Db;
use crate::models::{FileRecord, WebhookRecord};
use crate::security::SESSION_COOKIE;
use crate::security::{
    build_session_cookie, hash_password, verify_password, AuthCtx, SessionClaims,
};
use anyhow::Result;
use askama::Template;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, get_service, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use oauth2::{
    basic::BasicClient, basic::BasicErrorResponseType, reqwest::Error as ReqwestError, AuthUrl,
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, RequestTokenError, Scope,
    StandardErrorResponse, TokenResponse, TokenUrl,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{NaiveDateTime, Utc};
use std::fs;
use std::path::Path as FsPath;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::fs as tfs;
use tokio::fs::File as TokioFile;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing::info;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub db: Db,
}

#[derive(Clone)]
struct GithubOAuth {
    client: BasicClient,
}

pub fn gen_slug(len: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}

type OAuthError =
    RequestTokenError<ReqwestError<reqwest::Error>, StandardErrorResponse<BasicErrorResponseType>>;

pub fn router(state: Arc<AppState>) -> Router {
    let oauth = build_github_client(&state.config);

    let serve_dir = ServeDir::new("build").not_found_service(ServeDir::new("build/index.html"));

    Router::new()
        // auth
        .route("/auth/github/login", get(github_login))
        .route("/auth/github/callback", get(github_callback))
        .route("/auth/me", get(get_current_user))
        .route("/auth/logout", post(logout))
        .route("/", get_service(serve_dir.clone()).post(universal_upload))
        // url shortener
        .route("/s/:slug", get(resolve_url))
        // files
        .route("/i/:slug", get(view_handler))
        .route("/i/:mode/:slug", get(serve_file_handler))
        // misc
        .route("/api/files", get(list_files))
        .route("/api/urls", get(list_urls))
        .route("/api/:kind/delete", post(delete_any))
        .route("/api/webhooks", post(create_webhook))
        .layer(DefaultBodyLimit::max(1024 * 1024 * 100))
        .with_state(state.clone())
        .fallback_service(serve_dir)
        .layer(
            TraceLayer::new_for_http()
                .on_request(|request: &Request<_>, _span: &tracing::Span| {
                    let uri = request.uri();
                    let method = request.method();
                    let ip = request
                        .headers()
                        .get(header::HOST)
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("unknown");
                    info!("Incoming request: [IP: {}] [{}] {}", ip, method, uri);
                })
                .on_response(
                    |response: &Response, latency: std::time::Duration, _span: &tracing::Span| {
                        info!(
                            "Finished with status {} in {:?}",
                            response.status(),
                            latency
                        );
                    },
                ),
        )
        .layer(axum::Extension(Arc::new(oauth)))
        .layer(axum::Extension::<Arc<AppConfig>>(Arc::new(
            state.config.clone(),
        )))
}

// Auth
fn build_github_client(config: &AppConfig) -> GithubOAuth {
    let client = BasicClient::new(
        ClientId::new(config.github_client_id.clone()),
        Some(ClientSecret::new(config.github_client_secret.clone())),
        AuthUrl::new("https://github.com/login/oauth/authorize".to_string()).unwrap(),
        Some(TokenUrl::new("https://github.com/login/oauth/access_token".to_string()).unwrap()),
    )
    .set_redirect_uri(
        RedirectUrl::new(format!("{}/auth/github/callback", config.base_url))
            .expect("invalid redirect url"),
    );

    GithubOAuth { client }
}

async fn github_login(
    axum::Extension(oauth): axum::Extension<Arc<GithubOAuth>>,
) -> impl IntoResponse {
    let (auth_url, _csrf) = oauth
        .client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("read:user".to_string()))
        .url();

    Redirect::temporary(&auth_url.to_string())
}

#[derive(Deserialize)]
struct GithubCallbackParams {
    code: String,
    //state: String,
}

async fn github_callback(
    State(state): State<Arc<AppState>>,
    axum::Extension(oauth): axum::Extension<Arc<GithubOAuth>>,
    jar: CookieJar,
    Query(params): Query<GithubCallbackParams>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    // Use reqwest directly for OAuth2 token exchange
    let token_res = oauth
        .client
        .exchange_code(AuthorizationCode::new(params.code))
        .request_async(|req| {
            let client = reqwest::Client::new();
            async move {
                let method = match req.method {
                    oauth2::http::Method::GET => reqwest::Method::GET,
                    oauth2::http::Method::POST => reqwest::Method::POST,
                    _ => {
                        return Err(OAuthError::Other("invalid oauth response".to_string()));
                    }
                };
                let mut builder = client.request(method, req.url.to_string());
                for (k, v) in req.headers.iter() {
                    builder = builder.header(k.as_str(), v.as_bytes());
                }
                if !req.body.is_empty() {
                    builder = builder.body(req.body);
                }
                let resp = builder
                    .send()
                    .await
                    .map_err(|e| RequestTokenError::Other(e.to_string()))?;
                let status = resp.status();
                let headers = resp.headers().clone();
                let body = resp
                    .bytes()
                    .await
                    .map_err(|e| RequestTokenError::Other(e.to_string()))?;
                Ok(oauth2::HttpResponse {
                    status_code: oauth2::http::StatusCode::from_u16(status.as_u16()).unwrap(),
                    headers: headers
                        .iter()
                        .map(|(k, v)| {
                            (
                                oauth2::http::HeaderName::from_bytes(k.as_str().as_bytes())
                                    .unwrap(),
                                oauth2::http::HeaderValue::from_bytes(v.as_bytes()).unwrap(),
                            )
                        })
                        .collect(),
                    body: body.to_vec(),
                })
            }
        })
        .await
        .map_err(|e| {
            eprintln!("OAUTH ERROR DETAIL: {:?}", e); // This will show in your terminal
            (StatusCode::BAD_GATEWAY, "oauth error")
        })?;

    let client = reqwest::Client::new();
    let user_res = client
        .get("https://api.github.com/user")
        .bearer_auth(token_res.access_token().secret())
        .header("User-Agent", "nxs")
        .send()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "github error"))?;

    let gh_user: serde_json::Value = user_res
        .json()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "github parse error"))?;

    let provider = "github";
    let provider_id = gh_user
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or((StatusCode::BAD_GATEWAY, "github user missing id"))?
        .to_string();
    let username = gh_user
        .get("login")
        .and_then(|v| v.as_str())
        .unwrap_or("github-user");
    let avatar_url = gh_user
        .get("avatar_url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let user = if let Some(user) = state
        .db
        .get_user_by_oauth(provider, &provider_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
    {
        user
    } else {
        state
            .db
            .insert_user(provider, &provider_id, username, avatar_url.as_deref())
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
    };

    let exp = (OffsetDateTime::now_utc() + time::Duration::days(30)).unix_timestamp() as usize;
    let claims = SessionClaims { sub: user.id, exp };
    let token = claims
        .encode(&state.config.session_secret)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "session error"))?;

    let cookie = build_session_cookie(&token);
    let jar = jar.add(cookie);
    let redirect = Redirect::temporary(&state.config.base_url);
    Ok((jar, redirect))
}

// Get user details for frontend
async fn get_current_user(
    State(state): State<Arc<AppState>>,
    auth: AuthCtx,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let user = state
        .db
        .get_user_by_id(auth.user_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or((StatusCode::UNAUTHORIZED, "unknown session"))?;

    Ok(Json(user))
}

async fn logout(jar: CookieJar) -> impl IntoResponse {
    // Remove the "session" cookie by adding a removal cookie to the jar
    let cookie = Cookie::build((SESSION_COOKIE, ""))
        .path("/")
        .max_age(time::Duration::ZERO) // Expire immediately
        .http_only(true)
        .build();
    (jar.add(cookie), StatusCode::OK)
}

async fn universal_upload(
    State(state): State<Arc<AppState>>,
    auth: Option<AuthCtx>,
    mut multipart: axum::extract::Multipart,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let owner_id = auth.map(|a| a.user_id);
    let slug = gen_slug(7);

    // Temp storage for multipart parsing
    let mut url_val: Option<String> = None;
    let mut content_val: Option<String> = None;
    let mut title_val: Option<String> = None;
    let mut syntax_val: Option<String> = None;
    let mut password_val: Option<String> = None;
    let mut expires_val: Option<String> = None;
    let mut file_data: Option<(String, String, i64)> = None; // (Path, Mime, Size)

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "multipart error"))?
    {
        let name = field.name().unwrap_or("").to_string();

        match name.as_str() {
            "url" => url_val = Some(field.text().await.unwrap_or_default()),
            "content" => content_val = Some(field.text().await.unwrap_or_default()),
            "title" => title_val = Some(field.text().await.unwrap_or_default()),
            "syntax" => syntax_val = Some(field.text().await.unwrap_or_default()),
            "password" => password_val = Some(field.text().await.unwrap_or_default()),
            "expires_at" => expires_val = Some(field.text().await.unwrap_or_default()),
            "file" => {
                let filename = field.file_name().map(|s| s.to_string());
                let mime = field
                    .content_type()
                    .unwrap_or("application/octet-stream")
                    .to_string();
                let dir = FsPath::new(&state.config.data_dir).join(&slug);
                tfs::create_dir_all(&dir)
                    .await
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "fs error"))?;

                let fname = filename.unwrap_or_else(|| slug.clone());
                let full_path = dir.join(&fname);
                let mut f = TokioFile::create(&full_path)
                    .await
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "fs error"))?;

                let mut size_bytes = 0;
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|_| (StatusCode::BAD_REQUEST, "read error"))?
                {
                    f.write_all(&chunk)
                        .await
                        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "write error"))?;
                    size_bytes += chunk.len() as i64;
                }
                file_data = Some((full_path.to_string_lossy().to_string(), mime, size_bytes));
                if title_val.is_none() {
                    title_val = Some(fname);
                }
            }
            _ => {}
        }
    }

    let expires_at = expires_val.and_then(|s| {
        // We try a few formats just in case
        NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S")
            .or_else(|_| NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M"))
            .ok()
    });

    let password_hash = password_val
        .filter(|p| !p.trim().is_empty()) // Don't hash empty strings
        .map(|p| hash_password(&p).unwrap_or_default());

    // URL Shortener
    if let Some(target) = url_val {
        let rec = state
            .db
            .insert_url(
                owner_id,
                &slug,
                &target,
                password_hash.as_deref(),
                expires_at,
            )
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

        let msg = format!(
            "New url: {}/s/{} => {}",
            state.config.base_url, rec.slug, target
        );
        dispatch_webhooks(&state, owner_id, "url.created", rec, msg).await;

        return Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": slug, "url": format!("{}/s/{}", state.config.base_url, slug) }))).into_response());
    }

    let final_rec = if let Some((path, mime, size)) = file_data {
        // It was a real file
        Some(FileRecord {
            id: Uuid::new_v4(),
            owner_id,
            slug: slug.clone(),
            path,
            mime_type: mime.clone(),
            size_bytes: size,
            title: title_val.clone(),
            syntax: Some(syntax_val.clone().unwrap_or_default()),
            password_hash: password_hash.clone(),
            delete_at: expires_at,
            created_at: Utc::now(),
        })
    } else if let Some(content) = content_val {
        // It was a paste, so we make it a file
        let dir = FsPath::new(&state.config.data_dir).join(&slug);
        fs::create_dir_all(&dir).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "fs error"))?;
        let full_path = dir.join(format!("{}.txt", slug));

        fs::write(&full_path, &content)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "write error"))?;
        Some(FileRecord {
            id: Uuid::new_v4(),
            owner_id,
            slug: slug.clone(),
            path: full_path.to_string_lossy().to_string(),
            mime_type: "text/plain".to_string(),
            size_bytes: content.len() as i64,
            title: title_val.clone(),
            syntax: Some(syntax_val.clone().unwrap_or_default()),
            password_hash: password_hash.clone(),
            delete_at: expires_at,
            created_at: Utc::now(),
        })
    } else {
        None
    };

    if let Some(rec) = final_rec {
        let rec = state.db.insert_file(&rec).await.map_err(|e| {
            eprintln!("❌ DATABASE ERROR: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "db error")
        })?;

        let msg = format!("New file: {}/i/{}", state.config.base_url, rec.slug);
        dispatch_webhooks(&state, owner_id, "file.created", rec, msg).await;

        return Ok((
            StatusCode::CREATED,
            Json(UploadResponse {
                id: slug.clone(),
                url: format!("{}/i/{}", state.config.base_url, slug),
                raw_url: format!("{}/i/raw/{}", state.config.base_url, slug),
                bin_url: format!("{}/i/bin/{}", state.config.base_url, slug),
            }),
        )
            .into_response());
    }

    Err((
        StatusCode::BAD_REQUEST,
        "Empty request: provide 'url', 'file', or 'content'",
    ))
}

// Helper to keep the main logic clean
async fn dispatch_webhooks<T: Serialize + Clone + Send + 'static>(
    state: &Arc<AppState>,
    owner: Option<Uuid>,
    event: &str,
    data: T,
    msg: String,
) {
    if let Ok(hooks) = state.db.get_active_webhooks_for_event(owner, event).await {
        crate::webhooks::dispatch(hooks, event.to_string(), data, msg);
    }
}

// URL Shortener
#[derive(Deserialize)]
struct UrlQuery {
    password: Option<String>,
}

async fn resolve_url(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    Query(q): Query<UrlQuery>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let rec = state
        .db
        .get_url_by_slug(&slug)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or((StatusCode::NOT_FOUND, "not found"))?;

    if let Some(expires_at) = rec.expires_at {
        if expires_at < Utc::now().naive_utc() {
            return Err((StatusCode::NOT_FOUND, "expired"));
        }
    }

    if let Some(hash) = rec.password_hash.as_deref() {
        let Some(pass) = q.password.as_deref() else {
            return Err((StatusCode::UNAUTHORIZED, "missing password"));
        };
        let ok = verify_password(pass, hash)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "verify error"))?;
        if !ok {
            return Err((StatusCode::UNAUTHORIZED, "bad password"));
        }
    }

    Ok(Redirect::temporary(&rec.target_url))
}

// Pastebin
#[derive(Deserialize)]
struct PasteQuery {
    password: Option<String>,
}

fn access_verify(
    password_hash: Option<&str>,
    provided_password: Option<&str>,
) -> Result<(), (StatusCode, &'static str)> {
    let Some(hash) = password_hash else {
        return Ok(());
    };

    let Some(pass) = provided_password else {
        return Err((StatusCode::UNAUTHORIZED, "missing password"));
    };

    let ok = verify_password(pass, hash)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "verify error"))?;
    if !ok {
        return Err((StatusCode::UNAUTHORIZED, "bad password"));
    }

    Ok(())
}

#[derive(Template)]
#[template(path = "view.html")]
struct ViewTemplate {
    title: String,
    created_at: String,
    syntax: String,
    content: String,
    slug: String,
    mime_type: String,
}

async fn view_handler(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    Query(q): Query<PasteQuery>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let rec = state
        .db
        .get_file_by_slug(&slug)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or((StatusCode::NOT_FOUND, "not found"))?;

    access_verify(rec.password_hash.as_deref(), q.password.as_deref())?;

    // 2. Prepare content if it's a text file/paste
    let is_text = rec.mime_type.starts_with("text/") || rec.syntax.is_some();

    let content = if is_text {
        // Only read into memory if we actually need to highlight it
        tokio::fs::read_to_string(&rec.path)
            .await
            .unwrap_or_else(|_| "Error reading file content".to_string())
    } else {
        String::new() // Binary files don't need 'content' in the HTML
    };

    Ok(ViewTemplate {
        title: rec.title.unwrap_or_else(|| rec.slug.clone()),
        created_at: rec.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        syntax: rec.syntax.unwrap_or_else(|| "plaintext".to_string()),
        slug: rec.slug,
        mime_type: rec.mime_type,
        content,
    })
}

// Files

#[derive(Serialize)]
struct UploadResponse {
    id: String,
    url: String,
    raw_url: String,
    bin_url: String,
}

async fn serve_file_handler(
    State(state): State<Arc<AppState>>,
    Path((mode, slug)): Path<(String, String)>, // mode is "raw" or "bin"
    Query(q): Query<UrlQuery>,
) -> Result<Response, (StatusCode, &'static str)> {
    let rec = state
        .db
        .get_file_by_slug(&slug)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or((StatusCode::NOT_FOUND, "not found"))?;

    // Verification
    access_verify(rec.password_hash.as_deref(), q.password.as_deref())?;

    let as_attachment = mode == "bin";
    serve_file(&rec.path, &rec.mime_type, as_attachment).await
}

async fn serve_file(
    path: &str,
    mime_type: &str,
    as_attachment: bool,
) -> Result<Response, (StatusCode, &'static str)> {
    let file = TokioFile::open(path)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "file missing"))?;
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    if as_attachment {
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment"),
        );
    }

    Ok((headers, body).into_response())
}

// List files

async fn list_files(
    State(state): State<Arc<AppState>>,
    auth: Option<AuthCtx>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let owner = auth.map(|a| a.user_id);
    let files = state
        .db
        .list_files(owner)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    Ok(Json(files))
}

async fn list_urls(
    State(state): State<Arc<AppState>>,
    auth: Option<AuthCtx>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let owner = auth.map(|a| a.user_id);
    let urls = state
        .db
        .list_urls(owner)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    Ok(Json(urls))
}

// Delete

#[derive(Deserialize)]
struct DeleteBody {
    id: String,
}

async fn delete_any(
    State(state): State<Arc<AppState>>,
    auth: AuthCtx,
    Path(kind): Path<String>,
    Json(body): Json<DeleteBody>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let user_id = auth.user_id;

    match kind.as_str() {
        "file" => {
            let rec = state
                .db
                .get_file_by_slug(&body.id)
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
                .ok_or((StatusCode::NOT_FOUND, "not found"))?;

            if rec.owner_id != Some(user_id) {
                return Err((StatusCode::FORBIDDEN, "denied"));
            }

            state
                .db
                .delete_file_by_slug(&body.id)
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
            let _ = fs::remove_file(&rec.path);
        }
        "url" => {
            let rec = state
                .db
                .get_url_by_slug(&body.id)
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
                .ok_or((StatusCode::NOT_FOUND, "not found"))?;

            if rec.owner_id != Some(user_id) {
                return Err((StatusCode::FORBIDDEN, "denied"));
            }

            state
                .db
                .delete_url_by_slug(&body.id)
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
        }
        _ => return Err((StatusCode::BAD_REQUEST, "unknown kind")),
    }

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct CreateWebhookBody {
    pub target_url: String,
}

pub async fn create_webhook(
    State(state): State<Arc<AppState>>,
    auth: AuthCtx,
    Json(body): Json<CreateWebhookBody>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let user_id = auth.user_id;

    if !body
        .target_url
        .starts_with("https://discord.com/api/webhooks/")
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Only Discord webhooks are supported for now",
        ));
    }

    let new_hook = WebhookRecord {
        id: uuid::Uuid::new_v4(),
        owner_id: user_id,
        target_url: body.target_url,
        secret: gen_slug(32),
        events: vec!["url.created".to_string(), "file.created".to_string()],
        active: true,
        created_at: chrono::Utc::now(),
    };

    state
        .db
        .insert_webhook(&new_hook)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to save webhook"))?;

    Ok(StatusCode::CREATED)
}

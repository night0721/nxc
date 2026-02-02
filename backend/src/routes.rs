use crate::config::AppConfig;
use crate::db::Db;
use crate::models::FileRecord;
use crate::security::{
    build_session_cookie, hash_password, verify_password, AuthCtx, SessionClaims,
};
use anyhow::Result;
use askama::Template;
use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::CookieJar;
use oauth2::{
    basic::BasicClient, basic::BasicErrorResponseType, reqwest::Error as ReqwestError, AuthUrl,
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, RequestTokenError, Scope,
    StandardErrorResponse, TokenResponse, TokenUrl,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{NaiveDateTime, Utc};
use std::fs;
use std::io::Write;
use std::path::Path as FsPath;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::fs::File as TokioFile;
use tokio::io::AsyncReadExt;
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
        // url shortener
        .route("/api/url", post(create_url))
        .route("/s/:slug", get(resolve_url))
        // pastebin
        .route("/api/paste", post(create_paste))
        .route("/p/:slug", get(view_paste))
        .route("/p/raw/:slug", get(raw_paste))
        // files
        .route("/api/file", post(upload_file))
        .route("/i/:slug", get(view_file))
        .route("/i/bin/:slug", get(raw_file))
        // misc
        .route("/api/files", get(list_files))
        .route("/api/pastes", get(list_pastes))
        .route("/api/urls", get(list_urls))
        .route("/api/:kind/delete", post(delete_any))
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

// URL Shortener

#[derive(Deserialize)]
struct CreateUrlBody {
    url: String,
    password: Option<String>,
    expires_at: Option<String>,
}

#[derive(Serialize)]
struct UrlResponse {
    id: String,
    short_url: String,
}

async fn create_url(
    State(state): State<Arc<AppState>>,
    auth: Option<AuthCtx>,
    Json(body): Json<CreateUrlBody>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let owner_id = auth.map(|a| a.user_id);
    let slug = gen_slug(7);
    let delete_hash = if let Some(password) = body.password.as_deref() {
        Some(
            hash_password(password)
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "hash error"))?,
        )
    } else {
        None
    };

    let expires_at = if let Some(s) = body.expires_at.as_deref() {
        Some(
            NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
                .map_err(|_| (StatusCode::BAD_REQUEST, "invalid expires_at"))?,
        )
    } else {
        None
    };

    let rec = state
        .db
        .insert_url(
            owner_id,
            &slug,
            &body.url,
            delete_hash.as_deref(),
            expires_at,
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    let short_url = format!("{}/s/{}", state.config.base_url, rec.slug);

    Ok((
        StatusCode::CREATED,
        Json(UrlResponse {
            id: rec.slug,
            short_url,
        }),
    ))
}

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
struct CreatePasteBody {
    content: String,
    title: Option<String>,
    syntax: Option<String>,
    password: Option<String>,
    temp: Option<bool>,
}

#[derive(Serialize)]
struct PasteResponse {
    id: String,
    url: String,
    raw_url: String,
}

async fn create_paste(
    State(state): State<Arc<AppState>>,
    auth: Option<AuthCtx>,
    Json(body): Json<CreatePasteBody>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    if body.content.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "empty content"));
    }
    let owner_id = auth.map(|a| a.user_id);
    let slug = gen_slug(7);
    let hash = if let Some(password) = body.password.as_deref() {
        Some(
            hash_password(password)
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "hash error"))?,
        )
    } else {
        None
    };

    let rec = state
        .db
        .insert_paste(
            owner_id,
            &slug,
            body.title.as_deref(),
            &body.content,
            body.syntax.as_deref(),
            hash.as_deref(),
            body.temp.unwrap_or(false),
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    let url = format!("{}/p/{}", state.config.base_url, rec.slug);
    let raw_url = format!("{}/p/raw/{}", state.config.base_url, rec.slug);

    Ok((
        StatusCode::CREATED,
        Json(PasteResponse {
            id: rec.slug,
            url,
            raw_url,
        }),
    ))
}

#[derive(Deserialize)]
struct PasteQuery {
    password: Option<String>,
}

#[derive(Template)]
#[template(path = "view.html")] // This looks in the /templates folder
struct PasteTemplate {
    title: String,
    content: String,
    syntax: String,
    created_at: String,
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

async fn view_paste(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    Query(q): Query<PasteQuery>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let rec = state
        .db
        .get_paste_by_slug(&slug)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or((StatusCode::NOT_FOUND, "not found"))?;

    access_verify(rec.password_hash.as_deref(), q.password.as_deref())?;

    let template = PasteTemplate {
        title: rec.title.clone().unwrap_or_else(|| "Untitled Paste".into()),
        content: rec.content,
        syntax: rec
            .syntax
            .clone()
            .unwrap_or_else(|| "plaintext".to_string()),
        created_at: rec.created_at.to_rfc3339(),
    };

    Ok(template)
}

async fn raw_paste(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    Query(q): Query<PasteQuery>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let rec = state
        .db
        .get_paste_by_slug(&slug)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or((StatusCode::NOT_FOUND, "not found"))?;

    access_verify(rec.password_hash.as_deref(), q.password.as_deref())?;

    Ok((
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        rec.content,
    )
        .into_response())
}

// File upload

#[derive(Serialize)]
struct UploadResponse {
    id: String,
    url: String,
    raw_url: String,
}

async fn upload_file(
    State(state): State<Arc<AppState>>,
    auth: Option<AuthCtx>,
    mut multipart: axum::extract::Multipart,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let owner_id = auth.map(|a| a.user_id);
    let slug = gen_slug(7);

    let mut filename = None;
    let mut mime = "application/octet-stream".to_string();
    let mut data: Vec<u8> = Vec::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid multipart"))?
    {
        if field.name() == Some("file") {
            filename = field.file_name().map(|s| s.to_string());
            if let Some(ct) = field.content_type() {
                mime = ct.to_string();
            }
            data = field
                .bytes()
                .await
                .map_err(|_| (StatusCode::BAD_REQUEST, "read error"))?
                .to_vec();
            break;
        }
    }

    if data.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "missing file"));
    }

    // determine kind
    let kind = if mime.starts_with("image/") {
        "image"
    } else if mime.starts_with("video/") {
        "video"
    } else {
        "file"
    }
    .to_string();

    let dir = FsPath::new(&state.config.data_dir).join("files");
    fs::create_dir_all(&dir).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "fs error"))?;
    let fname = filename.unwrap_or_else(|| format!("{slug}"));
    let full_path = dir.join(&fname);

    let mut f = fs::File::create(&full_path)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "fs error"))?;
    f.write_all(&data)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "fs error"))?;

    // Generate UUID v4 using rand
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 10

    let rec = FileRecord {
        id: Uuid::from_bytes(bytes),
        owner_id,
        slug: slug.clone(),
        path: full_path.to_string_lossy().to_string(),
        kind,
        mime_type: mime.clone(),
        size_bytes: data.len() as i64,
        is_temp: false,
        password_hash: None,
        delete_at: None,
        created_at: Utc::now(),
    };

    let rec = state
        .db
        .insert_file(&rec)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    let url = format!("{}/i/{}", state.config.base_url, rec.slug);
    let raw_url = format!("{}/i/bin/{}", state.config.base_url, rec.slug);

    Ok((
        StatusCode::CREATED,
        Json(UploadResponse {
            id: rec.slug,
            url,
            raw_url,
        }),
    ))
}

async fn view_file(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> Result<Response, (StatusCode, &'static str)> {
    let rec = state
        .db
        .get_file_by_slug(&slug)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or((StatusCode::NOT_FOUND, "not found"))?;

    serve_file(&rec.path, &rec.mime_type, false).await
}

async fn raw_file(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> Result<Response, (StatusCode, &'static str)> {
    let rec = state
        .db
        .get_file_by_slug(&slug)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        .ok_or((StatusCode::NOT_FOUND, "not found"))?;

    serve_file(&rec.path, &rec.mime_type, true).await
}

async fn serve_file(
    path: &str,
    mime_type: &str,
    as_attachment: bool,
) -> Result<Response, (StatusCode, &'static str)> {
    let mut file = TokioFile::open(path)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "file missing"))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "read error"))?;

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

    Ok((headers, Body::from(buf)).into_response())
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

async fn list_pastes(
    State(state): State<Arc<AppState>>,
    auth: Option<AuthCtx>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let owner = auth.map(|a| a.user_id);
    let pastes = state
        .db
        .list_pastes(owner)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    Ok(Json(pastes))
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
    Path(kind): Path<String>,
    Json(body): Json<DeleteBody>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    match kind.as_str() {
        "file" => {
            if let Some(rec) = state
                .db
                .delete_file_by_slug(&body.id)
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
            {
                let _ = fs::remove_file(&rec.path);
            }
        }
        "paste" => {
            state
                .db
                .delete_paste_by_slug(&body.id)
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;
        }
        "url" => {
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

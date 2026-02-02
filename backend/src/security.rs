use crate::config::AppConfig;
use anyhow::Result;
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::{request::Parts, StatusCode};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub const SESSION_COOKIE: &str = "nxc_session";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: Uuid,
    pub exp: usize,
}

impl SessionClaims {
    pub fn encode(&self, secret: &str) -> Result<String> {
        let key = EncodingKey::from_secret(secret.as_bytes());
        let token = encode(&Header::default(), self, &key)?;
        Ok(token)
    }

    pub fn decode(token: &str, secret: &str) -> Result<Self> {
        let key = DecodingKey::from_secret(secret.as_bytes());
        let data = decode::<SessionClaims>(token, &key, &Validation::default())?;
        Ok(data.claims)
    }
}

pub fn hash_password(password: &str) -> Result<String> {
    let mut rng = rand::thread_rng();
    let salt = SaltString::generate(&mut rng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Password hash error: {}", e))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash).map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))?;
    let argon2 = Argon2::default();
    Ok(argon2.verify_password(password.as_bytes(), &parsed).is_ok())
}

#[derive(Clone)]
pub struct AuthCtx {
    pub user_id: Uuid,
}

#[derive(Clone)]
pub struct SharedSecrets {
    pub config: Arc<AppConfig>,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthCtx
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let Some(cookie) = jar.get(SESSION_COOKIE) else {
            return Err((StatusCode::UNAUTHORIZED, "missing session"));
        };

        let secret = parts
            .extensions
            .get::<Arc<AppConfig>>()
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "missing config"))?
            .session_secret
            .clone();

        let claims = SessionClaims::decode(cookie.value(), &secret)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid session"))?;

        Ok(AuthCtx {
            user_id: claims.sub,
        })
    }
}

pub fn build_session_cookie(token: &str) -> Cookie<'static> {
    let cookie = Cookie::build((SESSION_COOKIE, token.to_owned()))
        .http_only(true)
        .path("/")
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .permanent()
        .build();
    cookie
}

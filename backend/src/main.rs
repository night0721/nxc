mod config;
mod db;
mod models;
mod routes;
mod security;
mod webhooks;

use crate::config::AppConfig;
use crate::db::Db;
use crate::routes::router;
use anyhow::Context;
use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing / logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("nxs=info,tower_http=info")),
        )
        .with_target(false)
        .compact()
        .init();

    // load configuration from env
    let config = AppConfig::from_env().context("failed to load configuration")?;
    let db = Db::connect(&config.database_url).await?;

    sqlx::migrate!("./migrations")
        .run(&db.pool)
        .await
        .context("failed to run database migrations")?;

    let shared_state = Arc::new(routes::AppState { config, db });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let middleware = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    let app: Router = router(shared_state.clone()).layer(middleware);

    // listen on special CLI port 5222 by default
    let addr: SocketAddr = shared_state
        .config
        .listen_addr
        .parse()
        .context("invalid LISTEN_ADDR")?;

    tracing::info!("nxs listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("failed to bind TCP listener")?;

    axum::serve(listener, app).await?;

    Ok(())
}

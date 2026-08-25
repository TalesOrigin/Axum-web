mod config;
mod db;
mod error;
mod models;
mod routes;
mod security;
mod services;
mod state;

use anyhow::Context;
use config::Config;
use sqlx::postgres::PgPoolOptions;
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpListener;
use tracing::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config = Config::from_env().context("loading configuration")?;

    let pool = PgPoolOptions::new()
        .min_connections(config.database_min_connections)
        .max_connections(config.database_max_connections)
        .acquire_timeout(Duration::from_secs(config.database_acquire_timeout_seconds))
        .connect(&config.database_url)
        .await
        .context("connecting to PostgreSQL")?;

    if config.run_migrations {
        info!("running database migrations");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("running migrations")?;
    }

    db::bootstrap_admin(&pool, &config)
        .await
        .context("bootstrapping administrator")?;

    let state = state::AppState::new(pool, config.clone());
    let app = routes::router(state);

    let listener = TcpListener::bind(config.http_addr)
        .await
        .with_context(|| format!("binding HTTP listener on {}", config.http_addr))?;

    info!(
        address = %config.http_addr,
        environment = %config.app_env,
        public_base_url = config.public_base_url.as_deref().unwrap_or(""),
        "Axum-web licensing platform started"
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("serving HTTP")?;

    Ok(())
}

fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "axum_web=info,tower_http=info,sqlx=warn".into());

    let json_logs = std::env::var("LOG_FORMAT")
        .map(|value| value.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    if json_logs {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .with_current_span(true)
            .with_span_list(true)
            .init();
    } else {
        tracing_subscriber::fmt()
            .compact()
            .with_env_filter(env_filter)
            .init();
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    error!("shutdown signal received; draining in-flight requests");
}

mod auth;
mod db;
mod handlers;
mod middleware;
mod webhook;

use std::net::SocketAddr;

use anyhow::{Context, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::auth::JwtConfig;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub jwt: JwtConfig,
    pub webhook_secret: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("VPN API server starting...");

    // Database connection
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            warn!("DATABASE_URL not set, using default");
            "postgres://vpn:vpn@localhost:5432/vpn".to_string()
        });

    let db_pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&database_url)
        .await
        .context("failed to connect to database")?;

    info!("Database connected");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .context("failed to run database migrations")?;

    info!("Migrations applied");

    // JWT configuration — require secrets in production
    let is_production = std::env::var("APP_ENV")
        .map(|v| v == "production")
        .unwrap_or(false);

    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
        if is_production {
            panic!("JWT_SECRET must be set in production");
        }
        warn!("JWT_SECRET not set, using default (INSECURE — dev only)");
        "dev-jwt-secret-change-in-production".to_string()
    });
    let vpn_session_secret = std::env::var("VPN_SESSION_SECRET").unwrap_or_else(|_| {
        if is_production {
            panic!("VPN_SESSION_SECRET must be set in production");
        }
        warn!("VPN_SESSION_SECRET not set, using default (INSECURE — dev only)");
        "dev-vpn-session-secret-change-in-production".to_string()
    });

    let jwt_config = JwtConfig::new(jwt_secret, vpn_session_secret);

    // Webhook secret for HMAC verification
    let webhook_secret = std::env::var("WEBHOOK_SECRET").ok();
    if webhook_secret.is_none() {
        if is_production {
            panic!("WEBHOOK_SECRET must be set in production");
        }
        warn!("WEBHOOK_SECRET not set — webhook signature verification disabled");
    }

    let state = AppState {
        db: db_pool,
        jwt: jwt_config.clone(),
        webhook_secret,
    };

    // CORS configuration
    let cors = if let Ok(origins) = std::env::var("ALLOWED_ORIGINS") {
        let allowed: Vec<_> = origins
            .split(',')
            .filter_map(|o| o.trim().parse().ok())
            .collect();
        info!(count = allowed.len(), "CORS: configured allowed origins");
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(allowed))
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
            ])
    } else {
        if is_production {
            panic!("ALLOWED_ORIGINS must be set in production");
        }
        warn!("ALLOWED_ORIGINS not set, using permissive CORS (dev only)");
        CorsLayer::permissive()
    };

    // Rate limiter state (shared across requests)
    let rate_limiter = middleware::RateLimiter::new(
        std::env::var("RATE_LIMIT_RPM")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30), // 30 requests per minute by default
    );

    // Build router
    let auth_routes = Router::new()
        .route("/auth/register", post(handlers::register))
        .route("/auth/login", post(handlers::login))
        .route("/auth/logout", post(handlers::logout))
        .route("/auth/refresh", post(handlers::refresh))
        .layer(axum::middleware::from_fn_with_state(
            rate_limiter.clone(),
            middleware::rate_limit_middleware,
        ));

    let app = Router::new()
        .merge(auth_routes)
        // Protected routes
        .route("/servers", get(handlers::list_servers))
        .route("/connect", post(handlers::connect))
        .route("/disconnect", post(handlers::disconnect))
        .route("/account", get(handlers::account_info))
        // Webhooks
        .route("/webhooks/revenuecat", post(webhook::revenuecat_webhook))
        // Health (checks DB connectivity)
        .route("/health", get(health_check))
        // Middleware
        .layer(DefaultBodyLimit::max(1024 * 64)) // 64 KB max body
        .layer(Extension(jwt_config))
        .layer(axum::middleware::from_fn(middleware::request_id_middleware))
        .layer(axum::middleware::from_fn(middleware::metrics_middleware))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state.clone());

    // Start metrics server on a separate localhost-only listener
    let metrics_addr: SocketAddr = std::env::var("METRICS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9091".to_string())
        .parse()
        .context("invalid metrics listen address")?;

    let metrics_app = Router::new()
        .route("/metrics", get(middleware::metrics_handler));

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(metrics_addr).await.unwrap();
        info!(addr = %metrics_addr, "Metrics server listening (localhost only)");
        axum::serve(listener, metrics_app).await.ok();
    });

    // Background: rate limiter cleanup every 5 minutes
    let rl_clone = rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            rl_clone.cleanup_stale_entries();
        }
    });

    // Background: revoked token cleanup every hour
    let db_for_cleanup = state.db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match db::Db::cleanup_expired_tokens(&db_for_cleanup).await {
                Ok(n) => {
                    if n > 0 {
                        info!(deleted = n, "Cleaned up expired revoked tokens");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to cleanup expired tokens");
                }
            }
        }
    });

    // Background: stale session cleanup every 30 minutes
    let db_for_sessions = state.db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1800));
        loop {
            interval.tick().await;
            match db::Db::cleanup_stale_sessions(&db_for_sessions, 24).await {
                Ok(n) => {
                    if n > 0 {
                        info!(cleaned = n, "Cleaned up stale sessions (>24h without disconnect)");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to cleanup stale sessions");
                }
            }
        }
    });

    // Start server with graceful shutdown
    let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let addr: SocketAddr = listen_addr.parse().context("invalid listen address")?;

    info!(addr = %addr, "API server listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("API server shut down gracefully");
    Ok(())
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
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("Received Ctrl+C, shutting down..."),
        _ = terminate => info!("Received SIGTERM, shutting down..."),
    }
}

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))).into_response(),
        Err(e) => {
            warn!(error = %e, "Health check: database unreachable");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"status": "unhealthy", "error": "database unreachable"})),
            )
                .into_response()
        }
    }
}

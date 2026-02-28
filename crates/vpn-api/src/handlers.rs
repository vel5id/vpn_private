//! API route handlers.

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::db::Db;
use crate::AppState;

// ─── Request / Response types ──────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct ServerInfo {
    pub id: Uuid,
    pub name: String,
    pub hostname: String,
    pub region: String,
    pub load: f64,
}

#[derive(Debug, Deserialize)]
pub struct ConnectRequest {
    pub server_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct ConnectResponse {
    pub session_token: String,
    pub hostname: String,
    pub port: u16,
    pub session_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct DisconnectRequest {
    pub session_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct AccountInfo {
    pub email: String,
    pub subscription: Option<SubscriptionInfo>,
}

#[derive(Debug, Serialize)]
pub struct SubscriptionInfo {
    pub tier: String,
    pub status: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

fn error_response(status: StatusCode, msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: msg.to_string(),
        }),
    )
}

// ─── Handlers ──────────────────────────────────────────

/// POST /auth/register
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    // Normalize email
    let email = req.email.trim().to_lowercase();

    // Validate input
    if !is_valid_email(&email) {
        return error_response(StatusCode::BAD_REQUEST, "Invalid email").into_response();
    }
    if req.password.len() < 8 {
        return error_response(StatusCode::BAD_REQUEST, "Password must be at least 8 characters")
            .into_response();
    }
    if req.password.len() > 128 {
        return error_response(StatusCode::BAD_REQUEST, "Password too long")
            .into_response();
    }
    // Require at least one uppercase, one lowercase, and one digit
    if !req.password.chars().any(|c| c.is_uppercase())
        || !req.password.chars().any(|c| c.is_lowercase())
        || !req.password.chars().any(|c| c.is_ascii_digit())
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            "Password must contain uppercase, lowercase, and a digit",
        )
        .into_response();
    }

    // Check if user already exists
    match Db::find_user_by_email(&state.db, &email).await {
        Ok(Some(_)) => {
            return error_response(StatusCode::CONFLICT, "Email already registered").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Database error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
        Ok(None) => {}
    }

    // Hash password
    let password_hash = match hash_password(&req.password) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!(error = %e, "Password hashing failed");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
    };

    // Create user
    let user = match Db::create_user(&state.db, &email, &password_hash).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create user");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
    };

    // Generate tokens
    let access_token = match state.jwt.create_access_token(user.id) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create access token");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
    };
    let refresh_token = match state.jwt.create_refresh_token(user.id) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create refresh token");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
    };

    (
        StatusCode::CREATED,
        Json(AuthResponse {
            access_token,
            refresh_token,
            user_id: user.id,
        }),
    )
        .into_response()
}

/// POST /auth/login
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let email = req.email.trim().to_lowercase();

    let user = match Db::find_user_by_email(&state.db, &email).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Database error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
    };

    // Verify password
    if !verify_password(&req.password, &user.password_hash) {
        return error_response(StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

    let access_token = match state.jwt.create_access_token(user.id) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create access token");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
    };
    let refresh_token = match state.jwt.create_refresh_token(user.id) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create refresh token");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
    };

    Json(AuthResponse {
        access_token,
        refresh_token,
        user_id: user.id,
    })
    .into_response()
}

/// POST /auth/logout — revoke the current refresh token.
pub async fn logout(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<LogoutRequest>,
) -> impl IntoResponse {
    // Hash the refresh token for storage
    use ring::digest;
    let token_hash = hex::encode(digest::digest(&digest::SHA256, req.refresh_token.as_bytes()));

    // Decode the token to get its expiration time
    let expires_at = match state.jwt.validate_refresh_token(&req.refresh_token) {
        Ok(claims) => {
            chrono::DateTime::from_timestamp(claims.exp, 0)
                .unwrap_or_else(chrono::Utc::now)
        }
        Err(_) => {
            // Even if the token is invalid/expired, return success
            // (don't leak information about token validity)
            return StatusCode::NO_CONTENT.into_response();
        }
    };

    match Db::revoke_token(&state.db, &token_hash, auth.user_id, expires_at).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to revoke token");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}

/// POST /auth/refresh — exchange a valid refresh token for a new access token.
pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> impl IntoResponse {
    // Validate the refresh token
    let claims = match state.jwt.validate_refresh_token(&req.refresh_token) {
        Ok(c) => c,
        Err(_) => {
            return error_response(StatusCode::UNAUTHORIZED, "Invalid or expired refresh token")
                .into_response();
        }
    };

    // Check if the token has been revoked
    use ring::digest;
    let token_hash = hex::encode(digest::digest(&digest::SHA256, req.refresh_token.as_bytes()));
    match Db::is_token_revoked(&state.db, &token_hash).await {
        Ok(true) => {
            return error_response(StatusCode::UNAUTHORIZED, "Token has been revoked")
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to check token revocation");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
        Ok(false) => {}
    }

    // Issue a new access token
    let access_token = match state.jwt.create_access_token(claims.sub) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create access token");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
    };

    Json(AuthResponse {
        access_token,
        refresh_token: req.refresh_token,
        user_id: claims.sub,
    })
    .into_response()
}

/// GET /servers
pub async fn list_servers(
    State(state): State<AppState>,
    _auth: AuthUser,
) -> impl IntoResponse {
    let servers = match Db::list_active_servers(&state.db).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "Failed to list servers");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
    };

    let mut server_infos = Vec::new();
    for server in servers {
        let active = match Db::active_session_count_for_server(&state.db, server.id).await {
            Ok(count) => count,
            Err(e) => {
                tracing::warn!(server_id = %server.id, error = %e, "Failed to count sessions, assuming 0");
                0
            }
        };
        let load = if server.capacity > 0 {
            active as f64 / server.capacity as f64
        } else {
            0.0
        };

        server_infos.push(ServerInfo {
            id: server.id,
            name: server.name,
            hostname: server.hostname,
            region: server.region,
            load,
        });
    }

    Json(server_infos).into_response()
}

/// POST /connect
pub async fn connect(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<ConnectRequest>,
) -> impl IntoResponse {
    // Check active subscription
    let _subscription = match Db::get_active_subscription(&state.db, auth.user_id).await {
        Ok(Some(sub)) => sub,
        Ok(None) => {
            return error_response(StatusCode::PAYMENT_REQUIRED, "Active subscription required")
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Database error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
    };

    // Per-user session limit (max 3 simultaneous connections)
    const MAX_USER_SESSIONS: i64 = 3;
    let user_sessions = Db::active_session_count_for_user(&state.db, auth.user_id)
        .await
        .unwrap_or(0);
    if user_sessions >= MAX_USER_SESSIONS {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Maximum simultaneous sessions reached",
        )
        .into_response();
    }

    // Find server
    let server = match Db::find_server_by_id(&state.db, req.server_id).await {
        Ok(Some(s)) if s.is_active => s,
        Ok(_) => {
            return error_response(StatusCode::NOT_FOUND, "Server not found or inactive")
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Database error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
    };

    // Check capacity
    let active = Db::active_session_count_for_server(&state.db, server.id)
        .await
        .unwrap_or(0);
    if active >= server.capacity as i64 {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "Server at capacity")
            .into_response();
    }

    // Create session record
    let session = match Db::create_session(&state.db, auth.user_id, server.id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create session");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
    };

    // Generate VPN session token (JWT for the VPN server)
    let session_token = match state.jwt.create_session_token(auth.user_id, server.id) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create session token");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
    };

    Json(ConnectResponse {
        session_token,
        hostname: server.hostname,
        port: 443,
        session_id: session.id,
    })
    .into_response()
}

/// POST /disconnect
pub async fn disconnect(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<DisconnectRequest>,
) -> impl IntoResponse {
    // Verify the session belongs to the authenticated user
    match Db::find_session_by_id(&state.db, req.session_id).await {
        Ok(Some(session)) => {
            if session.user_id != auth.user_id {
                return error_response(StatusCode::FORBIDDEN, "Session does not belong to you")
                    .into_response();
            }
        }
        Ok(None) => {
            return error_response(StatusCode::NOT_FOUND, "Session not found").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Database error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
    }

    match Db::end_session(&state.db, req.session_id, 0, 0).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to end session");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}

/// GET /account
pub async fn account_info(
    State(state): State<AppState>,
    auth: AuthUser,
) -> impl IntoResponse {
    let user = match Db::find_user_by_id(&state.db, auth.user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return error_response(StatusCode::NOT_FOUND, "User not found").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Database error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
                .into_response();
        }
    };

    let subscription = Db::get_active_subscription(&state.db, auth.user_id)
        .await
        .ok()
        .flatten()
        .map(|sub| SubscriptionInfo {
            tier: sub.tier,
            status: sub.status,
            expires_at: sub.expires_at.to_rfc3339(),
        });

    Json(AccountInfo {
        email: user.email,
        subscription,
    })
    .into_response()
}

// ─── Password helpers ──────────────────────────────────

fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    use argon2::Argon2;
    use password_hash::{PasswordHasher, SaltString, rand_core::OsRng};

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::Argon2;
    use password_hash::{PasswordHash, PasswordVerifier};

    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Validate email with basic structural checks (no heavy regex crate).
fn is_valid_email(email: &str) -> bool {
    if email.len() > 254 || email.is_empty() {
        return false;
    }
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if parts.len() != 2 {
        return false;
    }
    let (local, domain) = (parts[0], parts[1]);
    if local.is_empty() || local.len() > 64 {
        return false;
    }
    if domain.is_empty() || !domain.contains('.') {
        return false;
    }
    // No whitespace allowed
    if email.contains(char::is_whitespace) {
        return false;
    }
    true
}

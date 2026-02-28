//! Database models and queries.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// ─── Users ──────────────────────────────────────────────

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
}

// ─── Subscriptions ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[allow(dead_code)]
pub enum SubscriptionTier {
    Monthly,
    Yearly,
}

impl std::fmt::Display for SubscriptionTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Monthly => write!(f, "monthly"),
            Self::Yearly => write!(f, "yearly"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[allow(dead_code)]
pub enum SubscriptionStatus {
    Active,
    Expired,
    Cancelled,
}

impl std::fmt::Display for SubscriptionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Expired => write!(f, "expired"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Subscription {
    pub id: Uuid,
    pub user_id: Uuid,
    pub tier: String,
    pub status: String,
    pub provider: String,
    pub provider_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

// ─── Servers ────────────────────────────────────────────

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Server {
    pub id: Uuid,
    pub name: String,
    pub hostname: String,
    pub region: String,
    pub capacity: i32,
    pub is_active: bool,
}

// ─── Sessions ───────────────────────────────────────────

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub server_id: Uuid,
    pub connected_at: DateTime<Utc>,
    pub disconnected_at: Option<DateTime<Utc>>,
    pub bytes_up: i64,
    pub bytes_down: i64,
}

// ─── Database Queries ───────────────────────────────────

pub struct Db;

impl Db {
    // --- Users ---

    pub async fn create_user(
        pool: &sqlx::PgPool,
        email: &str,
        password_hash: &str,
    ) -> Result<User, sqlx::Error> {
        sqlx::query_as::<_, User>(
            r#"INSERT INTO users (email, password_hash) VALUES ($1, $2)
               RETURNING id, email, password_hash, created_at"#,
        )
        .bind(email)
        .bind(password_hash)
        .fetch_one(pool)
        .await
    }

    pub async fn find_user_by_email(
        pool: &sqlx::PgPool,
        email: &str,
    ) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, created_at FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(pool)
        .await
    }

    pub async fn find_user_by_id(
        pool: &sqlx::PgPool,
        id: Uuid,
    ) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, created_at FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    // --- Subscriptions ---

    pub async fn get_active_subscription(
        pool: &sqlx::PgPool,
        user_id: Uuid,
    ) -> Result<Option<Subscription>, sqlx::Error> {
        sqlx::query_as::<_, Subscription>(
            r#"SELECT id, user_id, tier, status, provider, provider_id, expires_at, created_at
               FROM subscriptions
               WHERE user_id = $1 AND status = 'active' AND expires_at > now()
               ORDER BY expires_at DESC
               LIMIT 1"#,
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn upsert_subscription(
        pool: &sqlx::PgPool,
        user_id: Uuid,
        tier: &str,
        status: &str,
        provider: &str,
        provider_id: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> Result<Subscription, sqlx::Error> {
        sqlx::query_as::<_, Subscription>(
            r#"INSERT INTO subscriptions (user_id, tier, status, provider, provider_id, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (user_id, provider) DO UPDATE
               SET tier = $2, status = $3, provider_id = $5, expires_at = $6
               RETURNING id, user_id, tier, status, provider, provider_id, expires_at, created_at"#,
        )
        .bind(user_id)
        .bind(tier)
        .bind(status)
        .bind(provider)
        .bind(provider_id)
        .bind(expires_at)
        .fetch_one(pool)
        .await
    }

    pub async fn update_subscription_status(
        pool: &sqlx::PgPool,
        provider_id: &str,
        status: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Option<Subscription>, sqlx::Error> {
        let query = if let Some(exp) = expires_at {
            sqlx::query_as::<_, Subscription>(
                r#"UPDATE subscriptions SET status = $2, expires_at = $3
                   WHERE provider_id = $1
                   RETURNING id, user_id, tier, status, provider, provider_id, expires_at, created_at"#,
            )
            .bind(provider_id)
            .bind(status)
            .bind(exp)
            .fetch_optional(pool)
            .await
        } else {
            sqlx::query_as::<_, Subscription>(
                r#"UPDATE subscriptions SET status = $2
                   WHERE provider_id = $1
                   RETURNING id, user_id, tier, status, provider, provider_id, expires_at, created_at"#,
            )
            .bind(provider_id)
            .bind(status)
            .fetch_optional(pool)
            .await
        };
        query
    }

    // --- Servers ---

    pub async fn list_active_servers(
        pool: &sqlx::PgPool,
    ) -> Result<Vec<Server>, sqlx::Error> {
        sqlx::query_as::<_, Server>(
            "SELECT id, name, hostname, region, capacity, is_active FROM servers WHERE is_active = true",
        )
        .fetch_all(pool)
        .await
    }

    pub async fn find_server_by_id(
        pool: &sqlx::PgPool,
        server_id: Uuid,
    ) -> Result<Option<Server>, sqlx::Error> {
        sqlx::query_as::<_, Server>(
            "SELECT id, name, hostname, region, capacity, is_active FROM servers WHERE id = $1",
        )
        .bind(server_id)
        .fetch_optional(pool)
        .await
    }

    // --- Sessions ---

    pub async fn create_session(
        pool: &sqlx::PgPool,
        user_id: Uuid,
        server_id: Uuid,
    ) -> Result<Session, sqlx::Error> {
        sqlx::query_as::<_, Session>(
            r#"INSERT INTO sessions (user_id, server_id)
               VALUES ($1, $2)
               RETURNING id, user_id, server_id, connected_at, disconnected_at, bytes_up, bytes_down"#,
        )
        .bind(user_id)
        .bind(server_id)
        .fetch_one(pool)
        .await
    }

    pub async fn find_session_by_id(
        pool: &sqlx::PgPool,
        session_id: Uuid,
    ) -> Result<Option<Session>, sqlx::Error> {
        sqlx::query_as::<_, Session>(
            "SELECT id, user_id, server_id, connected_at, disconnected_at, bytes_up, bytes_down FROM sessions WHERE id = $1",
        )
        .bind(session_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn end_session(
        pool: &sqlx::PgPool,
        session_id: Uuid,
        bytes_up: i64,
        bytes_down: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"UPDATE sessions SET disconnected_at = now(), bytes_up = $2, bytes_down = $3
               WHERE id = $1"#,
        )
        .bind(session_id)
        .bind(bytes_up)
        .bind(bytes_down)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn active_session_count_for_server(
        pool: &sqlx::PgPool,
        server_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sessions WHERE server_id = $1 AND disconnected_at IS NULL",
        )
        .bind(server_id)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Count active sessions for a user across all servers.
    pub async fn active_session_count_for_user(
        pool: &sqlx::PgPool,
        user_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND disconnected_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Clean up stale sessions (connected more than `max_age` ago without disconnect).
    pub async fn cleanup_stale_sessions(
        pool: &sqlx::PgPool,
        max_age_hours: i64,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"UPDATE sessions
               SET disconnected_at = now()
               WHERE disconnected_at IS NULL
                 AND connected_at < now() - ($1 || ' hours')::interval"#,
        )
        .bind(max_age_hours.to_string())
        .execute(pool)
        .await?;
        Ok(result.rows_affected())
    }

    // --- Revoked Tokens ---

    /// Revoke a token by storing its hash.
    pub async fn revoke_token(
        pool: &sqlx::PgPool,
        token_hash: &str,
        user_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"INSERT INTO revoked_tokens (token_hash, user_id, expires_at)
               VALUES ($1, $2, $3)
               ON CONFLICT (token_hash) DO NOTHING"#,
        )
        .bind(token_hash)
        .bind(user_id)
        .bind(expires_at)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Check if a token has been revoked.
    pub async fn is_token_revoked(
        pool: &sqlx::PgPool,
        token_hash: &str,
    ) -> Result<bool, sqlx::Error> {
        let row: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE token_hash = $1)",
        )
        .bind(token_hash)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Clean up expired revoked tokens.
    pub async fn cleanup_expired_tokens(
        pool: &sqlx::PgPool,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM revoked_tokens WHERE expires_at < now()")
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }
}

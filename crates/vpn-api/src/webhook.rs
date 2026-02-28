//! RevenueCat webhook handler.
//!
//! Handles subscription lifecycle events from RevenueCat:
//! - INITIAL_PURCHASE / RENEWAL → activate subscription
//! - CANCELLATION → mark cancelled
//! - EXPIRATION → mark expired
//!
//! Webhook requests are authenticated via HMAC-SHA256 signature
//! in the `X-RevenueCat-Signature` header.

use axum::{extract::State, http::StatusCode, response::IntoResponse};
use chrono::{DateTime, Utc};
use ring::hmac;
use serde::Deserialize;
use tracing::{error, info, warn};

use crate::db::Db;
use crate::AppState;

/// RevenueCat webhook event envelope.
#[derive(Debug, Deserialize)]
pub struct WebhookEvent {
    pub event: EventData,
}

/// RevenueCat event data.
#[derive(Debug, Deserialize)]
pub struct EventData {
    /// Event type.
    #[serde(rename = "type")]
    pub event_type: String,
    /// RevenueCat app user ID (maps to our user ID).
    pub app_user_id: String,
    /// Product identifier.
    pub product_id: Option<String>,
    /// Expiration date (ISO 8601).
    pub expiration_at_ms: Option<i64>,
    /// The customer's RevenueCat ID.
    pub id: Option<String>,
    /// Store that originated the event: APP_STORE, PLAY_STORE, STRIPE, etc.
    pub store: Option<String>,
}

/// POST /webhooks/revenuecat
pub async fn revenuecat_webhook(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Verify HMAC signature if webhook secret is configured
    if let Some(ref secret) = state.webhook_secret {
        let signature = match headers.get("x-revenuecat-signature") {
            Some(sig) => match sig.to_str() {
                Ok(s) => s.to_string(),
                Err(_) => {
                    warn!("Invalid signature header encoding");
                    return StatusCode::UNAUTHORIZED;
                }
            },
            None => {
                warn!("Missing X-RevenueCat-Signature header");
                return StatusCode::UNAUTHORIZED;
            }
        };

        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let expected = hex::encode(hmac::sign(&key, &body));

        if !constant_time_eq(signature.as_bytes(), expected.as_bytes()) {
            warn!("Webhook signature mismatch");
            return StatusCode::UNAUTHORIZED;
        }
    }

    // Parse the verified body
    let payload: WebhookEvent = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "Failed to parse webhook payload");
            return StatusCode::BAD_REQUEST;
        }
    };

    let event = &payload.event;
    info!(
        event_type = %event.event_type,
        user = %event.app_user_id,
        "RevenueCat webhook received"
    );

    // Parse user ID
    let user_id = match uuid::Uuid::parse_str(&event.app_user_id) {
        Ok(id) => id,
        Err(_) => {
            warn!(
                user = %event.app_user_id,
                "Invalid user ID in webhook, ignoring"
            );
            return StatusCode::OK;
        }
    };

    // Determine tier from product_id
    let tier = event
        .product_id
        .as_deref()
        .map(|p| {
            if p.contains("yearly") || p.contains("annual") {
                "yearly"
            } else {
                "monthly"
            }
        })
        .unwrap_or("monthly");

    // Parse expiration
    let expires_at = event
        .expiration_at_ms
        .map(|ms| {
            DateTime::from_timestamp(ms / 1000, ((ms % 1000) * 1_000_000) as u32)
                .unwrap_or_else(Utc::now)
        })
        .unwrap_or_else(|| Utc::now() + chrono::Duration::days(30));

    let provider_id = event.id.as_deref().unwrap_or("");

    // Determine provider from RevenueCat store field
    let provider = match event.store.as_deref() {
        Some("PLAY_STORE") => "google",
        Some("STRIPE") => "stripe",
        Some("PROMOTIONAL") => "promotional",
        _ => "apple", // APP_STORE or unknown defaults to apple
    };

    match event.event_type.as_str() {
        "INITIAL_PURCHASE" | "RENEWAL" | "PRODUCT_CHANGE" | "UNCANCELLATION" => {
            match Db::upsert_subscription(
                &state.db,
                user_id,
                tier,
                "active",
                provider,
                Some(provider_id),
                expires_at,
            )
            .await
            {
                Ok(sub) => {
                    info!(
                        user = %user_id,
                        tier = tier,
                        expires = %sub.expires_at,
                        "Subscription activated/renewed"
                    );
                }
                Err(e) => {
                    error!(error = %e, user = %user_id, "Failed to update subscription");
                    return StatusCode::INTERNAL_SERVER_ERROR;
                }
            }
        }

        "CANCELLATION" => {
            if !provider_id.is_empty() {
                match Db::update_subscription_status(&state.db, provider_id, "cancelled", None)
                    .await
                {
                    Ok(Some(_sub)) => {
                        info!(
                            user = %user_id,
                            "Subscription cancelled"
                        );
                    }
                    Ok(None) => {
                        warn!(
                            provider_id = provider_id,
                            "Subscription not found for cancellation"
                        );
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to cancel subscription");
                        return StatusCode::INTERNAL_SERVER_ERROR;
                    }
                }
            }
        }

        "EXPIRATION" => {
            if !provider_id.is_empty() {
                match Db::update_subscription_status(
                    &state.db,
                    provider_id,
                    "expired",
                    Some(expires_at),
                )
                .await
                {
                    Ok(Some(_)) => {
                        info!(user = %user_id, "Subscription expired");
                    }
                    Ok(None) => {
                        warn!(
                            provider_id = provider_id,
                            "Subscription not found for expiration"
                        );
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to expire subscription");
                        return StatusCode::INTERNAL_SERVER_ERROR;
                    }
                }
            }
        }

        other => {
            info!(event_type = other, "Ignoring unhandled webhook event type");
        }
    }

    StatusCode::OK
}

/// Constant-time byte comparison to prevent timing attacks on signatures.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

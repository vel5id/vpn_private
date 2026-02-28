//! JWT authentication for the API.

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWT claims for API authentication (access token).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// User ID.
    pub sub: Uuid,
    /// Expiration (Unix timestamp).
    pub exp: i64,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Token type: "access" or "refresh".
    pub token_type: String,
}

/// JWT claims for VPN session tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionTokenClaims {
    /// User ID.
    pub sub: Uuid,
    /// Server ID.
    pub server_id: Uuid,
    /// Expiration (Unix timestamp).
    pub exp: i64,
    /// Issued at (Unix timestamp).
    pub iat: i64,
}

/// JWT configuration.
#[derive(Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
    /// Shared secret for VPN session tokens (used by both API and VPN server).
    pub vpn_session_secret: String,
}

impl JwtConfig {
    pub fn new(secret: String, vpn_session_secret: String) -> Self {
        Self {
            secret,
            access_token_ttl: Duration::minutes(15),
            refresh_token_ttl: Duration::days(7),
            vpn_session_secret,
        }
    }

    /// Create an access token.
    pub fn create_access_token(&self, user_id: Uuid) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id,
            exp: (now + self.access_token_ttl).timestamp(),
            iat: now.timestamp(),
            token_type: "access".to_string(),
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
    }

    /// Create a refresh token.
    pub fn create_refresh_token(&self, user_id: Uuid) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id,
            exp: (now + self.refresh_token_ttl).timestamp(),
            iat: now.timestamp(),
            token_type: "refresh".to_string(),
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
    }

    /// Validate an access token and return claims.
    pub fn validate_access_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &Validation::default(),
        )?;
        if token_data.claims.token_type != "access" {
            return Err(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            ));
        }
        Ok(token_data.claims)
    }

    /// Validate a refresh token and return claims.
    pub fn validate_refresh_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &Validation::default(),
        )?;
        if token_data.claims.token_type != "refresh" {
            return Err(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            ));
        }
        Ok(token_data.claims)
    }

    /// Create a VPN session token (sent to VPN server during handshake).
    pub fn create_session_token(
        &self,
        user_id: Uuid,
        server_id: Uuid,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let claims = SessionTokenClaims {
            sub: user_id,
            server_id,
            exp: (now + Duration::hours(24)).timestamp(),
            iat: now.timestamp(),
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.vpn_session_secret.as_bytes()),
        )
    }
}

/// Authenticated user ID, extracted from the Authorization header.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
}

/// Axum extractor for authenticated requests.
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid Authorization format"))?;

        // Get JWT config from extensions
        let jwt_config = parts
            .extensions
            .get::<JwtConfig>()
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "JWT config not found"))?;

        let claims = jwt_config
            .validate_access_token(token)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;

        if claims.token_type != "access" {
            return Err((StatusCode::UNAUTHORIZED, "Invalid token type"));
        }

        Ok(AuthUser {
            user_id: claims.sub,
        })
    }
}

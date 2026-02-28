//! Custom middleware: rate limiting, request ID tracing, Prometheus metrics.

use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use prometheus::{Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

// ─── Rate Limiter ──────────────────────────────────────

/// Simple sliding-window rate limiter based on IP address.
#[derive(Clone)]
pub struct RateLimiter {
    /// Map from IP → list of request timestamps (as epoch millis).
    entries: Arc<DashMap<IpAddr, Vec<Instant>>>,
    /// Max requests per window.
    max_requests: u32,
    /// Window duration (1 minute).
    window: std::time::Duration,
}

impl RateLimiter {
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            max_requests: max_requests_per_minute,
            window: std::time::Duration::from_secs(60),
        }
    }

    /// Check if a request from the given IP is allowed.
    fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;

        let mut entry = self.entries.entry(ip).or_default();
        // Remove expired entries
        entry.retain(|t| *t > cutoff);
        if entry.len() >= self.max_requests as usize {
            return false;
        }
        entry.push(now);
        true
    }

    /// Remove stale entries from the rate limiter map to prevent memory leaks.
    /// Should be called periodically from a background task.
    pub fn cleanup_stale_entries(&self) {
        let now = Instant::now();
        let cutoff = now - self.window;
        self.entries.retain(|_ip, timestamps| {
            timestamps.retain(|t| *t > cutoff);
            !timestamps.is_empty()
        });
    }
}

/// Rate limiting middleware for auth routes.
pub async fn rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Prefer the real connection IP to avoid X-Forwarded-For spoofing.
    // Only use X-Forwarded-For when ConnectInfo is unavailable (i.e. behind reverse proxy).
    let ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
        .or_else(|| {
            req.headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .and_then(|s| s.trim().parse::<IpAddr>().ok())
        })
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

    if !limiter.check(ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", "60")],
            "Too many requests",
        )
            .into_response();
    }

    next.run(req).await
}

// ─── Request ID ────────────────────────────────────────

/// Adds a unique X-Request-Id header to every request/response and logs it.
pub async fn request_id_middleware(
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    req.headers_mut().insert(
        "x-request-id",
        request_id.parse().expect("valid header value"),
    );

    // Store in extensions for handlers to access
    req.extensions_mut().insert(RequestId(request_id.clone()));

    let mut response = next.run(req).await;

    response.headers_mut().insert(
        "x-request-id",
        request_id.parse().expect("valid header value"),
    );

    response
}

/// Request ID stored in extensions for handlers to access.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct RequestId(pub String);

// ─── Prometheus Metrics ────────────────────────────────

lazy_static::lazy_static! {
    static ref REGISTRY: Registry = Registry::new();

    static ref HTTP_REQUESTS_TOTAL: IntCounterVec = {
        let opts = Opts::new("http_requests_total", "Total HTTP requests")
            .namespace("vpn_api");
        let counter = IntCounterVec::new(opts, &["method", "path", "status"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    static ref HTTP_REQUEST_DURATION: HistogramVec = {
        let opts = HistogramOpts::new("http_request_duration_seconds", "HTTP request duration")
            .namespace("vpn_api")
            .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]);
        let histogram = HistogramVec::new(opts, &["method", "path"]).unwrap();
        REGISTRY.register(Box::new(histogram.clone())).unwrap();
        histogram
    };
}

/// Middleware to record request metrics.
pub async fn metrics_middleware(
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = req.method().to_string();
    // Normalize path to avoid cardinality explosion (strip UUIDs etc.)
    let path = normalize_path(req.uri().path());

    let start = Instant::now();
    let response = next.run(req).await;
    let duration = start.elapsed().as_secs_f64();

    let status = response.status().as_u16().to_string();

    HTTP_REQUESTS_TOTAL
        .with_label_values(&[&method, &path, &status])
        .inc();
    HTTP_REQUEST_DURATION
        .with_label_values(&[&method, &path])
        .observe(duration);

    response
}

/// GET /metrics — expose Prometheus metrics.
pub async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    if encoder.encode(&metric_families, &mut buffer).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to encode metrics".to_string());
    }
    (StatusCode::OK, String::from_utf8(buffer).unwrap_or_default())
}

/// Normalize URL paths to prevent label cardinality explosion.
fn normalize_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    let normalized: Vec<&str> = segments
        .iter()
        .map(|s| {
            // Replace UUID-like segments with :id
            if s.len() == 36 && s.chars().filter(|c| *c == '-').count() == 4 {
                ":id"
            } else {
                s
            }
        })
        .collect();
    normalized.join("/")
}

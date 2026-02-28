# ── Stage 1: Build all Rust binaries ────────────────────────────
FROM rust:1.88-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev cmake clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# sqlx uses runtime string queries (query_as::<>), no compile-time DB needed.
# Only sqlx::migrate!() macro needs the migrations dir (already copied).
RUN cargo build --release --workspace

# ── Stage 2: vpn-api runtime ───────────────────────────────────
FROM debian:bookworm-slim AS vpn-api
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/vpn-api /usr/local/bin/vpn-api
COPY crates/vpn-api/migrations/ /app/migrations/
WORKDIR /app
EXPOSE 8080
CMD ["vpn-api"]

# ── Stage 3: vpn-server runtime ────────────────────────────────
FROM debian:bookworm-slim AS vpn-server
RUN apt-get update && apt-get install -y ca-certificates iproute2 iptables && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/vpn-server /usr/local/bin/vpn-server
WORKDIR /app
EXPOSE 443
CMD ["vpn-server"]

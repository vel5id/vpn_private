-- Phase 3: Database schema for VPN API
-- Run with: sqlx migrate run

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- Subscriptions table
CREATE TABLE IF NOT EXISTS subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tier TEXT NOT NULL CHECK (tier IN ('monthly', 'yearly')),
    status TEXT NOT NULL CHECK (status IN ('active', 'expired', 'cancelled')),
    provider TEXT NOT NULL DEFAULT 'apple',
    provider_id TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions (user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_provider_id ON subscriptions (provider_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_active
    ON subscriptions (user_id) WHERE status = 'active';

-- Servers table
CREATE TABLE IF NOT EXISTS servers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    region TEXT NOT NULL,
    capacity INT NOT NULL DEFAULT 100,
    is_active BOOLEAN NOT NULL DEFAULT true
);

-- Seed initial servers
INSERT INTO servers (name, hostname, region, capacity, is_active) VALUES
    ('US East', 'us-east.vpn.example.com', 'us-east', 100, true),
    ('EU West', 'eu-west.vpn.example.com', 'eu-west', 100, true),
    ('Asia Tokyo', 'asia-tokyo.vpn.example.com', 'asia-tokyo', 100, true)
ON CONFLICT DO NOTHING;

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    connected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    disconnected_at TIMESTAMPTZ,
    bytes_up BIGINT NOT NULL DEFAULT 0,
    bytes_down BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_server_id ON sessions (server_id);
CREATE INDEX IF NOT EXISTS idx_sessions_active
    ON sessions (server_id) WHERE disconnected_at IS NULL;

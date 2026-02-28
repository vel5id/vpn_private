# VPN Service — MVP Project Plan

**Goal:** Ship a working iOS VPN app with custom obfuscated protocol, subscription billing, and 2-3 server locations.

**Timeline:** ~10-12 weeks
**Team:** Solo dev + Claude Code Agent
**Revenue model:** Apple IAP via RevenueCat

---

## Architecture Overview

```
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│   iOS App    │──TLS──│  VPN Node    │──NAT──│  Internet    │
│   (Swift)    │       │  (Rust)      │       │              │
└──────┬───────┘       └──────────────┘       └──────────────┘
       │
       │ HTTPS
       ▼
┌──────────────┐
│  API Backend │
│  (Rust/Axum) │
│  + PostgreSQL│
└──────────────┘
```

### Shared Rust Core (`vpn-core` crate)
Compiled for both `aarch64-apple-ios` and `x86_64-unknown-linux-gnu`.
Handles: crypto, handshake, framing, tunnel I/O.

---

## Phase 0: Project Scaffolding (Week 1)

### Task 0.1: Monorepo Setup

Create workspace structure:

```
vpn-project/
├── Cargo.toml              # workspace root
├── crates/
│   ├── vpn-core/           # shared protocol library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── crypto.rs
│   │       ├── handshake.rs
│   │       ├── framing.rs
│   │       └── tunnel.rs
│   ├── vpn-server/         # VPN node binary
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   └── vpn-api/            # API backend binary
│       ├── Cargo.toml
│       └── src/main.rs
├── ios/                    # Xcode project (created separately)
├── deploy/                 # Ansible playbooks
└── docs/
```

**Success criteria:** `cargo build --workspace` compiles. CI runs `cargo test --workspace` and `cargo clippy`.

### Task 0.2: CI/CD

- GitHub Actions: lint, test, build on every push
- Separate job for cross-compilation to `aarch64-apple-ios` (can be manual trigger initially)

---

## Phase 1: Protocol Core — `vpn-core` (Weeks 2-4)

Build bottom-up. Each layer has tests before implementation.

### Task 1.1: Crypto Primitives (`crypto.rs`)

Dependencies: `ring` or `aws-lc-rs`

Implement:
- `KeyPair` — X25519 keypair generation
- `SharedSecret` — X25519 ECDH
- `SessionKeys` — HKDF-SHA256 derivation (client_key, server_key, client_iv, server_iv)
- `encrypt(key, nonce, plaintext) -> ciphertext` — ChaCha20-Poly1305
- `decrypt(key, nonce, ciphertext) -> plaintext` — ChaCha20-Poly1305
- Nonce counter (u64, incremented per packet)

**Tests:**
- Roundtrip: encrypt then decrypt returns original
- Wrong key fails decryption
- Nonce reuse detection (counter must increment)
- Known test vectors from RFC 7539

**Success criteria:** All tests pass. No custom crypto — only `ring` primitives.

### Task 1.2: Framing (`framing.rs`)

Wire format for tunnel packets:

```
┌─────────┬──────────┬─────────────┬─────┐
│ Length   │ Type     │ Payload     │ Tag │
│ 2 bytes │ 1 byte   │ variable    │ 16B │
└─────────┴──────────┴─────────────┴─────┘
```

Types:
- `0x01` — Data (tunneled IP packet)
- `0x02` — Ping
- `0x03` — Pong
- `0x04` — Handshake

Implement:
- `Frame` enum
- `encode(frame) -> bytes`
- `decode(bytes) -> Result<Frame, Error>` (streaming decoder with internal buffer)
- Max frame size: 65535 bytes

**Tests:**
- Roundtrip encode/decode for each frame type
- Partial reads (feed bytes one at a time, verify buffering works)
- Oversized frame rejection
- Malformed length handling

### Task 1.3: Handshake (`handshake.rs`)

Simple 1-RTT handshake inside TLS:

```
Client → Server: ClientHello { client_ephemeral_pubkey, session_token }
Server → Client: ServerHello { server_ephemeral_pubkey, encrypted_config }

Both derive session keys from ECDH shared secret.
encrypted_config contains: assigned_ip, dns_servers, mtu
```

`session_token` is a JWT obtained from the API backend (proves subscription is active).

Implement:
- `ClientHandshake::initiate() -> (ClientHello, EphemeralSecret)`
- `ServerHandshake::respond(client_hello, token_validator) -> (ServerHello, SessionKeys)`
- `ClientHandshake::finalize(server_hello, secret) -> SessionKeys`

**Tests:**
- Successful handshake between client and server instances
- Invalid token rejection
- Key derivation produces different keys for client→server vs server→client directions

### Task 1.4: Tunnel I/O (`tunnel.rs`)

Async read/write over any `AsyncRead + AsyncWrite` transport.

```rust
pub struct Tunnel<T: AsyncRead + AsyncWrite> {
    transport: T,
    session_keys: SessionKeys,
    send_nonce: Counter,
    recv_nonce: Counter,
}

impl<T: AsyncRead + AsyncWrite> Tunnel<T> {
    pub async fn send(&mut self, data: &[u8]) -> Result<()>;
    pub async fn recv(&mut self) -> Result<Vec<u8>>;
}
```

**Tests:**
- Roundtrip over `tokio::io::duplex`
- Concurrent send/recv (bidirectional)
- Ping/pong keepalive

**Success criteria for Phase 1:** Integration test — two in-memory tunnel endpoints exchange 10,000 packets with verified integrity. Benchmarks show >500 Mbps throughput on localhost.

---

## Phase 2: VPN Server — `vpn-server` (Weeks 4-6)

### Task 2.1: TLS Listener with TLS Camouflage

- `tokio-rustls` TLS 1.3 acceptor
- Valid Let's Encrypt certificate (certbot on deploy)
- Server also serves a basic HTTPS landing page on `/` (camouflage — looks like a normal website)
- VPN handshake starts only after a specific HTTP upgrade path (e.g., `POST /ws` or WebSocket upgrade to blend in)

**Success criteria:** `curl https://your-server.com/` returns a landing page. DPI sees normal HTTPS.

### Task 2.2: TUN Device Management

- Create TUN interface on Linux (`/dev/net/tun` via ioctl)
- Assign IP range per server (e.g., `10.8.0.0/24`)
- Assign unique IP per client session from the pool
- NAT via iptables masquerade (configured by deploy scripts)

Dependencies: `tun` crate or raw ioctl.

**Tests:**
- TUN creation and read/write on Linux
- IP assignment/release from pool

### Task 2.3: Packet Routing

Main server loop:

```
for each connected client:
    tokio::spawn(async {
        loop {
            select! {
                // Encrypted packet from client → decrypt → write to TUN
                packet = tunnel.recv() => { tun.write(decrypt(packet)) }
                // IP packet from TUN → encrypt → send to client
                packet = tun.read() => { tunnel.send(encrypt(packet)) }
            }
        }
    })
```

- Route packets by destination IP → correct client session
- Kill switch: drop packets if session expired
- Configurable idle timeout (disconnect after 5 min no data)

**Tests:**
- End-to-end: client connects, sends ICMP ping through tunnel, receives reply
- Multiple concurrent clients
- Client disconnect cleanup (IP returned to pool)

### Task 2.4: Metrics & Health

- Prometheus `/metrics` endpoint (behind localhost-only bind or auth)
- Metrics: active_connections, bytes_in, bytes_out, handshake_failures
- `/health` endpoint for load balancer

---

## Phase 3: API Backend — `vpn-api` (Weeks 5-6)

### Task 3.1: Database Schema

PostgreSQL via `sqlx` (compile-time checked queries).

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    tier TEXT NOT NULL,              -- 'monthly', 'yearly'
    status TEXT NOT NULL,            -- 'active', 'expired', 'cancelled'
    provider TEXT NOT NULL,          -- 'apple'
    provider_id TEXT,                -- RevenueCat customer ID
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE servers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,              -- 'US East', 'EU West'
    hostname TEXT NOT NULL,
    region TEXT NOT NULL,
    capacity INT NOT NULL,
    is_active BOOLEAN DEFAULT true
);

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    server_id UUID REFERENCES servers(id),
    connected_at TIMESTAMPTZ DEFAULT now(),
    disconnected_at TIMESTAMPTZ,
    bytes_up BIGINT DEFAULT 0,
    bytes_down BIGINT DEFAULT 0
);
```

**Success criteria:** `sqlx migrate run` applies schema. Compile-time query checks pass.

### Task 3.2: API Endpoints

Framework: `axum` + `tower` middleware.

```
POST /auth/register         { email, password } → { token }
POST /auth/login            { email, password } → { token }

GET  /servers               → [{ id, name, region, load }]    (auth required)
POST /connect               { server_id } → { session_token, hostname, port }
POST /disconnect            { session_id }

POST /webhooks/revenuecat   (RevenueCat server webhook — updates subscription status)
GET  /account               → { email, subscription, usage }
```

Auth: JWT (HS256, short-lived access + refresh token pattern).

The `session_token` from `/connect` is what the client sends in the VPN handshake. It's a JWT containing: `{ user_id, server_id, exp }`. The VPN server validates it with a shared secret.

**Tests:**
- Register → login → get servers → connect flow (integration test with test DB)
- Expired subscription cannot connect
- RevenueCat webhook updates subscription

### Task 3.3: RevenueCat Integration

- Server-side webhook handler at `POST /webhooks/revenuecat`
- Events to handle: `INITIAL_PURCHASE`, `RENEWAL`, `CANCELLATION`, `EXPIRATION`
- On purchase/renewal: update `subscriptions.status = 'active'`, update `expires_at`
- On cancellation/expiration: update status accordingly

No client-side RevenueCat SDK validation needed on backend — RevenueCat handles Apple receipt validation and pushes events via webhook.

---

## Phase 4: iOS App (Weeks 6-9)

### Task 4.1: Rust → Swift FFI Bridge

Use `uniffi` to expose `vpn-core` to Swift.

Exposed interface:
```
fn create_tunnel_config(session_token: String, server_host: String, server_port: u16) -> TunnelConfig
fn perform_handshake(config: TunnelConfig) -> SessionHandle
fn encrypt_packet(handle: SessionHandle, data: Vec<u8>) -> Vec<u8>
fn decrypt_packet(handle: SessionHandle, data: Vec<u8>) -> Vec<u8>
```

Build as `libvpn_core.a` for `aarch64-apple-ios`.

**Success criteria:** Swift test target can call Rust functions and roundtrip encrypt/decrypt.

### Task 4.2: Network Extension

`NEPacketTunnelProvider` subclass:

```swift
class VPNTunnelProvider: NEPacketTunnelProvider {
    override func startTunnel(options: [String: NSObject]?) async throws {
        // 1. Read config from options (server host, session token)
        // 2. Open TLS connection to VPN server
        // 3. Perform handshake via Rust FFI
        // 4. Configure TUN: setTunnelNetworkSettings(...)
        // 5. Start packet forwarding loop
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
        // Cleanup
    }
}
```

Packet forwarding loop:
```swift
// Read from TUN → encrypt → send to server
packetFlow.readPackets { packets, protocols in
    for packet in packets {
        let encrypted = encrypt_packet(handle, packet)
        tlsConnection.send(encrypted)
    }
}

// Read from server → decrypt → write to TUN
while let data = try await tlsConnection.receive() {
    let decrypted = decrypt_packet(handle, data)
    packetFlow.writePackets([decrypted], withProtocols: [AF_INET])
}
```

**Memory constraint:** Extension process limited to ~15 MB. Monitor with `os_proc_available_memory()`.

**Success criteria:** VPN tunnel establishes on device. `curl ifconfig.me` through tunnel shows server IP.

### Task 4.3: Main App UI (SwiftUI)

Screens:
1. **Onboarding / Auth** — email + password register/login
2. **Home** — big connect button, current server, connection status, up/down speed
3. **Server List** — list of servers with ping latency, region flags
4. **Settings** — kill switch toggle, auto-connect on untrusted Wi-Fi, account info
5. **Subscription** — paywall (RevenueCat `PaywallView`)

Communication with extension:
- Start/stop: `NETunnelProviderManager.loadAllFromPreferences()` then `connection.startVPNTunnel()`
- Status: observe `NEVPNStatusDidChange` notification
- Config passing: via `protocolConfiguration.providerConfiguration` dictionary

### Task 4.4: RevenueCat Client SDK

- Initialize with API key on app launch
- Check subscription status: `Purchases.shared.customerInfo`
- Present paywall for non-subscribers
- Products: monthly ($9.99), yearly ($59.99)
- Free trial: 7 days (configured in App Store Connect)
- Gate the connect button behind active subscription

---

## Phase 5: Deployment & Infrastructure (Weeks 8-10)

### Task 5.1: Server Provisioning (Ansible)

Playbook that sets up a VPN node:

```yaml
# deploy/playbook.yml
- hosts: vpn_nodes
  tasks:
    - name: Install dependencies (build tools, certbot)
    - name: Copy vpn-server binary
    - name: Setup TUN interface
    - name: Configure iptables NAT
    - name: Obtain Let's Encrypt cert (certbot)
    - name: Create systemd service for vpn-server
    - name: Configure firewall (only 443 open)
    - name: Setup Prometheus node_exporter
```

Initial servers:
- US East (Vultr, New Jersey) — ~$6/mo
- EU West (Hetzner, Finland) — ~€4/mo
- Asia (Vultr, Tokyo) — ~$6/mo

### Task 5.2: API Backend Deployment

- Single VPS (Hetzner, cheapest) — ~€4/mo
- PostgreSQL on same machine (sufficient for MVP)
- Nginx reverse proxy + Let's Encrypt
- systemd service for vpn-api binary
- Automated DB backups (pg_dump cron → S3-compatible storage)

### Task 5.3: Monitoring

- Prometheus on API server, scraping all nodes
- Grafana dashboards: connections, bandwidth, errors, latency
- Alerting: PagerDuty or Telegram bot for downtime

---

## Phase 6: Polish & App Store (Weeks 10-12)

### Task 6.1: App Store Preparation

- Apple Developer Account ($99/yr)
- Create App ID with Network Extension capability
- App Store Connect: app listing, screenshots, description
- Privacy Policy page (hosted on landing site)
- Terms of Service page
- Focus marketing copy on "security" and "privacy", not "bypass" or "unblock"

### Task 6.2: Testing Checklist

- [ ] VPN connects and tunnels traffic on Wi-Fi
- [ ] VPN connects on cellular
- [ ] VPN reconnects after network switch (Wi-Fi → cellular)
- [ ] Kill switch blocks traffic when VPN drops
- [ ] Subscription paywall blocks unpaid users
- [ ] Subscription purchase flow works end-to-end
- [ ] Server switching works without app restart
- [ ] Memory usage stays under 15 MB in extension
- [ ] No DNS leaks (check dnsleaktest.com)
- [ ] Landing page loads on VPN server domain (camouflage)

### Task 6.3: Landing Page

Simple static site on the API domain:
- What the VPN does (privacy focused)
- Download link (App Store badge)
- Privacy Policy, Terms of Service
- Support email

---

## Dependencies & Crate List

### Rust (`vpn-core`)
- `ring` — crypto primitives
- `tokio` — async runtime
- `bytes` — buffer management

### Rust (`vpn-server`)
- `vpn-core`
- `tokio` + `tokio-rustls` — TLS
- `tun` — TUN device
- `tracing` + `tracing-subscriber` — structured logging
- `prometheus` — metrics

### Rust (`vpn-api`)
- `axum` + `tower` — HTTP framework
- `sqlx` — PostgreSQL (compile-time checked)
- `jsonwebtoken` — JWT
- `argon2` — password hashing
- `serde` + `serde_json`
- `tracing`

### iOS
- `NetworkExtension` framework
- `RevenueCat/Purchases` (SPM)
- `uniffi` generated Swift bindings

### Infrastructure
- Ansible
- Certbot
- Prometheus + Grafana

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| Apple rejects VPN app | Blocks launch | Clean description, have legal entity ready, expect extended review |
| Network Extension memory limit (15 MB) | Crashes on device | Profile early, keep Rust core lean, no allocations in hot path |
| DPI blocks TLS-based tunnel | Unusable in restricted networks | Fallback to QUIC-based transport (Phase 2 feature) |
| RevenueCat webhook reliability | Missed subscription events | Periodic polling of RevenueCat API as backup sync |
| Server bandwidth costs | Unprofitable at scale | Monitor per-user bandwidth, set soft limits, adjust pricing |
| One developer bus factor | Project stalls | Document everything, keep architecture simple |

---

## Definition of Done (MVP)

The MVP is shippable when:
1. A user can register, subscribe, and connect to a VPN server from iOS
2. All traffic routes through the tunnel with no DNS leaks
3. Traffic is indistinguishable from normal HTTPS to passive DPI observers
4. Connection survives network transitions (Wi-Fi ↔ cellular)
5. Kill switch works
6. At least 2 server locations are operational
7. Monitoring alerts on server downtime
8. App Store listing is approved

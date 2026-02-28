//! Integration tests for vpn-core.
//!
//! Phase 1 success criteria: two in-memory tunnel endpoints exchange
//! 10,000 packets with verified integrity.

use vpn_core::crypto::{SessionKeys, NONCE_LEN};
use vpn_core::handshake::{ClientHandshake, ServerHandshake, TokenValidator, TunnelConfig};
use vpn_core::tunnel::{Tunnel, TunnelRole};

use tokio::io::duplex;
use std::time::Instant;

/// Test token validator — accepts "valid-token".
struct TestValidator;

impl TokenValidator for TestValidator {
    fn validate(&self, token: &str) -> bool {
        token == "valid-token"
    }
}

/// Full end-to-end test: handshake → tunnel → 10,000 packets.
#[tokio::test]
async fn test_full_handshake_then_10k_packets() {
    let validator = TestValidator;
    let config = TunnelConfig {
        assigned_ip: "10.8.0.2".to_string(),
        dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        mtu: 1400,
    };

    // --- Handshake ---
    let (client_hello, client_keypair) =
        ClientHandshake::initiate("valid-token".to_string()).unwrap();

    let (server_hello, server_session_keys) =
        ServerHandshake::respond(&client_hello, &validator, config.clone()).unwrap();

    let (client_session_keys, received_config) =
        ClientHandshake::finalize(server_hello, client_keypair).unwrap();

    // Verify session keys match
    assert_eq!(client_session_keys.client_key, server_session_keys.client_key);
    assert_eq!(client_session_keys.server_key, server_session_keys.server_key);

    // Verify config
    assert_eq!(received_config.assigned_ip, "10.8.0.2");
    assert_eq!(received_config.mtu, 1400);

    // --- Tunnel: 10,000 packets ---
    let (client_stream, server_stream) = duplex(256 * 1024);

    let mut client_tunnel = Tunnel::new(client_stream, &client_session_keys, TunnelRole::Client);
    let mut server_tunnel = Tunnel::new(server_stream, &server_session_keys, TunnelRole::Server);

    let packet_count = 10_000;

    let start = Instant::now();

    let send_handle = tokio::spawn(async move {
        for i in 0u32..packet_count {
            let data = format!("packet-{i:05}");
            client_tunnel.send(data.as_bytes()).await.unwrap();
        }
        client_tunnel
    });

    let recv_handle = tokio::spawn(async move {
        for i in 0u32..packet_count {
            let received = server_tunnel.recv().await.unwrap();
            let expected = format!("packet-{i:05}");
            assert_eq!(
                received,
                expected.as_bytes(),
                "Mismatch at packet {i}"
            );
        }
        server_tunnel
    });

    let mut client_tunnel = send_handle.await.unwrap();
    let mut server_tunnel = recv_handle.await.unwrap();

    let elapsed = start.elapsed();
    eprintln!(
        "10,000 packets (client→server): {:.2?} ({:.0} pkt/s)",
        elapsed,
        packet_count as f64 / elapsed.as_secs_f64()
    );

    // --- Bidirectional: 5,000 packets each way simultaneously ---
    let bidir_count = 5_000u32;
    let start = Instant::now();

    let client_handle = tokio::spawn(async move {
        for i in 0..bidir_count {
            let data = format!("c2s-{i:05}");
            client_tunnel.send(data.as_bytes()).await.unwrap();

            let received = client_tunnel.recv().await.unwrap();
            let expected = format!("s2c-{i:05}");
            assert_eq!(received, expected.as_bytes());
        }
    });

    let server_handle = tokio::spawn(async move {
        for i in 0..bidir_count {
            let received = server_tunnel.recv().await.unwrap();
            let expected = format!("c2s-{i:05}");
            assert_eq!(received, expected.as_bytes());

            let response = format!("s2c-{i:05}");
            server_tunnel.send(response.as_bytes()).await.unwrap();
        }
    });

    client_handle.await.unwrap();
    server_handle.await.unwrap();

    let elapsed = start.elapsed();
    eprintln!(
        "5,000 bidirectional exchanges: {:.2?} ({:.0} roundtrips/s)",
        elapsed,
        bidir_count as f64 / elapsed.as_secs_f64()
    );
}

/// Test that large packets (MTU-sized) work correctly.
#[tokio::test]
async fn test_mtu_sized_packets() {
    let keys = SessionKeys {
        client_key: [0x01; 32],
        server_key: [0x02; 32],
        client_iv: [0x03; NONCE_LEN],
        server_iv: [0x04; NONCE_LEN],
    };

    let (client_stream, server_stream) = duplex(256 * 1024);
    let mut client_tunnel = Tunnel::new(client_stream, &keys, TunnelRole::Client);
    let mut server_tunnel = Tunnel::new(server_stream, &keys, TunnelRole::Server);

    // Simulate 1400-byte MTU packets (typical VPN MTU)
    let packet_sizes = [1400, 1200, 64, 1, 1400, 500];

    for (i, &size) in packet_sizes.iter().enumerate() {
        let data: Vec<u8> = (0..size).map(|b| (b % 256) as u8).collect();
        client_tunnel.send(&data).await.unwrap();

        let received = server_tunnel.recv().await.unwrap();
        assert_eq!(received.len(), size, "Size mismatch at packet {i}");
        assert_eq!(received, data, "Data mismatch at packet {i}");
    }
}

/// Test throughput benchmark with realistic packet sizes.
#[tokio::test]
async fn test_throughput_benchmark() {
    let keys = SessionKeys {
        client_key: [0xAA; 32],
        server_key: [0xBB; 32],
        client_iv: [0xCC; NONCE_LEN],
        server_iv: [0xDD; NONCE_LEN],
    };

    let (client_stream, server_stream) = duplex(1024 * 1024);
    let mut client_tunnel = Tunnel::new(client_stream, &keys, TunnelRole::Client);
    let mut server_tunnel = Tunnel::new(server_stream, &keys, TunnelRole::Server);

    let packet_size = 1400usize; // typical MTU
    let packet_count = 10_000u32;
    let total_bytes = packet_size as u64 * packet_count as u64;
    let data = vec![0xABu8; packet_size];

    let start = Instant::now();

    let send_data = data.clone();
    let send_handle = tokio::spawn(async move {
        for _ in 0..packet_count {
            client_tunnel.send(&send_data).await.unwrap();
        }
    });

    let recv_handle = tokio::spawn(async move {
        for _ in 0..packet_count {
            let received = server_tunnel.recv().await.unwrap();
            assert_eq!(received.len(), packet_size);
        }
    });

    send_handle.await.unwrap();
    recv_handle.await.unwrap();

    let elapsed = start.elapsed();
    let throughput_mbps = (total_bytes as f64 * 8.0) / (elapsed.as_secs_f64() * 1_000_000.0);
    eprintln!(
        "Throughput: {:.0} Mbps ({} bytes in {:.2?})",
        throughput_mbps, total_bytes, elapsed
    );

    // Success criteria: >500 Mbps on localhost (this may fail on very slow CI)
    // We don't hard-assert since it depends on the machine, but we log it.
    if throughput_mbps < 500.0 {
        eprintln!("WARNING: Throughput below 500 Mbps target: {throughput_mbps:.0} Mbps");
    }
}

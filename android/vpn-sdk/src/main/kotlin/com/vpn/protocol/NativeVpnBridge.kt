package com.vpn.protocol

/**
 * Low-level JNI bridge into the Rust vpn-core library.
 *
 * All methods are `external` (native) and map 1:1 to
 * `Java_com_vpn_protocol_NativeVpnBridge_*` symbols
 * in `libvpn_android.so`.
 *
 * Handles are opaque `Long` pointers into Rust heap objects.
 * You MUST call [destroySession] when done or memory will leak.
 */
internal object NativeVpnBridge {
    init {
        System.loadLibrary("vpn_android")
    }

    // ── Handshake ────────────────────────────────────────
    /** Begin handshake: returns a handshake handle (>0) or 0 on error. */
    external fun initHandshake(sessionToken: String): Long

    /** Get the serialised ClientHello to send to the VPN server. */
    external fun getClientHello(handle: Long): ByteArray

    /**
     * Complete the handshake with the server's response.
     * Returns a session handle (>0) or 0 on error.
     * Frees the handshake handle regardless of success.
     */
    external fun finishHandshake(handle: Long, serverHello: ByteArray): Long

    // ── Session – data path ──────────────────────────────
    /** Encrypt an IP packet → framed wire bytes. */
    external fun sendPacket(session: Long, plaintext: ByteArray): ByteArray?

    /** Feed raw bytes received from the TLS socket. */
    external fun feedData(session: Long, data: ByteArray)

    /** Decode + decrypt the next IP packet (null when nothing buffered). */
    external fun receivePacket(session: Long): ByteArray?

    /** Create a serialised Ping frame for keep-alive. */
    external fun createPingFrame(session: Long): ByteArray?

    // ── Session – metadata ───────────────────────────────
    /** Tunnel IP address assigned by the server. */
    external fun getAssignedIp(session: Long): String

    /** MTU value for the tunnel. */
    external fun getMtu(session: Long): Int

    /** Comma-separated DNS servers. */
    external fun getDnsServers(session: Long): String

    /** Whether the decoder has unprocessed frames buffered. */
    external fun hasBufferedData(session: Long): Boolean

    /** Free the native session. Call exactly once per session handle. */
    external fun destroySession(session: Long)
}

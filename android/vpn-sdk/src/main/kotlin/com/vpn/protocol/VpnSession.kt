package com.vpn.protocol

import java.io.Closeable

/**
 * Active VPN tunnel session.
 *
 * Wraps an opaque Rust handle that holds the ChaCha20-Poly1305 keys,
 * nonce counters, and the frame decoder.
 *
 * Thread-safety: each JNI call acquires a Mutex on the Rust side,
 * so concurrent calls are safe but serialised.
 *
 * **Important:** call [close] (or use `use {}`) when the session ends
 * to free native memory.
 */
class VpnSession internal constructor(private var handle: Long) : Closeable {

    /** Tunnel IP address the server assigned to this client. */
    val assignedIp: String
        get() = NativeVpnBridge.getAssignedIp(handle)

    /** Maximum transmission unit for the tunnel. */
    val mtu: Int
        get() = NativeVpnBridge.getMtu(handle)

    /** DNS servers the client should use (comma-separated). */
    val dnsServers: List<String>
        get() = NativeVpnBridge.getDnsServers(handle).split(",")

    /**
     * Encrypt an outgoing IP packet and produce framed wire bytes
     * ready to send over the TLS socket.
     *
     * @param packet raw IP packet from the TUN interface
     * @return framed ciphertext bytes, or `null` on error
     */
    fun sendPacket(packet: ByteArray): ByteArray? =
        NativeVpnBridge.sendPacket(handle, packet)

    /**
     * Feed raw bytes received from the TLS socket into the frame decoder.
     * Call [receivePacket] afterwards to drain decoded packets.
     */
    fun feedData(data: ByteArray) =
        NativeVpnBridge.feedData(handle, data)

    /**
     * Decode and decrypt the next available IP packet.
     *
     * @return decrypted IP packet bytes, or `null` when no
     *         complete frame is buffered yet
     */
    fun receivePacket(): ByteArray? =
        NativeVpnBridge.receivePacket(handle)

    /**
     * Drain all currently decodable packets.
     * Useful after a large `feedData` call.
     */
    fun receiveAll(): List<ByteArray> {
        val packets = mutableListOf<ByteArray>()
        while (true) {
            val pkt = receivePacket() ?: break
            packets.add(pkt)
        }
        return packets
    }

    /** Create a serialised Ping frame for keep-alive. */
    fun createPingFrame(): ByteArray? =
        NativeVpnBridge.createPingFrame(handle)

    /** Whether the frame decoder has unprocessed data buffered. */
    val hasBufferedData: Boolean
        get() = NativeVpnBridge.hasBufferedData(handle)

    /** Release native memory. Safe to call multiple times. */
    override fun close() {
        val h = handle
        if (h != 0L) {
            handle = 0
            NativeVpnBridge.destroySession(h)
        }
    }

    protected fun finalize() {
        close()
    }
}

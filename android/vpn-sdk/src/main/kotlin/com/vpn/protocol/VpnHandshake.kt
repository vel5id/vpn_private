package com.vpn.protocol

/**
 * High-level Kotlin wrapper around the VPN handshake.
 *
 * ```kotlin
 * val hs = VpnHandshake(sessionToken)
 * // Send hs.clientHelloData to the server over TLS
 * val session = hs.finish(serverHelloBytes)
 * // session is now ready to encrypt/decrypt
 * ```
 */
class VpnHandshake(sessionToken: String) : AutoCloseable {

    private var handle: Long = NativeVpnBridge.initHandshake(sessionToken)

    init {
        require(handle != 0L) { "Failed to initiate VPN handshake — invalid token?" }
    }

    /** Serialised ClientHello message to send to the VPN server. */
    val clientHelloData: ByteArray
        get() = NativeVpnBridge.getClientHello(handle)

    /**
     * Complete the handshake using the server's ServerHello response.
     *
     * @param serverHello raw bytes of the ServerHello message
     * @return an active [VpnSession] ready for data transfer
     * @throws IllegalStateException if the handshake fails
     */
    fun finish(serverHello: ByteArray): VpnSession {
        val sessionHandle = NativeVpnBridge.finishHandshake(handle, serverHello)
        handle = 0 // handle is freed by finishHandshake regardless
        check(sessionHandle != 0L) { "Handshake failed — server rejected or crypto error" }
        return VpnSession(sessionHandle)
    }

    override fun close() {
        // Nothing to free — handle is either consumed by finish()
        // or was never valid. The Rust side frees it in finishHandshake.
        handle = 0
    }
}

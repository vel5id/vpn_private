package com.vpn.protocol

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.Closeable
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLSocketFactory

/**
 * Android VpnService implementation powered by the Rust vpn-core engine.
 *
 * Lifecycle:
 * 1. `startService(intent)` with extras:
 *     - `server_host` — VPN server hostname
 *     - `server_port` — VPN server port (default 443)
 *     - `session_token` — JWT session token
 * 2. The service performs the handshake, configures the TUN interface,
 *    and starts the packet relay loop in a background thread.
 * 3. Send `ACTION_DISCONNECT` to stop.
 */
class ProtocolVpnService : VpnService() {

    companion object {
        const val TAG = "ProtocolVPN"
        const val ACTION_DISCONNECT = "com.vpn.protocol.DISCONNECT"
        private const val DEFAULT_PORT = 443
    }

    private val running = AtomicBoolean(false)
    private var vpnSession: VpnSession? = null
    private var tunFd: ParcelFileDescriptor? = null
    private var relayThread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            disconnect()
            return START_NOT_STICKY
        }

        val host = intent?.getStringExtra("server_host") ?: return START_NOT_STICKY
        val port = intent.getIntExtra("server_port", DEFAULT_PORT)
        val token = intent.getStringExtra("session_token") ?: return START_NOT_STICKY

        relayThread = Thread {
            try {
                runTunnel(host, port, token)
            } catch (e: Exception) {
                Log.e(TAG, "Tunnel failed", e)
            } finally {
                disconnect()
            }
        }.also { it.start() }

        return START_STICKY
    }

    private fun runTunnel(host: String, port: Int, token: String) {
        running.set(true)
        Log.i(TAG, "Connecting to $host:$port")

        // 1. TLS connection
        val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
        val rawSocket = Socket(host, port)
        protect(rawSocket)  // Must protect BEFORE TLS handshake
        val socket = sslFactory.createSocket(rawSocket, host, port, true) as javax.net.ssl.SSLSocket
        socket.startHandshake()

        val tlsIn = socket.inputStream
        val tlsOut = socket.outputStream

        // 2. HTTP upgrade (camouflage as WebSocket upgrade)
        val upgradePath = "/ws"  // Must match server's upgrade_path
        val httpRequest = "POST $upgradePath HTTP/1.1\r\n" +
            "Host: $host\r\n" +
            "Connection: Upgrade\r\n" +
            "Upgrade: websocket\r\n" +
            "Content-Length: 0\r\n" +
            "\r\n"
        tlsOut.write(httpRequest.toByteArray(Charsets.US_ASCII))
        tlsOut.flush()

        // Read HTTP 101 response
        val responseBuf = ByteArray(4096)
        val responseLen = tlsIn.read(responseBuf)
        if (responseLen < 0) throw Exception("No upgrade response from server")
        val responseStr = String(responseBuf, 0, responseLen, Charsets.US_ASCII)
        if (!responseStr.startsWith("HTTP/1.1 101")) {
            throw Exception("Server rejected VPN upgrade: ${responseStr.take(80)}")
        }

        // 3. VPN handshake via Rust (2-byte length prefix to match server)
        val handshake = VpnHandshake(token)
        val clientHello = handshake.clientHelloData
        // Write 2-byte big-endian length prefix + payload
        tlsOut.write(byteArrayOf(
            ((clientHello.size shr 8) and 0xFF).toByte(),
            (clientHello.size and 0xFF).toByte()
        ))
        tlsOut.write(clientHello)
        tlsOut.flush()

        // Read server hello (2-byte length-prefixed)
        val lenBuf = ByteArray(2)
        readFully(tlsIn, lenBuf)
        val serverHelloLen = ((lenBuf[0].toInt() and 0xFF) shl 8) or
            (lenBuf[1].toInt() and 0xFF)
        val serverHelloBytes = ByteArray(serverHelloLen)
        var read = 0
        while (read < serverHelloLen) {
            val n = tlsIn.read(serverHelloBytes, read, serverHelloLen - read)
            if (n < 0) throw Exception("EOF during handshake")
            read += n
        }

        val session = handshake.finish(serverHelloBytes)
        vpnSession = session

        // 3. Configure TUN interface
        val builder = Builder()
            .setSession("Protocol VPN")
            .setMtu(session.mtu)
            .addAddress(session.assignedIp, 24)

        for (dns in session.dnsServers) {
            if (dns.isNotBlank()) builder.addDnsServer(dns)
        }
        builder.addRoute("0.0.0.0", 0) // route all IPv4 traffic
        builder.addAddress("fd00::2", 64) // IPv6 tunnel address
        builder.addRoute("::", 0) // route all IPv6 traffic

        tunFd = builder.establish() ?: throw Exception("VPN permission not granted")
        val tunIn = FileInputStream(tunFd!!.fileDescriptor)
        val tunOut = FileOutputStream(tunFd!!.fileDescriptor)

        Log.i(TAG, "Tunnel established: ip=${session.assignedIp} mtu=${session.mtu}")

        // 4. Packet relay loop
        val buf = ByteArray(session.mtu + 100)

        // Keepalive — send a ping every 25 seconds to prevent idle disconnect
        val keepaliveThread = Thread {
            try {
                while (running.get()) {
                    Thread.sleep(25_000)
                    if (!running.get()) break
                    val pingFrame = session.createPingFrame() ?: continue
                    synchronized(tlsOut) {
                        tlsOut.write(pingFrame)
                        tlsOut.flush()
                    }
                }
            } catch (_: Exception) {}
        }
        keepaliveThread.start()

        // TUN → TLS  (outgoing)
        val outThread = Thread {
            try {
                while (running.get()) {
                    val n = tunIn.read(buf)
                    if (n > 0) {
                        val packet = buf.copyOf(n)
                        val wire = session.sendPacket(packet) ?: continue
                        synchronized(tlsOut) {
                            tlsOut.write(wire)
                            tlsOut.flush()
                        }
                    }
                }
            } catch (_: Exception) {}
        }
        outThread.start()

        // TLS → TUN  (incoming)
        try {
            val recvBuf = ByteArray(4096)
            while (running.get()) {
                val n = tlsIn.read(recvBuf)
                if (n < 0) break
                session.feedData(recvBuf.copyOf(n))
                for (pkt in session.receiveAll()) {
                    tunOut.write(pkt)
                }
            }
        } catch (_: Exception) {}

        outThread.join(2000)
        socket.close()
    }

    private fun disconnect() {
        running.set(false)
        vpnSession?.close()
        vpnSession = null
        tunFd?.close()
        tunFd = null
        stopSelf()
    }

    override fun onDestroy() {
        disconnect()
        super.onDestroy()
    }

    /** Read exactly buf.size bytes from the stream, or throw. */
    private fun readFully(stream: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = stream.read(buf, off, buf.size - off)
            if (n < 0) throw Exception("EOF during readFully")
            off += n
        }
    }
}

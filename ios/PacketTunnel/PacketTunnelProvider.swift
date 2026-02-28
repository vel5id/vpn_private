import NetworkExtension
import os.log

/// NEPacketTunnelProvider implementation that routes all device traffic through
/// the custom VPN protocol (TLS 1.3 + ChaCha20-Poly1305 tunnel).
///
/// The Rust `vpn-ffi` crate handles:
///   - Handshake (X25519 key exchange + session key derivation)
///   - Packet encryption / decryption (ChaCha20-Poly1305)
///   - Wire-format framing
///
/// This Swift side handles:
///   - TLS transport (NWConnection)
///   - TUN interface via NEPacketTunnelFlow
///   - Keepalive timer
///   - Network path changes
class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = OSLog(subsystem: "com.vpn.tunnel", category: "provider")

    /// Active VPN session (holds encryption keys and frame decoder).
    private var vpnSession: VpnSession?

    /// TLS connection to the VPN server.
    private var connection: NWTCPConnection?

    /// Keepalive timer — sends ping every 25 seconds.
    private var pingTimer: DispatchSourceTimer?

    /// Whether the tunnel is actively forwarding packets.
    private var isForwarding = false

    // MARK: - Tunnel Lifecycle

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard let config = options,
              let serverHost = config["serverHost"] as? String,
              let serverPort = config["serverPort"] as? NSNumber,
              let sessionToken = config["sessionToken"] as? String
        else {
            os_log(.error, log: log, "Missing tunnel configuration")
            completionHandler(NSError(domain: "VPN", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Missing configuration"]))
            return
        }

        os_log(.info, log: log, "Starting tunnel to %{public}@:%d",
               serverHost, serverPort.intValue)

        // 1. Establish TLS connection
        let endpoint = NWHostEndpoint(hostname: serverHost,
                                       port: String(serverPort.intValue))
        let tlsConnection = createTCPConnection(to: endpoint, enableTLS: true,
                                                 tlsParameters: nil, delegate: nil)
        self.connection = tlsConnection

        // 2. Observe connection state
        tlsConnection.addObserver(self, forKeyPath: "state",
                                  options: .new, context: nil)

        // Wait for connection to be ready
        waitForConnection(tlsConnection) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                os_log(.error, log: self.log, "TLS connection failed: %{public}@",
                       error.localizedDescription)
                completionHandler(error)
                return
            }

            // 3. Perform VPN handshake
            self.performHandshake(sessionToken: sessionToken,
                                  connection: tlsConnection) { result in
                switch result {
                case .failure(let error):
                    os_log(.error, log: self.log, "Handshake failed: %{public}@",
                           error.localizedDescription)
                    completionHandler(error)

                case .success(let session):
                    self.vpnSession = session

                    // 4. Configure TUN interface
                    self.setupTunnelInterface(session: session) { tunnelError in
                        if let tunnelError = tunnelError {
                            completionHandler(tunnelError)
                            return
                        }

                        // 5. Start forwarding packets
                        self.startForwarding(connection: tlsConnection, session: session)
                        self.startKeepalive(connection: tlsConnection, session: session)

                        os_log(.info, log: self.log, "Tunnel established — IP %{public}@",
                               session.assignedIp())
                        completionHandler(nil)
                    }
                }
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        os_log(.info, log: log, "Stopping tunnel (reason: %d)", reason.rawValue)

        isForwarding = false
        pingTimer?.cancel()
        pingTimer = nil
        connection?.cancel()
        connection = nil
        vpnSession = nil

        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)?) {
        // Can be used for IPC between the app and the extension
        completionHandler?(nil)
    }

    // MARK: - Handshake

    private func performHandshake(
        sessionToken: String,
        connection: NWTCPConnection,
        completion: @escaping (Result<VpnSession, Error>) -> Void
    ) {
        // First, send HTTP upgrade request for camouflage
        let upgradePath = "/ws"  // Must match server's upgrade_path
        let host = connection.endpoint.hostname ?? "vpn"
        let httpRequest = "POST \(upgradePath) HTTP/1.1\r\n" +
            "Host: \(host)\r\n" +
            "Connection: Upgrade\r\n" +
            "Upgrade: websocket\r\n" +
            "Content-Length: 0\r\n" +
            "\r\n"
        connection.write(httpRequest.data(using: .ascii)!, completionHandler: { error in
            if let error = error {
                completion(.failure(error))
                return
            }

            // Read HTTP 101 response
            connection.readMinimumLength(1, maximumLength: 4096) { responseData, error in
                if let error = error {
                    completion(.failure(error))
                    return
                }
                guard let responseData = responseData,
                      let responseStr = String(data: responseData, encoding: .ascii),
                      responseStr.hasPrefix("HTTP/1.1 101") else {
                    completion(.failure(NSError(domain: "VPN", code: 10,
                        userInfo: [NSLocalizedDescriptionKey: "Server rejected VPN upgrade"])))
                    return
                }

                // Now perform VPN handshake
                self.doVpnHandshake(sessionToken: sessionToken,
                                    connection: connection,
                                    completion: completion)
            }
        })
    }

    private func doVpnHandshake(
        sessionToken: String,
        connection: NWTCPConnection,
        completion: @escaping (Result<VpnSession, Error>) -> Void
    ) {
        do {
            // Create handshake state and client hello
            let state = try VpnHandshakeState(sessionToken: sessionToken)
            let clientHelloData = state.clientHelloData()

            // Send client hello with length prefix (2 bytes, big-endian, matching server)
            let framedHello = lengthPrefix(clientHelloData)
            connection.write(framedHello, completionHandler: { error in
                if let error = error {
                    completion(.failure(error))
                    return
                }

                // Read server hello (length-prefixed, 2 bytes)
                self.readLengthPrefixed(connection: connection) { result in
                    switch result {
                    case .failure(let error):
                        completion(.failure(error))
                    case .success(let serverHelloData):
                        do {
                            let session = try state.finish(serverHelloData: serverHelloData)
                            completion(.success(session))
                        } catch {
                            completion(.failure(error))
                        }
                    }
                }
            })
        } catch {
            completion(.failure(error))
        }
    }

    // MARK: - TUN Configuration

    private func setupTunnelInterface(
        session: VpnSession,
        completion: @escaping (Error?) -> Void
    ) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: session.assignedIp())

        // IPv4 config
        let ipv4 = NEIPv4Settings(addresses: [session.assignedIp()],
                                   subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4

        // IPv6 config — route IPv6 traffic through the tunnel as well
        let ipv6 = NEIPv6Settings(addresses: ["fd00::2"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6

        // DNS
        let dnsServers = session.dnsServers()
        if !dnsServers.isEmpty {
            settings.dnsSettings = NEDNSSettings(servers: dnsServers)
        }

        // MTU
        settings.mtu = NSNumber(value: session.mtu())

        setTunnelNetworkSettings(settings) { error in
            completion(error)
        }
    }

    // MARK: - Packet Forwarding

    private func startForwarding(connection: NWTCPConnection, session: VpnSession) {
        isForwarding = true
        readFromTUN(session: session, connection: connection)
        readFromServer(session: session, connection: connection)
    }

    /// TUN → Encrypt → Server
    private func readFromTUN(session: VpnSession, connection: NWTCPConnection) {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isForwarding else { return }

            for packet in packets {
                do {
                    let frameData = try session.sendPacket(plaintext: [UInt8](packet))
                    connection.write(Data(frameData), completionHandler: { _ in })
                } catch {
                    os_log(.error, log: self.log, "Encrypt error: %{public}@",
                           error.localizedDescription)
                }
            }

            // Continue reading
            self.readFromTUN(session: session, connection: connection)
        }
    }

    /// Server → Decrypt → TUN
    private func readFromServer(session: VpnSession, connection: NWTCPConnection) {
        connection.readMinimumLength(1, maximumLength: 65536) { [weak self] data, error in
            guard let self = self, self.isForwarding else { return }

            if let error = error {
                os_log(.error, log: self.log, "Read error: %{public}@",
                       error.localizedDescription)
                return
            }

            guard let data = data, !data.isEmpty else {
                os_log(.info, log: self.log, "Server closed connection")
                return
            }

            // Feed bytes to the frame decoder
            session.feedData(data: [UInt8](data))

            // Decode all available packets
            do {
                while let plaintext = try session.receivePacket() {
                    let packetData = Data(plaintext)
                    // Detect IP version from the first nibble of the packet header
                    let ipVersion = (plaintext.first ?? 0) >> 4
                    let proto: NSNumber = (ipVersion == 6)
                        ? NSNumber(value: AF_INET6)
                        : NSNumber(value: AF_INET)
                    self.packetFlow.writePackets([packetData], withProtocols: [proto])
                }
            } catch {
                os_log(.error, log: self.log, "Decrypt error: %{public}@",
                       error.localizedDescription)
                // Don't return — continue reading to recover from transient decode errors
            }

            // Continue reading
            self.readFromServer(session: session, connection: connection)
        }
    }

    // MARK: - Keepalive

    private func startKeepalive(connection: NWTCPConnection, session: VpnSession) {
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + 25, repeating: 25)
        timer.setEventHandler { [weak self] in
            guard let self = self, self.isForwarding else { return }
            do {
                let pingFrame = try session.createPingFrame()
                connection.write(Data(pingFrame), completionHandler: { _ in })
            } catch {
                os_log(.error, log: self.log, "Ping error: %{public}@",
                       error.localizedDescription)
            }
        }
        timer.resume()
        self.pingTimer = timer
    }

    // MARK: - Helpers

    private func waitForConnection(
        _ connection: NWTCPConnection,
        completion: @escaping (Error?) -> Void
    ) {
        var observer: NSKeyValueObservation?
        observer = connection.observe(\.state, options: [.new]) { conn, _ in
            switch conn.state {
            case .connected:
                observer?.invalidate()
                completion(nil)
            case .disconnected:
                observer?.invalidate()
                completion(NSError(domain: "VPN", code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Connection disconnected"]))
            case .cancelled:
                observer?.invalidate()
                completion(NSError(domain: "VPN", code: 3,
                    userInfo: [NSLocalizedDescriptionKey: "Connection cancelled"]))
            default:
                break // waiting
            }
        }
    }

    /// Prepend a 2-byte big-endian length header (matching server's u16 framing).
    private func lengthPrefix(_ data: [UInt8]) -> Data {
        var length = UInt16(data.count).bigEndian
        var result = Data(bytes: &length, count: 2)
        result.append(contentsOf: data)
        return result
    }

    /// Read a length-prefixed message from a TCP connection (2-byte header).
    private func readLengthPrefixed(
        connection: NWTCPConnection,
        completion: @escaping (Result<[UInt8], Error>) -> Void
    ) {
        connection.readMinimumLength(2, maximumLength: 2) { data, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            guard let data = data, data.count == 2 else {
                completion(.failure(NSError(domain: "VPN", code: 4,
                    userInfo: [NSLocalizedDescriptionKey: "Failed to read length"])))
                return
            }

            let length = data.withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }

            connection.readMinimumLength(Int(length), maximumLength: Int(length)) { payload, error in
                if let error = error {
                    completion(.failure(error))
                    return
                }
                guard let payload = payload else {
                    completion(.failure(NSError(domain: "VPN", code: 5,
                        userInfo: [NSLocalizedDescriptionKey: "Failed to read payload"])))
                    return
                }
                completion(.success([UInt8](payload)))
            }
        }
    }
}

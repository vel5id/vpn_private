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

    /// Saved tunnel parameters for reconnection
    private var savedServerHost: String?
    private var savedServerPort: Int?
    private var savedSessionToken: String?
    private var savedKillSwitch: Bool = true

    /// Whether the tunnel is actively forwarding packets.
    private var isForwarding = false

    /// Reconnection state
    private var reconnectAttempt = 0
    private static let maxReconnectAttempts = 5
    private static let reconnectDelays: [TimeInterval] = [1, 2, 4, 8, 15]

    // MARK: - Tunnel Lifecycle

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        // providerConfiguration from NETunnelProviderProtocol
        let providerConfig = (protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration ?? [:]

        // options can override providerConfiguration (e.g. on-demand connect)
        let config = providerConfig.merging(options ?? [:]) { _, new in new }

        guard let serverHost = config["serverHost"] as? String,
              let serverPort = config["serverPort"] as? NSNumber,
              let sessionToken = config["sessionToken"] as? String
        else {
            os_log(.error, log: log, "Missing tunnel configuration")
            completionHandler(NSError(domain: "VPN", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Missing configuration"]))
            return
        }

        let killSwitchEnabled = (config["killSwitch"] as? NSNumber)?.boolValue ?? true

        // Save parameters for reconnection
        savedServerHost = serverHost
        savedServerPort = serverPort.intValue
        savedSessionToken = sessionToken
        savedKillSwitch = killSwitchEnabled
        reconnectAttempt = 0

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
                    self.setupTunnelInterface(session: session, killSwitch: killSwitchEnabled) { tunnelError in
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
        killSwitch: Bool,
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

        // Kill Switch — block all traffic when VPN disconnects
        if killSwitch {
            if #available(iOS 14.2, *) {
                settings.includeAllNetworks = true
                settings.excludeLocalNetworks = true
            }
        }

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
                self.attemptReconnect()
                return
            }

            guard let data = data, !data.isEmpty else {
                os_log(.info, log: self.log, "Server closed connection")
                self.attemptReconnect()
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

    // MARK: - Auto-Reconnect

    private func attemptReconnect() {
        guard reconnectAttempt < Self.maxReconnectAttempts,
              let host = savedServerHost,
              let port = savedServerPort,
              let token = savedSessionToken
        else {
            os_log(.error, log: log, "Reconnect failed after %d attempts — giving up",
                   reconnectAttempt)
            cancelTunnelWithError(NSError(domain: "VPN", code: 20,
                userInfo: [NSLocalizedDescriptionKey: "Connection lost"]))
            return
        }

        let delay = Self.reconnectDelays[min(reconnectAttempt, Self.reconnectDelays.count - 1)]
        reconnectAttempt += 1

        os_log(.info, log: log, "Reconnecting (attempt %d/%d) in %.0fs...",
               reconnectAttempt, Self.maxReconnectAttempts, delay)

        // Signal the OS that we're reconnecting (keeps kill switch active)
        reasserting = true

        // Tear down old state
        isForwarding = false
        pingTimer?.cancel()
        pingTimer = nil
        connection?.cancel()
        connection = nil
        vpnSession = nil

        DispatchQueue.global().asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self = self else { return }

            let endpoint = NWHostEndpoint(hostname: host, port: String(port))
            let tlsConnection = self.createTCPConnection(to: endpoint, enableTLS: true,
                                                          tlsParameters: nil, delegate: nil)
            self.connection = tlsConnection

            self.waitForConnection(tlsConnection) { error in
                if let error = error {
                    os_log(.error, log: self.log, "Reconnect TLS failed: %{public}@",
                           error.localizedDescription)
                    self.attemptReconnect()
                    return
                }

                self.performHandshake(sessionToken: token, connection: tlsConnection) { result in
                    switch result {
                    case .failure(let error):
                        os_log(.error, log: self.log, "Reconnect handshake failed: %{public}@",
                               error.localizedDescription)
                        self.attemptReconnect()

                    case .success(let session):
                        self.vpnSession = session
                        self.setupTunnelInterface(session: session, killSwitch: self.savedKillSwitch) { tunnelError in
                            if let tunnelError = tunnelError {
                                os_log(.error, log: self.log, "Reconnect TUN setup failed: %{public}@",
                                       tunnelError.localizedDescription)
                                self.attemptReconnect()
                                return
                            }

                            self.reconnectAttempt = 0
                            self.reasserting = false
                            self.startForwarding(connection: tlsConnection, session: session)
                            self.startKeepalive(connection: tlsConnection, session: session)

                            os_log(.info, log: self.log, "Reconnected successfully — IP %{public}@",
                                   session.assignedIp())
                        }
                    }
                }
            }
        }
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

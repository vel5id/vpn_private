import Foundation
import NetworkExtension
import Combine

/// Manages the VPN tunnel lifecycle via NETunnelProviderManager.
class VPNManager: ObservableObject {
    @Published var status: ConnectionStatus = .disconnected
    @Published var connectedServer: ServerInfo?
    @Published var bytesIn: UInt64 = 0
    @Published var bytesOut: UInt64 = 0

    /// Currently active API session (for disconnect).
    private var currentSessionId: String?
    private var vpnManager: NETunnelProviderManager?
    private var statusObserver: Any?

    private let api = APIClient.shared

    init() {
        loadManager()
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    // MARK: - Public

    @MainActor
    func connect(to server: ServerInfo) async {
        status = .connecting

        do {
            // 1. Get session token from API
            let connectResponse = try await api.connect(serverId: server.id)
            currentSessionId = connectResponse.sessionId

            // 2. Configure and start the tunnel
            let manager = try await loadOrCreateManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.vpn.app.tunnel"
            proto.serverAddress = connectResponse.hostname
            proto.providerConfiguration = [
                "serverHost": connectResponse.hostname as NSString,
                "serverPort": NSNumber(value: connectResponse.port),
                "sessionToken": connectResponse.sessionToken as NSString,
                "killSwitch": NSNumber(value: UserDefaults.standard.bool(forKey: "killSwitch")),
            ]

            manager.protocolConfiguration = proto
            manager.isEnabled = true
            manager.localizedDescription = "VPN"

            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()

            try manager.connection.startVPNTunnel()

            connectedServer = server

        } catch {
            status = .error(error.localizedDescription)
        }
    }

    @MainActor
    func disconnect() async {
        status = .disconnecting
        vpnManager?.connection.stopVPNTunnel()

        // Tell the API backend the session ended
        if let sessionId = currentSessionId {
            try? await api.disconnect(sessionId: sessionId)
            currentSessionId = nil
        }

        connectedServer = nil
    }

    // MARK: - Manager Setup

    private func loadManager() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }
            if let manager = managers?.first {
                self.vpnManager = manager
                self.observeStatus(manager)
            }
        }
    }

    private func loadOrCreateManager() async throws -> NETunnelProviderManager {
        if let existing = vpnManager {
            return existing
        }

        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        if let existing = managers.first {
            vpnManager = existing
            observeStatus(existing)
            return existing
        }

        let manager = NETunnelProviderManager()
        vpnManager = manager
        observeStatus(manager)
        return manager
    }

    private func observeStatus(_ manager: NETunnelProviderManager) {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.connection,
            queue: .main
        ) { [weak self] _ in
            self?.handleStatusChange(manager.connection.status)
        }
    }

    @MainActor
    private func handleStatusChange(_ vpnStatus: NEVPNStatus) {
        switch vpnStatus {
        case .connecting:
            status = .connecting
        case .connected:
            status = .connected(serverName: connectedServer?.name ?? "VPN")
        case .disconnecting:
            status = .disconnecting
        case .disconnected:
            status = .disconnected
        case .invalid:
            status = .error("Invalid configuration")
        case .reasserting:
            status = .connecting
        @unknown default:
            break
        }
    }
}

// MARK: - NETunnelProviderManager async helpers

extension NETunnelProviderManager {
    static func loadAllFromPreferences() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { continuation in
            loadAllFromPreferences { managers, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }
    }

    func saveToPreferences() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            saveToPreferences { error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    func loadFromPreferences() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            loadFromPreferences { error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }
}

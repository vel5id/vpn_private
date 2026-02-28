import Foundation

// MARK: - API Models

struct AuthResponse: Codable {
    let accessToken: String
    let refreshToken: String
}

struct UserAccount: Codable {
    let id: String
    let email: String
    let subscription: SubscriptionInfo?
}

struct SubscriptionInfo: Codable {
    let tier: String
    let status: String
    let expiresAt: String
}

struct ServerInfo: Codable, Identifiable {
    let id: String
    let name: String
    let hostname: String
    let region: String
    let load: Double
}

struct ConnectResponse: Codable {
    let sessionId: String
    let sessionToken: String
    let hostname: String
    let port: Int
}

// MARK: - App State

enum ConnectionStatus: Equatable {
    case disconnected
    case connecting
    case connected(serverName: String)
    case disconnecting
    case error(String)

    var displayText: String {
        switch self {
        case .disconnected: return "Not Connected"
        case .connecting: return "Connecting…"
        case .connected(let name): return "Connected to \(name)"
        case .disconnecting: return "Disconnecting…"
        case .error(let msg): return "Error: \(msg)"
        }
    }

    var isConnected: Bool {
        if case .connected = self { return true }
        return false
    }
}

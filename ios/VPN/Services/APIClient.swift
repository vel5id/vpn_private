import Foundation

/// HTTP client for the VPN API backend.
class APIClient {
    static let shared = APIClient()

    private let baseURL: URL
    private let session = URLSession.shared
    private let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return d
    }()
    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.keyEncodingStrategy = .convertToSnakeCase
        return e
    }()

    /// Whether a token refresh is currently in progress (prevents concurrent refreshes).
    private var isRefreshing = false

    /// Current access token (stored in Keychain in production).
    var accessToken: String?

    private init() {
        // Read API base URL from Info.plist or fall back to a default
        let urlString: String
        if let plistURL = Bundle.main.infoDictionary?["VPN_API_BASE_URL"] as? String,
           !plistURL.isEmpty {
            urlString = plistURL
        } else {
            urlString = "https://api.vpn.example.com"
            #if DEBUG
            print("⚠️ VPN_API_BASE_URL not set in Info.plist, using default")
            #endif
        }
        self.baseURL = URL(string: urlString)!
    }

    // MARK: - Auth

    func register(email: String, password: String) async throws -> AuthResponse {
        let body: [String: String] = ["email": email, "password": password]
        return try await post("/auth/register", body: body)
    }

    func login(email: String, password: String) async throws -> AuthResponse {
        let body: [String: String] = ["email": email, "password": password]
        return try await post("/auth/login", body: body)
    }

    // MARK: - Servers

    func listServers() async throws -> [ServerInfo] {
        return try await get("/servers")
    }

    // MARK: - Connect / Disconnect

    func connect(serverId: String) async throws -> ConnectResponse {
        let body: [String: String] = ["server_id": serverId]
        return try await post("/connect", body: body)
    }

    func disconnect(sessionId: String) async throws {
        let body: [String: String] = ["session_id": sessionId]
        let _: EmptyResponse = try await post("/disconnect", body: body)
    }

    // MARK: - Account

    func account() async throws -> UserAccount {
        return try await get("/account")
    }

    // MARK: - Token Refresh

    /// Attempt to refresh the access token using the stored refresh token.
    /// Returns `true` if refresh succeeded, `false` otherwise.
    private func refreshAccessToken() async -> Bool {
        guard !isRefreshing else { return false }
        isRefreshing = true
        defer { isRefreshing = false }

        guard let refreshToken = KeychainHelper.load(key: "refreshToken") else {
            return false
        }

        do {
            let body: [String: String] = ["refresh_token": refreshToken]
            var request = URLRequest(url: baseURL.appendingPathComponent("/auth/refresh"))
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try encoder.encode(body)

            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                return false
            }

            let authResponse = try decoder.decode(AuthResponse.self, from: data)
            accessToken = authResponse.accessToken
            KeychainHelper.save(key: "accessToken", value: authResponse.accessToken)
            return true
        } catch {
            return false
        }
    }

    // MARK: - Networking

    private func get<T: Decodable>(_ path: String) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "GET"
        addAuth(&request)

        let (data, response) = try await session.data(for: request)

        // Retry once on 401 with token refresh
        if let http = response as? HTTPURLResponse, http.statusCode == 401 {
            if await refreshAccessToken() {
                var retryRequest = URLRequest(url: baseURL.appendingPathComponent(path))
                retryRequest.httpMethod = "GET"
                addAuth(&retryRequest)
                let (retryData, retryResponse) = try await session.data(for: retryRequest)
                try validateResponse(retryResponse)
                return try decoder.decode(T.self, from: retryData)
            }
            throw APIError.unauthorized
        }

        try validateResponse(response)
        return try decoder.decode(T.self, from: data)
    }

    private func post<B: Encodable, T: Decodable>(
        _ path: String,
        body: B
    ) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try encoder.encode(body)
        addAuth(&request)

        let (data, response) = try await session.data(for: request)

        // Retry once on 401 with token refresh
        if let http = response as? HTTPURLResponse, http.statusCode == 401 {
            if await refreshAccessToken() {
                var retryRequest = URLRequest(url: baseURL.appendingPathComponent(path))
                retryRequest.httpMethod = "POST"
                retryRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
                retryRequest.httpBody = try encoder.encode(body)
                addAuth(&retryRequest)
                let (retryData, retryResponse) = try await session.data(for: retryRequest)
                try validateResponse(retryResponse)
                return try decoder.decode(T.self, from: retryData)
            }
            throw APIError.unauthorized
        }

        try validateResponse(response)
        return try decoder.decode(T.self, from: data)
    }

    private func addAuth(_ request: inout URLRequest) {
        if let token = accessToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
    }

    private func validateResponse(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse else {
            throw APIError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            throw APIError.httpError(statusCode: http.statusCode)
        }
    }
}

enum APIError: LocalizedError {
    case invalidResponse
    case httpError(statusCode: Int)
    case unauthorized

    var errorDescription: String? {
        switch self {
        case .invalidResponse: return "Invalid server response"
        case .httpError(let code): return "Server error (\(code))"
        case .unauthorized: return "Authentication required"
        }
    }
}

/// Placeholder for endpoints that return empty bodies.
private struct EmptyResponse: Decodable {}

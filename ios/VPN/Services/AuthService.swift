import Foundation
import Combine

/// Manages authentication state and token storage.
class AuthService: ObservableObject {
    @Published var isAuthenticated = false
    @Published var currentUser: UserAccount?
    @Published var isLoading = false
    @Published var errorMessage: String?

    private let api = APIClient.shared

    init() {
        // Restore token from Keychain on launch
        if let token = KeychainHelper.load(key: "accessToken") {
            api.accessToken = token
            isAuthenticated = true
            Task { await loadAccount() }
        }
    }

    // MARK: - Actions

    @MainActor
    func register(email: String, password: String) async {
        isLoading = true
        errorMessage = nil

        do {
            let response = try await api.register(email: email, password: password)
            saveTokens(response)
            isAuthenticated = true
            await loadAccount()
        } catch {
            errorMessage = error.localizedDescription
        }

        isLoading = false
    }

    @MainActor
    func login(email: String, password: String) async {
        isLoading = true
        errorMessage = nil

        do {
            let response = try await api.login(email: email, password: password)
            saveTokens(response)
            isAuthenticated = true
            await loadAccount()
        } catch {
            errorMessage = error.localizedDescription
        }

        isLoading = false
    }

    @MainActor
    func logout() {
        KeychainHelper.delete(key: "accessToken")
        KeychainHelper.delete(key: "refreshToken")
        api.accessToken = nil
        isAuthenticated = false
        currentUser = nil
    }

    @MainActor
    func loadAccount() async {
        do {
            currentUser = try await api.account()
        } catch {
            // Silent failure — user stays logged in
        }
    }

    // MARK: - Token Management

    private func saveTokens(_ response: AuthResponse) {
        api.accessToken = response.accessToken
        KeychainHelper.save(key: "accessToken", value: response.accessToken)
        KeychainHelper.save(key: "refreshToken", value: response.refreshToken)
    }
}

// MARK: - Keychain Helper

enum KeychainHelper {
    static func save(key: String, value: String) {
        let data = value.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "com.vpn.app",
        ]
        SecItemDelete(query as CFDictionary)

        var addQuery = query
        addQuery[kSecValueData as String] = data
        SecItemAdd(addQuery as CFDictionary, nil)
    }

    static func load(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "com.vpn.app",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func delete(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "com.vpn.app",
        ]
        SecItemDelete(query as CFDictionary)
    }
}

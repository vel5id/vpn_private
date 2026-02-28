import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var authService: AuthService
    @EnvironmentObject var vpnManager: VPNManager

    @AppStorage("killSwitch") private var killSwitch = true
    @AppStorage("autoConnect") private var autoConnectOnUntrusted = false
    @AppStorage("selectedProtocol") private var selectedProtocol = "Auto"

    var body: some View {
        NavigationStack {
            List {
                // Account
                Section("Account") {
                    if let user = authService.currentUser {
                        HStack {
                            Text("Email")
                            Spacer()
                            Text(user.email)
                                .foregroundStyle(.secondary)
                        }

                        if let sub = user.subscription {
                            HStack {
                                Text("Plan")
                                Spacer()
                                Text(sub.tier.capitalized)
                                    .foregroundStyle(.secondary)
                            }
                            HStack {
                                Text("Status")
                                Spacer()
                                StatusBadge(status: sub.status)
                            }
                        } else {
                            Button("Subscribe") {
                                // TODO: show RevenueCat paywall
                            }
                        }
                    }
                }

                // VPN Settings
                Section("VPN") {
                    Toggle("Kill Switch", isOn: $killSwitch)

                    Toggle("Auto-connect on untrusted Wi-Fi", isOn: $autoConnectOnUntrusted)

                    Picker("Protocol", selection: $selectedProtocol) {
                        Text("Auto").tag("Auto")
                        Text("TLS 1.3").tag("TLS")
                    }
                }

                // Info
                Section("About") {
                    HStack {
                        Text("Version")
                        Spacer()
                        Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0")
                            .foregroundStyle(.secondary)
                    }

                    Link("Privacy Policy", destination: URL(string: "https://vpn.example.com/privacy")!)
                    Link("Terms of Service", destination: URL(string: "https://vpn.example.com/terms")!)
                }

                // Sign Out
                Section {
                    Button("Sign Out", role: .destructive) {
                        Task {
                            if vpnManager.status.isConnected {
                                await vpnManager.disconnect()
                            }
                            authService.logout()
                        }
                    }
                }
            }
            .navigationTitle("Settings")
        }
    }
}

struct StatusBadge: View {
    let status: String

    var body: some View {
        Text(status.capitalized)
            .font(.caption.bold())
            .padding(.horizontal, 8)
            .padding(.vertical, 2)
            .background(badgeColor.opacity(0.15))
            .foregroundStyle(badgeColor)
            .clipShape(Capsule())
    }

    private var badgeColor: Color {
        switch status.lowercased() {
        case "active": return .green
        case "cancelled": return .orange
        case "expired": return .red
        default: return .gray
        }
    }
}

#Preview {
    SettingsView()
        .environmentObject(AuthService())
        .environmentObject(VPNManager())
}

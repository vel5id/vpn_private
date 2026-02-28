import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var authService: AuthService
    @EnvironmentObject var vpnManager: VPNManager

    @AppStorage("killSwitch") private var killSwitch = true
    @AppStorage("autoConnect") private var autoConnectOnUntrusted = false
    @AppStorage("selectedProtocol") private var selectedProtocol = "Auto"

    @State private var showPaywall = false

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
                                showPaywall = true
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
            .sheet(isPresented: $showPaywall) {
                PaywallView()
            }
        }
    }
}

// MARK: - Paywall View (RevenueCat integration point)

/// Paywall presented when the user taps "Subscribe".
///
/// To integrate RevenueCat:
/// 1. `import RevenueCatUI`
/// 2. Replace the body with `PaywallView()` from RevenueCatUI
///    or use `Purchases.shared.offerings` to build a custom paywall.
struct PaywallView: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Spacer()

                Image(systemName: "shield.checkered")
                    .font(.system(size: 64))
                    .foregroundStyle(.blue)

                Text("Unlock Premium VPN")
                    .font(.title.bold())

                VStack(alignment: .leading, spacing: 12) {
                    FeatureRow(icon: "bolt.fill", text: "Unlimited bandwidth")
                    FeatureRow(icon: "globe", text: "All server locations")
                    FeatureRow(icon: "lock.shield", text: "Kill switch & auto-reconnect")
                    FeatureRow(icon: "person.2.fill", text: "Up to 5 devices")
                }
                .padding(.horizontal)

                Spacer()

                Button {
                    // TODO: Purchases.shared.purchase(package:)
                    // For now, dismiss after a simulated purchase
                    dismiss()
                } label: {
                    Text("Start Free Trial — $4.99/month")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(.blue)
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                }
                .padding(.horizontal)

                Button("Restore Purchases") {
                    // TODO: Purchases.shared.restorePurchases()
                }
                .font(.footnote)

                Text("Cancel anytime. Terms apply.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .padding(.bottom)
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
        }
    }
}

private struct FeatureRow: View {
    let icon: String
    let text: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(.blue)
                .frame(width: 24)
            Text(text)
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

import SwiftUI

struct HomeView: View {
    @EnvironmentObject var vpnManager: VPNManager
    @EnvironmentObject var authService: AuthService

    var body: some View {
        NavigationStack {
            VStack(spacing: 40) {
                Spacer()

                // Connection status ring
                ZStack {
                    Circle()
                        .stroke(statusColor.opacity(0.2), lineWidth: 8)
                        .frame(width: 200, height: 200)

                    Circle()
                        .stroke(statusColor, lineWidth: 8)
                        .frame(width: 200, height: 200)
                        .opacity(vpnManager.status.isConnected ? 1 : 0)

                    VStack(spacing: 8) {
                        Image(systemName: statusIcon)
                            .font(.system(size: 48))
                            .foregroundStyle(statusColor)

                        Text(vpnManager.status.displayText)
                            .font(.headline)
                            .multilineTextAlignment(.center)
                    }
                }

                // Connect / Disconnect
                Button {
                    Task {
                        if vpnManager.status.isConnected {
                            await vpnManager.disconnect()
                        } else if let server = vpnManager.connectedServer ?? defaultServer() {
                            await vpnManager.connect(to: server)
                        }
                    }
                } label: {
                    Text(vpnManager.status.isConnected ? "Disconnect" : "Connect")
                        .font(.title3.bold())
                        .frame(width: 180, height: 50)
                }
                .buttonStyle(.borderedProminent)
                .tint(vpnManager.status.isConnected ? .red : .blue)
                .disabled(isTransitioning)

                // Server info
                if let server = vpnManager.connectedServer {
                    HStack {
                        Image(systemName: "globe")
                        Text(server.name)
                        Text("•")
                        Text(server.region)
                            .foregroundStyle(.secondary)
                    }
                    .font(.subheadline)
                }

                Spacer()
            }
            .padding()
            .navigationTitle("Protocol VPN")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    // MARK: - Helpers

    private var statusColor: Color {
        switch vpnManager.status {
        case .connected: return .green
        case .connecting, .disconnecting: return .orange
        case .error: return .red
        case .disconnected: return .gray
        }
    }

    private var statusIcon: String {
        switch vpnManager.status {
        case .connected: return "lock.shield.fill"
        case .connecting: return "arrow.trianglehead.2.clockwise"
        case .disconnecting: return "arrow.trianglehead.2.clockwise"
        case .error: return "exclamationmark.triangle.fill"
        case .disconnected: return "shield.slash"
        }
    }

    private var isTransitioning: Bool {
        if case .connecting = vpnManager.status { return true }
        if case .disconnecting = vpnManager.status { return true }
        return false
    }

    /// Returns a default server to connect to if none is selected.
    private func defaultServer() -> ServerInfo? {
        // In a real app, this would come from cached server list
        return nil
    }
}

#Preview {
    HomeView()
        .environmentObject(VPNManager())
        .environmentObject(AuthService())
}

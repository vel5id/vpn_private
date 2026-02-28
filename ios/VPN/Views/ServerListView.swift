import SwiftUI

struct ServerListView: View {
    @EnvironmentObject var vpnManager: VPNManager
    @State private var servers: [ServerInfo] = []
    @State private var isLoading = true
    @State private var errorMessage: String?

    private let api = APIClient.shared

    var body: some View {
        NavigationStack {
            Group {
                if isLoading {
                    ProgressView("Loading servers…")
                } else if let error = errorMessage {
                    VStack(spacing: 16) {
                        Image(systemName: "exclamationmark.triangle")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                        Text(error)
                            .foregroundStyle(.secondary)
                        Button("Retry") {
                            Task { await loadServers() }
                        }
                    }
                } else {
                    List(servers) { server in
                        ServerRow(server: server,
                                  isSelected: vpnManager.connectedServer?.id == server.id)
                            .onTapGesture {
                                Task { await vpnManager.connect(to: server) }
                            }
                    }
                    .refreshable {
                        await loadServers()
                    }
                }
            }
            .navigationTitle("Servers")
            .task { await loadServers() }
        }
    }

    private func loadServers() async {
        isLoading = true
        errorMessage = nil
        do {
            servers = try await api.listServers()
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
    }
}

// MARK: - Server Row

struct ServerRow: View {
    let server: ServerInfo
    let isSelected: Bool

    var body: some View {
        HStack {
            // Region flag placeholder
            Text(regionEmoji(server.region))
                .font(.title2)

            VStack(alignment: .leading, spacing: 2) {
                Text(server.name)
                    .font(.body.weight(.medium))
                Text(server.region)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            // Load indicator
            LoadIndicator(load: server.load)

            if isSelected {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            }
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }

    private func regionEmoji(_ region: String) -> String {
        let r = region.lowercased()
        if r.contains("us") || r.contains("america") { return "🇺🇸" }
        if r.contains("eu") || r.contains("europe") || r.contains("finland") || r.contains("germany") { return "🇪🇺" }
        if r.contains("asia") || r.contains("japan") || r.contains("tokyo") { return "🇯🇵" }
        if r.contains("uk") || r.contains("london") { return "🇬🇧" }
        if r.contains("australia") || r.contains("sydney") { return "🇦🇺" }
        return "🌍"
    }
}

struct LoadIndicator: View {
    let load: Double

    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(loadColor)
                .frame(width: 8, height: 8)
            Text("\(Int(load * 100))%")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    private var loadColor: Color {
        if load < 0.5 { return .green }
        if load < 0.8 { return .orange }
        return .red
    }
}

#Preview {
    ServerListView()
        .environmentObject(VPNManager())
}

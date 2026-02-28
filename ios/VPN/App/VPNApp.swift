import SwiftUI

@main
struct VPNApp: App {
    @StateObject private var authService = AuthService()
    @StateObject private var vpnManager = VPNManager()

    var body: some Scene {
        WindowGroup {
            Group {
                if authService.isAuthenticated {
                    MainTabView()
                        .environmentObject(authService)
                        .environmentObject(vpnManager)
                } else {
                    OnboardingView()
                        .environmentObject(authService)
                }
            }
        }
    }
}

struct MainTabView: View {
    var body: some View {
        TabView {
            HomeView()
                .tabItem {
                    Label("VPN", systemImage: "shield.checkered")
                }

            ServerListView()
                .tabItem {
                    Label("Servers", systemImage: "globe")
                }

            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gear")
                }
        }
    }
}

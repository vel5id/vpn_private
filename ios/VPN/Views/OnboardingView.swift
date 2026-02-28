import SwiftUI

struct OnboardingView: View {
    @EnvironmentObject var authService: AuthService

    @State private var email = ""
    @State private var password = ""
    @State private var isLogin = true

    var body: some View {
        NavigationStack {
            VStack(spacing: 32) {
                Spacer()

                // Logo
                Image(systemName: "shield.checkered")
                    .font(.system(size: 72))
                    .foregroundStyle(.blue)

                Text("Protocol VPN")
                    .font(.largeTitle.bold())

                Text("Secure, private, fast")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                // Form
                VStack(spacing: 16) {
                    TextField("Email", text: $email)
                        .textContentType(.emailAddress)
                        .keyboardType(.emailAddress)
                        .autocapitalization(.none)
                        .textFieldStyle(.roundedBorder)

                    SecureField("Password", text: $password)
                        .textContentType(isLogin ? .password : .newPassword)
                        .textFieldStyle(.roundedBorder)
                }
                .padding(.horizontal, 32)

                // Error
                if let error = authService.errorMessage {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .padding(.horizontal)
                }

                // Action button
                Button {
                    Task {
                        if isLogin {
                            await authService.login(email: email, password: password)
                        } else {
                            await authService.register(email: email, password: password)
                        }
                    }
                } label: {
                    if authService.isLoading {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(isLogin ? "Sign In" : "Create Account")
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(email.isEmpty || password.isEmpty || authService.isLoading)
                .padding(.horizontal, 32)

                // Toggle mode
                Button(isLogin ? "Don't have an account? Sign Up" : "Already have an account? Sign In") {
                    isLogin.toggle()
                    authService.errorMessage = nil
                }
                .font(.footnote)

                Spacer()
            }
            .navigationBarBackButtonHidden()
        }
    }
}

#Preview {
    OnboardingView()
        .environmentObject(AuthService())
}

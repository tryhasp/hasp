#if os(iOS)
  import HaspDesign
  import SwiftUI

  struct MobileUnlockAdviceSheet: View {
    let app: AppModel
    @Environment(\.openURL) private var openURL
    @State private var password = ""

    var body: some View {
      ScrollView {
        content
          .frame(maxWidth: MobileMetrics.formWidth)
          .padding(HaspSpace.s24)
          .frame(maxWidth: .infinity)
      }
      .background(HaspColor.window.ignoresSafeArea())
      .presentationDetents([.large])
    }

    private var content: some View {
      VStack(spacing: HaspSpace.s16) {
        Text(title)
          .haspText(HaspFont.titleLocked)
          .foregroundStyle(HaspColor.text)
          .multilineTextAlignment(.center)
          .fixedSize(horizontal: false, vertical: true)
          .accessibilityAddTraits(.isHeader)
        Text(bodyText(for: app.unlockAdvice))
          .haspText(HaspFont.bodyLarge)
          .foregroundStyle(HaspColor.textSecondary)
          .multilineTextAlignment(.center)
          .fixedSize(horizontal: false, vertical: true)
          .accessibilityIdentifier("advice.body")
        if app.unlockAdvice == .enableBiometrics {
          SecureField("locked.password", text: $password)
            .mobileField()
            .textContentType(.none)
            .accessibilityLabel("locked.password")
            .accessibilityIdentifier("advice.password")
          if let notice = app.notice { NoticeText(text: notice) }
        }
        primary
        Button("m.advice.later") { app.showsUnlockAdvice = false }
          .buttonStyle(MobileSecondaryButtonStyle())
          .accessibilityIdentifier("advice.later")
      }
    }

    @ViewBuilder private var primary: some View {
      if app.unlockAdvice == .enableBiometrics {
        Button("m.advice.enable") {
          let typed = password
          password = ""
          Task { await app.enableHardwareUnlock(password: typed) }
        }
        .buttonStyle(MobilePrimaryButtonStyle())
        .disabled(password.isEmpty || app.busy)
        .accessibilityIdentifier("advice.enable")
      } else {
        Button("m.advice.openSettings") {
          if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
        }
        .buttonStyle(MobilePrimaryButtonStyle())
        .accessibilityIdentifier("advice.openSettings")
      }
    }

    private var title: LocalizedStringKey {
      app.unlockAdvice == .enableBiometrics
        ? "m.advice.biometrics.title" : "m.advice.passcode.title"
    }

    private func bodyText(for advice: UnlockAdvice?) -> LocalizedStringKey {
      advice == .enableBiometrics ? "m.advice.biometrics.body" : "m.advice.passcode.body"
    }
  }
#endif

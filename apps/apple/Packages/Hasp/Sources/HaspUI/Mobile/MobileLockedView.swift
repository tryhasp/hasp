#if os(iOS)
  import HaspDesign
  import HaspKit
  import SwiftUI

  struct MobileLockedView: View {
    let app: AppModel
    @State private var password = ""
    @FocusState private var focused: Bool

    var body: some View {
      ScrollView {
        VStack(spacing: HaspSpace.s16) {
          HaspMark()
          Text("locked.title")
            .haspText(HaspFont.titleLocked)
            .foregroundStyle(HaspColor.text)
            .accessibilityAddTraits(.isHeader)
          Text("locked.prompt")
            .haspText(HaspFont.bodyLarge)
            .foregroundStyle(HaspColor.textSecondary)
            .multilineTextAlignment(.center)
          form
          if app.status?.unlockMode == .passwordOnly {
            Text("m.locked.passwordOnly")
              .haspText(HaspFont.caption)
              .foregroundStyle(HaspColor.textSecondary)
              .multilineTextAlignment(.center)
              .accessibilityIdentifier("unlock.passwordOnly")
          }
          if let reason = reasonText {
            Text(reason).haspText(HaspFont.caption).foregroundStyle(HaspColor.textSecondary)
          }
          if let notice = app.notice { NoticeText(text: notice) }
        }
        .frame(maxWidth: MobileMetrics.formWidth)
        .padding(.horizontal, HaspSpace.s24)
        .padding(.top, HaspSpace.s40 + HaspSpace.s40)
        .frame(maxWidth: .infinity)
      }
      .scrollDismissesKeyboard(.interactively)
      .background(HaspColor.window.ignoresSafeArea())
      .task {
        if app.biometricsAvailable && app.lockReason == nil { await app.unlockWithBiometrics() }
      }
    }

    private var form: some View {
      VStack(spacing: HaspSpace.s12) {
        SecureField("locked.password", text: $password)
          .mobileField()
          .focused($focused)
          .submitLabel(.go)
          .onSubmit(unlock)
          .textContentType(.none)
          .accessibilityLabel("locked.password")
          .accessibilityIdentifier("unlock.password")
        Button("locked.unlock", action: unlock)
          .buttonStyle(MobilePrimaryButtonStyle())
          .disabled(password.isEmpty || app.busy)
          .accessibilityIdentifier("unlock.submit")
        if app.biometricsAvailable {
          Button {
            Task { await app.unlockWithBiometrics() }
          } label: {
            Label("m.locked.biometric", systemImage: "faceid")
          }
          .buttonStyle(MobileSecondaryButtonStyle())
          .accessibilityIdentifier("unlock.biometric")
        }
      }
    }

    private var reasonText: String? {
      switch app.lockReason {
      case .idle(let minutes)?: String(localized: "locked.reason.idle \(minutes)")
      case .sleep?: String(localized: "locked.reason.sleep")
      case .screenLock?: String(localized: "locked.reason.screenLock")
      case .userSwitch?: String(localized: "locked.reason.userSwitch")
      case .manual?: String(localized: "locked.reason.manual")
      case .policy?: String(localized: "locked.reason.policy")
      case nil: nil
      }
    }

    private func unlock() {
      let typed = password
      password = ""
      Task { await app.unlock(password: typed) }
    }
  }
#endif

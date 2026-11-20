import HaspDesign
import HaspKit
import SwiftUI

struct LockedView: View {
  let app: AppModel
  @State private var password = ""
  @FocusState private var focused: Bool

  var body: some View {
    VStack(spacing: HaspSpace.s16) {
      HaspMark()
      Text("locked.title")
        .haspText(HaspFont.titleLocked)
        .foregroundStyle(HaspColor.text)
        .accessibilityAddTraits(.isHeader)
      Text("locked.prompt")
        .haspText(HaspFont.bodyLarge)
        .foregroundStyle(HaspColor.textSecondary)
      form
      if let reason = reasonText {
        Text(reason)
          .haspText(HaspFont.caption)
          .foregroundStyle(HaspColor.textSecondary)
      }
      if let notice = app.notice {
        NoticeText(text: notice)
      }
    }
    .frame(width: HaspSize.unlockFieldWidth)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(HaspColor.window)
    .onAppear { focused = true }
  }

  private var form: some View {
    VStack(spacing: HaspSpace.s8) {
      HStack(spacing: HaspSpace.s8) {
        SecureField("locked.password", text: $password)
          .haspField()
          .focused($focused)
          .onSubmit(unlock)
          .accessibilityLabel("locked.password")
          .accessibilityIdentifier("unlock.password")
        if app.biometricsAvailable {
          Button(action: unlockWithBiometrics) {
            Image(systemName: "touchid")
              .font(.system(size: HaspSize.iconBiometric))
              .frame(width: HaspSize.controlHeightLarge, height: HaspSize.controlHeightLarge)
          }
          .buttonStyle(HaspBorderedButtonStyle())
          .accessibilityLabel("locked.touchID")
          .keyboardShortcut("b", modifiers: .command)
        }
      }
      Button("locked.unlock", action: unlock)
        .buttonStyle(HaspPrimaryButtonStyle())
        .keyboardShortcut(.defaultAction)
        .disabled(password.isEmpty || app.busy)
        .accessibilityIdentifier("unlock.submit")
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

  private func unlockWithBiometrics() {
    Task { await app.unlockWithBiometrics() }
  }
}

struct NoticeText: View {
  let text: String

  var body: some View {
    Text(text)
      .haspText(HaspFont.caption)
      .foregroundStyle(HaspColor.warning)
      .multilineTextAlignment(.center)
      .accessibilityIdentifier("notice")
  }
}

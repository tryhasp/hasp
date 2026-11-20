import HaspDesign
import HaspKit
import HaspProvider
import SwiftUI

struct ProviderStatusView: View {
  let key: LocalizedStringKey
  let showsProgress: Bool

  var body: some View {
    VStack(spacing: 12) {
      if showsProgress { ProgressView() }
      Text(key)
        .foregroundStyle(HaspColor.textSecondary)
        .multilineTextAlignment(.center)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .padding()
    .accessibilityIdentifier("provider.status")
  }
}

struct ProviderFailureView: View {
  let model: ProviderScreenModel
  let failure: ProviderFailure

  var body: some View {
    VStack(spacing: 16) {
      Text(message)
        .multilineTextAlignment(.center)
        .accessibilityIdentifier("provider.failure")
      HStack {
        Button("provider.retry") { Task { await model.start() } }
          .accessibilityIdentifier("provider.retry")
        Button("provider.close") { Task { await model.close(after: failure) } }
          .accessibilityIdentifier("provider.close")
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .padding()
  }

  private var message: LocalizedStringKey {
    switch failure {
    case .openApp: "provider.openApp"
    case .passwordOnly: "provider.passwordOnly"
    default: "provider.failed"
    }
  }
}

struct ProviderConfirmView: View {
  let model: ProviderScreenModel

  var body: some View {
    VStack(spacing: 16) {
      if let fill = model.pendingFill {
        Text("provider.fill.body \(fill.title) \(fill.host)")
          .multilineTextAlignment(.center)
          .accessibilityIdentifier("provider.fill.body")
        Button("provider.fill.action") { Task { await model.confirmFill() } }
          .buttonStyle(.borderedProminent)
          .accessibilityIdentifier("provider.fill.action")
      } else if let input = model.registrationSubject {
        Text("provider.save.body \(input.rpID) \(input.userName)")
          .multilineTextAlignment(.center)
          .accessibilityIdentifier("provider.save.body")
      }
      if model.pendingFill == nil {
        Button("provider.save.action") { Task { await model.confirmRegistration() } }
          .buttonStyle(.borderedProminent)
          .accessibilityIdentifier("provider.save.action")
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .padding()
  }
}

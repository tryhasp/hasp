import HaspDesign
import HaspKit
import SwiftUI
import UniformTypeIdentifiers

struct OnboardingView: View {
  let app: AppModel
  @State private var model: OnboardingModel
  @State private var importing = false

  init(app: AppModel) {
    self.app = app
    _model = State(initialValue: OnboardingModel(app: app))
  }

  var body: some View {
    VStack(spacing: HaspSpace.s16) {
      HaspMark()
      Text("onboarding.title")
        .haspText(HaspFont.titleLocked)
        .foregroundStyle(HaspColor.text)
        .accessibilityAddTraits(.isHeader)
      Text("onboarding.subtitle")
        .haspText(HaspFont.bodyLarge)
        .foregroundStyle(HaspColor.textSecondary)
      Picker("onboarding.method", selection: $model.method) {
        Text("onboarding.method.secretKey").tag(OnboardingModel.Method.secretKey)
        Text("onboarding.method.signUp").tag(OnboardingModel.Method.signUp)
        Text("onboarding.method.kit").tag(OnboardingModel.Method.kit)
      }
      .pickerStyle(.segmented)
      .labelsHidden()
      .accessibilityLabel("onboarding.method")
      fields
      if let notice = app.notice { NoticeText(text: notice) }
      Button(model.method == .signUp ? "onboarding.signUp" : "onboarding.signIn") {
        Task { await model.submit() }
      }
      .buttonStyle(HaspPrimaryButtonStyle())
      .keyboardShortcut(.defaultAction)
      .disabled(!model.canSubmit)
      .accessibilityIdentifier("onboarding.submit")
    }
    .frame(width: HaspSize.unlockFieldWidth)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(HaspColor.window)
    .fileImporter(isPresented: $importing, allowedContentTypes: [.image]) { result in
      if case .success(let url) = result { importKit(url) }
    }
  }

  @ViewBuilder private var fields: some View {
    VStack(spacing: HaspSpace.s8) {
      switch model.method {
      case .secretKey, .signUp:
        TextField("onboarding.server", text: $model.origin)
          .haspField()
          .accessibilityLabel("onboarding.server")
          .accessibilityIdentifier("onboarding.server")
        ServerCheckRow(model: model)
        TextField("onboarding.login", text: $model.login)
          .haspField()
          .accessibilityLabel("onboarding.login")
          .accessibilityIdentifier("onboarding.login")
        if model.method == .signUp {
          SecureField("onboarding.code", text: $model.code)
            .haspField()
            .accessibilityLabel("onboarding.code")
            .accessibilityIdentifier("onboarding.code")
        } else {
          SecureField("onboarding.secretKey", text: $model.secretKey)
            .haspField()
            .accessibilityLabel("onboarding.secretKey")
            .accessibilityIdentifier("onboarding.secretKey")
        }
      case .kit:
        KitImportRow(model: model) { importing = true }
      }
      SecureField("onboarding.password", text: $model.password)
        .haspField()
        .onSubmit { Task { await model.submit() } }
        .accessibilityLabel("onboarding.password")
        .accessibilityIdentifier("onboarding.password")
    }
  }

  private func importKit(_ url: URL) {
    let granted = url.startAccessingSecurityScopedResource()
    defer { if granted { url.stopAccessingSecurityScopedResource() } }
    model.importKit(from: url)
  }
}

struct KitImportRow: View {
  let model: OnboardingModel
  let choose: () -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: HaspSpace.s8) {
      Button("onboarding.kit.choose", action: choose)
        .buttonStyle(HaspBorderedButtonStyle())
      if let preview = model.kitPreview {
        VStack(alignment: .leading, spacing: HaspSpace.s4) {
          Text(preview.login).haspText(HaspFont.bodyMedium)
          Text(preview.origin).haspText(HaspFont.origin)
          Text("onboarding.kit.fingerprint").haspText(HaspFont.caption)
            .foregroundStyle(HaspColor.textSecondary)
          Text(preview.serverFingerprint).haspText(HaspFont.hostInline)
            .textSelection(.enabled)
        }
        .accessibilityElement(children: .combine)
      } else if model.kitFailed {
        NoticeText(text: String(localized: "onboarding.kit.failed"))
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}

struct ServerCheckRow: View {
  @Bindable var model: OnboardingModel

  var body: some View {
    VStack(alignment: .leading, spacing: HaspSpace.s8) {
      if let fingerprint = model.fingerprint {
        Text("onboarding.fingerprint.title").haspText(HaspFont.caption)
          .foregroundStyle(HaspColor.textSecondary)
        Text(fingerprint).haspText(HaspFont.hostInline)
          .textSelection(.enabled)
          .accessibilityIdentifier("onboarding.fingerprint")
        Toggle("onboarding.fingerprint.confirm", isOn: $model.fingerprintConfirmed)
          .accessibilityIdentifier("onboarding.fingerprintConfirm")
      } else {
        Button("onboarding.checkServer") { Task { await model.checkServer() } }
          .buttonStyle(HaspBorderedButtonStyle())
          .disabled(model.origin.isEmpty)
          .accessibilityIdentifier("onboarding.checkServer")
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}

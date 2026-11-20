#if os(iOS)
  import HaspDesign
  import HaspKit
  import PhotosUI
  import SwiftUI

  struct MobileOnboardingView: View {
    let app: AppModel
    @State private var model: OnboardingModel
    @State private var scanning = false
    @State private var photo: PhotosPickerItem?

    init(app: AppModel) {
      self.app = app
      _model = State(initialValue: OnboardingModel(app: app))
    }

    var body: some View {
      ScrollView {
        VStack(spacing: HaspSpace.s16) {
          HaspMark()
          Text("onboarding.title")
            .haspText(HaspFont.titleLocked)
            .foregroundStyle(HaspColor.text)
            .multilineTextAlignment(.center)
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
          .accessibilityIdentifier("onboarding.method")
          fields
          if let notice = app.notice { NoticeText(text: notice) }
          Button(model.method == .signUp ? "onboarding.signUp" : "onboarding.signIn") {
            Task { await model.submit() }
          }
          .buttonStyle(MobilePrimaryButtonStyle())
          .disabled(!model.canSubmit)
          .accessibilityIdentifier("onboarding.submit")
        }
        .frame(maxWidth: MobileMetrics.formWidth)
        .padding(.horizontal, HaspSpace.s24)
        .padding(.vertical, HaspSpace.s32)
        .frame(maxWidth: .infinity)
      }
      .scrollDismissesKeyboard(.interactively)
      .background(HaspColor.window.ignoresSafeArea())
      .fullScreenCover(isPresented: $scanning) {
        MobileScanSheet(model: model, isPresented: $scanning)
      }
      .onChange(of: photo) { _, item in loadPhoto(item) }
    }

    @ViewBuilder private var fields: some View {
      VStack(spacing: HaspSpace.s12) {
        switch model.method {
        case .secretKey, .signUp:
          serverFields
          TextField("onboarding.login", text: $model.login)
            .mobileField()
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .keyboardType(.emailAddress)
            .accessibilityLabel("onboarding.login")
            .accessibilityIdentifier("onboarding.login")
          if model.method == .signUp {
            SecureField("onboarding.code", text: $model.code)
              .mobileField()
              .accessibilityLabel("onboarding.code")
              .accessibilityIdentifier("onboarding.code")
          } else {
            SecureField("onboarding.secretKey", text: $model.secretKey)
              .mobileField()
              .textContentType(.oneTimeCode)
              .textInputAutocapitalization(.characters)
              .accessibilityLabel("onboarding.secretKey")
              .accessibilityIdentifier("onboarding.secretKey")
          }
        case .kit:
          kitFields
        }
        SecureField("onboarding.password", text: $model.password)
          .mobileField()
          .textContentType(.none)
          .submitLabel(.go)
          .onSubmit { Task { await model.submit() } }
          .accessibilityLabel("onboarding.password")
          .accessibilityIdentifier("onboarding.password")
      }
    }

    private var serverFields: some View {
      VStack(alignment: .leading, spacing: HaspSpace.s12) {
        TextField("onboarding.server", text: $model.origin)
          .mobileField()
          .textInputAutocapitalization(.never)
          .autocorrectionDisabled()
          .keyboardType(.URL)
          .accessibilityLabel("onboarding.server")
          .accessibilityIdentifier("onboarding.server")
        MobileServerCheck(model: model)
      }
    }

    private var kitFields: some View {
      VStack(alignment: .leading, spacing: HaspSpace.s12) {
        Button {
          scanning = true
        } label: {
          Label("m.onboarding.scan", systemImage: "qrcode.viewfinder")
        }
        .buttonStyle(MobileSecondaryButtonStyle())
        .accessibilityIdentifier("onboarding.kit.scan")
        PhotosPicker(selection: $photo, matching: .images) {
          PickLabel()
        }
        .accessibilityIdentifier("onboarding.kit.pick")
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
    }

    private func loadPhoto(_ item: PhotosPickerItem?) {
      guard let item else { return }
      Task {
        if let data = try? await item.loadTransferable(type: Data.self) {
          model.importKit(imageData: data)
        } else {
          model.scanUnavailable()
        }
        photo = nil
      }
    }
  }

  struct PickLabel: View {
    var body: some View {
      Label("m.onboarding.pick", systemImage: "photo")
        .haspText(HaspFont.bodyMedium)
        .foregroundStyle(HaspColor.text)
        .frame(maxWidth: .infinity, minHeight: MobileMetrics.touchTarget)
        .background(HaspColor.field, in: RoundedRectangle(cornerRadius: HaspRadius.field))
        .overlay(
          RoundedRectangle(cornerRadius: HaspRadius.field)
            .stroke(HaspColor.controlBorder, lineWidth: HaspBorder.hairline)
        )
    }
  }

  struct MobileServerCheck: View {
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
            .haspText(HaspFont.body)
            .accessibilityIdentifier("onboarding.fingerprintConfirm")
        } else {
          Button("onboarding.checkServer") { Task { await model.checkServer() } }
            .buttonStyle(MobileSecondaryButtonStyle())
            .disabled(model.origin.isEmpty)
            .accessibilityIdentifier("onboarding.checkServer")
        }
      }
      .frame(maxWidth: .infinity, alignment: .leading)
    }
  }
#endif

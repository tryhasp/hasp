#if os(iOS)
  import HaspDesign
  import HaspKit
  import SwiftUI

  struct MobileSettingsView: View {
    let app: AppModel
    @State private var model: SettingsModel

    init(app: AppModel) {
      self.app = app
      _model = State(initialValue: SettingsModel(app: app))
    }

    var body: some View {
      NavigationStack {
        Form {
          Section {
            Button("m.settings.lockNow") { Task { await app.lock() } }
              .frame(minHeight: MobileMetrics.touchTarget)
              .accessibilityIdentifier("settings.lockNow")
          }
          Section {
            security
          } header: {
            MobileSectionHeader("settings.security")
          }
          MobileAutoFillSection()
          Section {
            devices
          } header: {
            MobileSectionHeader("settings.devices")
          }
          Section {
            account
          } header: {
            MobileSectionHeader("settings.account")
          }
        }
        .navigationTitle("m.tab.settings")
        .task { await model.loadDevices() }
      }
    }

    @ViewBuilder private var security: some View {
      Picker("m.settings.background", selection: backgroundBinding) {
        ForEach(Self.backgroundChoices, id: \.self) { seconds in
          Text(Self.backgroundTitle(seconds)).tag(seconds)
        }
      }
      Picker("settings.passwordEvery", selection: daysBinding) {
        ForEach([1, 7, 14, 30], id: \.self) { days in Text("settings.days \(days)").tag(days) }
      }
      Picker("settings.clipboard", selection: clipboardBinding) {
        Text("settings.clipboard.never").tag(0)
        ForEach([10, 30, 60, 90, 120], id: \.self) { seconds in
          Text("settings.seconds \(seconds)").tag(seconds)
        }
      }
      Toggle(
        "settings.breach",
        isOn: Binding(
          get: { model.settings.breachCheck },
          set: { value in Task { await model.update { $0.breachCheck = value } } },
        ),
      )
    }

    @ViewBuilder private var devices: some View {
      ForEach(model.devices) { device in
        HStack {
          VStack(alignment: .leading) {
            Text(device.label ?? device.platform).haspText(HaspFont.bodyMedium)
            Text(device.current ? "devices.current" : "devices.other")
              .haspText(HaspFont.caption)
              .foregroundStyle(HaspColor.textSecondary)
          }
          Spacer()
          if device.revoked {
            Text("devices.revoked").haspText(HaspFont.caption)
          } else if !device.current {
            Button("devices.revoke", role: .destructive) {
              Task { await model.revoke(device) }
            }
            .buttonStyle(.borderless)
            .frame(minHeight: MobileMetrics.touchTarget)
          }
        }
        .accessibilityElement(children: .combine)
      }
    }

    @ViewBuilder private var account: some View {
      LabeledContent("account.login", value: app.status?.login ?? "—")
      LabeledContent("account.server", value: app.status?.origin ?? "—")
      VStack(alignment: .leading, spacing: HaspSpace.s4) {
        Text("account.fingerprint").haspText(HaspFont.caption)
          .foregroundStyle(HaspColor.textSecondary)
        Text(app.status?.fingerprint ?? "—").haspText(HaspFont.hostInline)
          .textSelection(.enabled)
      }
      LabeledContent("account.unlockMode", value: modeText)
      if app.unlockAdvice != nil {
        Button(adviceTitle) { app.showsUnlockAdvice = true }
          .frame(minHeight: MobileMetrics.touchTarget)
          .accessibilityIdentifier("settings.unlockAdvice")
      }
    }

    static let backgroundChoices = [0, 15, 30, 60, 120, 300, 600, 900]

    static func backgroundTitle(_ seconds: Int) -> LocalizedStringKey {
      switch seconds {
      case 0: "m.settings.background.now"
      case ..<60: "settings.seconds \(seconds)"
      default: "m.settings.background.minutes \(seconds / 60)"
      }
    }

    private var adviceTitle: LocalizedStringKey {
      app.unlockAdvice == .enableBiometrics
        ? "m.advice.biometrics.title" : "m.advice.passcode.title"
    }

    private var modeText: String {
      switch app.status?.unlockMode {
      case .hardware?: String(localized: "m.account.mode.hardware")
      case .passwordOnly?: String(localized: "account.mode.passwordOnly")
      case .desktopExtension?: String(localized: "account.mode.extension")
      case nil: "—"
      }
    }

    private var backgroundBinding: Binding<Int> {
      Binding(
        get: { Int(model.settings.lock.background.components.seconds) },
        set: { seconds in Task { await model.update { $0.lock.background = .seconds(seconds) } } },
      )
    }

    private var daysBinding: Binding<Int> {
      Binding(
        get: { model.settings.lock.passwordEveryDays },
        set: { days in Task { await model.update { $0.lock.passwordEveryDays = days } } },
      )
    }

    private var clipboardBinding: Binding<Int> {
      Binding(
        get: { Int(model.settings.lock.clipboardClear.components.seconds) },
        set: { seconds in Task { await model.update { $0.lock.clipboardClear = .seconds(seconds) } }
        },
      )
    }
  }
#endif

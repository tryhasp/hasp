import HaspDesign
import HaspKit
import SwiftUI

struct WatchtowerSettings: View {
  let model: SettingsModel

  var body: some View {
    Form {
      Toggle(
        "settings.breach",
        isOn: Binding(
          get: { model.settings.breachCheck },
          set: { value in Task { await model.update { $0.breachCheck = value } } },
        ),
      )
      Text("watchtower.disclosure")
        .haspText(HaspFont.caption)
        .foregroundStyle(HaspColor.textSecondary)
    }
    .formStyle(.grouped)
  }
}

struct DevicesSettings: View {
  let model: SettingsModel

  var body: some View {
    List(model.devices) { device in
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
          Button("devices.revoke") { Task { await model.revoke(device) } }
            .buttonStyle(HaspBorderedButtonStyle())
        }
      }
      .accessibilityElement(children: .combine)
    }
    .task { await model.loadDevices() }
  }
}

struct AccountSettings: View {
  let app: AppModel

  var body: some View {
    Form {
      LabeledContent("account.login", value: app.status?.login ?? "—")
      LabeledContent("account.server", value: app.status?.origin ?? "—")
      LabeledContent("account.fingerprint") {
        Text(app.status?.fingerprint ?? "—").haspText(HaspFont.hostInline).textSelection(.enabled)
      }
      LabeledContent("account.unlockMode", value: modeText)
      Picker("account.language", selection: languageBinding) {
        Text("한국어").tag("ko")
        Text("English").tag("en")
      }
      Text("account.languageNote").haspText(HaspFont.caption)
        .foregroundStyle(HaspColor.textSecondary)
    }
    .formStyle(.grouped)
  }

  private var modeText: String {
    switch app.status?.unlockMode {
    case .hardware?: String(localized: "account.mode.hardware")
    case .passwordOnly?: String(localized: "account.mode.passwordOnly")
    case .desktopExtension?: String(localized: "account.mode.extension")
    case nil: "—"
    }
  }

  private var languageBinding: Binding<String> {
    Binding(
      get: { app.settings.language },
      set: { language in
        Task {
          await SettingsModel(app: app).update { $0.language = language }
          UserDefaults.standard.set([language], forKey: "AppleLanguages")
        }
      },
    )
  }
}

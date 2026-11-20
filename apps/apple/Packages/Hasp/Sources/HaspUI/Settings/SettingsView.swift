#if os(macOS)
  import HaspDesign
  public import SwiftUI

  public struct SettingsView: View {
    let app: AppModel
    @State private var model: SettingsModel

    public init(app: AppModel) {
      self.app = app
      _model = State(initialValue: SettingsModel(app: app))
    }

    public var body: some View {
      if app.phase == .unlocked {
        @Bindable var app = app
        TabView(selection: $app.settingsTab) {
          SecuritySettings(model: model)
            .tabItem { Label("settings.security", systemImage: "lock.shield") }
            .tag(SettingsTab.security)
          QuickAccessSettings(app: app)
            .tabItem { Label("settings.quick", systemImage: "command") }
            .tag(SettingsTab.quickAccess)
          SecretTagSettings(model: model)
            .tabItem { Label("settings.tag", systemImage: "tag") }
            .tag(SettingsTab.tag)
          WatchtowerSettings(model: model)
            .tabItem { Label("settings.watchtower", systemImage: "checkmark.shield") }
            .tag(SettingsTab.watchtower)
          DevicesSettings(model: model)
            .tabItem { Label("settings.devices", systemImage: "laptopcomputer.and.iphone") }
            .tag(SettingsTab.devices)
          AccountSettings(app: app)
            .tabItem { Label("settings.account", systemImage: "person.crop.circle") }
            .tag(SettingsTab.account)
        }
        .frame(width: HaspSize.settingsWidth, height: HaspSize.settingsHeight)
      } else {
        Text("settings.locked")
          .haspText(HaspFont.body)
          .foregroundStyle(HaspColor.textSecondary)
          .frame(width: HaspSize.settingsWidth, height: HaspSize.settingsHeight)
      }
    }
  }
#endif

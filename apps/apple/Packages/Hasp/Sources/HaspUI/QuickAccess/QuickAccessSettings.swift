#if os(macOS)
  import AppKit
  import HaspDesign
  import HaspQuickAccessCore
  import SwiftUI

  struct QuickAccessSettings: View {
    let app: AppModel
    @State private var model: QuickAccessSettingsModel

    init(app: AppModel) {
      self.app = app
      _model = State(initialValue: QuickAccessSettingsModel(app: app))
    }

    var body: some View {
      Form {
        if app.quickAccess == nil {
          Text("quick.settings.unavailable")
            .haspText(HaspFont.body)
            .foregroundStyle(HaspColor.textSecondary)
        } else {
          Section("quick.settings.hotkey") { hotKeyRow }
          Section("quick.settings.accessibility") { accessibilityRows }
        }
      }
      .formStyle(.grouped)
      .accessibilityIdentifier("settings.quick")
      .task { await model.watchAccessibility() }
      .onDisappear { model.stopRecording() }
    }

    private var hotKeyRow: some View {
      VStack(alignment: .leading, spacing: HaspSpace.s8) {
        LabeledContent("quick.settings.shortcut") {
          HStack {
            Text(model.recording ? String(localized: "quick.settings.press") : model.hotKeyText)
              .haspText(HaspFont.hostInline)
              .accessibilityIdentifier("quick.settings.current")
            Button(model.recording ? "common.cancel" : "quick.settings.change") {
              model.recording ? model.stopRecording() : model.startRecording()
            }
            .buttonStyle(HaspBorderedButtonStyle())
            .accessibilityIdentifier("quick.settings.change")
          }
        }
        if let failure = model.failure {
          NoticeText(text: failure.message)
        }
        Text("quick.settings.hotkeyNote")
          .haspText(HaspFont.caption)
          .foregroundStyle(HaspColor.textSecondary)
      }
    }

    private var accessibilityRows: some View {
      VStack(alignment: .leading, spacing: HaspSpace.s8) {
        LabeledContent("quick.settings.status") {
          Text(model.trusted ? "quick.settings.allowed" : "quick.settings.notAllowed")
            .haspText(HaspFont.bodyMedium)
            .accessibilityIdentifier("quick.settings.accessibilityStatus")
        }
        Text("quick.access.why")
          .haspText(HaspFont.caption)
          .foregroundStyle(HaspColor.textSecondary)
        if !model.trusted {
          Button("quick.access.allow") { model.allowAccessibility() }
            .buttonStyle(HaspBorderedButtonStyle())
            .accessibilityIdentifier("quick.access.allow")
        }
      }
    }
  }

  extension HotKeyFailure {
    var message: String {
      switch self {
      case .needsModifier: String(localized: "quick.settings.error.modifier")
      case .conflictsWithSystem: String(localized: "quick.settings.error.system")
      case .unavailable: String(localized: "quick.settings.error.unavailable")
      }
    }
  }
#endif

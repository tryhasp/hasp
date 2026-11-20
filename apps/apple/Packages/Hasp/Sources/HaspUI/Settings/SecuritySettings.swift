import HaspDesign
import HaspKit
import SwiftUI

struct SecuritySettings: View {
  let model: SettingsModel

  var body: some View {
    Form {
      Picker("settings.idle", selection: idleBinding) {
        Text("settings.idle.never").tag(0)
        ForEach([1, 5, 10, 15, 30, 60], id: \.self) { minutes in
          Text("settings.idle.minutes \(minutes)").tag(minutes)
        }
      }
      Toggle("settings.lockSleep", isOn: flag(\.lockOnSleep))
      Toggle("settings.lockScreen", isOn: flag(\.lockOnScreenLock))
      Toggle("settings.lockUser", isOn: flag(\.lockOnUserSwitch))
      Toggle("settings.lockQuit", isOn: flag(\.lockOnQuit))
      Picker("settings.passwordEvery", selection: daysBinding) {
        ForEach([1, 7, 14, 30], id: \.self) { days in
          Text("settings.days \(days)").tag(days)
        }
      }
      Picker("settings.clipboard", selection: clipboardBinding) {
        Text("settings.clipboard.never").tag(0)
        ForEach([10, 30, 60, 90, 120], id: \.self) { seconds in
          Text("settings.seconds \(seconds)").tag(seconds)
        }
      }
    }
    .formStyle(.grouped)
    .accessibilityIdentifier("settings.security")
  }

  private var idleBinding: Binding<Int> {
    Binding(
      get: { Int(model.settings.lock.idle.components.seconds / 60) },
      set: { minutes in Task { await model.update { $0.lock.idle = .seconds(minutes * 60) } } },
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

  private func flag(_ path: WritableKeyPath<LockPolicy, Bool>) -> Binding<Bool> {
    Binding(
      get: { model.settings.lock[keyPath: path] },
      set: { value in Task { await model.update { $0.lock[keyPath: path] = value } } },
    )
  }
}

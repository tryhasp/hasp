public import SwiftUI

public struct HaspCommands: Commands {
  let app: AppModel

  public init(app: AppModel) {
    self.app = app
  }

  public var body: some Commands {
    CommandGroup(replacing: .newItem) {
      Button("command.newItem") { app.library?.beginCreate(kind: "login") }
        .keyboardShortcut("n")
        .disabled(app.phase != .unlocked)
    }
    CommandGroup(after: .textEditing) {
      Button("command.find") { app.library?.focusSearch() }
        .keyboardShortcut("f")
        .disabled(app.phase != .unlocked)
    }
    CommandMenu("command.menu") {
      Button("command.edit") { app.library?.beginEdit() }
        .keyboardShortcut("e")
        .disabled(app.library?.selectedKey == nil)
      Button("command.sync") { Task { await app.syncNow() } }
        .keyboardShortcut("r")
        .disabled(app.phase != .unlocked)
      Divider()
      Button("command.lock") { Task { await app.lock() } }
        .keyboardShortcut("l")
        .disabled(app.phase != .unlocked)
    }
  }
}

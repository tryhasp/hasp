import AppKit
import HaspUI
import SwiftUI

@main
struct HaspApp: App {
  @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
  @State private var model: AppModel
  @Environment(\.openWindow) private var openWindow
  @Environment(\.openSettings) private var openSettings
  private let bootstrap: AppBootstrap

  init() {
    let made = AppBootstrap.make()
    bootstrap = made
    _model = State(initialValue: made.model)
  }

  var body: some Scene {
    Window("Hasp", id: "main") {
      RootView(app: model)
        .onAppear {
          delegate.attach(model: model, bridge: bootstrap.bridge)
          start()
        }
    }
    .defaultSize(width: 1280, height: 800)
    .commands { HaspCommands(app: model) }
    Settings {
      SettingsView(app: model)
    }
    MenuBarExtra("Hasp", systemImage: "lock.shield") {
      Button("menu.quickAccess") { bootstrap.quickAccess.toggle() }
        .disabled(!bootstrap.quickAccess.isInstalled)
      Button("menu.open") { bootstrap.quickAccess.openMainWindow() }
      Divider()
      Button("menu.lock") { Task { await model.lock() } }
        .disabled(model.phase != .unlocked)
      Button("menu.quit") { NSApp.terminate(nil) }
    }
    .menuBarExtraStyle(.menu)
  }

  private func start() {
    let quick = bootstrap.quickAccess
    quick.openMainWindow = {
      NSApp.activate()
      if let window = NSApp.windows.first(where: { $0.title == "Hasp" }) {
        window.makeKeyAndOrderFront(nil)
      } else {
        openWindow(id: "main")
      }
    }
    quick.openSettings = {
      NSApp.activate()
      openSettings()
    }
    quick.install(model: model)
    #if DEBUG
      ScreenshotRun.start(options: bootstrap.options, model: model, quickAccess: quick)
    #endif
  }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
  private var model: AppModel?
  private var bridge: BridgeCoordinator?

  func attach(model: AppModel, bridge: BridgeCoordinator) {
    self.model = model
    self.bridge = bridge
  }

  func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
    guard let model else { return .terminateNow }
    Task {
      await model.lockForQuit()
      bridge?.stop()
      sender.reply(toApplicationShouldTerminate: true)
    }
    return .terminateLater
  }
}

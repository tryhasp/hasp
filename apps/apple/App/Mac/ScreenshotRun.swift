#if DEBUG
  import AppKit
  import HaspQuickAccessCore
  import HaspUI
  import OSLog

  private let log = Logger(subsystem: "kr.jmo.hasp", category: "shots")

  struct Fixture: Decodable {
    let origin: String
    let login: String
    let secretKey: String
    let password: String
    let fingerprint: String
  }

  /// Debug-only walkthrough: signs in with a fixture account and writes PNGs of each screen.
  @MainActor
  enum ScreenshotRun {
    private static var started = false

    static func start(options: LaunchOptions, model: AppModel, quickAccess: QuickAccessHost) {
      guard !started, let fixtureURL = options.fixture, let directory = options.shotsDirectory
      else { return }
      started = true
      NSApp.appearance = NSAppearance(named: .aqua)
      Task {
        do {
          let fixture = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: fixtureURL))
          try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
          await walk(fixture, directory, model, quickAccess)
        } catch {
          log.error("screenshot run failed to start")
        }
        NSApp.terminate(nil)
      }
    }

    private static func walk(
      _ fixture: Fixture,
      _ directory: URL,
      _ model: AppModel,
      _ quickAccess: QuickAccessHost,
    ) async {
      NSApp.appearance = NSAppearance(named: .aqua)
      await until { model.phase != .starting }
      if model.phase == .onboarding {
        capture(mainWindow(), "onboarding", directory)
        await model.signIn(
          origin: fixture.origin,
          login: fixture.login,
          secretKey: fixture.secretKey,
          password: fixture.password,
          fingerprint: fixture.fingerprint,
        )
      }
      await until { model.phase == .unlocked }
      await pause(2.5)
      capture(mainWindow(), "intro", directory)
      model.dismissQuickAccessIntro()
      await pause(0.5)
      if let first = try? await quickAccess.engine.items().first {
        model.openItem(vault: first.id.vault, item: first.id.item)
      }
      await pause(2)
      capture(mainWindow(), "main", directory)
      await appearance(.darkAqua) { capture(mainWindow(), "main-dark", directory) }

      quickAccess.show()
      await pause(1.2)
      capture(panelWindow(), "quick-access", directory)
      await appearance(.darkAqua) { capture(panelWindow(), "quick-access-dark", directory) }
      quickAccess.toggle()

      for (name, tab) in [
        ("settings-security", SettingsTab.security), ("settings-quick-access", .quickAccess),
        ("settings-tag", .tag),
      ] {
        model.settingsTab = tab
        quickAccess.openSettings()
        await pause(1)
        capture(settingsWindow(), name, directory)
      }

      settingsWindow()?.close()
      await model.lock()
      await pause(1)
      capture(mainWindow(), "locked", directory)
      quickAccess.show()
      await pause(1)
      capture(panelWindow(), "quick-access-locked", directory)
    }

    private static func mainWindow() -> NSWindow? {
      NSApp.windows.first { $0.isVisible && !($0 is NSPanel) && $0.title == "Hasp" }
    }

    private static func settingsWindow() -> NSWindow? {
      NSApp.windows.first { $0.isVisible && $0.styleMask.contains(.titled) && $0.title != "Hasp" }
    }

    private static func panelWindow() -> NSWindow? {
      NSApp.windows.first { $0 is NSPanel && $0.isVisible && $0.frame.width > 300 }
    }

    private static func appearance(_ name: NSAppearance.Name, _ body: () -> Void) async {
      let previous = NSApp.appearance
      NSApp.appearance = NSAppearance(named: name)
      await pause(0.8)
      body()
      NSApp.appearance = previous ?? NSAppearance(named: .aqua)
      await pause(0.3)
    }

    private static func capture(_ window: NSWindow?, _ name: String, _ directory: URL) {
      if ProcessInfo.processInfo.environment["HASP_SHOTS_NATIVE"] == "1" {
        captureNative(window, name, directory)
        return
      }
      guard let view = window?.contentView?.superview ?? window?.contentView,
        let representation = view.bitmapImageRepForCachingDisplay(in: view.bounds)
      else {
        log.error("no window for \(name, privacy: .public)")
        return
      }
      view.cacheDisplay(in: view.bounds, to: representation)
      let png = representation.representation(using: .png, properties: [:])
      try? png?.write(to: directory.appending(path: "\(name).png"))
    }

    private static func captureNative(_ window: NSWindow?, _ name: String, _ directory: URL) {
      guard let window else {
        log.error("no window for \(name, privacy: .public)")
        return
      }
      window.sharingType = .readOnly
      let process = Process()
      process.executableURL = URL(filePath: "/usr/sbin/screencapture")
      process.arguments = [
        "-x", "-o", "-l", String(window.windowNumber),
        directory.appending(path: "\(name).png").path,
      ]
      try? process.run()
      process.waitUntilExit()
    }

    private static func until(_ condition: () -> Bool) async {
      for _ in 0..<300 where !condition() { await pause(0.1) }
    }

    private static func pause(_ seconds: Double) async {
      try? await Task.sleep(for: .seconds(seconds))
    }
  }
#endif

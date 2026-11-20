import AppKit
import ApplicationServices
import HaspKit
import HaspQuickAccess
import HaspQuickAccessCore
import HaspUI
import OSLog
import Synchronization

private let log = Logger(subsystem: "kr.jmo.hasp", category: "quick-access")

enum NoSession: Error {
  case locked
}

/// Quick Access is installed once; the account behind it changes when the user signs in to another server.
actor SwitchableQuickAccessEngine: QuickAccessEngine {
  private var current: (any QuickAccessEngine)?

  func use(_ engine: (any QuickAccessEngine)?) {
    current = engine
  }

  func lockState() async throws -> QuickAccessLockState {
    guard let current else { return .locked }
    return try await current.lockState()
  }

  func items() async throws -> [QuickItem] { try await engine().items() }

  func otpPreview(for item: QuickItemID) async throws -> OTPPreview {
    try await engine().otpPreview(for: item)
  }

  func password(for item: QuickItemID) async throws -> Data {
    try await engine().password(for: item)
  }

  func otpCode(for item: QuickItemID) async throws -> Data {
    try await engine().otpCode(for: item)
  }

  func username(for item: QuickItemID) async throws -> Data {
    try await engine().username(for: item)
  }

  func loginValues(for item: QuickItemID) async throws -> LoginValues {
    try await engine().loginValues(for: item)
  }

  private func engine() throws -> any QuickAccessEngine {
    guard let current else { throw NoSession.locked }
    return current
  }
}

/// The bridge is rebuilt with each session; Quick Access keeps one channel that follows it.
final class SwitchableFillChannel: BrowserFillChannel {
  private let current = Mutex<(any BrowserFillChannel)?>(nil)

  func use(_ channel: (any BrowserFillChannel)?) {
    current.withLock { $0 = channel }
  }

  func hasPairedExtension(browserBundleID: String) async -> Bool {
    guard let channel = current.withLock({ $0 }) else { return false }
    return await channel.hasPairedExtension(browserBundleID: browserBundleID)
  }

  func pageHost(browserBundleID: String) async -> String? {
    guard let channel = current.withLock({ $0 }) else { return nil }
    return await channel.pageHost(browserBundleID: browserBundleID)
  }

  func requestFill(browserBundleID: String, item: QuickItemID) async -> BrowserFillOutcome {
    guard let channel = current.withLock({ $0 }) else { return .unavailable }
    return await channel.requestFill(browserBundleID: browserBundleID, item: item)
  }
}

@MainActor
final class QuickAccessHost: QuickAccessControl {
  nonisolated let engine = SwitchableQuickAccessEngine()
  var openMainWindow: () -> Void = {}
  var openSettings: () -> Void = {}
  nonisolated let fillChannel = SwitchableFillChannel()
  private let clipboard: ClipboardClearer

  init(clipboard: ClipboardClearer) {
    self.clipboard = clipboard
  }

  private var quickAccess: QuickAccess?
  private static let hotKeyDefaultsKey = "quickAccess.hotKey"

  var isInstalled: Bool { quickAccess != nil }

  func install(model: AppModel) {
    guard quickAccess == nil else { return }
    let callbacks = QuickAccess.Callbacks(
      openInMainWindow: { [weak self, weak model] id in
        model?.openItem(vault: id.vault, item: id.item)
        self?.openMainWindow()
      },
      requestUnlock: { [weak self] in self?.openMainWindow() },
    )
    do {
      quickAccess = try QuickAccess.install(
        engine: engine,
        clipboard: clipboard,
        browserChannel: fillChannel,
        callbacks: callbacks,
      )
    } catch {
      log.error("stored hotkey did not register, falling back to the default")
      UserDefaults.standard.removeObject(forKey: Self.hotKeyDefaultsKey)
      quickAccess = try? QuickAccess.install(
        engine: engine,
        clipboard: clipboard,
        browserChannel: fillChannel,
        callbacks: callbacks,
      )
    }
    model.quickAccess = quickAccess == nil ? nil : self
  }

  func lock() async {
    await quickAccess?.lock()
  }

  func toggle() { quickAccess?.toggle() }

  func show() { quickAccess?.show() }

  var hotKey: HotKeyBinding { quickAccess?.hotKey ?? .standard }

  var accessibilityTrusted: Bool { AXIsProcessTrusted() }

  func setHotKey(_ binding: HotKeyBinding) throws(HotKeyFailure) {
    guard let quickAccess else { throw .unavailable }
    do {
      try quickAccess.setHotKey(binding)
    } catch HotKeyError.needsModifier {
      throw .needsModifier
    } catch HotKeyError.conflictsWithSystemShortcut {
      throw .conflictsWithSystem
    } catch {
      throw .unavailable
    }
  }

  func requestAccessibility() {
    _ = AXIsProcessTrustedWithOptions(["AXTrustedCheckOptionPrompt": true] as CFDictionary)
  }

  func openAccessibilitySettings() {
    guard
      let url = URL(
        string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"
      )
    else { return }
    NSWorkspace.shared.open(url)
  }
}

public import Foundation
import HaspKit

extension AppModel {
  public func fetchFingerprint(origin: String) async -> String? {
    guard let url = Self.normalizedOrigin(origin) else {
      notice = UserMessage.text(for: HaspError.refused)
      return nil
    }
    busy = true
    notice = nil
    defer { busy = false }
    do {
      return try await environment.makeSession(url).serverFingerprint()
    } catch {
      show(error: error)
      return nil
    }
  }

  public func signIn(
    origin: String,
    login: String,
    secretKey: String,
    password: String,
    fingerprint: String,
  ) async {
    guard let url = Self.normalizedOrigin(origin) else {
      notice = UserMessage.text(for: HaspError.refused)
      return
    }
    await perform {
      let opened = try self.environment.makeSession(url)
      try await opened.signIn(
        login: login,
        secretKey: secretKey,
        password: password,
        serverFingerprint: fingerprint,
      )
      self.environment.rememberOrigin(url)
      await self.adopt(opened, firstSignIn: true)
    }
  }

  public func signUp(
    origin: String,
    login: String,
    code: String,
    password: String,
    fingerprint: String,
  ) async {
    guard let url = Self.normalizedOrigin(origin) else {
      notice = UserMessage.text(for: HaspError.refused)
      return
    }
    await perform {
      let opened = try self.environment.makeSession(url)
      let kit = try await opened.signUp(
        login: login,
        code: code,
        password: password,
        serverFingerprint: fingerprint,
      )
      if try await opened.status().state != .unlocked { try await opened.unlockPassword(password) }
      self.environment.rememberOrigin(url)
      self.emergencyKit = kit
      await self.adopt(opened, firstSignIn: true)
    }
  }

  public func finishEmergencyKit() {
    emergencyKit = nil
  }

  public func signIn(kit: Data, password: String) async {
    await perform {
      let preview = try AccountSession.previewKit(blob: kit)
      guard let url = Self.normalizedOrigin(preview.origin) else { throw HaspError.refused }
      let opened = try self.environment.makeSession(url)
      try await opened.signInWithKit(blob: kit, password: password)
      self.environment.rememberOrigin(url)
      await self.adopt(opened, firstSignIn: true)
    }
  }

  public func unlock(password: String) async {
    guard let session else { return }
    await perform {
      try await session.unlockPassword(password)
      await self.finishUnlock(firstSignIn: false)
    }
  }

  public func unlockWithBiometrics() async {
    guard let session else { return }
    await perform {
      try await session.unlockBiometric()
      await self.finishUnlock(firstSignIn: false)
    }
  }

  public var biometricsAvailable: Bool {
    guard let status else { return false }
    return status.biometricReady && !status.passwordRequired && status.unlockMode == .hardware
  }

  func adopt(_ opened: any VaultServing, firstSignIn: Bool) async {
    if firstSignIn { await environment.accountDidEnd() }
    session = opened
    startEventLoop(for: opened)
    await finishUnlock(firstSignIn: firstSignIn)
  }

  func finishUnlock(firstSignIn: Bool) async {
    guard let session else { return }
    await loadSettings(from: session, firstSignIn: firstSignIn)
    await refreshStatus()
    lockReason = nil
    notice = nil
    library = LibraryModel(session: session, app: self)
    if firstSignIn && quickAccess != nil && !UserDefaults.standard.bool(forKey: Self.introSeenKey) {
      showsQuickAccessIntro = true
    }
    phase = .unlocked
    refreshUnlockAdvice()
    startPolicyLoops(for: session)
    await library?.refresh()
    Task { await syncAndWatch(session) }
  }

  func loadSettings(from session: any VaultServing, firstSignIn: Bool) async {
    do {
      var current = try await session.settings()
      if firstSignIn && current.lock.clipboardClear != Self.defaultClipboardClear {
        current.lock.clipboardClear = Self.defaultClipboardClear
        try await session.setSettings(current)
      }
      settings = current
    } catch {
      show(error: error)
    }
  }

  func syncAndWatch(_ session: any VaultServing) async {
    do {
      try await session.startHints()
      _ = try await session.sync()
      await library?.refresh()
      await environment.afterSync(session)
    } catch {
      toastMessage(UserMessage.text(for: error))
    }
  }

  func perform(_ work: @escaping () async throws -> Void) async {
    busy = true
    notice = nil
    defer { busy = false }
    do {
      try await work()
    } catch {
      show(error: error)
      await refreshStatus()
    }
  }

  static func normalizedOrigin(_ text: String) -> URL? {
    var trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    while trimmed.hasSuffix("/") { trimmed.removeLast() }
    guard let url = URL(string: trimmed), let scheme = url.scheme, url.host() != nil,
      scheme == "https" || scheme == "http"
    else { return nil }
    return url
  }

  static let defaultClipboardClear = Duration.seconds(30)
}

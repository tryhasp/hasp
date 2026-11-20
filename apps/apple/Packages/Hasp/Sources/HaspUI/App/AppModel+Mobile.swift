import Foundation
import HaspKit

extension AppModel {
  public func sceneDidBackground(at instant: ContinuousClock.Instant) {
    guard phase == .unlocked else { return }
    backgroundedAt = instant
  }

  /// Runs synchronously on the scene change so the shield stays up until the lock decision is made.
  public func sceneWillActivate() {
    isDecidingLock = backgroundedAt != nil && phase == .unlocked
  }

  /// A policy of "immediately" locks as the app leaves the screen, not when it returns.
  public func lockForBackground() async {
    guard phase == .unlocked, let session else { return }
    await apply(.background, elapsed: .zero, on: session)
  }

  /// Applies the mobile background rule: the policy decides from the time spent away.
  public func sceneDidActivate(at instant: ContinuousClock.Instant) async {
    defer { isDecidingLock = false }
    guard let left = backgroundedAt else { return }
    backgroundedAt = nil
    guard phase == .unlocked, let session else { return }
    await apply(.background, elapsed: instant - left, on: session)
    if phase == .unlocked { await syncNow() }
  }

  /// A background refresh runs the lock rule first and only syncs while the keys are still allowed to be open.
  public func refreshInBackground(at instant: ContinuousClock.Instant = .now) async -> Bool {
    guard phase == .unlocked, let session else { return false }
    if let left = backgroundedAt {
      await apply(.background, elapsed: instant - left, on: session)
      guard phase == .unlocked else { return false }
    }
    do {
      _ = try await session.sync()
      await environment.afterSync(session)
      return true
    } catch {
      return false
    }
  }

  public var asksForPasswordFirst: Bool {
    guard let status else { return true }
    return status.passwordRequired || status.unlockMode != .hardware || !status.biometricReady
  }
}

extension AppModel {
  func settingsDidChange(_ session: any VaultServing) async {
    await environment.afterSettingsChange(session)
  }

  func accountEnded() async {
    await environment.accountDidEnd()
  }

  public func announce(_ text: String) {
    toastMessage(text)
  }

  public func announce(error: any Error) {
    show(error: error)
  }
}

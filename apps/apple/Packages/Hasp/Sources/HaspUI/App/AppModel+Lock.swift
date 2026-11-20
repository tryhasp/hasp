import Foundation
import HaspKit
import HaspQuickAccessCore

extension AppModel {
  public func lock() async {
    guard let session else { return }
    await session.lock()
    await didLock(reason: .manual)
  }

  func startPolicyLoops(for session: any VaultServing) {
    cancelLoops()
    loops.append(
      Task { [weak self] in
        guard let self else { return }
        for await trigger in environment.systemLockTriggers() {
          await apply(trigger, elapsed: .zero, on: session)
        }
      }
    )
    loops.append(
      Task { [weak self] in
        while !Task.isCancelled {
          try? await Task.sleep(for: .seconds(5))
          guard let self else { return }
          await checkIdle(on: session)
        }
      }
    )
  }

  func cancelLoops() {
    loops.forEach { $0.cancel() }
    loops.removeAll()
  }

  func checkIdle(on session: any VaultServing) async {
    let limit = settings.lock.idle
    guard phase == .unlocked, limit > .zero else { return }
    let idle = environment.systemIdle()
    if idle >= limit { await apply(.idle, elapsed: idle, on: session) }
  }

  func apply(_ trigger: LockTrigger, elapsed: Duration, on session: any VaultServing) async {
    guard phase == .unlocked else { return }
    do {
      if try await session.applyLockTrigger(trigger, elapsed: elapsed) {
        await didLock(reason: Self.reason(for: trigger, settings: settings))
      }
    } catch {
      show(error: error)
    }
  }

  func didLock(reason: LockReason) async {
    cancelLoops()
    lockReason = reason
    library?.discard()
    library = nil
    await environment.clipboard.clearIfOurs()
    await refreshStatus()
    phase = .locked
    await onLocked()
  }

  func startEventLoop(for session: any VaultServing) {
    eventLoop?.cancel()
    eventLoop = Task { [weak self] in
      for await event in session.events {
        guard let self else { return }
        await handle(event)
      }
    }
  }

  func handle(_ event: SessionEvent) async {
    switch event {
    case .locked:
      guard phase == .unlocked else { return }
      let state = try? await session?.status().state
      if state != .unlocked { await didLock(reason: .policy) }
    case .vaultChanged:
      await library?.refresh()
    case .syncFinished:
      await library?.refresh()
      if let session { await environment.afterSync(session) }
    case .sessionRevoked, .deviceRevoked:
      await environment.accountDidEnd()
      await didLock(reason: .policy)
      notice = UserMessage.text(for: HaspError.deviceRevoked)
    case .settingsChanged:
      if let session, let current = try? await session.settings() { settings = current }
    case .unlocked, .syncStarted, .conflict, .needsAttention, .offline:
      break
    }
  }

  static func reason(for trigger: LockTrigger, settings: AppSettings) -> LockReason {
    switch trigger {
    case .idle: .idle(minutes: Int(settings.lock.idle.components.seconds / 60))
    case .sleep: .sleep
    case .screenLock: .screenLock
    case .userSwitch: .userSwitch
    case .manual: .manual
    case .quit, .background: .policy
    }
  }
}

extension AppModel {
  public func syncNow() async {
    guard let session else { return }
    do {
      _ = try await session.sync()
      await library?.refresh()
      await environment.afterSync(session)
    } catch {
      toastMessage(UserMessage.text(for: error))
    }
  }
}

extension AppModel {
  public func lockForQuit() async {
    await environment.clipboard.clearIfOurs()
    guard phase == .unlocked, let session else { return }
    do {
      _ = try await session.applyLockTrigger(.quit, elapsed: .zero)
    } catch {
      show(error: error)
    }
    await session.stopHints()
    await onLocked()
  }
}

public import Foundation
public import HaspKit
public import HaspQuickAccessCore

public struct AppEnvironment: Sendable {
  public var storedOrigin: @Sendable () -> URL?
  public var rememberOrigin: @Sendable (URL) -> Void
  public var makeSession: @Sendable (URL) throws -> any VaultServing
  public var clipboard: ClipboardClearer
  public var breachSource: any BreachRangeSource
  public var systemIdle: @Sendable () -> Duration
  public var systemLockTriggers: @Sendable () -> AsyncStream<LockTrigger>
  public var isHardwareBacked: Bool
  public var unlockCapability: @Sendable () -> UnlockCapability
  public var storeFailure: @Sendable () -> StoreFailure?
  public var afterSync: @Sendable (any VaultServing) async -> Void
  public var afterSettingsChange: @Sendable (any VaultServing) async -> Void
  public var accountDidEnd: @Sendable () async -> Void

  public init(
    storedOrigin: @escaping @Sendable () -> URL?,
    rememberOrigin: @escaping @Sendable (URL) -> Void,
    makeSession: @escaping @Sendable (URL) throws -> any VaultServing,
    clipboard: ClipboardClearer,
    breachSource: any BreachRangeSource,
    systemIdle: @escaping @Sendable () -> Duration,
    systemLockTriggers: @escaping @Sendable () -> AsyncStream<LockTrigger>,
    isHardwareBacked: Bool,
    unlockCapability: @escaping @Sendable () -> UnlockCapability = { .softwareOnly },
    storeFailure: @escaping @Sendable () -> StoreFailure? = { nil },
    afterSync: @escaping @Sendable (any VaultServing) async -> Void = { _ in },
    afterSettingsChange: @escaping @Sendable (any VaultServing) async -> Void = { _ in },
    accountDidEnd: @escaping @Sendable () async -> Void = {},
  ) {
    self.storedOrigin = storedOrigin
    self.rememberOrigin = rememberOrigin
    self.makeSession = makeSession
    self.clipboard = clipboard
    self.breachSource = breachSource
    self.systemIdle = systemIdle
    self.systemLockTriggers = systemLockTriggers
    self.isHardwareBacked = isHardwareBacked
    self.unlockCapability = unlockCapability
    self.storeFailure = storeFailure
    self.afterSync = afterSync
    self.afterSettingsChange = afterSettingsChange
    self.accountDidEnd = accountDidEnd
  }
}

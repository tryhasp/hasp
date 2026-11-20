public import Foundation
import HaspFFI

/// Holds the device unlock key. `get` is the gated release: it asks for user presence first.
public protocol SecureStore: Sendable {
  var hardwareGated: Bool { get }
  var lastFailure: StoreFailure? { get }
  func put(label: String, secret: Data) throws
  func get(label: String) throws -> Data
  func delete(label: String) throws
}

extension SecureStore {
  public var lastFailure: StoreFailure? { nil }
}

/// Why the system store refused, kept beside the engine error because the engine reports every store failure as internal.
public enum StoreFailure: Error, Equatable, Sendable {
  case passcodeNotSet
  case missingEntitlement
  case deviceLocked
  case authenticationFailed
  case status(Int32)

  public init(keychainPutStatus status: Int32) {
    self = status == -25291 || status == -25293 ? .passcodeNotSet : Self(keychainStatus: status)
  }

  public init(keychainStatus status: Int32) {
    self =
      switch status {
      case -34018: .missingEntitlement
      case -25308: .deviceLocked
      default: .status(status)
      }
  }
}

/// What this device can offer for unlocking without typing the password, decided by the platform.
public enum UnlockCapability: Equatable, Sendable {
  case hardwareReady
  case needsPasscode
  case softwareOnly

  public static func resolve(hasAccessGroup: Bool, hasPasscode: Bool, hasBiometrics: Bool)
    -> UnlockCapability
  {
    guard hasAccessGroup else { return .softwareOnly }
    guard hasPasscode else { return .needsPasscode }
    return hasBiometrics ? .hardwareReady : .softwareOnly
  }
}

public protocol BiometricAuthenticator: Sendable {
  var isAvailable: Bool { get }
  func authenticate(reason: String) throws
  func invalidate()
}

public protocol BreachRangeSource: Sendable {
  func range(prefix: String) throws -> String
}

public protocol ExtensionLink: Sendable {
  func send(_ message: Data) throws
  func receive() throws -> Data
}

final class StoreAdapter: PlatformStore {
  private let store: any SecureStore

  init(_ store: any SecureStore) {
    self.store = store
  }

  func hardwareGated() -> Bool { store.hardwareGated }

  func put(label: String, secret: Data) throws {
    try forward { try store.put(label: label, secret: secret) }
  }

  func get(label: String) throws -> Data {
    try forward { try store.get(label: label) }
  }

  func delete(label: String) throws {
    try forward { try store.delete(label: label) }
  }
}

final class BiometricAdapter: PlatformBiometric {
  private let authenticator: any BiometricAuthenticator

  init(_ authenticator: any BiometricAuthenticator) {
    self.authenticator = authenticator
  }

  func available() -> Bool { authenticator.isAvailable }

  func authenticate(reason: String) throws {
    try forward { try authenticator.authenticate(reason: reason) }
  }
}

final class BreachRangeAdapter: BreachRange {
  private let source: any BreachRangeSource

  init(_ source: any BreachRangeSource) {
    self.source = source
  }

  func range(prefix: String) throws -> String {
    try forward { try source.range(prefix: prefix) }
  }
}

final class LinkAdapter: PairingChannel {
  private let link: any ExtensionLink

  init(_ link: any ExtensionLink) {
    self.link = link
  }

  func send(message: Data) throws {
    try forward { try link.send(message) }
  }

  func recv() throws -> Data {
    try forward { try link.receive() }
  }
}

final class EventAdapter: EventListener {
  private let continuation: AsyncStream<SessionEvent>.Continuation
  private let onLocked: @Sendable () -> Void

  init(
    _ continuation: AsyncStream<SessionEvent>.Continuation,
    onLocked: @escaping @Sendable () -> Void,
  ) {
    self.continuation = continuation
    self.onLocked = onLocked
  }

  func onEvent(event: EngineEvent) {
    let mapped = SessionEvent(event)
    if mapped == .locked { onLocked() }
    continuation.yield(mapped)
  }
}

private func forward<T>(_ body: () throws -> T) throws -> T {
  do {
    return try body()
  } catch let error as HaspError {
    throw error.ffi
  } catch {
    throw HaspFFI.HaspError.Internal
  }
}

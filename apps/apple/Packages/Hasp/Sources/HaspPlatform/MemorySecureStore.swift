public import Foundation
public import HaspKit
import Synchronization

/// Keeps secrets in process memory only. Nothing is persisted.
public final class MemorySecureStore: SecureStore {
  private let entries = Mutex<[String: Data]>([:])

  public init() {}

  public var hardwareGated: Bool { false }

  public func put(label: String, secret: Data) throws {
    entries.withLock { $0[label] = secret }
  }

  public func get(label: String) throws -> Data {
    guard let secret = entries.withLock({ $0[label] }) else { throw HaspError.notFound }
    return secret
  }

  public func delete(label: String) throws {
    entries.withLock { $0[label] = nil }
  }
}

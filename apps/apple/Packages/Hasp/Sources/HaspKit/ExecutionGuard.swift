import Foundation
import Synchronization

/// Keeps the process running while an engine call holds the shared store lock.
/// A process suspended inside a call would keep the flock and the system kills it for it.
public protocol ExecutionGrant: Sendable {
  func begin() -> @Sendable () -> Void
}

public struct ProcessActivityGrant: ExecutionGrant {
  public init() {}

  public func begin() -> @Sendable () -> Void {
    let token = ProcessInfo.processInfo.beginActivity(
      options: [.userInitiated, .idleSystemSleepDisabled],
      reason: "vault store write",
    )
    nonisolated(unsafe) let held = token
    return { ProcessInfo.processInfo.endActivity(held) }
  }
}

public enum ExecutionGuard {
  private static let grant = Mutex<any ExecutionGrant>(ProcessActivityGrant())

  public static func install(_ replacement: any ExecutionGrant) {
    grant.withLock { $0 = replacement }
  }

  static func hold<T>(_ body: () throws -> T) rethrows -> T {
    let end = grant.withLock { $0 }.begin()
    defer { end() }
    return try body()
  }
}

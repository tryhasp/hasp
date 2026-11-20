import HaspKit
import UIKit

/// Asks the system for time to finish a store write before it suspends the app.
struct ApplicationBackgroundGrant: ExecutionGrant {
  func begin() -> @Sendable () -> Void {
    let identifier = onMain { UIApplication.shared.beginBackgroundTask(withName: "hasp.store") {} }
    return {
      guard identifier != .invalid else { return }
      onMain { UIApplication.shared.endBackgroundTask(identifier) }
    }
  }
}

private func onMain<T: Sendable>(_ body: @MainActor () -> T) -> T {
  if Thread.isMainThread { return MainActor.assumeIsolated(body) }
  return DispatchQueue.main.sync { MainActor.assumeIsolated(body) }
}

import HaspKit
import Synchronization

final class FailureLog: Sendable {
  private let value = Mutex<StoreFailure?>(nil)

  var last: StoreFailure? { value.withLock { $0 } }

  func record(_ failure: StoreFailure) {
    value.withLock { $0 = failure }
  }

  func clear() {
    value.withLock { $0 = nil }
  }
}

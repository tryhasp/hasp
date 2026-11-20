import Synchronization

@testable import HaspQuickAccessCore

final class FakePasteboard: PasteboardAccess, Sendable {
  private struct State {
    var count = 0
    var text: String?
    var concealed = false
  }

  private let state = Mutex(State())

  var changeCount: Int { state.withLock { $0.count } }
  var text: String? { state.withLock { $0.text } }
  var lastWriteWasConcealed: Bool { state.withLock { $0.concealed } }

  func writeConcealed(_ text: String, expiringAfter delay: Duration?) -> Int {
    state.withLock {
      $0.count += 1
      $0.text = text
      $0.concealed = true
      return $0.count
    }
  }

  func clear() -> Int {
    state.withLock {
      $0.count += 1
      $0.text = nil
      return $0.count
    }
  }

  func foreignWrite(_ text: String) {
    state.withLock {
      $0.count += 1
      $0.text = text
      $0.concealed = false
    }
  }
}

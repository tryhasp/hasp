public import Foundation

public protocol PasteboardAccess: Sendable {
  var changeCount: Int { get }
  func writeConcealed(_ text: String, expiringAfter delay: Duration?) -> Int
  func clear() -> Int
}

public actor ClipboardClearer {
  private let pasteboard: any PasteboardAccess
  private let clock: any Clock<Duration>
  private var ownedChangeCount: Int?
  private var pendingClear: Task<Void, Never>?

  public init(pasteboard: any PasteboardAccess, clock: any Clock<Duration>) {
    self.pasteboard = pasteboard
    self.clock = clock
  }

  public func copy(_ secret: Data, clearAfter delay: Duration?) {
    pendingClear?.cancel()
    pendingClear = nil
    ownedChangeCount = pasteboard.writeConcealed(
      String(decoding: secret, as: UTF8.self),
      expiringAfter: delay,
    )
    guard let delay, delay > .zero else { return }
    let clock = clock
    pendingClear = Task { [weak self] in
      do { try await clock.sleep(for: delay) } catch { return }
      await self?.clearIfOurs()
    }
  }

  @discardableResult
  public func clearIfOurs() -> Bool {
    pendingClear?.cancel()
    pendingClear = nil
    guard let owned = ownedChangeCount else { return false }
    ownedChangeCount = nil
    guard pasteboard.changeCount == owned else { return false }
    _ = pasteboard.clear()
    return true
  }

  public var holdsOurValue: Bool {
    guard let owned = ownedChangeCount else { return false }
    return pasteboard.changeCount == owned
  }
}

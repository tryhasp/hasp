#if os(iOS)
  import UIKit
  import UniformTypeIdentifiers

  /// Writes to the general pasteboard on this device only, with an expiry the system enforces
  /// even when the app is suspended.
  public struct GeneralPasteboard: PasteboardAccess {
    public init() {}

    private var board: UIPasteboard { UIPasteboard.general }

    public var changeCount: Int { board.changeCount }

    public func writeConcealed(_ text: String, expiringAfter delay: Duration?) -> Int {
      var options: [UIPasteboard.OptionsKey: Any] = [.localOnly: true]
      if let delay, delay > .zero {
        let seconds = Double(delay.components.seconds)
        options[.expirationDate] = Date(timeIntervalSinceNow: seconds)
      }
      board.setItems([[UTType.plainText.identifier: text]], options: options)
      return board.changeCount
    }

    public func clear() -> Int {
      board.items = []
      return board.changeCount
    }
  }
#endif

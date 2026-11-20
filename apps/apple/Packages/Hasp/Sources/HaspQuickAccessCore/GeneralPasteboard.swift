#if os(macOS)
  import AppKit

  public struct GeneralPasteboard: PasteboardAccess {
    static let contentsOptions: NSPasteboard.ContentsOptions = .currentHostOnly

    private let name: NSPasteboard.Name

    public init() {
      name = NSPasteboard.general.name
    }

    init(name: NSPasteboard.Name) {
      self.name = name
    }

    private var board: NSPasteboard { NSPasteboard(name: name) }

    public var changeCount: Int { board.changeCount }

    public func writeConcealed(_ text: String, expiringAfter delay: Duration?) -> Int {
      let types =
        [NSPasteboard.PasteboardType.string]
        + ClipboardMarkers.all.map {
          NSPasteboard.PasteboardType($0)
        }
      _ = board.prepareForNewContents(with: Self.contentsOptions)
      board.addTypes(types, owner: nil)
      board.setString(text, forType: .string)
      for marker in ClipboardMarkers.all {
        board.setData(Data(), forType: NSPasteboard.PasteboardType(marker))
      }
      return board.changeCount
    }

    public func clear() -> Int {
      board.clearContents()
    }
  }
#endif

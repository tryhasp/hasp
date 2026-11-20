import AppKit
import Testing

@testable import HaspQuickAccessCore

@Suite struct GeneralPasteboardTests {
  @Test func writesStayOnThisMac() {
    #expect(GeneralPasteboard.contentsOptions == .currentHostOnly)
  }

  @Test func concealedWriteIsMarkedAndClearedOnlyByChangeCount() {
    let name = NSPasteboard.Name("hasp.test.\(UUID().uuidString)")
    let board = NSPasteboard(name: name)
    defer { board.releaseGlobally() }
    let access = GeneralPasteboard(name: name)
    let count = access.writeConcealed("secret", expiringAfter: nil)
    #expect(board.string(forType: .string) == "secret")
    for marker in ClipboardMarkers.all {
      #expect(board.types?.contains(NSPasteboard.PasteboardType(marker)) == true)
    }
    #expect(access.changeCount == count)
    _ = access.clear()
    #expect(board.string(forType: .string) == nil)
  }
}

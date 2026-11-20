import Foundation
import Testing

@testable import HaspQuickAccessCore

struct ClipboardClearerTests {
  let board = FakePasteboard()
  let clock = ManualClock()

  func waitForSleeper() async {
    while clock.pendingSleepers == 0 { await Task.yield() }
  }

  @Test func clearsAfterTheDelayWhenNothingElseWasCopied() async {
    let clearer = ClipboardClearer(pasteboard: board, clock: clock)
    await clearer.copy(Data("hunter2".utf8), clearAfter: .seconds(30))
    #expect(board.text == "hunter2")
    #expect(board.lastWriteWasConcealed)
    await waitForSleeper()
    clock.advance(by: .seconds(29))
    #expect(board.text == "hunter2")
    clock.advance(by: .seconds(1))
    while board.text != nil { await Task.yield() }
    #expect(board.text == nil)
  }

  @Test func leavesTheClipboardAloneWhenTheUserCopiedSomethingElse() async {
    let clearer = ClipboardClearer(pasteboard: board, clock: clock)
    await clearer.copy(Data("hunter2".utf8), clearAfter: .seconds(30))
    board.foreignWrite("grocery list")
    await waitForSleeper()
    clock.advance(by: .seconds(30))
    while clock.pendingSleepers > 0 { await Task.yield() }
    for _ in 0..<50 { await Task.yield() }
    #expect(board.text == "grocery list")
  }

  @Test func aSecondCopyRestartsTheTimer() async {
    let clearer = ClipboardClearer(pasteboard: board, clock: clock)
    await clearer.copy(Data("first".utf8), clearAfter: .seconds(30))
    await waitForSleeper()
    clock.advance(by: .seconds(20))
    await clearer.copy(Data("second".utf8), clearAfter: .seconds(30))
    while clock.pendingSleepers == 0 { await Task.yield() }
    clock.advance(by: .seconds(15))
    for _ in 0..<50 { await Task.yield() }
    #expect(board.text == "second")
    clock.advance(by: .seconds(15))
    while board.text != nil { await Task.yield() }
    #expect(board.text == nil)
  }

  @Test func lockClearsOurValueOnly() async {
    let clearer = ClipboardClearer(pasteboard: board, clock: clock)
    await clearer.copy(Data("secret".utf8), clearAfter: .seconds(30))
    #expect(await clearer.holdsOurValue)
    #expect(await clearer.clearIfOurs())
    #expect(board.text == nil)

    await clearer.copy(Data("secret".utf8), clearAfter: .seconds(30))
    board.foreignWrite("other")
    #expect(await clearer.holdsOurValue == false)
    #expect(await clearer.clearIfOurs() == false)
    #expect(board.text == "other")
  }
}

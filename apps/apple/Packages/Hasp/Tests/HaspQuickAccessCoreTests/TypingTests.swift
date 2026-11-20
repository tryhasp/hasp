import CoreGraphics
import Foundation
import Testing

@testable import HaspQuickAccessCore

struct UnicodeChunkerTests {
  func decode(_ chunks: [[UInt16]]) -> String {
    chunks.map { String(decoding: $0, as: UTF16.self) }.joined()
  }

  @Test(arguments: [
    "hunter2",
    "비밀번호123!",
    "한글🙂emoji",
    "🇰🇷🇺🇸",
    "👨‍👩‍👧‍👦 family",
    "e\u{301}\u{301}",
    "",
  ])
  func chunksRoundTripExactly(text: String) {
    #expect(decode(UnicodeChunker.chunks(text)) == text)
  }

  @Test func neverExceedsTheEventLimit() {
    let text = String(repeating: "한🙂a", count: 40)
    let chunks = UnicodeChunker.chunks(text)
    #expect(chunks.allSatisfy { $0.count <= UnicodeChunker.maxUTF16Units })
    #expect(decode(chunks) == text)
  }

  @Test func keepsASurrogatePairTogether() {
    let text = String(repeating: "a", count: 19) + "🙂"
    let chunks = UnicodeChunker.chunks(text)
    #expect(chunks.count == 2)
    #expect(chunks[1] == Array("🙂".utf16))
  }

  @Test func keepsAGraphemeClusterTogetherWhenItFits() {
    let family = "👨‍👩‍👧‍👦"
    let text = String(repeating: "a", count: 10) + family
    let chunks = UnicodeChunker.chunks(text)
    #expect(chunks.count == 2)
    #expect(String(decoding: chunks[1], as: UTF16.self) == family)
  }

  @Test func splitsAnOversizedClusterOnScalarBoundaries() {
    let cluster = "e" + String(repeating: "\u{301}", count: 30)
    let chunks = UnicodeChunker.chunks(cluster)
    #expect(chunks.allSatisfy { $0.count <= UnicodeChunker.maxUTF16Units })
    #expect(decode(chunks) == cluster)
  }

  @Test func hangulSyllablesAreSingleUnits() {
    let chunks = UnicodeChunker.chunks("비밀번호")
    #expect(chunks == [Array("비밀번호".utf16)])
  }
}

struct TypingPlanTests {
  @Test func typesUsernameTabPasswordInAPlainField() {
    let plan = TypingPlan.login(
      username: "mino",
      password: "pw",
      focus: .plain,
      secureInputActive: false,
    )
    #expect(plan.steps == [.text("mino"), .tab, .text("pw")])
  }

  @Test func typesOnlyThePasswordInASecureField() {
    let plan = TypingPlan.login(
      username: "mino",
      password: "pw",
      focus: .secure,
      secureInputActive: true,
    )
    #expect(plan.steps == [.text("pw")])
  }

  @Test func unknownFocusWithSecureInputActiveIsTreatedAsAPasswordField() {
    let plan = TypingPlan.login(
      username: "mino",
      password: "pw",
      focus: .unknown,
      secureInputActive: true,
    )
    #expect(plan.steps == [.text("pw")])
  }

  @Test func unknownFocusWithoutSecureInputTypesBoth() {
    let plan = TypingPlan.login(
      username: "mino",
      password: "pw",
      focus: .unknown,
      secureInputActive: false,
    )
    #expect(plan.steps == [.text("mino"), .tab, .text("pw")])
  }

  @Test func skipsAnEmptyUsername() {
    let plan = TypingPlan.login(
      username: "",
      password: "pw",
      focus: .plain,
      secureInputActive: false,
    )
    #expect(plan.steps == [.text("pw")])
  }
}

struct TypingEventTests {
  func unicode(of event: CGEvent) -> String {
    var length = 0
    var buffer = [UniChar](repeating: 0, count: 64)
    event.keyboardGetUnicodeString(
      maxStringLength: buffer.count,
      actualStringLength: &length,
      unicodeString: &buffer,
    )
    return String(decoding: buffer.prefix(length), as: UTF16.self)
  }

  @Test(arguments: ["비밀번호!", "pässwörd", "한🙂글", "👩🏽‍💻x"])
  func eventsCarryTheUnicodeStringWithoutKeycodeTranslation(text: String) {
    let strokes = TypingEvents.strokes(for: .single(text))
    let source = CGEventSource(stateID: .privateState)
    var typed = ""
    for stroke in strokes {
      let events = TypingEvents.events(for: stroke, source: source)
      #expect(events.count == 2)
      #expect(events[0].type == .keyDown)
      #expect(events[1].type == .keyUp)
      #expect(events.allSatisfy { $0.flags.isEmpty })
      typed += unicode(of: events[0])
    }
    #expect(typed == text)
  }

  @Test func tabUsesTheRealTabKeyWithNoText() {
    let strokes = TypingEvents.strokes(for: TypingPlan(steps: [.tab]))
    #expect(strokes == [KeyStroke(keyCode: 0x30, unicode: [])])
    let events = TypingEvents.events(for: strokes[0], source: nil)
    #expect(events.count == 2)
    #expect(events[0].getIntegerValueField(.keyboardEventKeycode) == 0x30)
  }

  @MainActor
  @Test func typerPostsEveryEventInOrderToTheTargetProcess() async throws {
    let poster = RecordingPoster()
    let surroundings = FixedSurroundings()
    let typer = KeystrokeTyper(
      poster: poster,
      surroundings: surroundings,
      clock: ImmediateClock(),
      focusTimeout: .seconds(1),
    )
    let focus = try await typer.captureFocus(of: 5)
    try await typer.type(
      TypingPlan.login(username: "미노", password: "p🙂", focus: .plain, secureInputActive: false),
      expecting: focus,
    )
    #expect(poster.count == 2 * 3)
    #expect(poster.targets == [5])
  }

  @MainActor
  @Test func aFocusChangeBetweenChunksStopsEveryFurtherEvent() async throws {
    let poster = RecordingPoster()
    let surroundings = FixedSurroundings()
    let typer = KeystrokeTyper(
      poster: poster,
      surroundings: surroundings,
      clock: ImmediateClock(),
      focusTimeout: .seconds(1),
    )
    let focus = try await typer.captureFocus(of: 5)
    poster.onPost = { surroundings.front = 6 }
    await #expect(throws: TypingError.focusChanged) {
      try await typer.type(.single(String(repeating: "a", count: 60)), expecting: focus)
    }
    #expect(poster.count == 2)
  }
}

@MainActor
final class FixedSurroundings: TypingSurroundings {
  var front: Int32? = 5
  func frontmostProcessID() -> Int32? { front }
  func focus(in processID: Int32) -> FocusSnapshot? {
    FocusSnapshot(processID: processID, kind: .plain, element: 1)
  }
  func hasKeyWindow() -> Bool { false }
  func secureInputEnabled() -> Bool { false }
}

final class RecordingPoster: EventPoster, @unchecked Sendable {
  // Why: tests only; single-threaded after the awaited call returns.
  private(set) var count = 0
  private(set) var targets: Set<Int32> = []
  var onPost: (() -> Void)?

  func post(_ event: CGEvent, toProcess processID: Int32) {
    count += 1
    targets.insert(processID)
    onPost?()
  }
}

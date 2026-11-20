#if os(macOS)
  public import CoreGraphics
  import Foundation

  public struct KeyStroke: Equatable, Sendable {
    public let keyCode: CGKeyCode
    public let unicode: [UInt16]
  }

  public enum TypingEvents {
    public static let tabKeyCode: CGKeyCode = 0x30

    public static func strokes(for plan: TypingPlan) -> [KeyStroke] {
      plan.steps.flatMap { step -> [KeyStroke] in
        switch step {
        case .text(let text):
          UnicodeChunker.chunks(text).map { KeyStroke(keyCode: 0, unicode: $0) }
        case .tab:
          [KeyStroke(keyCode: tabKeyCode, unicode: [])]
        }
      }
    }

    public static func events(for stroke: KeyStroke, source: CGEventSource?) -> [CGEvent] {
      [true, false].compactMap { keyDown in
        guard
          let event = CGEvent(
            keyboardEventSource: source,
            virtualKey: stroke.keyCode,
            keyDown: keyDown,
          )
        else { return nil }
        event.flags = []
        if !stroke.unicode.isEmpty {
          var units = stroke.unicode
          event.keyboardSetUnicodeString(stringLength: units.count, unicodeString: &units)
        }
        return event
      }
    }
  }

  public protocol EventPoster: Sendable {
    func post(_ event: CGEvent, toProcess processID: Int32)
  }

  public struct ProcessEventPoster: EventPoster {
    public init() {}

    public func post(_ event: CGEvent, toProcess processID: Int32) {
      event.postToPid(processID)
    }
  }

  public struct FocusSnapshot: Equatable, Sendable {
    public let processID: Int32
    public let kind: FocusedFieldKind
    public let element: UInt

    public init(processID: Int32, kind: FocusedFieldKind, element: UInt) {
      self.processID = processID
      self.kind = kind
      self.element = element
    }
  }

  @MainActor
  public protocol TypingSurroundings: Sendable {
    func frontmostProcessID() -> Int32?
    func focus(in processID: Int32) -> FocusSnapshot?
    func hasKeyWindow() -> Bool
    func secureInputEnabled() -> Bool
  }

  public enum TypingError: Error, Equatable, Sendable {
    case focusChanged
    case focusNeverReturned
  }

  public struct KeystrokeTyper: Sendable {
    public static let focusPollInterval = Duration.milliseconds(20)

    private let poster: any EventPoster
    private let surroundings: any TypingSurroundings
    private let clock: any Clock<Duration>
    private let interval: Duration
    private let focusTimeout: Duration

    public init(
      poster: any EventPoster,
      surroundings: any TypingSurroundings,
      clock: any Clock<Duration>,
      interval: Duration = .milliseconds(4),
      focusTimeout: Duration,
    ) {
      self.poster = poster
      self.surroundings = surroundings
      self.clock = clock
      self.interval = interval
      self.focusTimeout = focusTimeout
    }

    /// Waits for the target to be frontmost and Hasp to hold no key window, then captures its focused element.
    @MainActor
    public func captureFocus(of processID: Int32) async throws -> FocusSnapshot {
      let attempts = max(1, Int(focusTimeout / Self.focusPollInterval))
      for _ in 0..<attempts {
        try Task.checkCancellation()
        if surroundings.frontmostProcessID() == processID, !surroundings.hasKeyWindow() {
          guard let snapshot = surroundings.focus(in: processID) else {
            throw TypingError.focusChanged
          }
          return snapshot
        }
        try await clock.sleep(for: Self.focusPollInterval)
      }
      throw TypingError.focusNeverReturned
    }

    @MainActor
    public func type(_ plan: TypingPlan, expecting expected: FocusSnapshot) async throws {
      let source = CGEventSource(stateID: .privateState)
      for stroke in TypingEvents.strokes(for: plan) {
        try Task.checkCancellation()
        try verify(expected)
        for event in TypingEvents.events(for: stroke, source: source) {
          poster.post(event, toProcess: expected.processID)
        }
        try await clock.sleep(for: interval)
      }
    }

    @MainActor
    private func verify(_ expected: FocusSnapshot) throws {
      guard surroundings.frontmostProcessID() == expected.processID,
        !surroundings.hasKeyWindow(),
        surroundings.focus(in: expected.processID) == expected,
        !surroundings.secureInputEnabled() || expected.kind == .secure
      else { throw TypingError.focusChanged }
    }
  }
#endif

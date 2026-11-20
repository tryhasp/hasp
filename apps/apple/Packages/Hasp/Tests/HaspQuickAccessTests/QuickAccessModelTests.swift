import CoreGraphics
import Foundation
import Synchronization
import Testing

@testable import HaspQuickAccess
@testable import HaspQuickAccessCore

func makeItem(
  _ title: String,
  hosts: [String] = [],
  favourite: Bool = false,
  kind: QuickItemKind = .login,
) -> QuickItem {
  QuickItem(
    id: QuickItemID(vault: "v", item: title),
    kind: kind,
    title: title,
    username: "mino@example.com",
    hosts: hosts,
    vaultName: "Private",
    isShared: false,
    favourite: favourite,
    hasOTP: false,
    modified: Date(timeIntervalSince1970: 1_000_000_000),
  )
}

final class FakeEngine: QuickAccessEngine, Sendable {
  struct State {
    var lock = QuickAccessLockState.unlocked(clipboardClear: .seconds(30))
    var items: [QuickItem] = []
    var passwordRequests = 0
  }

  let state = Mutex(State())

  func lockState() async throws -> QuickAccessLockState { state.withLock { $0.lock } }
  func items() async throws -> [QuickItem] { state.withLock { $0.items } }

  func otpPreview(for item: QuickItemID) async throws -> OTPPreview {
    OTPPreview(code: "207546", secondsRemaining: 18)
  }

  func password(for item: QuickItemID) async throws -> Data {
    state.withLock { $0.passwordRequests += 1 }
    return Data("pw-\(item.item)".utf8)
  }

  func otpCode(for item: QuickItemID) async throws -> Data { Data("207546".utf8) }
  func username(for item: QuickItemID) async throws -> Data { Data("mino".utf8) }

  func loginValues(for item: QuickItemID) async throws -> LoginValues {
    LoginValues(username: Data("미노".utf8), password: Data("비번🙂".utf8))
  }
}

@MainActor
final class FakeEnvironment: SystemEnvironment {
  var app: TargetApp?
  var trusted = true
  var secureInput = false
  var focus = FocusedFieldKind.plain
  var requestedAccessibility = 0
  var openedSettings = 0

  func frontmostApp() -> TargetApp? { app }
  var accessibilityTrusted: Bool { trusted }
  var secureInputActive: Bool { secureInput }
  var frontPID: Int32?
  var keyWindow = false
  var elementHash: UInt = 1
  var onFocusRead: (() -> Void)?

  func frontmostProcessID() -> Int32? { frontPID ?? app?.processID }
  func hasKeyWindow() -> Bool { keyWindow }
  func secureInputEnabled() -> Bool { secureInput }
  func focus(in processID: Int32) -> FocusSnapshot? {
    onFocusRead?()
    return FocusSnapshot(processID: processID, kind: focus, element: elementHash)
  }
  func requestAccessibility() { requestedAccessibility += 1 }
  func openAccessibilitySettings() { openedSettings += 1 }
}

struct FakeChannel: BrowserFillChannel {
  var paired = true
  var host: String?
  var outcome = BrowserFillOutcome.filled

  func hasPairedExtension(browserBundleID: String) async -> Bool { paired }
  func pageHost(browserBundleID: String) async -> String? { host }
  func requestFill(browserBundleID: String, item: QuickItemID) async -> BrowserFillOutcome {
    outcome
  }
}

final class EventCounter: EventPoster, @unchecked Sendable {
  // Why: tests only; read after the awaited typing call completes.
  private(set) var events: [CGEvent] = []
  private(set) var postedTo: [Int32] = []

  var onPost: (() -> Void)?

  func post(_ event: CGEvent, toProcess processID: Int32) {
    events.append(event)
    postedTo.append(processID)
    onPost?()
  }

  var typed: String {
    events.filter { $0.type == .keyDown }.map { event in
      var length = 0
      var buffer = [UniChar](repeating: 0, count: 32)
      event.keyboardGetUnicodeString(
        maxStringLength: 32,
        actualStringLength: &length,
        unicodeString: &buffer,
      )
      return length == 0 ? "\t" : String(decoding: buffer.prefix(length), as: UTF16.self)
    }.joined()
  }
}

struct Harness {
  let engine = FakeEngine()
  let environment = FakeEnvironment()
  let board = FakePasteboard()
  let poster = EventCounter()
  let model: QuickAccessModel
  let log = Log()

  final class Log {
    var closed = 0
    var toasts: [String] = []
    var opened: [QuickItemID] = []
    var unlockRequests = 0
  }

  init(channel: (any BrowserFillChannel)? = nil, clock: any Clock<Duration> = ImmediateClock()) {
    let immediate = ImmediateClock()
    let model = QuickAccessModel(
      dependencies: QuickAccessModel.Dependencies(
        engine: engine,
        clipboard: ClipboardClearer(pasteboard: board, clock: ManualClock()),
        typer: KeystrokeTyper(
          poster: poster,
          surroundings: environment,
          clock: immediate,
          focusTimeout: .seconds(1),
        ),
        environment: environment,
        browserChannel: channel,
        clock: clock,
        now: { Date(timeIntervalSince1970: 2_000_000_000) },
      )
    )
    let log = log
    model.setHooks(
      QuickAccessModel.Hooks(
        closePanel: { log.closed += 1 },
        showToast: { log.toasts.append($0) },
        openInMainWindow: { log.opened.append($0) },
        requestUnlock: { log.unlockRequests += 1 },
      )
    )
    self.model = model
    engine.state.withLock {
      $0.items = [
        makeItem("쿠팡", hosts: ["www.coupang.com"], favourite: true),
        makeItem("GitHub", hosts: ["github.com"]),
      ]
    }
  }
}

@Suite(.serialized) struct QuickAccessModelTests {
  let notes = TargetApp(bundleID: "com.apple.Notes", name: "Notes", processID: 9)
  let safari = TargetApp(bundleID: "com.apple.Safari", name: "Safari", processID: 8)

  @Test func presentLoadsRanksAndSelectsTheFirstResult() async {
    let harness = Harness()
    await harness.model.present()
    #expect(harness.model.results.count == 2)
    #expect(harness.model.selectedItem?.title == "쿠팡")
    harness.model.query = "git"
    #expect(harness.model.results.map(\.title) == ["GitHub"])
    #expect(harness.model.selectedItem?.title == "GitHub")
  }

  @Test func lockedEngineShowsTheUnlockPromptAndLoadsNothing() async {
    let harness = Harness()
    harness.engine.state.withLock { $0.lock = .locked }
    await harness.model.present()
    #expect(harness.model.mode == .locked)
    #expect(harness.model.results.isEmpty)
    await harness.model.perform(.fill)
    #expect(harness.log.unlockRequests == 1)
    await harness.model.perform(.close)
    #expect(harness.log.closed == 1)
  }

  @Test func arrowKeysMoveTheSelectionWithinBounds() async {
    let harness = Harness()
    await harness.model.present()
    harness.model.moveSelection(by: -1)
    #expect(harness.model.selectedItem?.title == "쿠팡")
    harness.model.moveSelection(by: 1)
    #expect(harness.model.selectedItem?.title == "GitHub")
    harness.model.moveSelection(by: 5)
    #expect(harness.model.selectedItem?.title == "GitHub")
  }

  @Test func copyPasswordWritesConcealedClosesAndToastsTheTimer() async {
    let harness = Harness()
    await harness.model.present()
    await harness.model.perform(.copyPassword)
    #expect(harness.board.text == "pw-쿠팡")
    #expect(harness.board.lastWriteWasConcealed)
    #expect(harness.log.closed == 1)
    #expect(harness.log.toasts == [Strings.copied(clearAfterSeconds: 30)])
  }

  @Test func copyOTPNeedsAnOTPItem() async {
    let harness = Harness()
    await harness.model.present()
    await harness.model.perform(.copyOTP)
    #expect(harness.board.text == nil)
    #expect(harness.log.toasts == [Strings.toastNoOTP])
  }

  @Test func copyOTPCopiesTheCode() async {
    let harness = Harness()
    harness.engine.state.withLock {
      $0.items = [
        QuickItem(
          id: QuickItemID(vault: "v", item: "x"),
          kind: .login,
          title: "X",
          username: "u",
          hosts: [],
          vaultName: "P",
          isShared: false,
          favourite: false,
          hasOTP: true,
          modified: .distantPast,
        )
      ]
    }
    await harness.model.present()
    await harness.model.perform(.copyOTP)
    #expect(harness.board.text == "207546")
  }

  @Test func showAllActionsTogglesAndEscClosesTheOverlayFirst() async {
    let harness = Harness()
    await harness.model.present()
    await harness.model.perform(.showAllActions)
    #expect(harness.model.showsActions)
    await harness.model.perform(.close)
    #expect(!harness.model.showsActions)
    #expect(harness.log.closed == 0)
    await harness.model.perform(.close)
    #expect(harness.log.closed == 1)
  }

  @Test func openInMainWindowClosesAndForwardsTheItem() async {
    let harness = Harness()
    await harness.model.present()
    await harness.model.perform(.openInMainWindow)
    #expect(harness.log.opened == [QuickItemID(vault: "v", item: "쿠팡")])
    #expect(harness.log.closed == 1)
  }

  @Test func fillIntoANativeAppAsksFirstThenTypesHangulAndEmoji() async {
    let harness = Harness()
    harness.environment.app = notes
    await harness.model.present()
    await harness.model.perform(.fill)
    guard case .confirmTyping(.nativeApp(let app, _), _) = harness.model.mode else {
      Issue.record("expected a confirmation")
      return
    }
    #expect(app == "Notes")
    #expect(harness.poster.events.isEmpty)
    await harness.model.perform(.fill)
    #expect(harness.poster.typed == "미노\t비번🙂")
    #expect(harness.log.closed == 1)
  }

  @Test func secureFieldTypesOnlyThePassword() async {
    let harness = Harness()
    harness.environment.app = notes
    harness.environment.focus = .secure
    await harness.model.present()
    await harness.model.perform(.fill)
    await harness.model.perform(.fill)
    #expect(harness.poster.typed == "비번🙂")
  }

  @Test func cancellingTheConfirmationTypesNothing() async {
    let harness = Harness()
    harness.environment.app = notes
    await harness.model.present()
    await harness.model.perform(.fill)
    await harness.model.perform(.close)
    #expect(harness.model.mode == .search)
    #expect(harness.poster.events.isEmpty)
  }

  @Test func withoutAccessibilityTheGuideAppearsAndCopyStillWorks() async {
    let harness = Harness()
    harness.environment.app = notes
    harness.environment.trusted = false
    await harness.model.present()
    await harness.model.perform(.fill)
    guard case .needsAccessibility = harness.model.mode else {
      Issue.record("expected the accessibility guide")
      return
    }
    harness.model.openAccessibilitySettings()
    #expect(harness.environment.requestedAccessibility == 1)
    #expect(harness.environment.openedSettings == 1)
    await harness.model.copyPasswordFromPrompt()
    #expect(harness.board.text == "pw-쿠팡")
    #expect(harness.poster.events.isEmpty)
  }

  @Test func pairedBrowserFillsThroughTheExtensionAndTypesNothing() async {
    let harness = Harness(channel: FakeChannel(host: "www.coupang.com"))
    harness.environment.app = safari
    await harness.model.present()
    await harness.model.perform(.fill)
    #expect(harness.log.closed == 1)
    #expect(harness.poster.events.isEmpty)
  }

  @Test func extensionFailuresStayOpenAndExplain() async {
    let harness = Harness(channel: FakeChannel(outcome: .extensionLocked))
    harness.environment.app = safari
    await harness.model.present()
    await harness.model.perform(.fill)
    #expect(harness.log.closed == 0)
    #expect(harness.log.toasts == [Strings.toastExtensionLocked])
  }

  @Test func connectedBrowserPageBoostsMatchingItems() async {
    let harness = Harness(channel: FakeChannel(host: "github.com"))
    harness.environment.app = safari
    await harness.model.present()
    #expect(harness.model.selectedItem?.title == "GitHub")
  }

  @Test func nonLoginItemsAreNotFilled() async {
    let harness = Harness()
    harness.environment.app = notes
    harness.engine.state.withLock { $0.items = [makeItem("Visa", kind: .card)] }
    await harness.model.present()
    await harness.model.perform(.fill)
    #expect(harness.log.toasts == [Strings.toastLoginOnly])
  }

  @Test func noFrontmostAppCopiesThePassword() async {
    let harness = Harness()
    await harness.model.present()
    await harness.model.perform(.fill)
    #expect(harness.board.text == "pw-쿠팡")
    #expect(harness.log.toasts.last == Strings.toastCopiedInstead)
  }

  @Test func lockDropsEverythingTheModelHolds() async {
    let harness = Harness()
    await harness.model.present()
    harness.model.lock()
    #expect(harness.model.results.isEmpty)
    #expect(harness.model.selection == nil)
  }

  @Test func otpPreviewCountsDownAndRefetchesAtZero() async {
    let clock = ManualClock()
    let harness = Harness(clock: clock)
    harness.engine.state.withLock {
      $0.items = [
        QuickItem(
          id: QuickItemID(vault: "v", item: "x"),
          kind: .login,
          title: "X",
          username: "u",
          hosts: [],
          vaultName: "P",
          isShared: false,
          favourite: false,
          hasOTP: true,
          modified: .distantPast,
        )
      ]
    }
    await harness.model.present()
    while harness.model.otp == nil { await Task.yield() }
    #expect(harness.model.otp?.secondsRemaining == 18)
    while clock.pendingSleepers == 0 { await Task.yield() }
    clock.advance(by: .seconds(1))
    while harness.model.otp?.secondsRemaining != 17 { await Task.yield() }
    #expect(harness.model.otp?.secondsRemaining == 17)
    #expect(PreviewPane.grouped("207546") == "207 546")
  }
}

@Suite(.serialized) struct QuickAccessTypingGuardTests {
  let notes = TargetApp(bundleID: "com.apple.Notes", name: "Notes", processID: 9)

  private func ready() async -> Harness {
    let harness = Harness()
    harness.environment.app = notes
    await harness.model.present()
    return harness
  }

  @Test func typingStopsWhenFocusLeavesTheTargetMidway() async {
    let harness = await ready()
    let environment = harness.environment
    let poster = harness.poster
    poster.onPost = { if poster.events.count == 2 { environment.frontPID = 77 } }
    await harness.model.perform(.fill)
    await harness.model.confirmTyping()
    #expect(poster.events.count == 2)
    #expect(poster.postedTo.allSatisfy { $0 == 9 })
  }

  @Test func typingStopsWhenTheFocusedElementChanges() async {
    let harness = await ready()
    let environment = harness.environment
    let poster = harness.poster
    poster.onPost = { environment.elementHash = 2 }
    await harness.model.perform(.fill)
    await harness.model.confirmTyping()
    #expect(poster.events.count == 2)
  }

  @Test func nothingIsTypedWhileAHaspWindowIsKey() async {
    let harness = await ready()
    harness.environment.keyWindow = true
    await harness.model.perform(.fill)
    await harness.model.confirmTyping()
    #expect(harness.poster.events.isEmpty)
    #expect(harness.log.toasts.contains(Strings.toastFailed))
  }

  @Test func foreignSecureInputRefusesToType() async {
    let harness = await ready()
    harness.environment.secureInput = true
    harness.environment.focus = .plain
    await harness.model.perform(.fill)
    await harness.model.confirmTyping()
    #expect(harness.poster.events.isEmpty)
  }

  @Test func secureInputInTheTargetsOwnPasswordFieldIsAllowed() async {
    let harness = await ready()
    harness.environment.secureInput = true
    harness.environment.focus = .secure
    await harness.model.perform(.fill)
    await harness.model.confirmTyping()
    #expect(!harness.poster.events.isEmpty)
  }

  @Test func focusThatNeverReturnsFailsClosed() async {
    let harness = await ready()
    harness.environment.frontPID = 77
    await harness.model.perform(.fill)
    await harness.model.confirmTyping()
    #expect(harness.poster.events.isEmpty)
    #expect(harness.log.toasts.contains(Strings.toastFailed))
  }
}

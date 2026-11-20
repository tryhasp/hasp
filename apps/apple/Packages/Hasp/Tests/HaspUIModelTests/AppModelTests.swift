import Foundation
import HaspKit
import HaspPlatform
import HaspQuickAccessCore
import Synchronization
import Testing

@testable import HaspUI

struct RecordingBoard: PasteboardAccess {
  var changeCount: Int { 1 }
  func writeConcealed(_ text: String, expiringAfter delay: Duration?) -> Int { 1 }
  func clear() -> Int { 2 }
}

private struct NoBreach: BreachRangeSource {
  func range(prefix: String) throws -> String { "" }
}

private final class CountingBoard: PasteboardAccess {
  private let writes = Mutex(0)
  private let clears = Mutex(0)
  var clearCount: Int { clears.withLock { $0 } }
  var changeCount: Int { writes.withLock { $0 } }
  func writeConcealed(_ text: String, expiringAfter delay: Duration?) -> Int {
    writes.withLock {
      $0 += 1; return $0
    }
  }
  func clear() -> Int {
    clears.withLock { $0 += 1 }
    return writes.withLock {
      $0 += 1; return $0
    }
  }
}

@MainActor
func makeModel(
  origin: URL?,
  vault: FakeVault,
  board: any PasteboardAccess = RecordingBoard(),
  afterSync: @escaping @Sendable (any VaultServing) async -> Void = { _ in },
  capability: @escaping @Sendable () -> UnlockCapability = { .softwareOnly },
  storeFailure: @escaping @Sendable () -> StoreFailure? = { nil },
) -> AppModel {
  AppModel(
    environment: AppEnvironment(
      storedOrigin: { origin },
      rememberOrigin: { _ in },
      makeSession: { _ in vault },
      clipboard: ClipboardClearer(pasteboard: board, clock: ContinuousClock()),
      breachSource: NoBreach(),
      systemIdle: { .zero },
      systemLockTriggers: { AsyncStream { _ in } },
      isHardwareBacked: false,
      unlockCapability: capability,
      storeFailure: storeFailure,
      afterSync: afterSync,
    )
  )
}

@MainActor
struct AppModelTests {
  @Test func launchWithoutServerShowsOnboarding() async {
    let model = makeModel(origin: nil, vault: FakeVault())
    await model.launch()
    #expect(model.phase == .onboarding)
  }

  @Test func launchWithKnownAccountShowsLockScreen() async {
    let model = makeModel(origin: URL(string: "http://127.0.0.1:1"), vault: FakeVault())
    await model.launch()
    #expect(model.phase == .locked)
  }

  @Test func wrongPasswordKeepsItLockedWithAMessage() async {
    let model = makeModel(origin: URL(string: "http://127.0.0.1:1"), vault: FakeVault())
    await model.launch()
    await model.unlock(password: "nope")
    #expect(model.phase == .locked)
    #expect(model.notice != nil)
  }

  @Test func firstSignInSetsTheThirtySecondClipboardClearAndOpensTheLibrary() async {
    let vault = FakeVault(items: [
      ItemSummary(key: ItemKey(vault: VaultID("v1"), item: "i"), kind: "login", title: "네이버")
    ])
    let model = makeModel(origin: nil, vault: vault)
    await model.launch()
    await model.signIn(
      origin: "http://127.0.0.1:1",
      login: "me",
      secretKey: "k",
      password: "pw",
      fingerprint: "AAAA-BBBB",
    )
    #expect(model.phase == .unlocked)
    #expect(vault.settingsValue.lock.clipboardClear == .seconds(30))
    #expect(model.library?.visibleItems.count == 1)
  }

  @Test func signUpShowsTheEmergencyKitUntilItIsAcknowledged() async {
    let vault = FakeVault()
    let model = makeModel(origin: nil, vault: vault)
    await model.launch()
    await model.signUp(
      origin: "http://127.0.0.1:1",
      login: "me",
      code: "code",
      password: "pw",
      fingerprint: "AAAA-BBBB",
    )
    #expect(model.phase == .unlocked)
    #expect(model.emergencyKit?.secretKey == "V1-TEST")
    model.finishEmergencyKit()
    #expect(model.emergencyKit == nil)
  }

  @Test func aWrongServerFingerprintRefusesSignIn() async {
    let model = makeModel(origin: nil, vault: FakeVault())
    await model.launch()
    await model.signIn(
      origin: "http://127.0.0.1:1",
      login: "me",
      secretKey: "k",
      password: "pw",
      fingerprint: "WRONG",
    )
    #expect(model.phase == .onboarding)
    #expect(model.notice != nil)
  }

  @Test func idleTriggerLocksAndDropsTheLibrary() async {
    let vault = FakeVault()
    let model = makeModel(origin: nil, vault: vault)
    await model.launch()
    await model.signIn(
      origin: "http://127.0.0.1:1",
      login: "me",
      secretKey: "k",
      password: "pw",
      fingerprint: "AAAA-BBBB",
    )
    await model.apply(.idle, elapsed: .seconds(700), on: vault)
    #expect(model.phase == .locked)
    #expect(model.library == nil)
    #expect(model.lockReason == .idle(minutes: 10))
  }

  @Test func quittingClearsTheClipboardEvenWhenAlreadyLocked() async {
    let board = CountingBoard()
    let model = makeModel(origin: nil, vault: FakeVault(), board: board)
    await model.clipboard.copy(Data("secret".utf8), clearAfter: nil)
    await model.lockForQuit()
    #expect(board.clearCount == 1)
  }

  @Test func lockingClearsTheSharedClipboard() async {
    let board = CountingBoard()
    let vault = FakeVault()
    let model = makeModel(origin: nil, vault: vault, board: board)
    await model.launch()
    await model.signIn(
      origin: "http://127.0.0.1:1",
      login: "me",
      secretKey: "k",
      password: "pw",
      fingerprint: "AAAA-BBBB",
    )
    await model.clipboard.copy(Data("secret".utf8), clearAfter: nil)
    await model.lock()
    #expect(board.clearCount == 1)
  }

  @Test func breachCheckNeverRunsWhenTheSettingIsOff() async {
    let vault = FakeVault()
    let model = makeModel(origin: nil, vault: vault)
    let watchtower = WatchtowerModel(
      library: LibraryModel(session: vault, app: model),
      app: model,
      session: vault,
    )
    await watchtower.runBreachCheck()
    #expect(vault.breachChecks == 0)
    model.settings.breachCheck = true
    await watchtower.runBreachCheck()
    #expect(vault.breachChecks == 1)
  }

  @Test func copyShowsTheClearingToast() async {
    let model = makeModel(origin: nil, vault: FakeVault())
    await model.copyPlain("x")
    #expect(model.toast != nil)
  }

  @Test func originsNeedHttpOrHttpsAndAHost() {
    #expect(AppModel.normalizedOrigin("https://hasp.example.com/") != nil)
    #expect(AppModel.normalizedOrigin("ftp://x") == nil)
    #expect(AppModel.normalizedOrigin("nonsense") == nil)
  }
}

@MainActor
struct LibraryModelTests {
  @Test func selectionFiltersByStatusAndCategory() async {
    let vault = VaultID("v1")
    let items = [
      ItemSummary(key: ItemKey(vault: vault, item: "1"), kind: "login", title: "b"),
      ItemSummary(key: ItemKey(vault: vault, item: "2"), kind: "card", title: "a"),
      ItemSummary(
        key: ItemKey(vault: vault, item: "3"),
        kind: "login",
        title: "c",
        status: .trashed,
      ),
    ]
    let library = LibraryModel(session: FakeVault(items: items), app: nil)
    await library.refresh()
    #expect(library.visibleItems.map(\.title) == ["a", "b"])
    library.selection = .category("login")
    #expect(library.visibleItems.map(\.title) == ["b"])
    library.selection = .trash
    #expect(library.visibleItems.map(\.title) == ["c"])
  }
}

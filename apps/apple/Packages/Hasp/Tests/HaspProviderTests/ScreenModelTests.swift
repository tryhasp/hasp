import AuthenticationServices
import Foundation
import HaspKit
import HaspProvider
import Testing

@testable import HaspProviderUI

@MainActor
final class RecordingResponder: ProviderResponder {
  private(set) var results: [ProviderResult] = []
  private(set) var failures: [ProviderFailure] = []
  private(set) var configured = 0

  func finish(with result: ProviderResult) { results.append(result) }
  func finish(failing failure: ProviderFailure) { failures.append(failure) }
  func finishConfiguration() { configured += 1 }
}

@MainActor
struct ScreenModelTests {
  private let github = ProviderEntry(
    key: ItemKey(vault: VaultID("v"), item: "gh"),
    title: "GitHub",
    subtitle: "alice",
    favourite: true,
    hasOneTimeCode: true,
    hasPasskey: false,
    hostToConfirm: nil,
  )
  private let bank = ProviderEntry(
    key: ItemKey(vault: VaultID("v"), item: "bank"),
    title: "Bank",
    subtitle: "bob",
    favourite: false,
    hasOneTimeCode: false,
    hasPasskey: false,
    hostToConfirm: nil,
  )

  private func make(
    _ intent: ProviderIntent,
    engine: FakeProvider,
    responder: RecordingResponder,
    configure: @escaping @Sendable () async throws -> Void = {},
  ) -> ProviderScreenModel {
    ProviderScreenModel(
      intent: intent,
      coordinator: ProviderCoordinator(engine: engine),
      responder: responder,
      configure: configure,
    )
  }

  @Test func theListLoadsAfterTheUnlockAndAPickCompletesWithThePassword() async throws {
    let engine = FakeProvider()
    await engine.set(entries: [github, bank])
    let responder = RecordingResponder()
    let model = make(.passwords(identifiers: ["github.com"]), engine: engine, responder: responder)
    await model.start()
    #expect(model.phase == .list)
    #expect(model.rows.map(\.title) == ["GitHub", "Bank"])
    await model.select(try #require(model.rows.first))
    #expect(responder.results.count == 1)
    #expect(responder.results.first?.passwordCredential?.password == "pw-gh")
    #expect(await engine.calls.locks == 1)
  }

  @Test func searchingNarrowsTheRows() async {
    let engine = FakeProvider()
    await engine.set(entries: [github, bank])
    let model = make(
      .passwords(identifiers: []),
      engine: engine,
      responder: RecordingResponder(),
    )
    await model.start()
    model.query = "bank"
    await model.reload()
    #expect(model.rows.map(\.title) == ["Bank"])
  }

  @Test func theCodeListShowsOnlyItemsWithACode() async {
    let engine = FakeProvider()
    await engine.set(entries: [github, bank])
    let model = make(
      .oneTimeCodes(identifiers: []),
      engine: engine,
      responder: RecordingResponder(),
    )
    await model.start()
    #expect(model.rows.map(\.title) == ["GitHub"])
    #expect(model.rows.first?.kind == .oneTimeCode)
  }

  @Test func aPasskeySignInListsPasskeysBeforePasswordsAndSignsTheChallenge() async throws {
    let engine = FakeProvider()
    await engine.set(entries: [github])
    let responder = RecordingResponder()
    let parameters = PasskeyAssertionParameters(
      rpID: "example.com",
      clientDataHash: Data(repeating: 1, count: 32),
      allowedCredentialIDs: [],
      userVerification: .preferred,
    )
    let model = make(
      .passkeys(parameters, identifiers: ["example.com"]),
      engine: engine,
      responder: responder,
    )
    await model.start()
    #expect(model.rows.map(\.kind) == [.passkey, .password])
    await model.select(try #require(model.rows.first))
    #expect(responder.results.first?.assertionCredential?.relyingParty == "example.com")
    #expect(await engine.calls.assertions.first?.userVerified == true)
  }

  @Test func aCancelledFaceIDEndsTheRequestAsCancelled() async {
    let engine = FakeProvider()
    await engine.set(unlockError: HaspError.cancelled)
    let responder = RecordingResponder()
    let model = make(.passwords(identifiers: []), engine: engine, responder: responder)
    await model.start()
    #expect(responder.failures == [.userCancelled])
  }

  @Test func aRevokedDeviceShowsTheOpenAppScreenAndKeepsTheRequestOpen() async {
    let engine = FakeProvider()
    await engine.set(unlockError: HaspError.deviceRevoked)
    let responder = RecordingResponder()
    let model = make(.passwords(identifiers: []), engine: engine, responder: responder)
    await model.start()
    #expect(model.phase == .failed(.openApp))
    #expect(responder.failures.isEmpty)
    await model.close(after: .openApp)
    #expect(responder.failures == [.openApp])
  }

  @Test func withoutAnAccountTheScreenSaysToOpenTheApp() async {
    let responder = RecordingResponder()
    let model = ProviderScreenModel(
      intent: .passwords(identifiers: []),
      coordinator: nil,
      responder: responder,
      configure: {},
    )
    await model.start()
    #expect(model.phase == .failed(.openApp))
  }

  @Test func aQuickTypePickFillsWithoutShowingAList() async {
    let engine = FakeProvider()
    let responder = RecordingResponder()
    let request = IdentityRequest(
      request: .password(key: github.key, service: "github.com", manual: false, confirmed: false),
      subject: "github.com",
    )
    let model = make(.fill(request), engine: engine, responder: responder)
    await model.start()
    #expect(responder.results.first?.passwordCredential?.user == "alice")
    #expect(await engine.calls.passwords == ["github.com"])
  }

  @Test func aPickedLoginThatNeedsConfirmationShowsTheHostAndFillsOnTheSecondTap() async {
    let engine = FakeProvider()
    await engine.set(entries: [github])
    await engine.set(fillNeedsConfirmation: true)
    let responder = RecordingResponder()
    let model = make(
      .passwords(identifiers: ["evil.example.com"]),
      engine: engine,
      responder: responder,
    )
    await model.start()
    await model.select(model.rows[0])
    #expect(model.phase == .confirm)
    #expect(model.pendingFill?.host == "evil.example.com")
    #expect(responder.results.isEmpty)
    #expect(await engine.calls.passwords.isEmpty)
    await model.confirmFill()
    #expect(responder.results.first?.passwordCredential?.user == "alice")
    #expect(await engine.calls.confirmations == [true])
  }

  @Test func aQuickTypePickThatNeedsConfirmationAsksBeforeFilling() async {
    let engine = FakeProvider()
    await engine.set(fillNeedsConfirmation: true)
    let responder = RecordingResponder()
    let request = IdentityRequest(
      request: .password(key: github.key, service: "github.com", manual: false, confirmed: false),
      subject: "github.com",
    )
    let model = make(.fill(request), engine: engine, responder: responder)
    await model.start()
    #expect(model.phase == .confirm)
    #expect(responder.results.isEmpty)
    await model.confirmFill()
    #expect(responder.results.count == 1)
  }

  @Test func aPasskeyRegistrationWaitsForTheUserToConfirm() async {
    let engine = FakeProvider()
    let responder = RecordingResponder()
    let input = PasskeyRegistrationInput(
      rpID: "example.com",
      rpName: "Example",
      clientDataHash: Data(repeating: 2, count: 32),
      userName: "alice",
      userDisplayName: "Alice",
      userHandle: Data([1]),
      algorithms: [-7],
      excludedCredentialIDs: [],
      userVerification: .preferred,
      userVerified: false,
    )
    let model = make(.register(input), engine: engine, responder: responder)
    await model.start()
    #expect(model.phase == .confirm)
    #expect(await engine.calls.registrations.isEmpty)
    await model.confirmRegistration()
    #expect(await engine.calls.registrations.count == 1)
    #expect(responder.results.count == 1)
  }

  @Test func enablingTheExtensionRefreshesTheIdentitiesThenFinishesConfiguration() async {
    let engine = FakeProvider()
    let responder = RecordingResponder()
    let ran = Counter()
    let model = make(.configure, engine: engine, responder: responder) { await ran.bump() }
    await model.start()
    #expect(await ran.count == 1)
    #expect(responder.configured == 1)
    #expect(await engine.calls.locks == 1)
  }
}

extension ScreenModelTests {
  @Test func enablingWithoutAnAccountClearsTheIdentitiesAndSaysToOpenTheApp() async {
    let store = FakeIdentityStore()
    let model = ProviderScreenModel(
      intent: .configure,
      coordinator: nil,
      responder: RecordingResponder(),
      configure: {
        await IdentityRefresh.clear(store)
        throw ProviderFailure.openApp
      },
    )
    await model.start()
    #expect(await store.removals == 1)
    #expect(model.phase == .failed(.openApp))
  }
}

actor Counter {
  private(set) var count = 0
  func bump() { count += 1 }
}

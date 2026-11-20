import AuthenticationServices
import Foundation
import HaspKit
import Testing

@testable import HaspProvider

struct CoordinatorTests {
  private let key = ItemKey(vault: VaultID("v"), item: "i")

  private func input(_ verification: PasskeyUserVerification) -> PasskeyAssertionInput {
    PasskeyAssertionInput(
      rpID: "example.com",
      clientDataHash: Data(repeating: 7, count: 32),
      allowedCredentialIDs: [],
      userVerification: verification,
      userVerified: false,
      credentialID: Data([1]),
    )
  }

  @Test func nothingIsAnsweredBeforeTheUnlock() async {
    let coordinator = ProviderCoordinator(engine: FakeProvider())
    await #expect(throws: ProviderFailure.interactionRequired) {
      try await coordinator.provide(
        .password(key: key, service: nil, manual: true, confirmed: false)
      )
    }
  }

  @Test func aSilentFillThatNeedsAConfirmationIsLeftToTheInteractiveSheet() async throws {
    let engine = FakeProvider()
    await engine.set(fillNeedsConfirmation: true)
    let coordinator = ProviderCoordinator(engine: engine)
    try await coordinator.unlock(prompting: false)
    await #expect(throws: ProviderFailure.interactionRequired) {
      try await coordinator.provide(
        .password(key: key, service: "example.com", manual: false, confirmed: false)
      )
    }
    #expect(await engine.calls.passwords.isEmpty)
    let result = try await coordinator.provide(
      .password(key: key, service: "example.com", manual: false, confirmed: true)
    )
    #expect(result.passwordCredential?.user == "alice")
    #expect(await engine.calls.confirmations == [true])
  }

  @Test func aPasswordOnlyDeviceSaysSoInsteadOfAskingToOpenTheApp() async {
    let engine = FakeProvider()
    await engine.set(unlockError: HaspError.refused)
    let coordinator = ProviderCoordinator(engine: engine)
    await #expect(throws: ProviderFailure.passwordOnly) {
      try await coordinator.unlock(prompting: true)
    }
    #expect(await coordinator.isUnlocked == false)
  }

  @Test func aPasswordFillUnlocksOnceAndLocksOnFinish() async throws {
    let engine = FakeProvider()
    let coordinator = ProviderCoordinator(engine: engine)
    try await coordinator.unlock(prompting: true)
    try await coordinator.unlock(prompting: true)
    let result = try await coordinator.provide(
      .password(key: key, service: "example.com", manual: false, confirmed: false)
    )
    await coordinator.finish()
    #expect(result.passwordCredential?.user == "alice")
    #expect(result.passwordCredential?.password == "pw-i")
    let calls = await engine.calls
    #expect(calls.unlocks == 1)
    #expect(calls.locks == 1)
    #expect(calls.passwords == ["example.com"])
    #expect(await coordinator.isUnlocked == false)
  }

  @Test(arguments: [
    (HaspError.cancelled, true, ProviderFailure.userCancelled),
    (.cancelled, false, .interactionRequired),
    (.authz, false, .interactionRequired),
    (.authz, true, .failed),
    (.locked, false, .interactionRequired),
    (.locked, true, .openApp),
    (.refused, true, .openApp),
    (.deviceRevoked, false, .openApp),
    (.notFound, true, .notFound),
    (.conflict, true, .excludedCredential),
    (.internal, true, .failed),
  ])
  func engineErrorsMapToOneProviderFailure(
    error: HaspError,
    prompting: Bool,
    expected: ProviderFailure,
  ) {
    #expect(ProviderFailure(error, prompting: prompting) == expected)
  }

  @Test func aSilentUnlockThatNeedsTheUserAsksForInteraction() async {
    let engine = FakeProvider()
    await engine.set(unlockError: HaspError.cancelled)
    let coordinator = ProviderCoordinator(engine: engine)
    await #expect(throws: ProviderFailure.interactionRequired) {
      try await coordinator.unlock(prompting: false)
    }
  }

  @Test func aCancelledFaceIDPromptIsACancelledRequest() async {
    let engine = FakeProvider()
    await engine.set(unlockError: HaspError.cancelled)
    let coordinator = ProviderCoordinator(engine: engine)
    await #expect(throws: ProviderFailure.userCancelled) {
      try await coordinator.unlock(prompting: true)
    }
  }

  @Test func aPasskeyThatRequiresVerificationRefusesASilentUnlock() async throws {
    let engine = FakeProvider()
    let coordinator = ProviderCoordinator(engine: engine)
    try await coordinator.unlock(prompting: false)
    await #expect(throws: ProviderFailure.interactionRequired) {
      try await coordinator.provide(.passkeyAssertion(input(.required), key: key))
    }
    #expect(await engine.calls.assertions.isEmpty)
  }

  @Test func userVerificationIsClaimedOnlyAfterAPrompt() async throws {
    let silent = FakeProvider()
    let silentCoordinator = ProviderCoordinator(engine: silent)
    try await silentCoordinator.unlock(prompting: false)
    _ = try await silentCoordinator.provide(.passkeyAssertion(input(.preferred), key: key))
    #expect(await silent.calls.assertions.map(\.userVerified) == [false])

    let prompted = FakeProvider()
    let promptedCoordinator = ProviderCoordinator(engine: prompted)
    try await promptedCoordinator.unlock(prompting: true)
    let result = try await promptedCoordinator.provide(
      .passkeyAssertion(input(.required), key: key)
    )
    #expect(await prompted.calls.assertions.map(\.userVerified) == [true])
    #expect(result.assertionCredential?.relyingParty == "example.com")
  }

  @Test func aPasskeyRegistrationReturnsTheAttestationForTheRequestHash() async throws {
    let engine = FakeProvider()
    let coordinator = ProviderCoordinator(engine: engine)
    try await coordinator.unlock(prompting: true)
    let hash = Data(repeating: 5, count: 32)
    let registration = PasskeyRegistrationInput(
      rpID: "example.com",
      rpName: "Example",
      clientDataHash: hash,
      userName: "alice",
      userDisplayName: "Alice",
      userHandle: Data([1]),
      algorithms: [-7],
      excludedCredentialIDs: [],
      userVerification: .preferred,
      userVerified: false,
    )
    let result = try await coordinator.provide(.passkeyRegistration(registration))
    let credential = result.registrationCredential(clientDataHash: hash)
    #expect(credential?.clientDataHash == hash)
    #expect(credential?.credentialID == Data([9]))
    #expect(await engine.calls.registrations.map(\.userVerified) == [true])
  }

  @Test func aOneTimeCodeAndTextReachTheirCredentialTypes() async throws {
    let coordinator = ProviderCoordinator(engine: FakeProvider())
    try await coordinator.unlock(prompting: true)
    let code = try await coordinator.provide(.oneTimeCode(key: key))
    #expect(code.oneTimeCodeCredential?.code == "123456")
    let text = try await coordinator.provide(.text(key: key, field: "f"))
    #expect(text.insertedText == "text")
  }
}

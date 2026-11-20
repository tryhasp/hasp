import AuthenticationServices
import Foundation
import HaspKit
import Testing

@testable import HaspProvider

struct SystemMappingTests {
  @Test func eachIdentityKindBecomesItsSystemIdentityWithTheRecordAndRank() throws {
    let password = try #require(
      identity(.password, record: "p:v:i:example.com").systemIdentity
        as? ASPasswordCredentialIdentity
    )
    #expect(password.serviceIdentifier.identifier == "example.com")
    #expect(password.serviceIdentifier.type == .domain)
    #expect(password.user == "alice")
    #expect(password.recordIdentifier == "p:v:i:example.com")

    let code = try #require(
      identity(.oneTimeCode, record: "o:v:i:example.com").systemIdentity
        as? ASOneTimeCodeCredentialIdentity
    )
    #expect(code.recordIdentifier == "o:v:i:example.com")
    #expect(code.label == "Example")

    let passkey = try #require(
      identity(.passkey, record: "k:v:i:AQID").systemIdentity as? ASPasskeyCredentialIdentity
    )
    #expect(passkey.relyingPartyIdentifier == "example.com")
    #expect(passkey.credentialID == Data([1, 2, 3]))
    #expect(passkey.userHandle == Data([4, 5]))
  }

  @Test func aPasskeyIdentityWithoutItsBytesIsLeftOut() {
    let broken = CredentialIdentity(
      record: "k:v:i:AQID",
      kind: .passkey,
      key: ItemKey(vault: VaultID("v"), item: "i"),
      service: "example.com",
      user: "alice",
      title: "Example",
      favourite: false,
      credentialID: nil,
      userHandle: nil,
    )
    #expect(broken.systemIdentity == nil)
  }

  @Test func aFavouriteRanksAboveTheRest() throws {
    let favourite = CredentialIdentity(
      record: "p:v:i:example.com",
      kind: .password,
      key: ItemKey(vault: VaultID("v"), item: "i"),
      service: "example.com",
      user: "alice",
      title: "Example",
      favourite: true,
      credentialID: nil,
      userHandle: nil,
    )
    #expect(favourite.systemIdentity?.rank == 1)
    #expect(identity(.password, record: "p:v:i:example.com").systemIdentity?.rank == 0)
  }

  @Test func aPasswordRequestNamesTheItemAndPinsTheHost() throws {
    let system = ASPasswordCredentialIdentity(
      serviceIdentifier: ASCredentialServiceIdentifier(identifier: "example.com", type: .domain),
      user: "alice",
      recordIdentifier: "p:ab:cd:example.com",
    )
    let read = try IdentityRequestReader.read(
      ASPasswordCredentialRequest(credentialIdentity: system)
    )
    guard case .password(let key, let service, let manual, let confirmed) = read.request else {
      Issue.record("not a password request")
      return
    }
    #expect(key == ItemKey(vault: VaultID("ab"), item: "cd"))
    #expect(service == "example.com")
    #expect(!manual && !confirmed)
    #expect(read.subject == "example.com")
  }

  @Test func aRequestWithoutAUsableRecordIsNotFound() {
    let system = ASPasswordCredentialIdentity(
      serviceIdentifier: ASCredentialServiceIdentifier(identifier: "example.com", type: .domain),
      user: "alice",
      recordIdentifier: nil,
    )
    #expect(throws: ProviderFailure.notFound) {
      try IdentityRequestReader.read(ASPasswordCredentialRequest(credentialIdentity: system))
    }
  }

  @Test func aPasskeyRequestCarriesTheChallengeHashAndTheCredential() throws {
    let system = ASPasskeyCredentialIdentity(
      relyingPartyIdentifier: "example.com",
      userName: "alice",
      credentialID: Data([1, 2]),
      userHandle: Data([3]),
      recordIdentifier: "k:ab:cd:AQI",
    )
    let hash = Data(repeating: 9, count: 32)
    let request = ASPasskeyCredentialRequest(
      credentialIdentity: system,
      clientDataHash: hash,
      userVerificationPreference: .required,
      supportedAlgorithms: [.ES256],
    )
    let read = try IdentityRequestReader.read(request)
    guard case .passkeyAssertion(let input, let key) = read.request else {
      Issue.record("not an assertion")
      return
    }
    #expect(input.clientDataHash == hash)
    #expect(input.credentialID == Data([1, 2]))
    #expect(input.userVerification == .required)
    #expect(key == ItemKey(vault: VaultID("ab"), item: "cd"))
  }

  @Test func aSystemErrorCarriesTheExtensionDomainAndCode() {
    let interaction = ProviderFailure.interactionRequired.systemError
    #expect(interaction.domain == ASExtensionErrorDomain)
    #expect(interaction.code == ASExtensionError.Code.userInteractionRequired.rawValue)
    #expect(
      ProviderFailure.notFound.systemError.code
        == ASExtensionError.Code.credentialIdentityNotFound.rawValue
    )
    #expect(
      ProviderFailure.excludedCredential.systemError.code
        == ASExtensionError.Code.matchedExcludedCredential.rawValue
    )
  }
}

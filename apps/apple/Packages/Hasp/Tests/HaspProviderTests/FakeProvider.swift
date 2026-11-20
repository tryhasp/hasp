import Foundation
import HaspKit
import HaspProvider

actor FakeProvider: ProviderServing {
  struct Calls {
    var unlocks = 0
    var locks = 0
    var acknowledged: [String] = []
    var assertions: [PasskeyAssertionInput] = []
    var registrations: [PasskeyRegistrationInput] = []
    var passwords: [String?] = []
    var confirmations: [Bool] = []
  }

  var unlockError: (any Error)?
  var passwordError: (any Error)?
  var fillNeedsConfirmation = false
  var changes: [IdentityChange] = []
  var acknowledgeErrors: [HaspError] = []
  var entries: [ProviderEntry] = []
  var importedDocuments: [Data] = []
  private(set) var calls = Calls()

  func set(unlockError: (any Error)?) { self.unlockError = unlockError }
  func set(passwordError: (any Error)?) { self.passwordError = passwordError }
  func set(fillNeedsConfirmation: Bool) { self.fillNeedsConfirmation = fillNeedsConfirmation }
  func set(changes: [IdentityChange]) { self.changes = changes }
  func set(acknowledgeErrors: [HaspError]) { self.acknowledgeErrors = acknowledgeErrors }
  func set(entries: [ProviderEntry]) { self.entries = entries }

  func providerUnlock() throws {
    calls.unlocks += 1
    if let unlockError { throw unlockError }
  }

  func lock() { calls.locks += 1 }

  func providerEntries(matching identifiers: [String], limit: Int) -> [ProviderEntry] { entries }

  func providerSearch(text: String, limit: Int) -> [ProviderEntry] {
    entries.filter { $0.title.localizedStandardContains(text) }
  }

  func providerFillCheck(_ key: ItemKey, service: String?, manual: Bool) -> ProviderFillCheck {
    ProviderFillCheck(needsConfirmation: fillNeedsConfirmation, host: service ?? "")
  }

  func providerPassword(_ key: ItemKey, service: String?, manual: Bool, confirmed: Bool) throws
    -> ProviderPassword
  {
    calls.passwords.append(service)
    calls.confirmations.append(confirmed)
    if let passwordError { throw passwordError }
    return ProviderPassword(
      key: key,
      user: "alice",
      password: RevealedSecret(text: "pw-\(key.item)"),
      host: service ?? "example.com",
    )
  }

  func oneTimeCode(_ key: ItemKey) -> String { "123456" }

  func providerPasskeys(rpID: String, allowed: [Data]) -> [ProviderPasskey] {
    [
      ProviderPasskey(
        key: ItemKey(vault: VaultID("v"), item: "k1"),
        credentialID: Data([1, 2, 3]),
        rpID: rpID,
        userName: "alice",
        displayName: "Alice",
        title: "Example",
      )
    ]
  }

  func assertPasskey(_ input: PasskeyAssertionInput, in key: ItemKey?) -> PasskeyAssertionOutput {
    calls.assertions.append(input)
    return PasskeyAssertionOutput(
      rpID: input.rpID,
      credentialID: input.credentialID ?? Data([1]),
      authenticatorData: Data([2]),
      signature: Data([3]),
      userHandle: Data([4]),
      clientDataHash: input.clientDataHash,
    )
  }

  func registerPasskey(_ input: PasskeyRegistrationInput) -> PasskeyRegistrationOutput {
    calls.registrations.append(input)
    return PasskeyRegistrationOutput(
      rpID: input.rpID,
      credentialID: Data([9]),
      attestationObject: Data([8]),
    )
  }

  func textOptions(matching text: String, limit: Int) -> [TextInsertOption] { [] }

  func textValue(_ key: ItemKey, field: String) -> RevealedSecret { RevealedSecret(text: "text") }

  func identityChange() throws -> IdentityChange {
    guard !changes.isEmpty else { throw HaspError.internal }
    return changes.count > 1 ? changes.removeFirst() : changes[0]
  }

  func acknowledgeIdentities(fingerprint: String) throws {
    calls.acknowledged.append(fingerprint)
    if !acknowledgeErrors.isEmpty { throw acknowledgeErrors.removeFirst() }
  }

  func importCredentialExchange(_ data: Data, dryRun: Bool) -> CredentialImportSummary {
    importedDocuments.append(data)
    return CredentialImportSummary(
      dryRun: dryRun,
      imported: 3,
      mergedPasskeys: 1,
      duplicates: 0,
      unchanged: 0,
      skipped: 0,
      withLoss: 0,
      passkeys: 1,
    )
  }
}

actor FakeIdentityStore: CredentialIdentityStoring {
  var enabled = true
  var failure: (any Error)?
  private(set) var sets: [[CredentialIdentity]] = []

  func set(enabled: Bool) { self.enabled = enabled }
  func set(failure: (any Error)?) { self.failure = failure }
  func isEnabled() -> Bool { enabled }

  private(set) var removals = 0

  func removeAll() throws {
    if let failure { throw failure }
    removals += 1
    sets.append([])
  }

  private(set) var rejected: Set<String> = []
  private(set) var saved: [CredentialIdentity] = []

  func reject(records: Set<String>) { rejected = records }

  func save(_ identity: CredentialIdentity) throws {
    if let failure { throw failure }
    if rejected.contains(identity.record) { throw HaspError.internal }
    saved.append(identity)
  }

  func replaceAll(with identities: [CredentialIdentity]) throws {
    if let failure { throw failure }
    if identities.contains(where: { rejected.contains($0.record) }) { throw HaspError.internal }
    sets.append(identities)
  }
}

func identity(
  _ kind: CredentialIdentityKind,
  record: String,
  service: String = "example.com",
  user: String = "alice",
) -> CredentialIdentity {
  CredentialIdentity(
    record: record,
    kind: kind,
    key: ItemKey(vault: VaultID("v"), item: "i"),
    service: service,
    user: user,
    title: "Example",
    favourite: false,
    credentialID: kind == .passkey ? Data([1, 2, 3]) : nil,
    userHandle: kind == .passkey ? Data([4, 5]) : nil,
  )
}

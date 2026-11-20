public import Foundation

/// What the OS credential provider needs from an account. Every call reads a sealed metadata index,
/// never the whole vault.
public protocol ProviderServing: Sendable {
  func providerUnlock() async throws
  func lock() async

  func providerEntries(matching identifiers: [String], limit: Int) async throws -> [ProviderEntry]
  func providerSearch(text: String, limit: Int) async throws -> [ProviderEntry]
  func providerFillCheck(_ key: ItemKey, service: String?, manual: Bool) async throws
    -> ProviderFillCheck
  func providerPassword(_ key: ItemKey, service: String?, manual: Bool, confirmed: Bool)
    async throws -> ProviderPassword
  func oneTimeCode(_ key: ItemKey) async throws -> String

  func providerPasskeys(rpID: String, allowed: [Data]) async throws -> [ProviderPasskey]
  func assertPasskey(_ input: PasskeyAssertionInput, in key: ItemKey?) async throws
    -> PasskeyAssertionOutput
  func registerPasskey(_ input: PasskeyRegistrationInput) async throws -> PasskeyRegistrationOutput

  func textOptions(matching text: String, limit: Int) async throws -> [TextInsertOption]
  func textValue(_ key: ItemKey, field: String) async throws -> RevealedSecret

  func identityChange() async throws -> IdentityChange
  func acknowledgeIdentities(fingerprint: String) async throws

  func importCredentialExchange(_ data: Data, dryRun: Bool) async throws -> CredentialImportSummary
}

public import Foundation
public import HaspKit

/// One extension invocation. It unlocks the engine once, answers requests from the metadata index
/// and locks again on `finish`, so no key outlives the request.
public actor ProviderCoordinator {
  private let engine: any ProviderServing
  private var unlocked = false
  private var verifiedByPrompt = false

  public init(engine: any ProviderServing) {
    self.engine = engine
  }

  public var isUnlocked: Bool { unlocked }

  public func unlock(prompting: Bool) async throws {
    guard !unlocked else { return }
    do {
      try await engine.providerUnlock()
    } catch HaspError.refused {
      throw ProviderFailure.passwordOnly
    } catch {
      throw ProviderFailure(error, prompting: prompting)
    }
    unlocked = true
    verifiedByPrompt = prompting
  }

  public func entries(matching identifiers: [String], limit: Int) async throws -> [ProviderEntry] {
    try await whenUnlocked {
      try await engine.providerEntries(matching: identifiers, limit: limit)
    }
  }

  public func search(_ text: String, limit: Int) async throws -> [ProviderEntry] {
    try await whenUnlocked { try await engine.providerSearch(text: text, limit: limit) }
  }

  public func passkeys(rpID: String, allowed: [Data]) async throws -> [ProviderPasskey] {
    try await whenUnlocked { try await engine.providerPasskeys(rpID: rpID, allowed: allowed) }
  }

  public func textOptions(matching text: String, limit: Int) async throws -> [TextInsertOption] {
    try await whenUnlocked { try await engine.textOptions(matching: text, limit: limit) }
  }

  public func provide(_ request: ProviderRequest) async throws -> ProviderResult {
    try await whenUnlocked {
      switch request {
      case .password(let key, let service, let manual, let confirmed):
        if !confirmed {
          let check = try await engine.providerFillCheck(key, service: service, manual: manual)
          if check.needsConfirmation { throw ProviderFailure.interactionRequired }
        }
        let value = try await engine.providerPassword(
          key,
          service: service,
          manual: manual,
          confirmed: confirmed,
        )
        return .password(user: value.user, password: value.password)
      case .oneTimeCode(let key):
        return .oneTimeCode(try await engine.oneTimeCode(key))
      case .passkeyAssertion(let input, let key):
        return .passkeyAssertion(try await assert(input, in: key))
      case .passkeyRegistration(let input):
        return .passkeyRegistration(try await register(input))
      case .text(let key, let field):
        return .text(try await engine.textValue(key, field: field))
      }
    }
  }

  public func fillCheck(_ request: ProviderRequest) async throws -> ProviderFillCheck? {
    guard case .password(let key, let service, let manual, let confirmed) = request, !confirmed
    else { return nil }
    return try await whenUnlocked {
      try await engine.providerFillCheck(key, service: service, manual: manual)
    }
  }

  public func identityChange() async throws -> IdentityChange {
    try await whenUnlocked { try await engine.identityChange() }
  }

  public func acknowledgeIdentities(fingerprint: String) async throws {
    try await whenUnlocked { try await engine.acknowledgeIdentities(fingerprint: fingerprint) }
  }

  public func finish() async {
    guard unlocked else { return }
    unlocked = false
    verifiedByPrompt = false
    await engine.lock()
  }

  private func assert(_ input: PasskeyAssertionInput, in key: ItemKey?) async throws
    -> PasskeyAssertionOutput
  {
    if input.userVerification == .required && !verifiedByPrompt {
      throw ProviderFailure.interactionRequired
    }
    let verified = PasskeyAssertionInput(
      rpID: input.rpID,
      clientDataHash: input.clientDataHash,
      allowedCredentialIDs: input.allowedCredentialIDs,
      userVerification: input.userVerification,
      userVerified: verifiedByPrompt,
      credentialID: input.credentialID,
    )
    return try await engine.assertPasskey(verified, in: key)
  }

  private func register(_ input: PasskeyRegistrationInput) async throws
    -> PasskeyRegistrationOutput
  {
    let verified = PasskeyRegistrationInput(
      rpID: input.rpID,
      rpName: input.rpName,
      clientDataHash: input.clientDataHash,
      userName: input.userName,
      userDisplayName: input.userDisplayName,
      userHandle: input.userHandle,
      algorithms: input.algorithms,
      excludedCredentialIDs: input.excludedCredentialIDs,
      userVerification: input.userVerification,
      userVerified: verifiedByPrompt,
    )
    return try await engine.registerPasskey(verified)
  }

  private func whenUnlocked<T: Sendable>(_ body: () async throws -> T) async throws -> T {
    guard unlocked else { throw ProviderFailure.interactionRequired }
    do {
      return try await body()
    } catch {
      throw ProviderFailure(error, prompting: verifiedByPrompt)
    }
  }
}

import AuthenticationServices
public import HaspKit

/// The real `ASCredentialIdentityStore`. Identities carry metadata only.
public struct SystemIdentityStore: CredentialIdentityStoring {
  public init() {}

  public func isEnabled() async -> Bool {
    await ASCredentialIdentityStore.shared.state().isEnabled
  }

  public func removeAll() async throws {
    try await ASCredentialIdentityStore.shared.removeAllCredentialIdentities()
  }

  public func save(_ identity: CredentialIdentity) async throws {
    guard let system = identity.systemIdentity else { throw HaspError.internal }
    try await ASCredentialIdentityStore.shared.saveCredentialIdentities([system])
  }

  public func replaceAll(with identities: [CredentialIdentity]) async throws {
    try await ASCredentialIdentityStore.shared.replaceCredentialIdentities(
      identities.compactMap(\.systemIdentity)
    )
  }
}

extension CredentialIdentity {
  var systemIdentity: (any ASCredentialIdentity)? {
    let rank = favourite ? 1 : 0
    switch kind {
    case .password:
      let identity = ASPasswordCredentialIdentity(
        serviceIdentifier: ASCredentialServiceIdentifier(identifier: service, type: .domain),
        user: user,
        recordIdentifier: record,
      )
      identity.rank = rank
      return identity
    case .oneTimeCode:
      let identity = ASOneTimeCodeCredentialIdentity(
        serviceIdentifier: ASCredentialServiceIdentifier(identifier: service, type: .domain),
        label: title,
        recordIdentifier: record,
      )
      identity.rank = rank
      return identity
    case .passkey:
      guard let credentialID, let userHandle else { return nil }
      let identity = ASPasskeyCredentialIdentity(
        relyingPartyIdentifier: service,
        userName: user,
        credentialID: credentialID,
        userHandle: userHandle,
        recordIdentifier: record,
      )
      identity.rank = rank
      return identity
    }
  }
}

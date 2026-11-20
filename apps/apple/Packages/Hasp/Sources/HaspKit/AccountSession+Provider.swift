public import Foundation
import HaspFFI

extension AccountSession: ProviderServing {
  public func providerUnlock() throws {
    try mapped { try client.providerUnlock() }
  }

  public func providerEntries(matching identifiers: [String], limit: Int) throws
    -> [ProviderEntry]
  {
    let query = ProviderQuery(identifiers: identifiers, limit: UInt32(max(0, limit)))
    return try mapped { try client.providerCandidates(query: query) }.map {
      ProviderEntry(
        key: ItemKey(vault: VaultID($0.vault), item: $0.item),
        title: $0.title,
        subtitle: $0.subtitle,
        favourite: $0.favourite,
        hasOneTimeCode: $0.hasTotp,
        hasPasskey: $0.hasPasskey,
        hostToConfirm: $0.hostToConfirm,
      )
    }
  }

  public func providerSearch(text: String, limit: Int) throws -> [ProviderEntry] {
    let query = SearchQuery(
      text: text,
      vault: nil,
      kind: "login",
      tag: nil,
      favouritesOnly: false,
      status: nil,
      boostUrl: nil,
      limit: UInt32(max(0, limit)),
    )
    return try mapped { try client.providerList(query: query) }.map {
      ProviderEntry(
        key: ItemKey(vault: VaultID($0.vault), item: $0.id),
        title: $0.title,
        subtitle: $0.subtitle,
        favourite: $0.favourite,
        hasOneTimeCode: $0.hasTotp,
        hasPasskey: $0.hasPasskey,
        hostToConfirm: nil,
      )
    }
  }

  public func providerFillCheck(_ key: ItemKey, service: String?, manual: Bool) throws
    -> ProviderFillCheck
  {
    let value = try mapped {
      try client.providerFillCheck(
        vault: key.vault.rawValue,
        item: key.item,
        service: service,
        manual: manual,
      )
    }
    return ProviderFillCheck(needsConfirmation: value.fill != .oneClick, host: value.host)
  }

  public func providerPassword(
    _ key: ItemKey,
    service: String?,
    manual: Bool,
    confirmed: Bool,
  ) throws -> ProviderPassword {
    let value = try mapped {
      try client.providerPassword(
        vault: key.vault.rawValue,
        item: key.item,
        service: service,
        manual: manual,
        confirmed: confirmed,
      )
    }
    return ProviderPassword(
      key: key,
      user: value.user,
      password: RevealedSecret(value.password),
      host: value.host,
    )
  }

  public func oneTimeCode(_ key: ItemKey) throws -> String {
    try totp(key, field: nil).code
  }

  public func providerPasskeys(rpID: String, allowed: [Data]) throws -> [ProviderPasskey] {
    let query = ProviderPasskeyQuery(rpId: rpID, allow: allowed.map { $0.base64URLString() })
    return try mapped { try client.providerPasskeys(query: query) }.compactMap { found in
      guard let credentialID = Data(base64URLString: found.credentialId) else { return nil }
      return ProviderPasskey(
        key: ItemKey(vault: VaultID(found.vault), item: found.item),
        credentialID: credentialID,
        rpID: found.rpId,
        userName: found.userName,
        displayName: found.displayName,
        title: found.title,
      )
    }
  }

  public func assertPasskey(_ input: PasskeyAssertionInput, in key: ItemKey?) throws
    -> PasskeyAssertionOutput
  {
    let request = OsAssertionRequest(
      rpId: input.rpID,
      clientDataHash: input.clientDataHash.base64URLString(),
      allow: input.allowedCredentialIDs.map { $0.base64URLString() },
      userVerification: input.userVerification.ffi,
      userVerified: input.userVerified,
      vault: key?.vault.rawValue,
      item: key?.item,
      credentialId: input.credentialID?.base64URLString(),
    )
    let result = try mapped { try client.providerPasskeyAssert(request: request) }
    guard
      let credentialID = Data(base64URLString: result.credentialId),
      let authenticatorData = Data(base64URLString: result.authenticatorData),
      let signature = Data(base64URLString: result.signature),
      let userHandle = Data(base64URLString: result.userHandle),
      let clientDataHash = Data(base64URLString: result.clientDataHash)
    else { throw HaspError.internal }
    return PasskeyAssertionOutput(
      rpID: result.rpId,
      credentialID: credentialID,
      authenticatorData: authenticatorData,
      signature: signature,
      userHandle: userHandle,
      clientDataHash: clientDataHash,
    )
  }

  public func registerPasskey(_ input: PasskeyRegistrationInput) throws
    -> PasskeyRegistrationOutput
  {
    let request = OsRegistrationRequest(
      rpId: input.rpID,
      rpName: input.rpName,
      clientDataHash: input.clientDataHash.base64URLString(),
      userName: input.userName,
      userDisplayName: input.userDisplayName,
      userHandle: input.userHandle.base64URLString(),
      algorithms: input.algorithms.map { Int32(truncatingIfNeeded: $0) },
      exclude: input.excludedCredentialIDs.map { $0.base64URLString() },
      userVerification: input.userVerification.ffi,
      userVerified: input.userVerified,
      vault: nil,
      item: nil,
    )
    let result = try mapped { try client.providerPasskeyRegister(request: request) }
    guard
      let credentialID = Data(base64URLString: result.credentialId),
      let attestationObject = Data(base64URLString: result.attestationObject)
    else { throw HaspError.internal }
    return PasskeyRegistrationOutput(
      rpID: result.rpId,
      credentialID: credentialID,
      attestationObject: attestationObject,
    )
  }

  public func textOptions(matching text: String, limit: Int) throws -> [TextInsertOption] {
    let query = TextQuery(text: text, limit: UInt32(max(0, limit)))
    return try mapped { try client.textCandidates(query: query) }.map {
      TextInsertOption(
        key: ItemKey(vault: VaultID($0.vault), item: $0.item),
        field: $0.field,
        itemTitle: $0.itemTitle,
        itemKind: $0.itemKind,
        label: $0.label,
        preview: $0.preview,
        concealed: $0.concealed,
      )
    }
  }

  public func textValue(_ key: ItemKey, field: String) throws -> RevealedSecret {
    let value = try mapped {
      try client.textValue(vault: key.vault.rawValue, item: key.item, field: field)
    }
    return RevealedSecret(value)
  }

  public func identityChange() throws -> IdentityChange {
    let diff = try mapped { try client.identityDiff() }
    return IdentityChange(
      changed: diff.changed,
      fingerprint: diff.fingerprint,
      identities: diff.identities.map(CredentialIdentity.init),
    )
  }

  public func acknowledgeIdentities(fingerprint: String) throws {
    try mapped { try client.identityAck(fingerprint: fingerprint) }
  }

  public func importCredentialExchange(_ data: Data, dryRun: Bool) throws
    -> CredentialImportSummary
  {
    let request = CxfImportRequest(data: data, dryRun: dryRun)
    let report = try mapped { try client.cxfImport(request: request) }
    return CredentialImportSummary(
      dryRun: report.dryRun,
      imported: Int(report.imported),
      mergedPasskeys: Int(report.mergedPasskeys),
      duplicates: Int(report.duplicates),
      unchanged: Int(report.unchanged),
      skipped: Int(report.skipped),
      withLoss: Int(report.withLoss),
      passkeys: Int(report.passkeys),
    )
  }
}

extension PasskeyUserVerification {
  var ffi: UserVerification {
    switch self {
    case .required: .required
    case .preferred: .preferred
    case .discouraged: .discouraged
    }
  }
}

extension CredentialIdentity {
  init(_ identity: HaspFFI.CredentialIdentity) {
    self.init(
      record: identity.record,
      kind: CredentialIdentityKind(identity.kind),
      key: ItemKey(vault: VaultID(identity.vault), item: identity.item),
      service: identity.service,
      user: identity.user,
      title: identity.title,
      favourite: identity.favourite,
      credentialID: identity.credentialId.flatMap { Data(base64URLString: $0) },
      userHandle: identity.userHandle.flatMap { Data(base64URLString: $0) },
    )
  }
}

extension CredentialIdentityKind {
  init(_ kind: IdentityKind) {
    self =
      switch kind {
      case .password: .password
      case .oneTimeCode: .oneTimeCode
      case .passkey: .passkey
      }
  }
}

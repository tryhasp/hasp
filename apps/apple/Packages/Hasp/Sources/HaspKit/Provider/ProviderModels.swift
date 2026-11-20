public import Foundation

/// One row of the password list: a login the provider can offer, with no secret in it.
public struct ProviderEntry: Sendable, Equatable, Identifiable {
  public let key: ItemKey
  public let title: String
  public let subtitle: String
  public let favourite: Bool
  public let hasOneTimeCode: Bool
  public let hasPasskey: Bool
  public let hostToConfirm: String?

  public var id: ItemKey { key }

  public init(
    key: ItemKey,
    title: String,
    subtitle: String,
    favourite: Bool,
    hasOneTimeCode: Bool,
    hasPasskey: Bool,
    hostToConfirm: String?,
  ) {
    self.key = key
    self.title = title
    self.subtitle = subtitle
    self.favourite = favourite
    self.hasOneTimeCode = hasOneTimeCode
    self.hasPasskey = hasPasskey
    self.hostToConfirm = hostToConfirm
  }
}

/// What filling one login for a service needs. `host` is what the confirmation must show.
public struct ProviderFillCheck: Sendable, Equatable {
  public let needsConfirmation: Bool
  public let host: String

  public init(needsConfirmation: Bool, host: String) {
    self.needsConfirmation = needsConfirmation
    self.host = host
  }
}

public struct ProviderPassword: Sendable {
  public let key: ItemKey
  public let user: String
  public let password: RevealedSecret
  public let host: String

  public init(key: ItemKey, user: String, password: RevealedSecret, host: String) {
    self.key = key
    self.user = user
    self.password = password
    self.host = host
  }
}

public struct ProviderPasskey: Sendable, Equatable, Identifiable {
  public let key: ItemKey
  public let credentialID: Data
  public let rpID: String
  public let userName: String
  public let displayName: String
  public let title: String

  public var id: Data { credentialID }

  public init(
    key: ItemKey,
    credentialID: Data,
    rpID: String,
    userName: String,
    displayName: String,
    title: String,
  ) {
    self.key = key
    self.credentialID = credentialID
    self.rpID = rpID
    self.userName = userName
    self.displayName = displayName
    self.title = title
  }
}

public enum PasskeyUserVerification: Sendable, Equatable {
  case required, preferred, discouraged
}

public struct PasskeyAssertionInput: Sendable {
  public let rpID: String
  public let clientDataHash: Data
  public let allowedCredentialIDs: [Data]
  public let userVerification: PasskeyUserVerification
  public let userVerified: Bool
  public let credentialID: Data?

  public init(
    rpID: String,
    clientDataHash: Data,
    allowedCredentialIDs: [Data],
    userVerification: PasskeyUserVerification,
    userVerified: Bool,
    credentialID: Data?,
  ) {
    self.rpID = rpID
    self.clientDataHash = clientDataHash
    self.allowedCredentialIDs = allowedCredentialIDs
    self.userVerification = userVerification
    self.userVerified = userVerified
    self.credentialID = credentialID
  }
}

public struct PasskeyAssertionOutput: Sendable, Equatable {
  public let rpID: String
  public let credentialID: Data
  public let authenticatorData: Data
  public let signature: Data
  public let userHandle: Data
  public let clientDataHash: Data

  public init(
    rpID: String,
    credentialID: Data,
    authenticatorData: Data,
    signature: Data,
    userHandle: Data,
    clientDataHash: Data,
  ) {
    self.rpID = rpID
    self.credentialID = credentialID
    self.authenticatorData = authenticatorData
    self.signature = signature
    self.userHandle = userHandle
    self.clientDataHash = clientDataHash
  }
}

public struct PasskeyRegistrationInput: Sendable {
  public let rpID: String
  public let rpName: String
  public let clientDataHash: Data
  public let userName: String
  public let userDisplayName: String
  public let userHandle: Data
  public let algorithms: [Int]
  public let excludedCredentialIDs: [Data]
  public let userVerification: PasskeyUserVerification
  public let userVerified: Bool

  public init(
    rpID: String,
    rpName: String,
    clientDataHash: Data,
    userName: String,
    userDisplayName: String,
    userHandle: Data,
    algorithms: [Int],
    excludedCredentialIDs: [Data],
    userVerification: PasskeyUserVerification,
    userVerified: Bool,
  ) {
    self.rpID = rpID
    self.rpName = rpName
    self.clientDataHash = clientDataHash
    self.userName = userName
    self.userDisplayName = userDisplayName
    self.userHandle = userHandle
    self.algorithms = algorithms
    self.excludedCredentialIDs = excludedCredentialIDs
    self.userVerification = userVerification
    self.userVerified = userVerified
  }
}

public struct PasskeyRegistrationOutput: Sendable, Equatable {
  public let rpID: String
  public let credentialID: Data
  public let attestationObject: Data

  public init(rpID: String, credentialID: Data, attestationObject: Data) {
    self.rpID = rpID
    self.credentialID = credentialID
    self.attestationObject = attestationObject
  }
}

public struct TextInsertOption: Sendable, Equatable, Identifiable {
  public let key: ItemKey
  public let field: String
  public let itemTitle: String
  public let itemKind: String
  public let label: String
  public let preview: String
  public let concealed: Bool

  public var id: String { "\(key.vault.rawValue)/\(key.item)/\(field)" }

  public init(
    key: ItemKey,
    field: String,
    itemTitle: String,
    itemKind: String,
    label: String,
    preview: String,
    concealed: Bool,
  ) {
    self.key = key
    self.field = field
    self.itemTitle = itemTitle
    self.itemKind = itemKind
    self.label = label
    self.preview = preview
    self.concealed = concealed
  }
}

public enum CredentialIdentityKind: Sendable, Equatable {
  case password, oneTimeCode, passkey
}

/// Metadata for the system QuickType store. It never holds a password, seed or key.
public struct CredentialIdentity: Sendable, Equatable {
  public let record: String
  public let kind: CredentialIdentityKind
  public let key: ItemKey
  public let service: String
  public let user: String
  public let title: String
  public let favourite: Bool
  public let credentialID: Data?
  public let userHandle: Data?

  public init(
    record: String,
    kind: CredentialIdentityKind,
    key: ItemKey,
    service: String,
    user: String,
    title: String,
    favourite: Bool,
    credentialID: Data?,
    userHandle: Data?,
  ) {
    self.record = record
    self.kind = kind
    self.key = key
    self.service = service
    self.user = user
    self.title = title
    self.favourite = favourite
    self.credentialID = credentialID
    self.userHandle = userHandle
  }
}

public struct IdentityChange: Sendable, Equatable {
  public let changed: Bool
  public let fingerprint: String
  public let identities: [CredentialIdentity]

  public init(changed: Bool, fingerprint: String, identities: [CredentialIdentity]) {
    self.changed = changed
    self.fingerprint = fingerprint
    self.identities = identities
  }
}

public struct CredentialImportSummary: Sendable, Equatable {
  public let dryRun: Bool
  public let imported: Int
  public let mergedPasskeys: Int
  public let duplicates: Int
  public let unchanged: Int
  public let skipped: Int
  public let withLoss: Int
  public let passkeys: Int

  public init(
    dryRun: Bool,
    imported: Int,
    mergedPasskeys: Int,
    duplicates: Int,
    unchanged: Int,
    skipped: Int,
    withLoss: Int,
    passkeys: Int,
  ) {
    self.dryRun = dryRun
    self.imported = imported
    self.mergedPasskeys = mergedPasskeys
    self.duplicates = duplicates
    self.unchanged = unchanged
    self.skipped = skipped
    self.withLoss = withLoss
    self.passkeys = passkeys
  }
}

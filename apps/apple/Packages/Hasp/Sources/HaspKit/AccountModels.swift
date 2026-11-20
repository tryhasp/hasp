public import Foundation

public enum LockState: Equatable, Sendable {
  case empty
  case locked
  case unlocked
}

public enum UnlockMode: Equatable, Sendable {
  case hardware
  case passwordOnly
  case desktopExtension
}

public struct AccountStatus: Equatable, Sendable {
  public var state: LockState
  public var login: String?
  public var origin: String?
  public var unlockMode: UnlockMode?
  public var biometricReady: Bool
  public var retryAfter: Duration
  public var deviceConfirmed: Bool
  public var fingerprint: String?
  public var passwordRequired: Bool

  public init(
    state: LockState,
    login: String? = nil,
    origin: String? = nil,
    unlockMode: UnlockMode? = nil,
    biometricReady: Bool = false,
    retryAfter: Duration = .zero,
    deviceConfirmed: Bool = false,
    fingerprint: String? = nil,
    passwordRequired: Bool = false,
  ) {
    self.state = state
    self.login = login
    self.origin = origin
    self.unlockMode = unlockMode
    self.biometricReady = biometricReady
    self.retryAfter = retryAfter
    self.deviceConfirmed = deviceConfirmed
    self.fingerprint = fingerprint
    self.passwordRequired = passwordRequired
  }
}

public struct KitPreview: Equatable, Sendable {
  public var origin: String
  public var login: String
  public var serverFingerprint: String

  public init(origin: String, login: String, serverFingerprint: String) {
    self.origin = origin
    self.login = login
    self.serverFingerprint = serverFingerprint
  }
}

public struct SyncOutcome: Equatable, Sendable {
  public var vaults: Int
  public var changed: Int
  public var needsAttention: Int

  public init(vaults: Int, changed: Int, needsAttention: Int) {
    self.vaults = vaults
    self.changed = changed
    self.needsAttention = needsAttention
  }
}

public struct DeviceSummary: Identifiable, Equatable, Sendable {
  public var session: String
  public var device: String
  public var platform: String
  public var label: String?
  public var current: Bool
  public var revoked: Bool

  public var id: String { session + device }

  public init(
    session: String,
    device: String,
    platform: String,
    label: String?,
    current: Bool,
    revoked: Bool,
  ) {
    self.session = session
    self.device = device
    self.platform = platform
    self.label = label
    self.current = current
    self.revoked = revoked
  }
}

public enum SessionEvent: Equatable, Sendable {
  case locked
  case unlocked
  case syncStarted
  case syncFinished
  case vaultChanged(VaultID?)
  case conflict
  case needsAttention
  case sessionRevoked
  case deviceRevoked
  case settingsChanged
  case offline
}

public struct EmergencyKit: Equatable, Sendable, Identifiable {
  public var id: String { origin + login }
  public var origin: String
  public var login: String
  public var serverFingerprint: String
  public var secretKey: String
  public var documentText: String
  public var documentPdf: Data

  public init(
    origin: String,
    login: String,
    serverFingerprint: String,
    secretKey: String,
    documentText: String,
    documentPdf: Data,
  ) {
    self.origin = origin
    self.login = login
    self.serverFingerprint = serverFingerprint
    self.secretKey = secretKey
    self.documentText = documentText
    self.documentPdf = documentPdf
  }
}

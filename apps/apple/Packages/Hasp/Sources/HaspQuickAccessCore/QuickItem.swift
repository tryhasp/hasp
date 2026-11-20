public import Foundation

public struct QuickItemID: Hashable, Sendable {
  public let vault: String
  public let item: String

  public init(vault: String, item: String) {
    self.vault = vault
    self.item = item
  }
}

public enum QuickItemKind: Hashable, Sendable {
  case login
  case card
  case identity
  case other
}

public struct QuickItem: Equatable, Identifiable, Sendable {
  public let id: QuickItemID
  public let kind: QuickItemKind
  public let title: String
  public let username: String
  public let hosts: [String]
  public let vaultName: String
  public let isShared: Bool
  public let favourite: Bool
  public let hasOTP: Bool
  public let modified: Date

  public init(
    id: QuickItemID,
    kind: QuickItemKind,
    title: String,
    username: String,
    hosts: [String],
    vaultName: String,
    isShared: Bool,
    favourite: Bool,
    hasOTP: Bool,
    modified: Date,
  ) {
    self.id = id
    self.kind = kind
    self.title = title
    self.username = username
    self.hosts = hosts
    self.vaultName = vaultName
    self.isShared = isShared
    self.favourite = favourite
    self.hasOTP = hasOTP
    self.modified = modified
  }
}

public struct OTPPreview: Equatable, Sendable {
  public let code: String
  public let secondsRemaining: Int

  public init(code: String, secondsRemaining: Int) {
    self.code = code
    self.secondsRemaining = secondsRemaining
  }
}

public struct LoginValues: Sendable {
  public let username: Data
  public let password: Data

  public init(username: Data, password: Data) {
    self.username = username
    self.password = password
  }
}

public enum QuickAccessLockState: Equatable, Sendable {
  case locked
  case unlocked(clipboardClear: Duration)
}

public protocol QuickAccessEngine: Sendable {
  func lockState() async throws -> QuickAccessLockState
  func items() async throws -> [QuickItem]
  func otpPreview(for item: QuickItemID) async throws -> OTPPreview
  func password(for item: QuickItemID) async throws -> Data
  func otpCode(for item: QuickItemID) async throws -> Data
  func username(for item: QuickItemID) async throws -> Data
  func loginValues(for item: QuickItemID) async throws -> LoginValues
}

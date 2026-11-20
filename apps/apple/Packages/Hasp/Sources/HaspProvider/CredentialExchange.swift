import AuthenticationServices
public import Foundation

/// Reads the Credential Exchange (CXF) data the system staged for an import (iOS 26, macOS 26).
public protocol CredentialExchangeSource: Sendable {
  func document(token: UUID) async throws -> Data
}

@available(iOS 26.0, macOS 26.0, *)
public struct SystemCredentialExchange: CredentialExchangeSource {
  public init() {}

  public func document(token: UUID) async throws -> Data {
    let exported = try await ASCredentialImportManager().importCredentials(token: token)
    return try Self.cxfJSON(exported)
  }

  /// Apple's `Codable` writes the CXF member names. Dates must be Unix seconds: the default strategy
  /// writes seconds since 2001, which shifts every date by 31 years (checked against the SDK).
  static func cxfJSON(_ exported: ASExportedCredentialData) throws -> Data {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .secondsSince1970
    return try encoder.encode(exported)
  }
}

public enum CredentialExchangeActivity {
  /// The values of `ASCredentialExchangeActivity` and `ASCredentialImportToken`. The SDK declares both
  /// for iOS 26 and later only, and a test compares these literals with the SDK constants.
  public static let activityType = "ASCredentialExchangeActivity"
  public static let tokenKey = "ASCredentialImportToken"

  public static func token(from userInfo: [AnyHashable: Any]?) -> UUID? {
    userInfo?[tokenKey] as? UUID
  }
}

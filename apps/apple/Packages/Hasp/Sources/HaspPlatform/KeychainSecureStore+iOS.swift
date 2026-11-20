#if os(iOS)
  public import Foundation
  public import HaspKit
  import LocalAuthentication
  import Security

  /// Keeps the device unlock key as one keychain item per label in the shared access group
  /// (protocol 4.6: this device only, passcode required, access control gated by the user).
  /// The Secure Enclave holds only P-256 keys, so the key is protected by the Enclave-derived class keys.
  public final class KeychainSecureStore: SecureStore {
    public enum Policy: Sendable {
      case userPresence
      case biometryCurrentSet

      var flags: SecAccessControlCreateFlags {
        switch self {
        case .userPresence: .userPresence
        case .biometryCurrentSet: .biometryCurrentSet
        }
      }
    }

    private static let service = "kr.jmo.hasp.store"

    private let accessGroup: String
    private let policy: Policy
    private let shared: AuthenticationContext
    private let failures = FailureLog()

    init(accessGroup: String, policy: Policy, shared: AuthenticationContext) {
      self.accessGroup = accessGroup
      self.policy = policy
      self.shared = shared
    }

    public var hardwareGated: Bool { true }

    public var lastFailure: StoreFailure? { failures.last }

    public func put(label: String, secret: Data) throws {
      var accessError: Unmanaged<CFError>?
      guard
        let access = SecAccessControlCreateWithFlags(
          nil,
          kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
          policy.flags,
          &accessError,
        )
      else {
        failures.record(.passcodeNotSet)
        throw HaspError.internal
      }
      _ = SecItemDelete(itemQuery(label: label) as CFDictionary)
      var attributes = itemQuery(label: label)
      attributes[kSecValueData] = secret
      attributes[kSecAttrAccessControl] = access
      let status = SecItemAdd(attributes as CFDictionary, nil)
      guard status == errSecSuccess else {
        failures.record(StoreFailure(keychainPutStatus: status))
        throw HaspError.internal
      }
      failures.clear()
    }

    public func get(label: String) throws -> Data {
      var query = itemQuery(label: label)
      query[kSecReturnData] = true
      query[kSecMatchLimit] = kSecMatchLimitOne
      query[kSecUseAuthenticationContext] = shared.context
      var result: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &result)
      guard status == errSecSuccess, let data = result as? Data else {
        if status != errSecItemNotFound { failures.record(StoreFailure(keychainStatus: status)) }
        throw Self.map(status)
      }
      return data
    }

    public func delete(label: String) throws {
      let status = SecItemDelete(itemQuery(label: label) as CFDictionary)
      guard status == errSecSuccess || status == errSecItemNotFound else {
        throw HaspError.internal
      }
    }

    private func itemQuery(label: String) -> [CFString: Any] {
      [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: Self.service,
        kSecAttrAccount: label,
        kSecAttrAccessGroup: accessGroup,
        kSecAttrSynchronizable: false,
      ]
    }

    private static func map(_ status: OSStatus) -> HaspError {
      switch status {
      case errSecItemNotFound: .notFound
      case errSecUserCanceled: .cancelled
      case errSecAuthFailed: .authz
      default: .internal
      }
    }
  }
#endif

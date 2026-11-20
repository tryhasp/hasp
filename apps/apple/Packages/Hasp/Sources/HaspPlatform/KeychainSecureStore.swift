#if os(macOS)
  public import Foundation
  public import HaspKit
  import LocalAuthentication
  import Security

  /// Seals every secret with a Secure Enclave P-256 key gated by user presence
  /// (`.userPresence`, protocol 4.6, this device only) and keeps the sealed bytes in the data-protection keychain.
  public final class KeychainSecureStore: SecureStore {
    private static let service = "kr.jmo.hasp.store"
    private static let keyTag = Data("kr.jmo.hasp.enclave-key".utf8)
    private static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM

    static let accessFlags: SecAccessControlCreateFlags = [.privateKeyUsage, .userPresence]

    private let accessGroup: String
    private let shared: AuthenticationContext

    init(accessGroup: String, shared: AuthenticationContext) {
      self.accessGroup = accessGroup
      self.shared = shared
    }

    public var hardwareGated: Bool { true }

    public func put(label: String, secret: Data) throws {
      let publicKey = try enclavePublicKey(createIfMissing: true)
      var error: Unmanaged<CFError>?
      guard
        let sealed = SecKeyCreateEncryptedData(
          publicKey,
          Self.algorithm,
          secret as CFData,
          &error,
        ) as Data?
      else { throw HaspError.internal }
      try store(label: label, sealed: sealed)
    }

    public func get(label: String) throws -> Data {
      let sealed = try load(label: label)
      let privateKey = try enclavePrivateKey()
      var error: Unmanaged<CFError>?
      guard
        let secret = SecKeyCreateDecryptedData(
          privateKey,
          Self.algorithm,
          sealed as CFData,
          &error,
        ) as Data?
      else { throw Self.map(error?.takeRetainedValue()) }
      return secret
    }

    public func delete(label: String) throws {
      let status = SecItemDelete(itemQuery(label: label) as CFDictionary)
      guard status == errSecSuccess || status == errSecItemNotFound else {
        throw HaspError.internal
      }
    }
  }

  extension KeychainSecureStore {
    private func itemQuery(label: String) -> [CFString: Any] {
      [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: Self.service,
        kSecAttrAccount: label,
        kSecAttrAccessGroup: accessGroup,
        kSecUseDataProtectionKeychain: true,
        kSecAttrSynchronizable: false,
      ]
    }

    private func store(label: String, sealed: Data) throws {
      _ = SecItemDelete(itemQuery(label: label) as CFDictionary)
      var attributes = itemQuery(label: label)
      attributes[kSecValueData] = sealed
      attributes[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
      guard SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess else {
        throw HaspError.internal
      }
    }

    private func load(label: String) throws -> Data {
      var query = itemQuery(label: label)
      query[kSecReturnData] = true
      query[kSecMatchLimit] = kSecMatchLimitOne
      var result: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &result)
      guard status == errSecSuccess, let data = result as? Data else {
        throw status == errSecItemNotFound ? HaspError.notFound : HaspError.internal
      }
      return data
    }

    private func keyQuery() -> [CFString: Any] {
      [
        kSecClass: kSecClassKey,
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrApplicationTag: Self.keyTag,
        kSecAttrAccessGroup: accessGroup,
        kSecUseDataProtectionKeychain: true,
      ]
    }

    private func enclavePrivateKey() throws -> SecKey {
      var query = keyQuery()
      query[kSecReturnRef] = true
      query[kSecUseAuthenticationContext] = shared.context
      var result: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &result)
      guard status == errSecSuccess, let key = result else {
        throw status == errSecItemNotFound ? HaspError.notFound : HaspError.internal
      }
      return unsafeDowncast(key, to: SecKey.self)
    }

    private func enclavePublicKey(createIfMissing: Bool) throws -> SecKey {
      let privateKey: SecKey
      do {
        privateKey = try enclavePrivateKey()
      } catch HaspError.notFound where createIfMissing {
        privateKey = try createEnclaveKey()
      }
      guard let publicKey = SecKeyCopyPublicKey(privateKey) else { throw HaspError.internal }
      return publicKey
    }

    private func createEnclaveKey() throws -> SecKey {
      var accessError: Unmanaged<CFError>?
      guard
        let access = SecAccessControlCreateWithFlags(
          nil,
          kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
          Self.accessFlags,
          &accessError,
        )
      else { throw HaspError.internal }
      let attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256,
        kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs: [
          kSecAttrIsPermanent: true,
          kSecAttrApplicationTag: Self.keyTag,
          kSecAttrAccessControl: access,
          kSecAttrAccessGroup: accessGroup,
        ] as [CFString: Any],
        kSecUseDataProtectionKeychain: true,
      ]
      var error: Unmanaged<CFError>?
      guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw HaspError.internal
      }
      return key
    }

    private static func map(_ error: CFError?) -> HaspError {
      guard let error else { return .internal }
      let code = CFErrorGetCode(error)
      switch Int32(truncatingIfNeeded: code) {
      case errSecUserCanceled, Int32(LAError.userCancel.rawValue): return .cancelled
      case errSecAuthFailed: return .authz
      default: return .internal
      }
    }
  }
#endif

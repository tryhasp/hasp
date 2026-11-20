public import Foundation
public import HaspKit
import Security

/// Fallback for builds without a keychain access group and for Macs without Touch ID.
/// Not hardware-gated, so the engine treats the device as password-only.
public final class LoginKeychainStore: SecureStore {
  private static let service = "kr.jmo.hasp.store.software"

  private let failures = FailureLog()

  public init() {}

  public var hardwareGated: Bool { false }

  public var lastFailure: StoreFailure? { failures.last }

  public func put(label: String, secret: Data) throws {
    _ = SecItemDelete(query(label) as CFDictionary)
    var attributes = query(label)
    attributes[kSecValueData] = secret
    attributes[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    let status = SecItemAdd(attributes as CFDictionary, nil)
    guard status == errSecSuccess else {
      failures.record(StoreFailure(keychainStatus: status))
      throw HaspError.internal
    }
    failures.clear()
  }

  public func get(label: String) throws -> Data {
    var request = query(label)
    request[kSecReturnData] = true
    request[kSecMatchLimit] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(request as CFDictionary, &result)
    guard status == errSecSuccess, let data = result as? Data else {
      throw status == errSecItemNotFound ? HaspError.notFound : HaspError.internal
    }
    return data
  }

  public func delete(label: String) throws {
    let status = SecItemDelete(query(label) as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else { throw HaspError.internal }
  }

  private func query(_ label: String) -> [CFString: Any] {
    [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: Self.service,
      kSecAttrAccount: label,
      kSecAttrSynchronizable: false,
    ]
  }
}

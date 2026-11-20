#if os(iOS)
  import Foundation
  import HaspKit

  extension DevicePlatformFactory {
    public static let accessGroupInfoKey = "HaspKeychainAccessGroup"

    /// Hardware custody needs a signed build whose keychain access group is provisioned and a device
    /// with biometrics enrolled. Anything else keeps secrets in a device-only keychain and is password-only.
    public static func make(memoryOnly: Bool) -> DevicePlatform {
      make(memoryOnly: memoryOnly, interaction: .prompt)
    }

    /// The provider extension builds its platform with the interaction its entry point allows.
    public static func make(memoryOnly: Bool, interaction: AuthenticationInteraction)
      -> DevicePlatform
    {
      let shared = AuthenticationContext(interaction: interaction)
      let biometric = LocalAuthenticator(shared: shared)
      if memoryOnly {
        return DevicePlatform(
          store: MemorySecureStore(),
          biometric: biometric,
          isHardwareBacked: false,
        )
      }
      if let group = keychainAccessGroup(), unlockCapability() == .hardwareReady {
        let store = KeychainSecureStore(
          accessGroup: group,
          policy: .userPresence,
          shared: shared,
        )
        return DevicePlatform(store: store, biometric: biometric, isHardwareBacked: true)
      }
      return DevicePlatform(
        store: LoginKeychainStore(),
        biometric: biometric,
        isHardwareBacked: false,
      )
    }

    static func keychainAccessGroup() -> String? {
      let value = Bundle.main.object(forInfoDictionaryKey: accessGroupInfoKey) as? String
      guard let value, value.hasSuffix(".\(accessGroupSuffix)") else { return nil }
      let prefix = value.dropLast(accessGroupSuffix.count + 1)
      return prefix.count == 10 && prefix.allSatisfy({ $0.isNumber || $0.isUppercase })
        ? value : nil
    }
  }
#endif

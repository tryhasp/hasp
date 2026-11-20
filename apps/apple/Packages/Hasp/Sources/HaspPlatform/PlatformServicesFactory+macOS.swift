#if os(macOS)
  import HaspKit
  import Security

  extension DevicePlatformFactory {
    /// Hardware custody needs a signed build with a keychain access group, a device passcode and an enrolled biometric.
    /// Anything else gets the login keychain and is honestly password-only.
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
        let store = KeychainSecureStore(accessGroup: group, shared: shared)
        return DevicePlatform(store: store, biometric: biometric, isHardwareBacked: true)
      }
      return DevicePlatform(
        store: LoginKeychainStore(),
        biometric: biometric,
        isHardwareBacked: false,
      )
    }

    static func keychainAccessGroup() -> String? {
      guard let task = SecTaskCreateFromSelf(nil) else { return nil }
      let value = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil)
      let groups = value as? [String] ?? []
      return groups.first { $0.hasSuffix(accessGroupSuffix) }
    }
  }
#endif

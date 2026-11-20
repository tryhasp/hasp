import HaspKit
import Testing

struct UnlockCapabilityTests {
  @Test func hardwareNeedsAGroupAPasscodeAndABiometric() {
    func resolve(_ group: Bool, _ passcode: Bool, _ biometrics: Bool) -> UnlockCapability {
      .resolve(hasAccessGroup: group, hasPasscode: passcode, hasBiometrics: biometrics)
    }
    #expect(resolve(true, true, true) == .hardwareReady)
    #expect(resolve(true, false, false) == .needsPasscode)
    #expect(resolve(true, false, true) == .needsPasscode)
    #expect(resolve(true, true, false) == .softwareOnly)
    #expect(resolve(false, false, false) == .softwareOnly)
    #expect(resolve(false, true, true) == .softwareOnly)
  }

  @Test func keychainStatusesMapToActionableFailures() {
    #expect(StoreFailure(keychainStatus: -34018) == .missingEntitlement)
    #expect(StoreFailure(keychainStatus: -25308) == .deviceLocked)
    #expect(StoreFailure(keychainStatus: -50) == .status(-50))
    #expect(StoreFailure(keychainPutStatus: -25291) == .passcodeNotSet)
    #expect(StoreFailure(keychainPutStatus: -25293) == .passcodeNotSet)
    #expect(StoreFailure(keychainPutStatus: -34018) == .missingEntitlement)
  }
}

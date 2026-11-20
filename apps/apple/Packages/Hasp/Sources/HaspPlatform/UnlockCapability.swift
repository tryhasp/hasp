public import HaspKit
import LocalAuthentication

extension DevicePlatformFactory {
  /// Read live, so a passcode or Face ID set up while the app runs is noticed on the next check.
  public static func unlockCapability() -> UnlockCapability {
    UnlockCapability.resolve(
      hasAccessGroup: keychainAccessGroup() != nil,
      hasPasscode: LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil),
      hasBiometrics: LAContext().canEvaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        error: nil,
      ),
    )
  }
}

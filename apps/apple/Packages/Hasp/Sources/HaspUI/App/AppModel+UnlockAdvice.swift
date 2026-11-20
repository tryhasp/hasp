import Foundation
import HaspKit

public enum UnlockAdvice: Equatable, Sendable {
  case setPasscode
  case enableBiometrics
}

extension AppModel {
  static let passcodeAdviceKey = "hasp.passcodeAdviceSeen"
  static let biometricOfferKey = "hasp.biometricOfferSeen"

  /// A password-only device can say why, and what would change it, from what the platform reports now.
  public func refreshUnlockAdvice(offering: Bool = true) {
    guard status?.unlockMode == .passwordOnly else {
      unlockAdvice = nil
      showsUnlockAdvice = false
      return
    }
    let advice: UnlockAdvice? =
      switch environment.unlockCapability() {
      case .needsPasscode: .setPasscode
      case .hardwareReady: .enableBiometrics
      case .softwareOnly: nil
      }
    unlockAdvice = advice
    guard offering, phase == .unlocked, let advice else { return }
    let key = advice == .setPasscode ? Self.passcodeAdviceKey : Self.biometricOfferKey
    guard !UserDefaults.standard.bool(forKey: key) else { return }
    UserDefaults.standard.set(true, forKey: key)
    showsUnlockAdvice = true
  }

  /// Opens a second engine on the same store, because only a session built after the passcode
  /// existed has the hardware-gated store; the password proves the user and seals the new key.
  public func enableHardwareUnlock(password: String) async {
    guard phase == .unlocked, let text = status?.origin, let origin = URL(string: text) else {
      return
    }
    await perform {
      let upgraded = try self.environment.makeSession(origin)
      try await upgraded.enableHardwareUnlock(password: password)
      self.eventLoop?.cancel()
      await self.session?.lock()
      try await upgraded.unlockPassword(password)
      self.cancelLoops()
      self.showsUnlockAdvice = false
      await self.adopt(upgraded, firstSignIn: false)
      self.toastMessage(String(localized: "m.advice.enabled"))
    }
  }
}

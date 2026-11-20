public import HaspKit

public struct DevicePlatform: Sendable {
  public let store: any SecureStore
  public let biometric: any BiometricAuthenticator
  public let isHardwareBacked: Bool
}

/// How a provider process may ask for the user. `reuseOnly` never shows a prompt: it succeeds only
/// while the system still honours a recent device authentication, which is what a no-UI fill needs.
public enum AuthenticationInteraction: Sendable, Equatable {
  case prompt
  case reuseOnly(Duration)
}

public enum DevicePlatformFactory {
  public static let accessGroupSuffix = "kr.jmo.hasp.shared"
}

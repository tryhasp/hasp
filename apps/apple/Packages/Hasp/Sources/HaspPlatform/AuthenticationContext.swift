import LocalAuthentication
import Synchronization

/// One `LAContext` shared by the biometric prompt and the keychain read that follows it, so a single touch unlocks both.
final class AuthenticationContext: Sendable {
  private let make: @Sendable () -> LAContext
  private let current: Mutex<LAContext>

  convenience init(interaction: AuthenticationInteraction) {
    self.init(make: { Self.makeContext(interaction) })
  }

  init(make: @escaping @Sendable () -> LAContext = { LAContext() }) {
    self.make = make
    current = Mutex(make())
  }

  static func makeContext(_ interaction: AuthenticationInteraction) -> LAContext {
    let context = LAContext()
    guard case .reuseOnly(let window) = interaction else { return context }
    context.interactionNotAllowed = true
    let seconds = TimeInterval(window.components.seconds)
    context.touchIDAuthenticationAllowableReuseDuration = min(
      max(0, seconds),
      LATouchIDAuthenticationMaximumAllowableReuseDuration,
    )
    return context
  }

  var context: LAContext { current.withLock { $0 } }

  func renew() -> LAContext {
    replace()
  }

  func invalidate() {
    _ = replace()
  }

  private func replace() -> LAContext {
    current.withLock { context in
      context.invalidate()
      context = make()
      return context
    }
  }
}

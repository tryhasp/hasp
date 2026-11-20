import Dispatch
public import HaspKit
import LocalAuthentication

public final class LocalAuthenticator: BiometricAuthenticator {
  private let shared: AuthenticationContext

  init(shared: AuthenticationContext) {
    self.shared = shared
  }

  public var isAvailable: Bool {
    var error: NSError?
    return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
  }

  public func invalidate() {
    shared.invalidate()
  }

  public func authenticate(reason: String) throws {
    let context = shared.renew()
    context.localizedFallbackTitle = ""
    let outcome = Outcome()
    // Why: the engine calls from a Rust thread and waits; LocalAuthentication only has a reply block.
    let finished = DispatchSemaphore(value: 0)
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) {
      granted,
      error in
      outcome.record(granted: granted, error: error)
      finished.signal()
    }
    finished.wait()
    try outcome.result()
  }
}

private final class Outcome: @unchecked Sendable {
  // Why: written once in the reply block before the semaphore is signalled, read after it.
  private var granted = false
  private var failure: (any Error)?

  func record(granted: Bool, error: (any Error)?) {
    self.granted = granted
    failure = error
  }

  func result() throws {
    if granted { return }
    guard let code = (failure as? LAError)?.code else { throw HaspError.internal }
    switch code {
    case .userCancel, .appCancel, .systemCancel, .userFallback, .notInteractive:
      throw HaspError.cancelled
    case .biometryLockout, .authenticationFailed: throw HaspError.authz
    default: throw HaspError.internal
    }
  }
}

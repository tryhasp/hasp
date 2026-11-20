public import HaspKit

/// What a provider entry point asks the engine for once the user is known to be there.
public enum ProviderRequest: Sendable {
  case password(key: ItemKey, service: String?, manual: Bool, confirmed: Bool)
  case oneTimeCode(key: ItemKey)
  case passkeyAssertion(PasskeyAssertionInput, key: ItemKey?)
  case passkeyRegistration(PasskeyRegistrationInput)
  case text(key: ItemKey, field: String)
}

public enum ProviderResult: Sendable {
  case password(user: String, password: RevealedSecret)
  case oneTimeCode(String)
  case passkeyAssertion(PasskeyAssertionOutput)
  case passkeyRegistration(PasskeyRegistrationOutput)
  case text(RevealedSecret)
}

/// Why a request ended without a credential. The view controller maps each case to one system error.
public enum ProviderFailure: Error, Equatable, Sendable {
  case interactionRequired
  case userCancelled
  case notFound
  case excludedCredential
  case openApp
  case passwordOnly
  case failed

  public init(_ error: any Error, prompting: Bool) {
    if let failure = error as? ProviderFailure {
      self = failure
      return
    }
    guard let error = error as? HaspError else {
      self = .failed
      return
    }
    switch error {
    case .cancelled: self = prompting ? .userCancelled : .interactionRequired
    case .authz: self = prompting ? .failed : .interactionRequired
    case .locked: self = prompting ? .openApp : .interactionRequired
    case .refused, .auth, .deviceRevoked, .epoch, .rollback, .pin: self = .openApp
    case .notFound: self = .notFound
    case .conflict: self = .excludedCredential
    default: self = .failed
    }
  }
}

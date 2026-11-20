public import AuthenticationServices
public import Foundation
import HaspKit

extension ProviderFailure {
  /// The error the system expects from `cancelRequest(withError:)` (domain `ASExtensionErrorDomain`).
  public var systemError: NSError {
    let code: ASExtensionError.Code =
      switch self {
      case .interactionRequired: .userInteractionRequired
      case .userCancelled: .userCanceled
      case .notFound: .credentialIdentityNotFound
      case .excludedCredential: .matchedExcludedCredential
      case .openApp, .passwordOnly, .failed: .failed
      }
    return NSError(domain: ASExtensionErrorDomain, code: code.rawValue)
  }
}

extension ProviderResult {
  public var passwordCredential: ASPasswordCredential? {
    guard case .password(let user, let password) = self else { return nil }
    return ASPasswordCredential(user: user, password: password.text())
  }

  public var oneTimeCodeCredential: ASOneTimeCodeCredential? {
    guard case .oneTimeCode(let code) = self else { return nil }
    return ASOneTimeCodeCredential(code: code)
  }

  public var assertionCredential: ASPasskeyAssertionCredential? {
    guard case .passkeyAssertion(let output) = self else { return nil }
    return ASPasskeyAssertionCredential(
      userHandle: output.userHandle,
      relyingParty: output.rpID,
      signature: output.signature,
      clientDataHash: output.clientDataHash,
      authenticatorData: output.authenticatorData,
      credentialID: output.credentialID,
    )
  }

  public func registrationCredential(clientDataHash: Data) -> ASPasskeyRegistrationCredential? {
    guard case .passkeyRegistration(let output) = self else { return nil }
    return ASPasskeyRegistrationCredential(
      relyingParty: output.rpID,
      clientDataHash: clientDataHash,
      credentialID: output.credentialID,
      attestationObject: output.attestationObject,
    )
  }

  public var insertedText: String? {
    guard case .text(let secret) = self else { return nil }
    return secret.text()
  }
}

public import AuthenticationServices
public import Foundation
public import HaspKit

/// The parameters of a passkey sign-in the system hands to `prepareCredentialList`.
public struct PasskeyAssertionParameters: Sendable, Equatable {
  public let rpID: String
  public let clientDataHash: Data
  public let allowedCredentialIDs: [Data]
  public let userVerification: PasskeyUserVerification

  public init(
    rpID: String,
    clientDataHash: Data,
    allowedCredentialIDs: [Data],
    userVerification: PasskeyUserVerification,
  ) {
    self.rpID = rpID
    self.clientDataHash = clientDataHash
    self.allowedCredentialIDs = allowedCredentialIDs
    self.userVerification = userVerification
  }

  public init(_ parameters: ASPasskeyCredentialRequestParameters) {
    self.init(
      rpID: parameters.relyingPartyIdentifier,
      clientDataHash: parameters.clientDataHash,
      allowedCredentialIDs: parameters.allowedCredentials,
      userVerification: PasskeyUserVerification(parameters.userVerificationPreference),
    )
  }

  public func input(credentialID: Data?) -> PasskeyAssertionInput {
    PasskeyAssertionInput(
      rpID: rpID,
      clientDataHash: clientDataHash,
      allowedCredentialIDs: allowedCredentialIDs,
      userVerification: userVerification,
      userVerified: false,
      credentialID: credentialID,
    )
  }
}

extension PasskeyUserVerification {
  public init(_ preference: ASAuthorizationPublicKeyCredentialUserVerificationPreference) {
    self =
      switch preference {
      case .required: .required
      case .discouraged: .discouraged
      default: .preferred
      }
  }
}

/// A request the system made for one chosen identity, read into the engine's terms.
public struct IdentityRequest: Sendable {
  public let request: ProviderRequest
  public let subject: String

  public init(request: ProviderRequest, subject: String) {
    self.request = request
    self.subject = subject
  }
}

public enum IdentityRequestReader {
  public static func read(_ credentialRequest: any ASCredentialRequest) throws -> IdentityRequest {
    switch credentialRequest.type {
    case .password: try password(credentialRequest)
    case .oneTimeCode: try oneTimeCode(credentialRequest)
    case .passkeyAssertion: try passkeyAssertion(credentialRequest)
    case .passkeyRegistration: throw ProviderFailure.failed
    @unknown default: throw ProviderFailure.failed
    }
  }

  public static func registration(_ credentialRequest: any ASCredentialRequest) throws
    -> PasskeyRegistrationInput
  {
    guard let request = credentialRequest as? ASPasskeyCredentialRequest,
      let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
    else { throw ProviderFailure.failed }
    let algorithms = request.supportedAlgorithms.map(\.rawValue)
    let excluded = (request.excludedCredentials ?? []).map(\.credentialID)
    return PasskeyRegistrationInput(
      rpID: identity.relyingPartyIdentifier,
      rpName: identity.relyingPartyIdentifier,
      clientDataHash: request.clientDataHash,
      userName: identity.userName,
      userDisplayName: identity.userName,
      userHandle: identity.userHandle,
      algorithms: algorithms,
      excludedCredentialIDs: excluded,
      userVerification: PasskeyUserVerification(request.userVerificationPreference),
      userVerified: false,
    )
  }

  private static func password(_ credentialRequest: any ASCredentialRequest) throws
    -> IdentityRequest
  {
    guard let identity = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity,
      let record = CredentialRecord(identity.recordIdentifier), record.kind == .password
    else { throw ProviderFailure.notFound }
    return IdentityRequest(
      request: .password(key: record.key, service: record.tail, manual: false, confirmed: false),
      subject: identity.serviceIdentifier.identifier,
    )
  }

  private static func oneTimeCode(_ credentialRequest: any ASCredentialRequest) throws
    -> IdentityRequest
  {
    guard let identity = credentialRequest.credentialIdentity as? ASOneTimeCodeCredentialIdentity,
      let record = CredentialRecord(identity.recordIdentifier), record.kind == .oneTimeCode
    else { throw ProviderFailure.notFound }
    return IdentityRequest(
      request: .oneTimeCode(key: record.key),
      subject: identity.serviceIdentifier.identifier,
    )
  }

  private static func passkeyAssertion(_ credentialRequest: any ASCredentialRequest) throws
    -> IdentityRequest
  {
    guard let request = credentialRequest as? ASPasskeyCredentialRequest,
      let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
    else { throw ProviderFailure.notFound }
    let key = CredentialRecord(identity.recordIdentifier).map(\.key)
    let input = PasskeyAssertionInput(
      rpID: identity.relyingPartyIdentifier,
      clientDataHash: request.clientDataHash,
      allowedCredentialIDs: [identity.credentialID],
      userVerification: PasskeyUserVerification(request.userVerificationPreference),
      userVerified: false,
      credentialID: identity.credentialID,
    )
    return IdentityRequest(
      request: .passkeyAssertion(input, key: key),
      subject: identity.relyingPartyIdentifier,
    )
  }
}

import Foundation
import LocalAuthentication
import Synchronization
import Testing

@testable import HaspPlatform

private final class RecordingContext: LAContext, @unchecked Sendable {
  // Why: tests drive one context from one thread at a time.
  nonisolated(unsafe) static var reasons: [String] = []
  nonisolated(unsafe) var invalidations = 0

  override func evaluatePolicy(
    _ policy: LAPolicy,
    localizedReason: String,
    reply: @escaping @Sendable (Bool, (any Error)?) -> Void,
  ) {
    Self.reasons.append(localizedReason)
    reply(true, nil)
  }

  override func invalidate() {
    invalidations += 1
    super.invalidate()
  }
}

@Suite(.serialized) struct AuthenticationTests {
  @Test func theReasonReachesTheSystemPromptUnmodified() throws {
    RecordingContext.reasons = []
    let authenticator = LocalAuthenticator(
      shared: AuthenticationContext(make: { RecordingContext() })
    )
    let reason = "Unlock the Chrome extension. Code 123 456"
    try authenticator.authenticate(reason: reason)
    #expect(RecordingContext.reasons == [reason])
  }

  @Test func invalidatingReplacesTheContextWithAFreshOne() {
    let shared = AuthenticationContext(make: { RecordingContext() })
    let first = shared.context
    shared.invalidate()
    #expect(shared.context !== first)
    #expect((first as? RecordingContext)?.invalidations == 1)
  }

  @Test func theEnclaveKeyNeedsUserPresenceNotACurrentBiometricSet() {
    #expect(KeychainSecureStore.accessFlags.contains(.userPresence))
    #expect(!KeychainSecureStore.accessFlags.contains(.biometryCurrentSet))
  }
}

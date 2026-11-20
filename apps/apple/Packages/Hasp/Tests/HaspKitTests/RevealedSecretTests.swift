import Foundation
import Testing

@testable import HaspKit

struct RevealedSecretTests {
  @Test func textRoundTripsAndDescriptionIsRedacted() {
    let secret = RevealedSecret(text: "hunter2")
    #expect(secret.text() == "hunter2")
    #expect(secret.data() == Data("hunter2".utf8))
    #expect("\(secret)" == "<redacted>")
  }

  @Test func errorMappingRoundTrips() {
    for error in [HaspError.locked, .auth, .offline, .deviceRevoked, .internal] {
      #expect(HaspError(error.ffi) == error)
    }
  }
}

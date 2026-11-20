import XCTest

@MainActor
final class RealKeychainSignInTests: PhoneUITestCase {
  override func setUp() async throws {
    try await super.setUp()
    app.launchEnvironment["HASP_MEMORY_STORE"] = "0"
  }

  func testSignInSucceedsWithTheRealKeychain() throws {
    let fixture = try loadFixture()
    app.launch()
    XCTAssertTrue(app.textFields["onboarding.server"].waitForExistence(timeout: 20))
    signIn(fixture)
    let ready = app.buttons["item.new"].waitForExistence(timeout: 60)
    saveShot("real-keychain-after-signin")
    XCTAssertTrue(ready, app.debugDescription)
  }
}

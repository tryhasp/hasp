import XCTest

@MainActor
final class AccessibilityTests: HaspUITestCase {
  func testAccessibilityAuditOnboardingAndVault() throws {
    let fixture = try loadFixture()
    app.launch()
    XCTAssertTrue(app.textFields["onboarding.server"].waitForExistence(timeout: 20))
    try audit()

    signIn(fixture)
    XCTAssertTrue(app.buttons["item.new"].waitForExistence(timeout: 40))
    try audit()

    app.typeKey("l", modifierFlags: .command)
    XCTAssertTrue(app.secureTextFields["unlock.password"].waitForExistence(timeout: 10))
    try audit()
  }
}

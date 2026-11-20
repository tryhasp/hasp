import XCTest

@MainActor
final class PhoneAccessibilityTests: PhoneUITestCase {
  func testAccessibilityAuditOnEveryScreen() throws {
    let fixture = try loadFixture()
    app.launch()
    XCTAssertTrue(app.textFields["onboarding.server"].waitForExistence(timeout: 20))
    try audit("onboarding")

    signIn(fixture)
    XCTAssertTrue(app.buttons["item.new"].waitForExistence(timeout: 60))
    try audit("list")

    app.tabBars.buttons.element(boundBy: 1).tap()
    try audit("watchtower")

    app.tabBars.buttons.element(boundBy: 2).tap()
    try audit("settings")
    app.buttons["settings.lockNow"].tap()
    XCTAssertTrue(app.secureTextFields["unlock.password"].waitForExistence(timeout: 10))
    try audit("locked")
  }

  func testTextScalesAtTheLargestAccessibilitySize() throws {
    app.launchArguments += [
      "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL",
    ]
    app.launch()
    let login = app.textFields["onboarding.login"]
    XCTAssertTrue(login.waitForExistence(timeout: 20))
    saveShot("onboarding-ax-ko")
  }
}

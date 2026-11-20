import XCTest

@MainActor
final class UnlockAdviceUITests: PhoneUITestCase {
  func testWithoutAPasscodeSignInWorksAndTheAdviceShowsOnce() throws {
    app.launchEnvironment["HASP_CAPABILITY"] = "needsPasscode"
    let fixture = try loadFixture()
    app.launch()
    XCTAssertTrue(app.textFields["onboarding.server"].waitForExistence(timeout: 20))
    signIn(fixture)
    XCTAssertTrue(app.buttons["advice.openSettings"].waitForExistence(timeout: 60))
    saveShot("advice-passcode-ko")
    try audit("advice-passcode")
    app.buttons["advice.later"].tap()
    XCTAssertTrue(app.buttons["item.new"].waitForExistence(timeout: 10))

    app.tabBars.buttons.element(boundBy: 2).tap()
    let advice = app.buttons["settings.unlockAdvice"]
    for _ in 0..<4 where !advice.isHittable { app.swipeUp() }
    XCTAssertTrue(advice.waitForExistence(timeout: 10))
    saveShot("settings-advice-ko")
    app.swipeDown()
    app.swipeDown()
    app.buttons["settings.lockNow"].tap()
    XCTAssertTrue(app.staticTexts["unlock.passwordOnly"].waitForExistence(timeout: 10))
    saveShot("locked-password-only-ko")
    try audit("locked-password-only")
  }

  func testALaterPasscodeOffersBiometricUnlock() throws {
    app.launchEnvironment["HASP_CAPABILITY"] = "hardwareReady"
    let fixture = try loadFixture()
    app.launch()
    XCTAssertTrue(app.textFields["onboarding.server"].waitForExistence(timeout: 20))
    signIn(fixture)
    XCTAssertTrue(app.secureTextFields["advice.password"].waitForExistence(timeout: 60))
    saveShot("advice-biometrics-ko")
    try audit("advice-biometrics")
  }
}

import XCTest

@MainActor
final class AutoFillE2ETests: PhoneUITestCase {
  private let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
  private let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")

  override func setUp() async throws {
    try await super.setUp()
    app.launchEnvironment["HASP_MEMORY_STORE"] = "0"
  }

  func testEnableProviderAndFillInSafari() throws {
    guard let page = ProcessInfo.processInfo.environment["HASP_E2E_PAGE"] else {
      throw XCTSkip("needs a signed build with the AutoFill provider entitlement and HASP_E2E_PAGE")
    }
    let fixture = try loadFixture()
    app.launch()
    signIn(fixture)
    let ready = app.buttons["item.new"].waitForExistence(timeout: 60)
    shot(app, "01-app-after-signin")
    XCTAssertTrue(ready, app.debugDescription)
    shot(app, "01-app-signed-in")

    settings.launch()
    shot(settings, "02-settings")
    try enableProvider()
    shot(settings, "05-provider-enabled")

    safari.launch()
    let bar = safari.textFields.firstMatch
    XCTAssertTrue(bar.waitForExistence(timeout: 20))
    shot(safari, "06-safari")
    bar.tap()
    bar.typeText(page + "\n")
    let user = safari.textFields["username"]
    XCTAssertTrue(user.waitForExistence(timeout: 20), safari.debugDescription)
    shot(safari, "07-login-page")
    user.tap()
    shot(safari, "08-field-focused")
    let suggestion = safari.buttons.matching(
      NSPredicate(format: "label CONTAINS[c] 'octocat'")
    ).firstMatch
    XCTAssertTrue(suggestion.waitForExistence(timeout: 15), safari.debugDescription)
    shot(safari, "09-quicktype")
    suggestion.tap()
    shot(safari, "10-after-pick")
  }

  private func enableProvider() throws {
    settings.tables.staticTexts["General"].tap()
    settings.tables.staticTexts["AutoFill & Passwords"].tap()
    shot(settings, "03-autofill")
    let hasp = settings.switches["Hasp"]
    XCTAssertTrue(hasp.waitForExistence(timeout: 10), settings.debugDescription)
    if hasp.value as? String != "1" { hasp.tap() }
    shot(settings, "04-toggled")
  }

  private func shot(_ target: XCUIApplication, _ name: String) {
    let attachment = XCTAttachment(screenshot: target.screenshot())
    attachment.name = name
    attachment.lifetime = .keepAlways
    add(attachment)
  }
}

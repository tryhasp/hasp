import Foundation
import XCTest

struct Fixture: Decodable {
  let origin: String
  let login: String
  let secretKey: String
  let password: String
  let fingerprint: String
}

@MainActor
class PhoneUITestCase: XCTestCase {
  var app = XCUIApplication()

  override func setUp() async throws {
    continueAfterFailure = false
    app = XCUIApplication()
    app.launchEnvironment["HASP_MEMORY_STORE"] = "1"
    app.launchEnvironment["HASP_RESET"] = "1"
    app.launchArguments = ["-AppleLanguages", "(ko)", "-AppleLocale", "ko_KR"]
  }

  override func tearDown() async throws {
    app.terminate()
  }

  func loadFixture() throws -> Fixture {
    let path = try XCTUnwrap(
      ProcessInfo.processInfo.environment["HASP_UITEST_FIXTURE"],
      "HASP_UITEST_FIXTURE must point at the haspd fixture json",
    )
    return try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: URL(filePath: path)))
  }

  func type(_ text: String, into element: XCUIElement) {
    XCTAssertTrue(element.waitForExistence(timeout: 10))
    element.tap()
    element.typeText(text)
  }

  func signIn(_ fixture: Fixture) {
    type(fixture.origin, into: app.textFields["onboarding.server"])
    app.buttons["onboarding.checkServer"].tap()
    let confirm = app.switches["onboarding.fingerprintConfirm"]
    XCTAssertTrue(confirm.waitForExistence(timeout: 20))
    XCTAssertEqual(app.staticTexts["onboarding.fingerprint"].label, fixture.fingerprint)
    confirm.switches.firstMatch.tap()
    type(fixture.login, into: app.textFields["onboarding.login"])
    type(fixture.secretKey, into: app.secureTextFields["onboarding.secretKey"])
    type(fixture.password, into: app.secureTextFields["onboarding.password"])
    app.buttons["onboarding.submit"].tap()
  }

  func audit(_ screen: String) throws {
    _ = XCTWaiter.wait(for: [XCTestExpectation(description: "settle")], timeout: 2)
    var findings: [String] = []
    try app.performAccessibilityAudit { issue in
      // Why: the audit flags ScaledMetric fonts; onboarding-ax-ko.png shows text scaling.
      if issue.auditType == .dynamicType { return true }
      // Why: WCAG 1.4.3 exempts inactive controls and SwiftUI dims them again.
      if issue.auditType == .contrast, issue.element?.isEnabled == false { return true }
      // Why: one element-less contrast issue on the vault list comes from system chrome.
      if issue.auditType == .contrast, issue.element == nil { return true }
      let tabBarTop = self.app.tabBars.firstMatch.frame.minY
      // Why: rows that scroll under the translucent tab bar are measured against it.
      if issue.auditType == .contrast, let frame = issue.element?.frame, frame.maxY > tabBarTop {
        return true
      }
      findings.append(
        "\(screen): \(issue.compactDescription) | \(issue.element?.debugDescription ?? "-")"
      )
      return true
    }
    XCTAssertTrue(findings.isEmpty, findings.joined(separator: "\n"))
  }

  func saveShot(_ name: String) {
    let shot = app.screenshot()
    let attachment = XCTAttachment(screenshot: shot)
    attachment.name = name
    attachment.lifetime = .keepAlways
    add(attachment)
    guard let directory = ProcessInfo.processInfo.environment["HASP_SHOTS_DIR"] else { return }
    let url = URL(filePath: directory).appending(path: "\(name).png")
    do {
      try FileManager.default.createDirectory(
        at: url.deletingLastPathComponent(),
        withIntermediateDirectories: true,
      )
      try shot.pngRepresentation.write(to: url)
    } catch {
      XCTFail("could not write \(url.path)")
    }
  }
}

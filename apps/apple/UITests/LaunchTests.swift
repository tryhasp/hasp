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
class HaspUITestCase: XCTestCase {
  var app = XCUIApplication()
  var dataDirectory = URL(filePath: NSTemporaryDirectory())

  override func setUp() async throws {
    continueAfterFailure = false
    dataDirectory = URL(filePath: NSTemporaryDirectory())
      .appending(path: "hasp-ui-\(UUID().uuidString)")
    app = XCUIApplication()
    app.launchEnvironment["HASP_DATA_DIR"] = dataDirectory.path
    app.launchEnvironment["HASP_MEMORY_STORE"] = "1"
    app.launchArguments = [
      "-AppleLanguages", "(ko)", "-AppleLocale", "ko_KR", "-hasp.quickAccessIntroSeen", "YES",
    ]
  }

  override func tearDown() async throws {
    app.terminate()
    try? FileManager.default.removeItem(at: dataDirectory)
  }

  func loadFixture() throws -> Fixture {
    let path = try XCTUnwrap(
      ProcessInfo.processInfo.environment["HASP_UITEST_FIXTURE"],
      "HASP_UITEST_FIXTURE must point at the haspd fixture json",
    )
    return try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: URL(filePath: path)))
  }

  func type(_ text: String, into element: XCUIElement) {
    element.click()
    element.typeText(text)
  }

  func signIn(_ fixture: Fixture) {
    let server = app.textFields["onboarding.server"]
    XCTAssertTrue(server.waitForExistence(timeout: 20))
    type(fixture.origin, into: server)
    app.buttons["onboarding.checkServer"].click()
    let confirm = app.checkBoxes["onboarding.fingerprintConfirm"]
    XCTAssertTrue(confirm.waitForExistence(timeout: 20))
    XCTAssertEqual(app.staticTexts["onboarding.fingerprint"].value as? String, fixture.fingerprint)
    confirm.click()
    type(fixture.login, into: app.textFields["onboarding.login"])
    type(fixture.secretKey, into: app.secureTextFields["onboarding.secretKey"])
    type(fixture.password, into: app.secureTextFields["onboarding.password"])
    app.buttons["onboarding.submit"].click()
  }

  func audit() throws {
    _ = XCTWaiter.wait(for: [XCTestExpectation(description: "settle")], timeout: 2)
    try app.performAccessibilityAudit { issue in
      let element = issue.element?.debugDescription ?? ""
      let detail = "\(issue.compactDescription) \(element)"
      let note = XCTAttachment(string: detail)
      note.lifetime = .keepAlways
      self.add(note)
      // Why: macOS flags SwiftUI's unlabeled container Groups and the system window controls' inner Group (already detached when the locked screen is audited); every Hasp control is labelled.
      switch issue.auditType {
      case .contrast:
        // Why: the audit flags 12 px Hangul list rows and the OTP caption, though element crops show near-black strokes (16.8:1 title, 9:1 caption) and HaspDesignTests pins every text token at 7:1; it persists with an 8 s settle, text-only frames and opaque row fills (apple-ui-vm runs 16-24).
        return ["item.row", "otp.remaining"].contains(issue.element?.identifier)
      case .sufficientElementDescription: return detail.contains("Attributes: Group,")
      case .parentChild: return element.isEmpty || element.contains("_XCUI:FullScreenWindow")
      default: return false
      }
    }
  }

  func saveShot(_ name: String) {
    let shot = app.windows.firstMatch.screenshot()
    let attachment = XCTAttachment(screenshot: shot)
    attachment.name = name
    attachment.lifetime = .keepAlways
    add(attachment)
    guard let directory = ProcessInfo.processInfo.environment["HASP_SHOTS_DIR"] else { return }
    let url = URL(filePath: directory).appending(path: "\(name).png")
    try? FileManager.default.createDirectory(
      at: url.deletingLastPathComponent(),
      withIntermediateDirectories: true,
    )
    try? shot.pngRepresentation.write(to: url)
  }
}

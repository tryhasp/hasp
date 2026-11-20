import XCTest

@MainActor
final class DetailShotTests: HaspUITestCase {
  func testDetailEditorAndAccessibility() throws {
    let fixture = try loadFixture()
    app.launch()
    signIn(fixture)
    XCTAssertTrue(app.buttons["item.new"].waitForExistence(timeout: 40))

    let row = item("네이버")
    XCTAssertTrue(row.waitForExistence(timeout: 30))
    row.click()
    XCTAssertTrue(app.staticTexts["otp.code"].waitForExistence(timeout: 20))
    saveShot("detail-login-ko")
    try audit()

    app.buttons["item.edit"].click()
    XCTAssertTrue(app.textFields["editor.title"].waitForExistence(timeout: 10))
    for identifier in [
      "editor.field.username", "editor.title", "editor.url", "editor.tags", "editor.notes",
    ] {
      let field = app.descendants(matching: .any).matching(identifier: identifier).firstMatch
      XCTAssertTrue(field.waitForExistence(timeout: 5), identifier)
      XCTAssertFalse(field.label.isEmpty, identifier)
    }
    XCTAssertFalse(app.secureTextFields["editor.field.password"].label.isEmpty)
    saveShot("editor-login-ko")
    app.buttons["editor.save"].click()

    for (title, name) in [("신한카드", "card"), ("집 와이파이", "wifi"), ("서버 SSH 키", "ssh")] {
      let other = item(title)
      XCTAssertTrue(other.waitForExistence(timeout: 20), title)
      other.click()
      _ = XCTWaiter.wait(for: [XCTestExpectation(description: "settle")], timeout: 1)
      saveShot("detail-\(name)-ko")
    }
  }

  private func item(_ title: String) -> XCUIElement {
    app.staticTexts.matching(NSPredicate(format: "value BEGINSWITH %@", title)).firstMatch
  }
}

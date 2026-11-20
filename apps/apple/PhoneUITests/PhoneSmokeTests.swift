import XCTest

@MainActor
final class PhoneSmokeTests: PhoneUITestCase {
  func testSignInAddItemCopyLockUnlock() throws {
    let fixture = try loadFixture()
    app.launch()
    XCTAssertTrue(app.textFields["onboarding.server"].waitForExistence(timeout: 20))
    saveShot("onboarding-ko")
    signIn(fixture)

    let newItem = app.buttons["item.new"]
    XCTAssertTrue(newItem.waitForExistence(timeout: 60))
    saveShot("list-empty-ko")

    newItem.tap()
    type("깃랩", into: app.textFields["editor.title"])
    type("mino.dev", into: app.textFields["editor.field.username"])
    type("hunter2-correct-horse", into: app.secureTextFields["editor.field.password"])
    saveShot("editor-ko")
    app.buttons["editor.save"].tap()

    let copy = app.buttons["field.copy.password"]
    XCTAssertTrue(copy.waitForExistence(timeout: 30))
    saveShot("detail-ko")
    copy.tap()
    let toast = app.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "복사했어요"))
      .firstMatch
    XCTAssertTrue(toast.waitForExistence(timeout: 5))
    saveShot("copied-ko")

    app.tabBars.buttons.element(boundBy: 2).tap()
    saveShot("settings-ko")
    app.buttons["settings.lockNow"].tap()
    let unlock = app.secureTextFields["unlock.password"]
    XCTAssertTrue(unlock.waitForExistence(timeout: 10))
    saveShot("locked-ko")
    type(fixture.password, into: unlock)
    app.buttons["unlock.submit"].tap()
    XCTAssertTrue(app.buttons["item.new"].waitForExistence(timeout: 60))
  }
}

import XCTest

@MainActor
final class SmokeTests: HaspUITestCase {
  func testSignInAddItemCopyLockUnlock() throws {
    let fixture = try loadFixture()
    app.launch()
    saveShot("onboarding-ko")
    signIn(fixture)

    let newItem = app.buttons["item.new"]
    XCTAssertTrue(newItem.waitForExistence(timeout: 40))
    saveShot("main-list-ko")

    newItem.click()
    let title = app.textFields["editor.title"]
    XCTAssertTrue(title.waitForExistence(timeout: 10))
    type("깃랩", into: title)
    type("mino.dev", into: app.textFields["editor.field.username"])
    type("hunter2-correct-horse", into: app.secureTextFields["editor.field.password"])
    app.buttons["editor.save"].click()

    let copy = app.buttons["field.copy.password"]
    XCTAssertTrue(copy.waitForExistence(timeout: 20))
    saveShot("main-item-ko")
    copy.click()
    XCTAssertTrue(
      app.staticTexts.containing(
        NSPredicate(format: "label CONTAINS %@ OR value CONTAINS %@", "복사했어요", "복사했어요")
      ).firstMatch
        .waitForExistence(timeout: 5)
    )
    saveShot("main-copied-ko")

    app.typeKey("l", modifierFlags: .command)
    let unlock = app.secureTextFields["unlock.password"]
    XCTAssertTrue(unlock.waitForExistence(timeout: 10))
    saveShot("locked-ko")
    type(fixture.password, into: unlock)
    app.buttons["unlock.submit"].click()
    XCTAssertTrue(app.buttons["item.new"].waitForExistence(timeout: 40))
  }
}

import HaspQuickAccessCore
import Testing

@testable import HaspQuickAccess

struct StringsTests {
  @Test func catalogKeysResolveToText() {
    let samples =
      [
        Strings.searchPlaceholder, Strings.lockedTitle, Strings.confirmTitle,
        Strings.accessibilityBody, Strings.copied(clearAfterSeconds: 30),
        Strings.resultCount(2), Strings.secondsRemaining(18),
        Strings.confirmBody(.nativeApp(appName: "Notes", savedHosts: ["a.com"])),
      ] + QuickAction.allCases.map(Strings.label)
    #expect(samples.allSatisfy { !$0.hasPrefix("qa.") && !$0.isEmpty })
    #expect(Strings.copied(clearAfterSeconds: 30).contains("30"))
  }
}

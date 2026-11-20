import Foundation
import Testing

@testable import HaspQuickAccessCore

func makeItem(
  _ title: String,
  username: String = "mino@example.com",
  hosts: [String] = [],
  favourite: Bool = false,
  daysOld: Double = 400,
  kind: QuickItemKind = .login,
) -> QuickItem {
  QuickItem(
    id: QuickItemID(vault: "v", item: title),
    kind: kind,
    title: title,
    username: username,
    hosts: hosts,
    vaultName: "Private",
    isShared: false,
    favourite: favourite,
    hasOTP: false,
    modified: Date(timeIntervalSince1970: 2_000_000_000 - daysOld * 86_400),
  )
}

let now = Date(timeIntervalSince1970: 2_000_000_000)

func titles(_ items: [QuickItem]) -> [String] { items.map(\.title) }

struct SearchRankingTests {
  let context = SearchContext(frontmostHost: nil, now: now)

  @Test func emptyQueryKeepsFavouritesThenRecentFirst() {
    let items = [
      makeItem("Old", daysOld: 300), makeItem("Fav", favourite: true), makeItem("New", daysOld: 1),
    ]
    #expect(
      titles(SearchRanking.rank(items, query: "", context: context)) == ["Fav", "New", "Old"]
    )
  }

  @Test func exactBeatsPrefixBeatsContainsBeatsFuzzy() {
    let items = [
      makeItem("my github", username: ""), makeItem("gh", username: ""),
      makeItem("github", username: ""), makeItem("g-i-t-h-u-b", username: ""),
    ]
    let ranked = titles(SearchRanking.rank(items, query: "github", context: context))
    #expect(ranked == ["github", "my github", "g-i-t-h-u-b"])
  }

  @Test func matchesHostAndUsername() {
    let items = [
      makeItem("Work", username: "a", hosts: ["accounts.coupang.com"]),
      makeItem("Mail", username: "coupang-fan"),
      makeItem("Bank", username: "b"),
    ]
    #expect(
      Set(titles(SearchRanking.rank(items, query: "coupang", context: context))) == [
        "Work", "Mail",
      ]
    )
  }

  @Test func frontmostBrowserHostBoostsItsItems() {
    let items = [
      makeItem("Alpha", hosts: ["example.org"], favourite: true),
      makeItem("Beta", hosts: ["www.coupang.com"]),
    ]
    let boosted = SearchContext(frontmostHost: "coupang.com", now: now)
    #expect(titles(SearchRanking.rank(items, query: "", context: boosted)).first == "Beta")
  }

  @Test func hostBoostDoesNotMatchLookalikeSuffixes() {
    #expect(SearchRanking.hostMatches("coupang.com", "login.coupang.com"))
    #expect(!SearchRanking.hostMatches("coupang.com", "evilcoupang.com"))
  }

  @Test func koreanMatchesAcrossNormalisationForms() {
    let items = [makeItem("쿠팡"), makeItem("네이버")]
    let nfd = "쿠팡".decomposedStringWithCanonicalMapping
    #expect(titles(SearchRanking.rank(items, query: nfd, context: context)) == ["쿠팡"])
    #expect(titles(SearchRanking.rank(items, query: "네이", context: context)) == ["네이버"])
  }

  @Test func koreanInitialsMatch() {
    let items = [makeItem("쿠팡"), makeItem("네이버")]
    #expect(titles(SearchRanking.rank(items, query: "ㅋㅍ", context: context)) == ["쿠팡"])
    #expect(titles(SearchRanking.rank(items, query: "ㄴㅇㅂ", context: context)) == ["네이버"])
  }

  @Test func caseAndWidthAreIgnored() {
    let items = [makeItem("GitHub")]
    #expect(titles(SearchRanking.rank(items, query: "gITHUB", context: context)) == ["GitHub"])
    #expect(titles(SearchRanking.rank(items, query: "ｇｉｔ", context: context)) == ["GitHub"])
  }

  @Test func nonMatchesAreDropped() {
    #expect(SearchRanking.rank([makeItem("Bank")], query: "zzz", context: context).isEmpty)
  }

  @Test func tiesFallBackToTitleOrder() {
    let items = [makeItem("b"), makeItem("a")]
    #expect(titles(SearchRanking.rank(items, query: "", context: context)) == ["a", "b"])
  }
}

struct ActionRoutingTests {
  @Test func routesTheDocumentedChords() {
    #expect(QuickAction.route(KeyChord(.returnKey)) == .fill)
    #expect(QuickAction.route(KeyChord(.escape)) == .close)
    #expect(QuickAction.route(KeyChord(.character("c"), command: true)) == .copyPassword)
    #expect(QuickAction.route(KeyChord(.character("c"), command: true, shift: true)) == .copyOTP)
    #expect(QuickAction.route(KeyChord(.character("C"), command: true, shift: true)) == .copyOTP)
    #expect(
      QuickAction.route(KeyChord(.character("c"), command: true, option: true)) == .copyUsername
    )
    #expect(QuickAction.route(KeyChord(.character("/"), command: true)) == .showAllActions)
    #expect(QuickAction.route(KeyChord(.character("o"), command: true)) == .openInMainWindow)
  }

  @Test func ignoresPlainTypingAndUnknownChords() {
    #expect(QuickAction.route(KeyChord(.character("c"))) == nil)
    #expect(QuickAction.route(KeyChord(.character("x"), command: true)) == nil)
    #expect(QuickAction.route(KeyChord(.returnKey, command: true)) == nil)
    #expect(QuickAction.route(KeyChord(.character("c"), command: true, control: true)) == nil)
  }

  @Test func everyActionHasALabel() {
    #expect(QuickAction.allCases.allSatisfy { !$0.shortcutLabel.isEmpty })
  }
}

struct FillRoutingTests {
  let safari = TargetApp(bundleID: "com.apple.Safari", name: "Safari", processID: 1)
  let notes = TargetApp(bundleID: "com.apple.Notes", name: "Notes", processID: 2)

  func context(_ target: TargetApp?, paired: Bool, trusted: Bool, kind: QuickItemKind = .login)
    -> FillContext
  {
    FillContext(
      target: target,
      hasPairedExtension: paired,
      accessibilityTrusted: trusted,
      kind: kind,
    )
  }

  @Test func pairedBrowserGoesThroughTheExtension() {
    let route = FillRouter.route(context(safari, paired: true, trusted: true))
    #expect(route == .browserExtension(bundleID: "com.apple.Safari"))
  }

  @Test func unpairedBrowserTypesWhenTrusted() {
    #expect(FillRouter.route(context(safari, paired: false, trusted: true)) == .type(into: safari))
  }

  @Test func nativeAppTypesWhenTrustedAndAsksForAccessibilityOtherwise() {
    #expect(FillRouter.route(context(notes, paired: true, trusted: true)) == .type(into: notes))
    #expect(FillRouter.route(context(notes, paired: false, trusted: false)) == .needsAccessibility)
  }

  @Test func extensionRouteNeedsNoAccessibility() {
    let route = FillRouter.route(context(safari, paired: true, trusted: false))
    #expect(route == .browserExtension(bundleID: "com.apple.Safari"))
  }

  @Test func noTargetOrNonLoginCopiesOnly() {
    #expect(FillRouter.route(context(nil, paired: false, trusted: true)) == .copyOnly(.noTarget))
    #expect(
      FillRouter.route(context(notes, paired: false, trusted: true, kind: .card))
        == .copyOnly(.unsupportedKind)
    )
  }
}

struct StepUpTests {
  let item = makeItem("Coupang", hosts: ["www.coupang.com"])
  let notes = TargetApp(bundleID: "com.apple.Notes", name: "Notes", processID: 2)
  let chrome = TargetApp(bundleID: "com.google.Chrome", name: "Chrome", processID: 3)

  @Test func nativeAppAsksOncePerItemAndApp() {
    var approvals = TypingApprovals()
    #expect(
      approvals.decision(for: item, into: notes)
        == .confirm(.nativeApp(appName: "Notes", savedHosts: ["www.coupang.com"]))
    )
    approvals.approve(item.id, in: notes)
    #expect(approvals.decision(for: item, into: notes) == .proceed)
    #expect(approvals.decision(for: makeItem("Other"), into: notes) != .proceed)
    approvals.reset()
    #expect(approvals.decision(for: item, into: notes) != .proceed)
  }

  @Test func browserPagesAreNeverRemembered() {
    var approvals = TypingApprovals()
    approvals.approve(item.id, in: chrome)
    #expect(
      approvals.decision(for: item, into: chrome)
        == .confirm(.unverifiedBrowserPage(appName: "Chrome", savedHosts: ["www.coupang.com"]))
    )
  }
}

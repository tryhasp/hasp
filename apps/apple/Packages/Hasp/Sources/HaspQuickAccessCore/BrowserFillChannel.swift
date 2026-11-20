public enum BrowserFillOutcome: Equatable, Sendable {
  case filled
  case needsConfirmationInBrowser
  case noMatchingPage
  case extensionLocked
  case unavailable
}

public protocol BrowserFillChannel: Sendable {
  func hasPairedExtension(browserBundleID: String) async -> Bool
  func pageHost(browserBundleID: String) async -> String?
  func requestFill(browserBundleID: String, item: QuickItemID) async -> BrowserFillOutcome
}

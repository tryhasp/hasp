import Foundation
import HaspQuickAccessCore

enum Strings {
  static func text(_ key: String.LocalizationValue) -> String {
    String(localized: key, bundle: .module)
  }

  static var searchPlaceholder: String { text("qa.search.placeholder") }
  static var emptyResults: String { text("qa.results.empty") }
  static var username: String { text("qa.field.username") }
  static var password: String { text("qa.field.password") }
  static var oneTimeCode: String { text("qa.field.otp") }
  static var website: String { text("qa.field.website") }
  static var lockedTitle: String { text("qa.locked.title") }
  static var lockedBody: String { text("qa.locked.body") }
  static var lockedAction: String { text("qa.locked.action") }
  static var confirmTitle: String { text("qa.confirm.title") }
  static var confirmAction: String { text("qa.confirm.action") }
  static var cancelAction: String { text("qa.confirm.cancel") }
  static var accessibilityTitle: String { text("qa.accessibility.title") }
  static var accessibilityBody: String { text("qa.accessibility.body") }
  static var accessibilityOpen: String { text("qa.accessibility.open") }
  static var accessibilityCopy: String { text("qa.accessibility.copy") }
  static var actionsTitle: String { text("qa.actions.title") }
  static var toastNoOTP: String { text("qa.toast.noOTP") }
  static var toastLoginOnly: String { text("qa.toast.loginOnly") }
  static var toastExtensionLocked: String { text("qa.toast.extensionLocked") }
  static var toastNoMatchingPage: String { text("qa.toast.noMatchingPage") }
  static var toastConfirmInBrowser: String { text("qa.toast.confirmInBrowser") }
  static var toastBrowserUnavailable: String { text("qa.toast.browserUnavailable") }
  static var toastCopiedInstead: String { text("qa.toast.copiedInstead") }
  static var toastFailed: String { text("qa.toast.failed") }

  static func resultCount(_ count: Int) -> String { text("qa.results.count \(count)") }
  static func secondsRemaining(_ seconds: Int) -> String { text("qa.otp.remaining \(seconds)") }
  static func copied(clearAfterSeconds seconds: Int) -> String {
    text("qa.toast.copied \(seconds)")
  }

  static var copiedWithoutTimer: String { text("qa.toast.copiedNoTimer") }

  static func kindLine(_ item: QuickItem) -> String {
    let kind =
      switch item.kind {
      case .login: text("qa.kind.login")
      case .card: text("qa.kind.card")
      case .identity: text("qa.kind.identity")
      case .other: text("qa.kind.other")
      }
    return "\(kind) · \(item.vaultName)"
  }

  static func confirmBody(_ reason: ConfirmReason) -> String {
    switch reason {
    case .nativeApp(let app, let hosts):
      text("qa.confirm.native \(app) \(hosts.first ?? "-")")
    case .unverifiedBrowserPage(let app, let hosts):
      text("qa.confirm.browser \(app) \(hosts.first ?? "-")")
    }
  }

  static func label(_ action: QuickAction) -> String {
    switch action {
    case .fill: text("qa.hint.fill")
    case .copyPassword: text("qa.hint.copyPassword")
    case .copyOTP: text("qa.hint.copyOTP")
    case .copyUsername: text("qa.hint.copyUsername")
    case .openInMainWindow: text("qa.hint.open")
    case .showAllActions: text("qa.hint.allActions")
    case .close: text("qa.hint.close")
    }
  }
}

import Foundation
import HaspQuickAccessCore
public import HaspKit

extension AppModel {
  public func copy(_ secret: RevealedSecret) async {
    let delay = settings.lock.clipboardClear
    await environment.clipboard.copy(secret.data(), clearAfter: delay)
    toastMessage(Self.copiedMessage(clearAfter: delay))
  }

  public func copyPlain(_ text: String) async {
    await copy(RevealedSecret(text: text))
  }

  func toastMessage(_ text: String) {
    toast = text
    toastTask?.cancel()
    toastTask = Task { [weak self] in
      try? await Task.sleep(for: .seconds(3))
      if !Task.isCancelled { self?.toast = nil }
    }
  }

  static func copiedMessage(clearAfter delay: Duration) -> String {
    let seconds = Int(delay.components.seconds)
    if seconds <= 0 { return String(localized: "toast.copied.keep") }
    return String(localized: "toast.copied \(seconds)")
  }
}

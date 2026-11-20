import Foundation
import HaspKit
import HaspPlatform
import SafariServices

private actor SafariRuntime {
  static let shared = SafariRuntime()

  private var bridge: SafariBridge?

  private static var isIOS: Bool {
    #if os(iOS)
      true
    #else
      false
    #endif
  }

  func handle(_ frame: Data) async -> Data {
    if bridge == nil { bridge = Self.makeBridge() }
    guard let bridge else { return SafariBridge.unavailable(for: frame) }
    return await bridge.handle(frame)
  }

  private static func makeBridge() -> SafariBridge? {
    guard let directory = SharedState.directory(),
      let origin = OriginFile(directory: directory).read()
    else { return nil }
    let platform = DevicePlatformFactory.make(memoryOnly: false)
    guard platform.isHardwareBacked,
      let session = try? AccountSession(
        directory: directory.appending(path: "account"),
        origin: origin,
        store: platform.store,
        biometric: platform.biometric,
      )
    else { return nil }
    return SafariBridge(session: session, requiresPresenceToUnlock: Self.isIOS)
  }
}

final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
  func beginRequest(with context: NSExtensionContext) {
    let item = context.inputItems.first as? NSExtensionItem
    guard let message = item?.userInfo?[SFExtensionMessageKey],
      JSONSerialization.isValidJSONObject(message),
      let frame = try? JSONSerialization.data(withJSONObject: message)
    else {
      context.cancelRequest(withError: CocoaError(.coderInvalidValue))
      return
    }
    let completion = Completion(context: context)
    Task { completion.finish(with: await SafariRuntime.shared.handle(frame)) }
  }
}

private final class Completion: @unchecked Sendable {
  // Why: NSExtensionContext is not Sendable; it is completed exactly once, from one task.
  private let context: NSExtensionContext

  init(context: NSExtensionContext) {
    self.context = context
  }

  func finish(with reply: Data) {
    let object = (try? JSONSerialization.jsonObject(with: reply)) ?? [String: String]()
    let response = NSExtensionItem()
    response.userInfo = [SFExtensionMessageKey: object]
    context.completeRequest(returningItems: [response])
  }
}

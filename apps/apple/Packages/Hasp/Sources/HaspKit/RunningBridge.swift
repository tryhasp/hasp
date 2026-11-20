public import Foundation
import HaspFFI
public import HaspQuickAccessCore

public struct BridgeSettings: Sendable {
  public var directory: URL
  public var helper: URL
  public var teamID: String
  public var chromiumIDs: [String]
  public var geckoIDs: [String]
  public var anyTeamCertificate: Bool

  public init(
    directory: URL,
    helper: URL,
    teamID: String,
    chromiumIDs: [String],
    geckoIDs: [String],
    anyTeamCertificate: Bool,
  ) {
    self.directory = directory
    self.helper = helper
    self.teamID = teamID
    self.chromiumIDs = chromiumIDs
    self.geckoIDs = geckoIDs
    self.anyTeamCertificate = anyTeamCertificate
  }
}

public enum BridgeEvent: Equatable, Sendable {
  case peerRefused(String)
  case connected(browser: String, origin: String)
  case paired(browser: String, origin: String)
  case disconnected(browser: String, origin: String)
}

/// The app side of native messaging. The socket, the peer checks, pairing and key release all run in Rust;
/// this only starts it and adapts its fill channel to Quick Access.
public final class RunningBridge: BrowserFillChannel, Sendable {
  private static let browsers = [
    "com.google.Chrome": "chrome",
    "com.microsoft.edgemac": "edge",
    "com.brave.Browser": "brave",
    "org.mozilla.firefox": "firefox",
  ]

  private let bridge: ExtensionBridge

  init(bridge: ExtensionBridge) {
    self.bridge = bridge
  }

  public func start() throws {
    try mapped { try bridge.start() }
  }

  public func stop() {
    bridge.stop()
  }

  public func pushLock() {
    bridge.pushLock()
  }

  public func hasPairedExtension(browserBundleID: String) async -> Bool {
    guard let name = Self.browsers[browserBundleID] else { return false }
    return bridge.hasPairedExtension(browser: name)
  }

  @concurrent
  public func pageHost(browserBundleID: String) async -> String? {
    guard let name = Self.browsers[browserBundleID] else { return nil }
    return (try? bridge.pageHost(browser: name)) ?? nil
  }

  @concurrent
  public func requestFill(browserBundleID: String, item: QuickItemID) async
    -> HaspQuickAccessCore.BrowserFillOutcome
  {
    guard let name = Self.browsers[browserBundleID] else { return .unavailable }
    do {
      switch try bridge.requestFill(browser: name, vault: item.vault, item: item.item) {
      case .filled: return .filled
      case .needsConfirmation: return .needsConfirmationInBrowser
      case .noMatchingPage: return .noMatchingPage
      case .locked: return .extensionLocked
      case .unavailable: return .unavailable
      }
    } catch {
      return .unavailable
    }
  }
}

extension AccountSession {
  public nonisolated func makeBridge(
    _ settings: BridgeSettings,
    onEvent: @escaping @Sendable (BridgeEvent) -> Void,
  ) throws -> RunningBridge {
    let config = BridgeConfig(
      directory: settings.directory.path,
      helperPath: settings.helper.path,
      teamId: settings.teamID,
      chromiumIds: settings.chromiumIDs,
      geckoIds: settings.geckoIDs,
      anyTeamCertificate: settings.anyTeamCertificate,
    )
    return RunningBridge(
      bridge: try mapped {
        try ExtensionBridge(client: client, config: config, delegate: DelegateAdapter(onEvent))
      }
    )
  }
}

private final class DelegateAdapter: BridgeDelegate {
  private let onEvent: @Sendable (BridgeEvent) -> Void

  init(_ onEvent: @escaping @Sendable (BridgeEvent) -> Void) {
    self.onEvent = onEvent
  }

  func peerRefused(check: PeerCheck) {
    onEvent(.peerRefused(String(describing: check)))
  }

  func connected(browser: String, origin: String) {
    onEvent(.connected(browser: browser, origin: origin))
  }

  func paired(browser: String, origin: String, device: String) {
    onEvent(.paired(browser: browser, origin: origin))
  }

  func disconnected(browser: String, origin: String) {
    onEvent(.disconnected(browser: browser, origin: origin))
  }
}

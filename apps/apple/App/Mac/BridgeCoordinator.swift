import Foundation
import HaspKit
import HaspPlatform
import HaspQuickAccessCore
import HaspUI
import OSLog

private let log = Logger(subsystem: "kr.jmo.hasp", category: "bridge")

/// Starts the native-messaging bridge for each engine session and installs the browser manifests.
@MainActor
final class BridgeCoordinator {
  private weak var model: AppModel?
  private var bridge: RunningBridge?
  private var quickAccess: QuickAccessHost?

  func bind(_ quickAccess: QuickAccessHost) {
    self.quickAccess = quickAccess
  }

  func bind(_ model: AppModel) {
    self.model = model
    model.setLockObserver { [weak self] in await self?.pushLock() }
  }

  nonisolated func attach(_ session: AccountSession) {
    Task { await start(session) }
  }

  func stop() {
    bridge?.stop()
  }

  private func start(_ session: AccountSession) {
    bridge?.stop()
    bridge = nil
    quickAccess?.fillChannel.use(nil)
    let home = URL.homeDirectory
    guard let (settings, allowlist) = BridgeSetup.settings(bundle: .main, home: home) else {
      log.info("unsigned build: extension bridge disabled")
      return
    }
    let installed = NativeMessagingManifests.installAll(
      home: home,
      helper: settings.helper,
      allowlist: allowlist,
    )
    log.info("manifests checked: \(installed.count, privacy: .public)")
    for install in installed {
      if case .hostChanged(let previous) = install.outcome {
        log.error(
          "native host changed for \(install.browser.rawValue, privacy: .public): \(previous, privacy: .private)"
        )
      }
    }
    do {
      let next = try session.makeBridge(settings) { event in
        log.info("bridge event: \(String(describing: event), privacy: .private)")
      }
      try next.start()
      bridge = next
      quickAccess?.fillChannel.use(next)
    } catch {
      log.error("extension bridge did not start")
    }
  }

  private func pushLock() async {
    await quickAccess?.lock()
    bridge?.pushLock()
  }
}

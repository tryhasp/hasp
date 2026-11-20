import Foundation
import HaspKit
import HaspPlatform
import HaspProvider
import HaspQuickAccessCore
import HaspUI
import OSLog

private let log = Logger(subsystem: "kr.jmo.hasp", category: "bootstrap")

struct AppBootstrap {
  let model: AppModel
  let bridge: BridgeCoordinator
  let quickAccess: QuickAccessHost
  let options: LaunchOptions

  @MainActor
  static func make() -> AppBootstrap {
    let options = LaunchOptions.read(ProcessInfo.processInfo.environment)
    let directory = dataDirectory(options.dataDirectory)
    let platformSource = DevicePlatformSource(memoryOnly: options.memoryStore)
    let coordinator = BridgeCoordinator()
    let clipboard = ClipboardClearer(pasteboard: GeneralPasteboard(), clock: ContinuousClock())
    let quickAccess = QuickAccessHost(clipboard: clipboard)
    let engine = quickAccess.engine
    coordinator.bind(quickAccess)
    let environment = AppEnvironment(
      storedOrigin: { OriginFile(directory: directory).read() },
      rememberOrigin: { origin in
        do {
          try OriginFile(directory: directory).write(origin)
        } catch {
          log.error("could not remember the server address")
        }
      },
      makeSession: { origin in
        let platform = platformSource.make()
        let session = try AccountSession(
          directory: directory.appending(path: "account"),
          origin: origin,
          store: platform.store,
          biometric: platform.biometric,
        )
        coordinator.attach(session)
        let quick = session.quickAccessEngine()
        Task { await engine.use(quick) }
        return session
      },
      clipboard: clipboard,
      breachSource: BreachRangeFetcher(),
      systemIdle: { SystemIdle.sinceLastInput() },
      systemLockTriggers: { SystemLockEvents.triggers() },
      isHardwareBacked: platformSource.isHardwareBacked,
      unlockCapability: { platformSource.capability },
      storeFailure: { platformSource.lastFailure },
      afterSync: { session in
        await IdentityRefresh.run(after: session, into: SystemIdentityStore())
      },
      afterSettingsChange: { session in
        await IdentityRefresh.run(after: session, into: SystemIdentityStore())
      },
      accountDidEnd: { await IdentityRefresh.clear(SystemIdentityStore()) },
    )
    let model = AppModel(environment: environment)
    coordinator.bind(model)
    return AppBootstrap(
      model: model,
      bridge: coordinator,
      quickAccess: quickAccess,
      options: options,
    )
  }

  private static func dataDirectory(_ override: String?) -> URL {
    if let override, !override.isEmpty {
      return URL(filePath: override, directoryHint: .isDirectory)
    }
    if let shared = SharedState.directory() { return shared }
    return URL.applicationSupportDirectory.appending(path: "Hasp", directoryHint: .isDirectory)
  }
}

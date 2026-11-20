import Foundation
import HaspKit
import HaspPlatform
import HaspProvider
import HaspQuickAccessCore
import HaspUI
import OSLog
import Security

private let log = Logger(subsystem: "kr.jmo.hasp", category: "bootstrap")

enum PhoneBootstrap {
  @MainActor
  static func make() -> AppModel {
    let options = PhoneLaunchOptions.read(ProcessInfo.processInfo.environment)
    let directory = dataDirectory(options.dataDirectory)
    if options.reset {
      // Why: a missing directory on the first run is the expected state.
      try? FileManager.default.removeItem(at: directory)
      UserDefaults.standard.removePersistentDomain(forName: Bundle.main.bundleIdentifier ?? "")
      if !options.memoryStore { clearKeychainItems() }
    }
    let platformSource = DevicePlatformSource(memoryOnly: options.memoryStore)
    let clipboard = ClipboardClearer(pasteboard: GeneralPasteboard(), clock: ContinuousClock())
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
        return try AccountSession(
          directory: directory.appending(path: "account"),
          origin: origin,
          platformName: "ios",
          store: platform.store,
          biometric: platform.biometric,
        )
      },
      clipboard: clipboard,
      breachSource: BreachRangeFetcher(),
      systemIdle: { SystemIdle.sinceLastInput() },
      systemLockTriggers: { SystemLockEvents.triggers() },
      isHardwareBacked: platformSource.isHardwareBacked,
      unlockCapability: { options.capability ?? platformSource.capability },
      storeFailure: { platformSource.lastFailure },
      afterSync: { session in
        await IdentityRefresh.run(after: session, into: SystemIdentityStore())
      },
      afterSettingsChange: { session in
        await IdentityRefresh.run(after: session, into: SystemIdentityStore())
      },
      accountDidEnd: { await IdentityRefresh.clear(SystemIdentityStore()) },
    )
    return AppModel(environment: environment)
  }

  /// Why: a reset removes the account directory, so keychain items of the earlier run must go with it.
  private static func clearKeychainItems() {
    for service in ["kr.jmo.hasp.store", "kr.jmo.hasp.store.software"] {
      let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service]
      _ = SecItemDelete(query as CFDictionary)
    }
  }

  private static func dataDirectory(_ override: String?) -> URL {
    if let override, !override.isEmpty {
      return URL(filePath: override, directoryHint: .isDirectory)
    }
    if let shared = SharedState.directory() { return shared }
    return URL.applicationSupportDirectory.appending(path: "Hasp", directoryHint: .isDirectory)
  }
}

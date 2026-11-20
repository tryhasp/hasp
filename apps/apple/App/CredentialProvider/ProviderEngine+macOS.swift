#if os(macOS)
  import Foundation
  import HaspKit
  import HaspPlatform

  enum ProviderEngine {
    static func make(interaction: AuthenticationInteraction) throws -> AccountSession {
      guard let directory = SharedState.directory(),
        let origin = OriginFile(directory: directory).read()
      else { throw HaspError.notFound }
      let platform = DevicePlatformFactory.make(memoryOnly: false, interaction: interaction)
      return try AccountSession(
        directory: directory.appending(path: "account"),
        origin: origin,
        platformName: "macos",
        store: platform.store,
        biometric: platform.biometric,
      )
    }
  }
#endif

#if os(iOS)
  public import Foundation

  /// The app and its extensions share one directory in the app group container.
  ///
  /// Layout under `group.kr.jmo.hasp`:
  /// - `Hasp/server-url`: the origin file, read by every process before it opens the account
  /// - `Hasp/account/`: the engine's database and sealed local blobs, opened per call by extensions
  ///
  /// Keys never live in the container. The device unlock key sits in the keychain access group
  /// `<TeamID>.kr.jmo.hasp.shared`, named by `HaspKeychainAccessGroup` in Info.plist.
  public enum SharedState {
    public static let groupIdentifier = "group.kr.jmo.hasp"

    /// Nil when the build has no app group entitlement, for example a simulator build without signing.
    public static func directory() -> URL? {
      FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupIdentifier)?
        .appending(path: "Hasp", directoryHint: .isDirectory)
    }
  }
#endif

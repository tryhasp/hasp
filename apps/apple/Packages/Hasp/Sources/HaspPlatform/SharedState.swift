#if os(macOS)
  public import Foundation
  import Security

  /// The app and its Safari extension keep one account directory in the app group container, so both open the same state.
  public enum SharedState {
    public static func groupIdentifier() -> String? {
      signingTeam().map { "\($0).kr.jmo.hasp" }
    }

    /// Nil for an unsigned build: without a team there is no group and nothing to verify a peer against.
    public static func signingTeam() -> String? {
      var code: SecCode?
      guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
      var staticCode: SecStaticCode?
      guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
        return nil
      }
      var information: CFDictionary?
      let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
      guard SecCodeCopySigningInformation(staticCode, flags, &information) == errSecSuccess else {
        return nil
      }
      return (information as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String
    }

    public static func directory() -> URL? {
      guard let group = groupIdentifier(),
        let container = FileManager.default.containerURL(
          forSecurityApplicationGroupIdentifier: group
        )
      else { return nil }
      return container.appending(path: "Hasp", directoryHint: .isDirectory)
    }
  }
#endif

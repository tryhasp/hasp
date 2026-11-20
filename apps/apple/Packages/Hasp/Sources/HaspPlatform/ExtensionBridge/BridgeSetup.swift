#if os(macOS)
  public import Foundation
  public import HaspKit

  public enum BridgeSetup {
    /// Nil for an unsigned build: the Rust peer check has nothing to compare the helper against.
    public static func settings(bundle: Bundle, home: URL) -> (BridgeSettings, ExtensionAllowlist)?
    {
      guard let team = SharedState.signingTeam() else { return nil }
      let allowlist = ExtensionAllowlist.fromBundle(bundle)
      #if DEBUG
        let development = true
      #else
        let development = false
      #endif
      let settings = BridgeSettings(
        directory: home.appending(path: "Library/Group Containers/\(team).kr.jmo.hasp"),
        helper: bundle.bundleURL.appending(path: "Contents/Helpers/hasp-nmh"),
        teamID: team,
        chromiumIDs: allowlist.chromium.sorted(),
        geckoIDs: allowlist.gecko.sorted(),
        anyTeamCertificate: development,
      )
      return (settings, allowlist)
    }
  }
#endif

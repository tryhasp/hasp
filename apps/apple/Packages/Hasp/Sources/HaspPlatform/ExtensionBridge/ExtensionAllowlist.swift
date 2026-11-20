public import Foundation

public struct ExtensionAllowlist: Equatable, Sendable {
  public var chromium: Set<String>
  public var gecko: Set<String>

  public init(chromium: Set<String>, gecko: Set<String>) {
    self.chromium = chromium
    self.gecko = gecko
  }

  /// Published store ids plus the development ids a build lists in its Info.plist.
  public static func fromBundle(_ bundle: Bundle) -> ExtensionAllowlist {
    func ids(_ listKey: String, development devKey: String) -> Set<String> {
      let published = bundle.object(forInfoDictionaryKey: listKey) as? [String] ?? []
      let development = bundle.object(forInfoDictionaryKey: devKey) as? String ?? ""
      return Set(published + (development.isEmpty ? [] : [development]))
    }
    return ExtensionAllowlist(
      chromium: ids("HaspChromiumExtensionIDs", development: "HaspDevChromiumExtensionID"),
      gecko: ids("HaspFirefoxExtensionIDs", development: "HaspDevFirefoxExtensionID"),
    )
  }

  func permits(browser: NativeBrowser, origin: String) -> Bool {
    browser.isChromium ? chromium.contains(origin) : gecko.contains(origin)
  }
}

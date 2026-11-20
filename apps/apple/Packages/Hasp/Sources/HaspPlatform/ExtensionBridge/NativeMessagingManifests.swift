public import Foundation

public struct ManifestInstall: Equatable, Sendable {
  public enum Outcome: Equatable, Sendable {
    case written
    case hostChanged(previousPath: String)
    case refusedSymlink
    case helperOutsideBundle
    case browserNotInstalled
    case noExtensionIDs
    case failed
  }

  public let browser: NativeBrowser
  public let outcome: Outcome
}

public enum NativeMessagingManifests {
  public static let hostName = "kr.jmo.hasp.nmh"
  public static let hostDescription = "Hasp desktop bridge"

  /// Writes the host manifest for every installed browser. One browser failing never stops the others.
  public static func installAll(
    home: URL,
    helper: URL,
    allowlist: ExtensionAllowlist,
  ) -> [ManifestInstall] {
    NativeBrowser.allCases.map {
      ManifestInstall(
        browser: $0,
        outcome: install($0, home: home, helper: helper, allowlist: allowlist),
      )
    }
  }

  public static func manifestURL(for browser: NativeBrowser, home: URL) -> URL {
    supportDirectory(for: browser, home: home)
      .appending(path: "NativeMessagingHosts/\(hostName).json")
  }

  static func manifest(
    for browser: NativeBrowser,
    helper: URL,
    allowlist: ExtensionAllowlist,
  ) throws -> Data {
    var object: [String: Any] = [
      "name": hostName,
      "description": hostDescription,
      "path": helper.path,
      "type": "stdio",
    ]
    if browser.isChromium {
      object["allowed_origins"] = allowlist.chromium.sorted().map { "chrome-extension://\($0)/" }
    } else {
      object["allowed_extensions"] = allowlist.gecko.sorted()
    }
    return try JSONSerialization.data(
      withJSONObject: object,
      options: [.prettyPrinted, .sortedKeys],
    )
  }

  static func isBundledHelper(_ helper: URL) -> Bool {
    let folder = helper.deletingLastPathComponent()
    return folder.lastPathComponent == "Helpers"
      && folder.deletingLastPathComponent().lastPathComponent == "Contents"
      && helper.lastPathComponent == "hasp-nmh"
  }

  private static func install(
    _ browser: NativeBrowser,
    home: URL,
    helper: URL,
    allowlist: ExtensionAllowlist,
  ) -> ManifestInstall.Outcome {
    let ids = browser.isChromium ? allowlist.chromium : allowlist.gecko
    guard !ids.isEmpty else { return .noExtensionIDs }
    guard isBundledHelper(helper) else { return .helperOutsideBundle }
    let support = supportDirectory(for: browser, home: home)
    guard FileManager.default.fileExists(atPath: support.path) else { return .browserNotInstalled }
    let target = manifestURL(for: browser, home: home)
    let folder = target.deletingLastPathComponent()
    do {
      guard !isSymlink(folder), !isSymlink(target) else { return .refusedSymlink }
      if !FileManager.default.fileExists(atPath: folder.path) {
        try FileManager.default.createDirectory(
          at: folder,
          withIntermediateDirectories: false,
          attributes: [.posixPermissions: 0o700],
        )
      }
      let data = try manifest(for: browser, helper: helper, allowlist: allowlist)
      let previous = try? Data(contentsOf: target)
      if previous == data, isPrivateFile(target) { return .written }
      try writeAtomically(data, to: target)
      if let previous, let path = recordedPath(in: previous), path != helper.path {
        return .hostChanged(previousPath: path)
      }
      return .written
    } catch {
      return .failed
    }
  }

  private static func recordedPath(in manifest: Data) -> String? {
    (try? JSONSerialization.jsonObject(with: manifest) as? [String: Any])?["path"] as? String
  }

  private static func isSymlink(_ url: URL) -> Bool {
    var info = stat()
    return lstat(url.path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFLNK
  }

  private static func isPrivateFile(_ url: URL) -> Bool {
    var info = stat()
    guard lstat(url.path, &info) == 0 else { return false }
    return (info.st_mode & S_IFMT) == S_IFREG && info.st_uid == getuid()
      && (info.st_mode & 0o777) == 0o600
  }

  private static func writeAtomically(_ data: Data, to target: URL) throws {
    let temporary = target.deletingLastPathComponent().appending(path: ".\(UUID().uuidString).tmp")
    let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    guard descriptor >= 0 else { throw CocoaError(.fileWriteUnknown) }
    do {
      let written = data.withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
      guard written == data.count, fsync(descriptor) == 0 else {
        throw CocoaError(.fileWriteUnknown)
      }
      close(descriptor)
      guard rename(temporary.path, target.path) == 0 else { throw CocoaError(.fileWriteUnknown) }
    } catch {
      close(descriptor)
      unlink(temporary.path)
      throw error
    }
  }

  private static func supportDirectory(for browser: NativeBrowser, home: URL) -> URL {
    let base = home.appending(path: "Library/Application Support")
    return switch browser {
    case .chrome: base.appending(path: "Google/Chrome")
    case .edge: base.appending(path: "Microsoft Edge")
    case .brave: base.appending(path: "BraveSoftware/Brave-Browser")
    case .firefox: base.appending(path: "Mozilla")
    }
  }
}

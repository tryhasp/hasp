import Foundation
import Testing

@testable import HaspPlatform

@Suite struct ManifestInstallTests {
  private let helper = URL(filePath: "/Applications/Hasp.app/Contents/Helpers/hasp-nmh")
  private let allowlist = ExtensionAllowlist(chromium: ["abc"], gecko: [])

  private func home() throws -> URL {
    let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    try FileManager.default.createDirectory(
      at: home.appending(path: "Library/Application Support/Google/Chrome"),
      withIntermediateDirectories: true,
    )
    return home
  }

  private func chrome(_ home: URL, helper: URL? = nil) -> ManifestInstall.Outcome? {
    NativeMessagingManifests.installAll(
      home: home,
      helper: helper ?? self.helper,
      allowlist: allowlist,
    )
    .first { $0.browser == .chrome }?.outcome
  }

  private func mode(_ url: URL) throws -> Int {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    return try #require(attributes[.posixPermissions] as? Int)
  }

  @Test func writesPrivateFileInPrivateDirectory() throws {
    let home = try home()
    defer { try? FileManager.default.removeItem(at: home) }
    #expect(chrome(home) == .written)
    let target = NativeMessagingManifests.manifestURL(for: .chrome, home: home)
    #expect(try mode(target) == 0o600)
    #expect(try mode(target.deletingLastPathComponent()) == 0o700)
  }

  @Test func repairsLoosePermissionsOnTheNextLaunch() throws {
    let home = try home()
    defer { try? FileManager.default.removeItem(at: home) }
    _ = chrome(home)
    let target = NativeMessagingManifests.manifestURL(for: .chrome, home: home)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: target.path)
    #expect(chrome(home) == .written)
    #expect(try mode(target) == 0o600)
  }

  @Test func reportsAndRewritesAManifestPointingElsewhere() throws {
    let home = try home()
    defer { try? FileManager.default.removeItem(at: home) }
    _ = chrome(home)
    let target = NativeMessagingManifests.manifestURL(for: .chrome, home: home)
    let forged = try NativeMessagingManifests.manifest(
      for: .chrome,
      helper: URL(filePath: "/tmp/evil"),
      allowlist: allowlist,
    )
    try forged.write(to: target)
    #expect(chrome(home) == .hostChanged(previousPath: "/tmp/evil"))
    let object = try JSONSerialization.jsonObject(with: Data(contentsOf: target)) as? [String: Any]
    #expect(object?["path"] as? String == helper.path)
  }

  @Test func refusesASymlinkedManifest() throws {
    let home = try home()
    defer { try? FileManager.default.removeItem(at: home) }
    _ = chrome(home)
    let target = NativeMessagingManifests.manifestURL(for: .chrome, home: home)
    let elsewhere = home.appending(path: "elsewhere.json")
    try FileManager.default.removeItem(at: target)
    try FileManager.default.createSymbolicLink(at: target, withDestinationURL: elsewhere)
    #expect(chrome(home) == .refusedSymlink)
    #expect(!FileManager.default.fileExists(atPath: elsewhere.path))
  }

  @Test func refusesAHelperOutsideTheBundle() throws {
    let home = try home()
    defer { try? FileManager.default.removeItem(at: home) }
    #expect(chrome(home, helper: URL(filePath: "/tmp/hasp-nmh")) == .helperOutsideBundle)
    let target = NativeMessagingManifests.manifestURL(for: .chrome, home: home)
    #expect(!FileManager.default.fileExists(atPath: target.path))
  }
}

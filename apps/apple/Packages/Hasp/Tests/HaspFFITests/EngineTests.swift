import Foundation
import HaspFFI
import Synchronization
import Testing

private final class MemoryPlatformStore: PlatformStore {
  private let entries = Mutex<[String: Data]>([:])

  func hardwareGated() -> Bool { false }

  func put(label: String, secret: Data) throws {
    entries.withLock { $0[label] = secret }
  }

  func get(label: String) throws -> Data {
    guard let value = entries.withLock({ $0[label] }) else { throw HaspError.NotFound }
    return value
  }

  func delete(label: String) throws {
    entries.withLock { $0[label] = nil }
  }
}

private final class AbsentBiometric: PlatformBiometric {
  func available() -> Bool { false }

  func authenticate(reason: String) throws {
    throw HaspError.Cancelled
  }
}

@Suite struct EngineTests {
  private func makeClient() throws -> Client {
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("hasp-engine-\(UUID().uuidString)")
    return try Client.open(
      directory: directory.path,
      serverUrl: "https://hasp.example.com",
      platformName: "macos",
      store: MemoryPlatformStore(),
      biometric: AbsentBiometric(),
    )
  }

  @Test func aFreshClientHasNoAccount() throws {
    let client = try makeClient()
    let status = try client.status()
    #expect(status.state == .empty)
    #expect(status.login == nil)
    #expect(throws: HaspError.Locked) {
      try client.unlockPassword(password: Data("anything".utf8))
    }
  }

  @Test func generatesAPasswordThatFollowsSiteRules() throws {
    let client = try makeClient()
    let generated = try client.generate(
      request: GeneratorRequest(
        kind: .random,
        length: 24,
        lower: true,
        upper: true,
        digits: true,
        symbols: "!@#",
        excludeAmbiguous: false,
        words: 5,
        separator: "-",
        capitalize: false,
        appendDigit: false,
        origin: nil,
        siteRules: "minlength: 8; maxlength: 12; required: lower, digit;",
        fieldMinLength: nil,
        fieldMaxLength: nil,
      )
    )
    #expect((8...12).contains(generated.length))
    #expect(generated.siteRulesApplied)
    #expect(generated.value.count == Int(generated.length))
  }

  @Test func offersCategoriesAndABlankLogin() throws {
    let client = try makeClient()
    #expect(client.categories().contains { $0.id == "login" })
    let draft = try client.blankDraft(kind: "login")
    #expect(draft.kind == "login")
    #expect(draft.sections.flatMap(\.fields).contains { $0.purpose == "password" })
  }

  @Test func rejectsAnInsecureServerAddress() {
    #expect(throws: HaspError.Refused) {
      _ = try Client.open(
        directory: NSTemporaryDirectory() + "hasp-bad",
        serverUrl: "http://hasp.example.com",
        platformName: "macos",
        store: MemoryPlatformStore(),
        biometric: AbsentBiometric(),
      )
    }
  }
}

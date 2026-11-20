import Foundation
import HaspKit
import HaspPlatform
import Testing

struct SharedDirectoryTests {
  private func session(in directory: URL) throws -> AccountSession {
    let platform = DevicePlatformFactory.make(memoryOnly: true)
    return try AccountSession(
      directory: directory,
      origin: try #require(URL(string: "http://127.0.0.1:9")),
      store: platform.store,
      biometric: platform.biometric,
    )
  }

  @Test func theStoreKeepsOneClosedLockFileForEveryProcessThatOpensIt() async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "hasp-shared-\(UUID())")
    defer { try? FileManager.default.removeItem(at: directory) }
    let lock = directory.appending(path: "lock")
    let first = try session(in: directory)
    let attributes = try FileManager.default.attributesOfItem(atPath: lock.path)
    #expect((attributes[.posixPermissions] as? Int) == 0o600)
    #expect(try await first.status().state == .empty)
  }

  @Test func twoSessionsOnOneDirectoryOpenAndReadAtTheSameTime() async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "hasp-shared-\(UUID())")
    defer { try? FileManager.default.removeItem(at: directory) }
    let first = try session(in: directory)
    let second = try session(in: directory)
    async let one = first.status()
    async let two = second.status()
    let states = try await [one.state, two.state]
    #expect(states == [.empty, .empty])
  }
}

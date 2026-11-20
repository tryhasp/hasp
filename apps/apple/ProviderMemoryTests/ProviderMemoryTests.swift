import Foundation
import HaspKit
import HaspPlatform
import HaspProvider
import HaspProviderUI
import SwiftUI
import UIKit
import XCTest

actor FixtureProvider: ProviderServing {
  private let entries: [ProviderEntry]

  init(items: Int) {
    entries = (0..<items).map { index in
      ProviderEntry(
        key: ItemKey(vault: VaultID("v"), item: String(index)),
        title: "Item \(index)",
        subtitle: "user\(index)@example.com",
        favourite: index % 50 == 0,
        hasOneTimeCode: index % 7 == 0,
        hasPasskey: index % 40 == 0,
        hostToConfirm: nil,
      )
    }
  }

  func providerUnlock() {}
  func lock() {}
  func providerEntries(matching identifiers: [String], limit: Int) -> [ProviderEntry] {
    Array(entries.prefix(limit))
  }
  func providerSearch(text: String, limit: Int) -> [ProviderEntry] {
    Array(entries.filter { $0.title.contains(text) }.prefix(limit))
  }
  func providerFillCheck(_ key: ItemKey, service: String?, manual: Bool) throws
    -> ProviderFillCheck
  { throw HaspError.internal }
  func providerPassword(_ key: ItemKey, service: String?, manual: Bool, confirmed: Bool) throws
    -> ProviderPassword
  {
    throw HaspError.internal
  }
  func oneTimeCode(_ key: ItemKey) -> String { "000000" }
  func providerPasskeys(rpID: String, allowed: [Data]) -> [ProviderPasskey] { [] }
  func assertPasskey(_ input: PasskeyAssertionInput, in key: ItemKey?) throws
    -> PasskeyAssertionOutput
  { throw HaspError.internal }
  func registerPasskey(_ input: PasskeyRegistrationInput) throws -> PasskeyRegistrationOutput {
    throw HaspError.internal
  }
  func textOptions(matching text: String, limit: Int) -> [TextInsertOption] { [] }
  func textValue(_ key: ItemKey, field: String) throws -> RevealedSecret {
    throw HaspError.internal
  }
  func identityChange() throws -> IdentityChange { throw HaspError.internal }
  func acknowledgeIdentities(fingerprint: String) throws {}
  func importCredentialExchange(_ data: Data, dryRun: Bool) throws -> CredentialImportSummary {
    throw HaspError.internal
  }
}

@MainActor
final class Responder: ProviderResponder {
  func finish(with result: ProviderResult) {}
  func finish(failing failure: ProviderFailure) {}
  func finishConfiguration() {}
}

/// The extension process is not reachable from a test, and the process of a test host carries the XCTest
/// runtime (about 40 MB on the Simulator), so only the deltas mean something. This measures what the provider
/// screen adds to a process: the real engine opened on an empty store (runtime, transport, FFI), the Swift side of a
/// 2,000-entry index, and the SwiftUI list on screen. Rust heap with 2,000 real items is
/// `crates/testsupport/tests/provider_memory.rs`.
@MainActor
final class ProviderMemoryTests: XCTestCase {
  func testProviderScreenFootprintWithTwoThousandEntries() async throws {
    let baseline = Footprint.megabytes()
    let before = baseline
    let directory = FileManager.default.temporaryDirectory.appending(path: "hasp-memory-\(UUID())")
    let session = try AccountSession(
      directory: directory,
      origin: try XCTUnwrap(URL(string: "http://127.0.0.1:9")),
      platformName: "ios",
      store: MemorySecureStore(),
      biometric: DevicePlatformFactory.make(memoryOnly: true).biometric,
    )
    let afterEngine = Footprint.megabytes()

    let coordinator = ProviderCoordinator(engine: FixtureProvider(items: 2_000))
    let model = ProviderScreenModel(
      intent: .passwords(identifiers: []),
      coordinator: coordinator,
      responder: Responder(),
      configure: {},
    )
    let window = UIWindow(frame: UIScreen.main.bounds)
    window.rootViewController = UIHostingController(rootView: ProviderRootView(model: model))
    window.makeKeyAndVisible()
    await model.start()
    try await Task.sleep(for: .seconds(1))
    let afterScreen = Footprint.megabytes()
    XCTAssertEqual(model.rows.count, ProviderScreenModel.listLimit)

    let report = String(
      format:
        "empty SwiftUI host %.1f MB; engine +%.1f MB; screen with 2000-entry index +%.1f MB; process total %.1f MB",
      baseline,
      afterEngine - before,
      afterScreen - afterEngine,
      afterScreen,
    )
    let attachment = XCTAttachment(string: report)
    attachment.lifetime = .keepAlways
    add(attachment)
    try report.write(
      toFile: ProcessInfo.processInfo.environment["HASP_MEMORY_REPORT"] ?? "/tmp/hasp-memory.txt",
      atomically: true,
      encoding: .utf8,
    )
    XCTAssertLessThan(afterScreen - baseline, 30)
    withExtendedLifetime(session) {}
  }

  func testMeasureMetric() throws {
    measure(metrics: [XCTMemoryMetric()]) {
      let provider = FixtureProvider(items: 2_000)
      withExtendedLifetime(provider) {}
    }
  }
}

enum Footprint {
  static func megabytes() -> Double {
    var info = task_vm_info_data_t()
    var count = mach_msg_type_number_t(
      MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size
    )
    let result = withUnsafeMutablePointer(to: &info) {
      $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
        task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
      }
    }
    guard result == KERN_SUCCESS else { return 0 }
    return Double(info.phys_footprint) / 1_048_576
  }
}

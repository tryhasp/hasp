import Foundation
import Testing

@testable import HaspPlatform

struct BridgeTests {
  @Test func rejectsUnknownFieldsAndTypesOutsideTheClosedSet() {
    #expect(throws: MessageError.self) {
      try NativeMessage.decodeRequest(Data(#"{"type":"get_secret","id":1}"#.utf8))
    }
    #expect(throws: MessageError.self) {
      try NativeMessage.decodeRequest(
        Data(
          #"{"type":"unlock","id":1,"device_id":"AAAAAAAAAAAAAAAAAAAAAA","nonce":"AAAAAAAAAAAAAAAAAAAAAA","x":1}"#
            .utf8
        )
      )
    }
    #expect(throws: MessageError.self) {
      try NativeMessage.decodeRequest(
        Data(#"{"type":"enrol_request","id":9007199254740992,"data":"AAAA"}"#.utf8)
      )
    }
  }

  @Test func unlockWithoutAValidNonceIsMalformed() {
    let device = "AAAAAAAAAAAAAAAAAAAAAA"
    for tail in [
      #""#, #","nonce":"AAAA""#, #","nonce":7"#, #","nonce":"AAAAAAAAAAAAAAAAAAAAAAAA""#,
    ] {
      let frame = Data(#"{"type":"unlock","id":7,"device_id":"\#(device)"\#(tail)}"#.utf8)
      #expect(throws: MessageError.self) { try NativeMessage.decodeRequest(frame) }
    }
  }

  @Test func acceptsUnlockAndEnrol() throws {
    let unlock = try NativeMessage.decodeRequest(
      Data(
        #"{"type":"unlock","id":7,"device_id":"AAAAAAAAAAAAAAAAAAAAAA","nonce":"AQEBAQEBAQEBAQEBAQEBAQ"}"#
          .utf8
      )
    )
    #expect(
      unlock
        == .unlock(
          id: 7,
          deviceID: Data(repeating: 0, count: 16),
          nonce: Data(repeating: 1, count: 16),
        )
    )
    let enrol = try NativeMessage.decodeRequest(
      Data(#"{"type":"enrol_request","id":1,"data":"AAAA"}"#.utf8)
    )
    #expect(enrol == .enrol(id: 1, data: Data(repeating: 0, count: 3)))
  }

  @Test func attestationFixesPlatformAndBrowser() throws {
    let device = [UInt8](repeating: 7, count: 16)
    var request: [UInt8] = [0xA4, 0x00, 0x6D] + Array("enrol_request".utf8)
    request += [0x01, 0x50] + device
    request += [0x02, 0x63] + Array("evi".utf8)
    request += [0x03, 0x64] + Array("evil".utf8)
    let attested = try #require(PairingRequest.attested(Data(request), browser: .chrome))
    var expected: [UInt8] = [0xA4, 0x00, 0x6D] + Array("enrol_request".utf8)
    expected += [0x01, 0x50] + device
    expected += [0x02, 0x69] + Array("extension".utf8)
    expected += [0x03, 0x66] + Array("chrome".utf8)
    #expect(attested == Data(expected))
    #expect(PairingRequest.attested(Data(request.dropLast()), browser: .chrome) == nil)
  }

  @Test func manifestListsOnlyAllowedExtensions() throws {
    let allowlist = ExtensionAllowlist(chromium: ["abc"], gecko: ["x@y"])
    let helper = URL(filePath: "/Applications/Hasp.app/Contents/Helpers/hasp-nmh")
    let chromium = try NativeMessagingManifests.manifest(
      for: .brave,
      helper: helper,
      allowlist: allowlist,
    )
    let object = try #require(try JSONSerialization.jsonObject(with: chromium) as? [String: Any])
    #expect(object["allowed_origins"] as? [String] == ["chrome-extension://abc/"])
    #expect(object["allowed_extensions"] == nil)
  }

  @Test func installingOneBrowserNeverTouchesAnAbsentOne() throws {
    let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    try FileManager.default.createDirectory(
      at: home.appending(path: "Library/Application Support/Google/Chrome"),
      withIntermediateDirectories: true,
    )
    defer { try? FileManager.default.removeItem(at: home) }
    let results = NativeMessagingManifests.installAll(
      home: home,
      helper: URL(filePath: "/Applications/Hasp.app/Contents/Helpers/hasp-nmh"),
      allowlist: ExtensionAllowlist(chromium: ["abc"], gecko: []),
    )
    #expect(results.first { $0.browser == .chrome }?.outcome == .written)
    #expect(results.first { $0.browser == .edge }?.outcome == .browserNotInstalled)
    #expect(results.first { $0.browser == .firefox }?.outcome == .noExtensionIDs)
  }

  @Test func memoryStoreRoundTrips() throws {
    let store = MemorySecureStore()
    try store.put(label: "duk", secret: Data([1, 2]))
    #expect(try store.get(label: "duk") == Data([1, 2]))
    try store.delete(label: "duk")
    #expect(throws: (any Error).self) { try store.get(label: "duk") }
  }
}

struct SafariBridgeTests {
  @Test func unavailableRepliesCarryTheRequestIdentifier() throws {
    let reply = SafariBridge.unavailable(for: Data(#"{"type":"unlock","id":42}"#.utf8))
    let object = try #require(JSONSerialization.jsonObject(with: reply) as? [String: Any])
    #expect(object["type"] as? String == "error")
    #expect(object["code"] as? String == "unavailable")
    #expect(object["id"] as? Int == 42)
  }

  @Test func unavailableRepliesToGarbageHaveNoIdentifier() throws {
    let reply = SafariBridge.unavailable(for: Data("not json".utf8))
    let object = try #require(JSONSerialization.jsonObject(with: reply) as? [String: Any])
    #expect(object["id"] == nil)
  }
}

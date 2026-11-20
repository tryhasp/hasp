public import Foundation

public enum NativeBrowser: String, CaseIterable, Sendable {
  case chrome
  case edge
  case brave
  case firefox

  var isChromium: Bool { self != .firefox }
}

enum BridgeErrorCode: String {
  case malformed
  case refused
  case declined
  case revoked
  case locked
  case unavailable
}

enum ExtensionRequest: Equatable {
  case enrol(id: UInt64, data: Data)
  case unlock(id: UInt64, deviceID: Data, nonce: Data)
}

enum MessageError: Error {
  case malformed
}

private let maxJavaScriptInteger: UInt64 = (1 << 53) - 1

enum NativeMessage {
  static func decodeRequest(_ frame: Data) throws -> ExtensionRequest {
    let object = try dictionary(frame)
    guard let type = object["type"] as? String, let id = identifier(object["id"]) else {
      throw MessageError.malformed
    }
    switch type {
    case "enrol_request":
      guard Set(object.keys) == ["type", "id", "data"],
        let text = object["data"] as? String, let data = Base64URL.decode(text), !data.isEmpty
      else { throw MessageError.malformed }
      return .enrol(id: id, data: data)
    case "unlock":
      guard Set(object.keys) == ["type", "id", "device_id", "nonce"],
        let text = object["device_id"] as? String, let device = Base64URL.decode(text),
        device.count == 16,
        let nonceText = object["nonce"] as? String, let nonce = Base64URL.decode(nonceText),
        nonce.count == 16
      else { throw MessageError.malformed }
      return .unlock(id: id, deviceID: device, nonce: nonce)
    default:
      throw MessageError.malformed
    }
  }

  static func enrolReply(id: UInt64, payload: Data) throws -> Data {
    try encode(["type": "enrol_reply", "id": id, "data": Base64URL.encode(payload)])
  }

  static func unlockReply(id: UInt64, key: Data, validUntil: UInt64) throws -> Data {
    try encode([
      "type": "unlock_reply", "id": id, "k_ext": Base64URL.encode(key), "valid_until": validUntil,
    ])
  }

  static func error(id: UInt64?, code: BridgeErrorCode) throws -> Data {
    var object: [String: Any] = ["type": "error", "code": code.rawValue]
    if let id { object["id"] = id }
    return try encode(object)
  }

  private static func dictionary(_ frame: Data) throws -> [String: Any] {
    guard let object = try? JSONSerialization.jsonObject(with: frame) as? [String: Any] else {
      throw MessageError.malformed
    }
    return object
  }

  private static func identifier(_ value: Any?) -> UInt64? {
    guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
      !CFNumberIsFloatType(number), let id = value as? UInt64, id <= maxJavaScriptInteger
    else { return nil }
    return id
  }

  private static func encode(_ object: [String: Any]) throws -> Data {
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  }
}

enum Base64URL {
  static func encode(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  static func decode(_ text: String) -> Data? {
    guard !text.isEmpty, text.count % 4 != 1,
      text.utf8.allSatisfy({ $0.isASCIILetterOrDigit || $0 == 0x2D || $0 == 0x5F })
    else { return nil }
    var standard = text.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    standard += String(repeating: "=", count: (4 - standard.count % 4) % 4)
    return Data(base64Encoded: standard)
  }
}

extension UInt8 {
  fileprivate var isASCIILetterOrDigit: Bool {
    (0x30...0x39).contains(self) || (0x41...0x5A).contains(self) || (0x61...0x7A).contains(self)
  }
}

extension Data {
  var lowercaseHex: String {
    map { String(format: "%02x", $0) }.joined()
  }
}

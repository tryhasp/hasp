import Foundation

/// The `enrol_request` CBOR a page-controlled extension sends is rebuilt with the platform fixed to
/// `extension` and the browser the host attested, so the extension cannot choose the name shown at approval.
enum PairingRequest {
  private static let tag = "enrol_request"
  private static let platform = "extension"

  static func attested(_ cbor: Data, browser: NativeBrowser) -> Data? {
    attested(cbor, browserName: browser.rawValue)
  }

  static func attested(_ cbor: Data, browserName: String) -> Data? {
    var cursor = Cursor(bytes: [UInt8](cbor))
    guard cursor.take() == 0xA4, cursor.take() == 0x00, cursor.text() == tag,
      cursor.take() == 0x01, let device = cursor.rawItem(), cursor.take() == 0x02,
      cursor.text() != nil, cursor.take() == 0x03, cursor.text() != nil, cursor.atEnd
    else { return nil }
    var out: [UInt8] = [0xA4, 0x00]
    out += textItem(tag)
    out += [0x01] + device
    out += [0x02] + textItem(platform)
    out += [0x03] + textItem(browserName)
    return Data(out)
  }

  private static func textItem(_ text: String) -> [UInt8] {
    let bytes = Array(text.utf8)
    precondition(bytes.count < 24, "attested strings are short constants")
    return [0x60 | UInt8(bytes.count)] + bytes
  }

  private struct Cursor {
    let bytes: [UInt8]
    var position = 0

    init(bytes: [UInt8]) {
      self.bytes = bytes
    }

    var atEnd: Bool { position == bytes.count }

    mutating func take() -> UInt8? {
      guard position < bytes.count else { return nil }
      defer { position += 1 }
      return bytes[position]
    }

    mutating func text() -> String? {
      guard let raw = rawItem(), let head = raw.first, head & 0xE0 == 0x60 else { return nil }
      let start = head == 0x78 ? 2 : 1
      return String(bytes: raw[start...], encoding: .utf8)
    }

    mutating func rawItem() -> [UInt8]? {
      let start = position
      guard let head = take() else { return nil }
      let major = head & 0xE0
      guard major == 0x40 || major == 0x60 else { return nil }
      var length = Int(head & 0x1F)
      if length == 24 {
        guard let extended = take() else { return nil }
        length = Int(extended)
      } else if length > 24 {
        return nil
      }
      guard position + length <= bytes.count else { return nil }
      position += length
      return Array(bytes[start..<position])
    }
  }
}

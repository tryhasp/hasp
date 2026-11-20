public import Foundation

extension Data {
  /// Unpadded URL-safe base64, the encoding every provider id and WebAuthn byte string uses.
  public func base64URLString() -> String {
    base64EncodedString()
      .replacing("+", with: "-")
      .replacing("/", with: "_")
      .replacing("=", with: "")
  }

  public init?(base64URLString text: String) {
    var standard = text.replacing("-", with: "+").replacing("_", with: "/")
    while standard.count % 4 != 0 { standard.append("=") }
    self.init(base64Encoded: standard)
  }
}

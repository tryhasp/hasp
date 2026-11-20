import LocalAuthentication
import Security
import XCTest

final class KeychainProbe: XCTestCase {
  func testProbe() throws {
    var lines: [String] = []
    for (name, policy) in [("bio", LAPolicy.deviceOwnerAuthenticationWithBiometrics), ("owner", .deviceOwnerAuthentication)] {
      var error: NSError?
      let ok = LAContext().canEvaluatePolicy(policy, error: &error)
      lines.append("\(name) ok=\(ok) err=\(error?.code ?? 0) \(error?.localizedDescription ?? "")")
    }
    var cf: Unmanaged<CFError>?
    let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .userPresence, &cf)
    lines.append("access=\(access != nil) cf=\(String(describing: cf?.takeRetainedValue()))")
    var attrs: [CFString: Any] = [
      kSecClass: kSecClassGenericPassword, kSecAttrService: "probe", kSecAttrAccount: "a",
      kSecValueData: Data([1]),
    ]
    if let access { attrs[kSecAttrAccessControl] = access }
    _ = SecItemDelete(attrs as CFDictionary)
    lines.append("add status=\(SecItemAdd(attrs as CFDictionary, nil))")
    try lines.joined(separator: "\n").write(toFile: "/tmp/hasp-probe.txt", atomically: true, encoding: .utf8)
  }
}

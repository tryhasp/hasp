import Foundation
import HaspKit

/// Test-only switches. A release build ignores every one of them.
struct PhoneLaunchOptions {
  var dataDirectory: String?
  var memoryStore = false
  var reset = false
  var capability: UnlockCapability?

  static func read(_ environment: [String: String]) -> PhoneLaunchOptions {
    var options = PhoneLaunchOptions()
    #if DEBUG
      options.dataDirectory = environment["HASP_DATA_DIR"]
      options.memoryStore = environment["HASP_MEMORY_STORE"] == "1"
      options.reset = environment["HASP_RESET"] == "1"
      options.capability = environment["HASP_CAPABILITY"].flatMap(Self.capability(named:))
    #endif
    return options
  }

  private static func capability(named name: String) -> UnlockCapability? {
    switch name {
    case "needsPasscode": .needsPasscode
    case "hardwareReady": .hardwareReady
    case "softwareOnly": .softwareOnly
    default: nil
    }
  }
}

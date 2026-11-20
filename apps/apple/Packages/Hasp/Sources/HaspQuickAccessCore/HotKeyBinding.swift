public import Foundation

public struct HotKeyBinding: Codable, Equatable, Sendable {
  public static let carbonCommand: UInt32 = 0x100
  public static let carbonShift: UInt32 = 0x200
  public static let carbonOption: UInt32 = 0x800
  public static let carbonControl: UInt32 = 0x1000
  static let backslashKeyCode: UInt32 = 0x2A

  public static let standard = HotKeyBinding(
    keyCode: backslashKeyCode,
    modifiers: carbonCommand | carbonOption,
  )

  public let keyCode: UInt32
  public let modifiers: UInt32

  public init(keyCode: UInt32, modifiers: UInt32) {
    self.keyCode = keyCode
    self.modifiers = modifiers
  }

  public var hasModifier: Bool { modifiers != 0 }
}

public struct SystemShortcut: Equatable, Sendable {
  public let keyCode: UInt32
  public let modifiers: UInt32
  public let enabled: Bool

  public init(keyCode: UInt32, modifiers: UInt32, enabled: Bool) {
    self.keyCode = keyCode
    self.modifiers = modifiers
    self.enabled = enabled
  }
}

public enum HotKeyConflicts {
  public static func conflicts(_ binding: HotKeyBinding, with shortcuts: [SystemShortcut]) -> Bool {
    shortcuts.contains {
      $0.enabled && $0.keyCode == binding.keyCode && $0.modifiers == binding.modifiers
    }
  }
}

public struct HotKeyPreferences: Sendable {
  private static let key = "quickAccess.hotKey"
  private let defaults: UserDefaultsBox

  public init(defaults: UserDefaults) {
    self.defaults = UserDefaultsBox(defaults: defaults)
  }

  public func load() -> HotKeyBinding {
    guard let data = defaults.defaults.data(forKey: Self.key),
      let stored = try? JSONDecoder().decode(HotKeyBinding.self, from: data), stored.hasModifier
    else { return .standard }
    return stored
  }

  public func save(_ binding: HotKeyBinding) throws {
    defaults.defaults.set(try JSONEncoder().encode(binding), forKey: Self.key)
  }
}

struct UserDefaultsBox: @unchecked Sendable {
  // Why: UserDefaults is documented thread-safe (https://developer.apple.com/documentation/foundation/userdefaults)
  let defaults: UserDefaults
}

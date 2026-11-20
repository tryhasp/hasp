public enum QuickAction: CaseIterable, Equatable, Sendable {
  case fill
  case copyPassword
  case copyOTP
  case copyUsername
  case openInMainWindow
  case showAllActions
  case close
}

public struct KeyChord: Equatable, Sendable {
  public enum Key: Equatable, Sendable {
    case character(Character)
    case returnKey
    case escape
  }

  public let key: Key
  public let command: Bool
  public let shift: Bool
  public let option: Bool
  public let control: Bool

  public init(
    _ key: Key,
    command: Bool = false,
    shift: Bool = false,
    option: Bool = false,
    control: Bool = false,
  ) {
    self.key = key
    self.command = command
    self.shift = shift
    self.option = option
    self.control = control
  }
}

extension QuickAction {
  public static func route(_ chord: KeyChord) -> QuickAction? {
    if chord.control { return nil }
    switch chord.key {
    case .escape:
      return chord.command || chord.shift || chord.option ? nil : .close
    case .returnKey:
      return chord.command || chord.shift || chord.option ? nil : .fill
    case .character(let character):
      guard chord.command else { return nil }
      return commandAction(character, shift: chord.shift, option: chord.option)
    }
  }

  private static func commandAction(_ character: Character, shift: Bool, option: Bool)
    -> QuickAction?
  {
    switch (character.lowercased(), shift, option) {
    case ("c", false, false): .copyPassword
    case ("c", true, false): .copyOTP
    case ("c", false, true): .copyUsername
    case ("o", false, false): .openInMainWindow
    case ("/", false, false), ("?", true, false): .showAllActions
    default: nil
    }
  }

  public var shortcutLabel: String {
    switch self {
    case .fill: "↩"
    case .copyPassword: "⌘C"
    case .copyOTP: "⌘⇧C"
    case .copyUsername: "⌘⌥C"
    case .openInMainWindow: "⌘O"
    case .showAllActions: "⌘/"
    case .close: "esc"
    }
  }
}

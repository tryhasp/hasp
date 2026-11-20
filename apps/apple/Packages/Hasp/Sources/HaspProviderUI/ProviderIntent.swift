public import HaspKit
public import HaspProvider

/// What the system asked the extension to do. It decides the screen and the list that fills it.
public enum ProviderIntent: Sendable {
  case passwords(identifiers: [String])
  case oneTimeCodes(identifiers: [String])
  case passkeys(PasskeyAssertionParameters, identifiers: [String])
  case text
  case fill(IdentityRequest)
  case register(PasskeyRegistrationInput)
  case configure
}

public enum ProviderRowKind: Sendable, Equatable {
  case password, passkey, oneTimeCode, text
}

public enum ProviderRowAction: Sendable, Equatable {
  case entry(ProviderEntry)
  case passkey(ProviderPasskey)
  case text(TextInsertOption)
}

public struct ProviderRow: Sendable, Equatable, Identifiable {
  public let id: String
  public let kind: ProviderRowKind
  public let title: String
  public let subtitle: String
  public let favourite: Bool
  public let action: ProviderRowAction

  init(entry: ProviderEntry, kind: ProviderRowKind) {
    id = "e:\(entry.key.vault.rawValue):\(entry.key.item)"
    self.kind = kind
    title = entry.title
    subtitle = entry.hostToConfirm.map { "\(entry.subtitle) · \($0)" } ?? entry.subtitle
    favourite = entry.favourite
    action = .entry(entry)
  }

  init(passkey: ProviderPasskey) {
    id =
      "k:\(passkey.key.vault.rawValue):\(passkey.key.item):\(passkey.credentialID.base64URLString())"
    kind = .passkey
    title = passkey.title
    subtitle = passkey.userName
    favourite = false
    action = .passkey(passkey)
  }

  init(text option: TextInsertOption) {
    id = "t:\(option.id)"
    kind = .text
    title = option.label
    subtitle = option.preview.isEmpty ? option.itemTitle : "\(option.itemTitle) · \(option.preview)"
    favourite = false
    action = .text(option)
  }
}

/// The view controller implements this; the model never touches the extension context.
@MainActor
public protocol ProviderResponder: AnyObject {
  func finish(with result: ProviderResult)
  func finish(failing failure: ProviderFailure)
  func finishConfiguration()
}

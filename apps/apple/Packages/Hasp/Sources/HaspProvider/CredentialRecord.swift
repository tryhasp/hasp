public import HaspKit

/// The stable `recordIdentifier` the engine gives each system identity (QuickType).
/// `p:<vault>:<item>:<host>`, `o:<vault>:<item>:<host>`, `k:<vault>:<item>:<credentialId>`.
public struct CredentialRecord: Sendable, Equatable {
  public enum Kind: Sendable, Equatable {
    case password, oneTimeCode, passkey
  }

  public let kind: Kind
  public let key: ItemKey
  public let tail: String

  public init(kind: Kind, key: ItemKey, tail: String) {
    self.kind = kind
    self.key = key
    self.tail = tail
  }

  public init?(_ identifier: String?) {
    guard let identifier else { return nil }
    let parts = identifier.split(separator: ":", maxSplits: 3, omittingEmptySubsequences: false)
    guard parts.count == 4, !parts[1].isEmpty, !parts[2].isEmpty, !parts[3].isEmpty else {
      return nil
    }
    switch parts[0] {
    case "p": kind = .password
    case "o": kind = .oneTimeCode
    case "k": kind = .passkey
    default: return nil
    }
    key = ItemKey(vault: VaultID(String(parts[1])), item: String(parts[2]))
    tail = String(parts[3])
  }
}

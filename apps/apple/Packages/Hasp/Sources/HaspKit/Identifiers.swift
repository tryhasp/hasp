public struct VaultID: Hashable, Sendable {
  public let rawValue: String

  public init(_ rawValue: String) {
    self.rawValue = rawValue
  }
}

public struct ItemKey: Hashable, Sendable {
  public let vault: VaultID
  public let item: String

  public init(vault: VaultID, item: String) {
    self.vault = vault
    self.item = item
  }
}

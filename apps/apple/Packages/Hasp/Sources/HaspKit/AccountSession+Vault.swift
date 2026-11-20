import Foundation
import HaspFFI

extension AccountSession {
  public func vaults() throws -> [VaultSummary] {
    try mapped { try client.vaults() }.map(VaultSummary.init)
  }

  public func categories() -> [ItemCategory] {
    client.categories().map(ItemCategory.init)
  }

  public func items(in vault: VaultID) throws -> [ItemSummary] {
    try mapped { try client.items(vault: vault.rawValue) }.map(ItemSummary.init)
  }

  public func search(_ filter: SearchFilter) throws -> [ItemSummary] {
    try mapped { try client.search(query: filter.ffi) }.map(ItemSummary.init)
  }

  public func detail(_ key: ItemKey) throws -> ItemDetail {
    ItemDetail(try mapped { try client.itemDetail(vault: key.vault.rawValue, item: key.item) })
  }

  public func blankDraft(kind: String) throws -> ItemDraft {
    ItemDraft(try mapped { try client.blankDraft(kind: kind) })
  }

  public func editDraft(_ key: ItemKey) throws -> ItemDraft {
    ItemDraft(try mapped { try client.editDraft(vault: key.vault.rawValue, item: key.item) })
  }

  public func createItem(in vault: VaultID, draft: ItemDraft) throws -> ItemKey {
    let reference = try mapped { try client.createItem(vault: vault.rawValue, draft: draft.ffi) }
    return ItemKey(vault: VaultID(reference.vault), item: reference.item)
  }

  public func editItem(_ key: ItemKey, draft: ItemDraft) throws {
    try mapped {
      try client.editItem(vault: key.vault.rawValue, item: key.item, draft: draft.ffi)
    }
  }

  public func setStatus(_ key: ItemKey, status: ItemStatus) throws {
    try mapped {
      try client.setStatus(vault: key.vault.rawValue, item: key.item, status: status.ffi)
    }
  }

  public func setFavourite(_ key: ItemKey, favourite: Bool) throws {
    try mapped {
      try client.setFavourite(vault: key.vault.rawValue, item: key.item, favourite: favourite)
    }
  }

  public func deleteItem(_ key: ItemKey) throws {
    try mapped { try client.deleteItem(vault: key.vault.rawValue, item: key.item) }
  }

  public func history(_ key: ItemKey) throws -> [HistoryEntry] {
    try mapped { try client.history(vault: key.vault.rawValue, item: key.item) }
      .map(HistoryEntry.init)
  }

  public func restoreVersion(_ key: ItemKey, version: Int) throws {
    try mapped {
      try client.restoreVersion(
        vault: key.vault.rawValue,
        item: key.item,
        version: UInt64(max(0, version)),
      )
    }
  }
}

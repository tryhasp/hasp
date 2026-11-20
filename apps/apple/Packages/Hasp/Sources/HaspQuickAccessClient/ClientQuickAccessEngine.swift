public import Foundation
public import HaspFFI
public import HaspQuickAccessCore

public enum QuickAccessEngineError: Error, Equatable {
  case noPasswordField
  case noOTP
}

public actor ClientQuickAccessEngine: QuickAccessEngine {
  private let client: any ClientProtocol

  public init(client: any ClientProtocol) {
    self.client = client
  }

  public func lockState() throws -> QuickAccessLockState {
    guard try client.status().state == .unlocked else { return .locked }
    let seconds = try client.settings().lock.clipboardClearSeconds
    return .unlocked(clipboardClear: .seconds(Int64(seconds)))
  }

  public func items() throws -> [QuickItem] {
    let vaults = Dictionary(uniqueKeysWithValues: try client.vaults().map { ($0.id, $0) })
    let query = SearchQuery(
      text: "",
      vault: nil,
      kind: nil,
      tag: nil,
      favouritesOnly: false,
      status: .active,
      boostUrl: nil,
      limit: 0,
    )
    return try client.search(query: query).map { row in
      let vault = vaults[row.vault]
      return QuickItem(
        id: QuickItemID(vault: row.vault, item: row.id),
        kind: Self.kind(row.kind),
        title: row.title,
        username: row.subtitle,
        hosts: row.hosts,
        vaultName: vault?.name ?? "",
        isShared: vault.map { $0.kind != "private" && $0.members > 1 } ?? false,
        favourite: row.favourite,
        hasOTP: row.hasTotp,
        modified: Date(timeIntervalSince1970: TimeInterval(row.modified)),
      )
    }
  }

  public func otpPreview(for item: QuickItemID) throws -> OTPPreview {
    let code = try client.totp(vault: item.vault, item: item.item, field: nil)
    return OTPPreview(
      code: String(decoding: code.code, as: UTF8.self),
      secondsRemaining: Int(code.remaining),
    )
  }

  public func password(for item: QuickItemID) throws -> Data {
    let detail = try client.itemDetail(vault: item.vault, item: item.item)
    guard let field = Self.field(detail, purpose: "password") else {
      throw QuickAccessEngineError.noPasswordField
    }
    return try client.revealField(vault: item.vault, item: item.item, field: field.id)
  }

  public func otpCode(for item: QuickItemID) throws -> Data {
    try client.totp(vault: item.vault, item: item.item, field: nil).code
  }

  public func username(for item: QuickItemID) throws -> Data {
    let detail = try client.itemDetail(vault: item.vault, item: item.item)
    return Data((Self.field(detail, purpose: "username")?.value ?? detail.row.subtitle).utf8)
  }

  public func loginValues(for item: QuickItemID) throws -> LoginValues {
    LoginValues(username: try username(for: item), password: try password(for: item))
  }

  private static func field(_ detail: ItemDetail, purpose: String) -> FieldView? {
    detail.sections.lazy.flatMap(\.fields).first { $0.purpose == purpose }
  }

  private static func kind(_ raw: String) -> QuickItemKind {
    switch raw {
    case "login": .login
    case "card": .card
    case "identity": .identity
    default: .other
    }
  }
}

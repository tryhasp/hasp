public import Foundation

public enum ItemStatus: Equatable, Sendable {
  case active
  case archived
  case trashed
}

public struct VaultSummary: Identifiable, Equatable, Sendable {
  public var id: VaultID
  public var name: String
  public var kind: String
  public var role: String
  public var confirmed: Bool
  public var quarantined: Bool
  public var members: Int
  public var writable: Bool

  public init(
    id: VaultID,
    name: String,
    kind: String,
    role: String,
    confirmed: Bool = true,
    quarantined: Bool = false,
    members: Int = 1,
    writable: Bool = true,
  ) {
    self.id = id
    self.name = name
    self.kind = kind
    self.role = role
    self.confirmed = confirmed
    self.quarantined = quarantined
    self.members = members
    self.writable = writable
  }
}

public struct ItemSummary: Identifiable, Equatable, Sendable {
  public var key: ItemKey
  public var kind: String
  public var title: String
  public var subtitle: String
  public var hosts: [String]
  public var tags: [String]
  public var favourite: Bool
  public var status: ItemStatus
  public var hasTotp: Bool
  public var hasPasskey: Bool
  public var hasAttachments: Bool
  public var modified: Date
  public var pending: Bool

  public var id: ItemKey { key }

  public init(
    key: ItemKey,
    kind: String,
    title: String,
    subtitle: String = "",
    hosts: [String] = [],
    tags: [String] = [],
    favourite: Bool = false,
    status: ItemStatus = .active,
    hasTotp: Bool = false,
    hasPasskey: Bool = false,
    hasAttachments: Bool = false,
    modified: Date = .distantPast,
    pending: Bool = false,
  ) {
    self.key = key
    self.kind = kind
    self.title = title
    self.subtitle = subtitle
    self.hosts = hosts
    self.tags = tags
    self.favourite = favourite
    self.status = status
    self.hasTotp = hasTotp
    self.hasPasskey = hasPasskey
    self.hasAttachments = hasAttachments
    self.modified = modified
    self.pending = pending
  }
}

public struct ItemCategory: Identifiable, Equatable, Sendable {
  public var id: String
  public var nameEn: String
  public var nameKo: String
  public var icon: String

  public init(id: String, nameEn: String, nameKo: String, icon: String) {
    self.id = id
    self.nameEn = nameEn
    self.nameKo = nameKo
    self.icon = icon
  }
}

public struct FieldValue: Identifiable, Equatable, Sendable {
  public var id: String
  public var label: String
  public var kind: String
  public var purpose: String?
  public var concealed: Bool
  public var value: String?
  public var expiresAlert: Bool

  public init(
    id: String,
    label: String,
    kind: String,
    purpose: String? = nil,
    concealed: Bool = false,
    value: String? = nil,
    expiresAlert: Bool = false,
  ) {
    self.id = id
    self.label = label
    self.kind = kind
    self.purpose = purpose
    self.concealed = concealed
    self.value = value
    self.expiresAlert = expiresAlert
  }
}

public struct SectionValue: Identifiable, Equatable, Sendable {
  public var id: String
  public var title: String
  public var fields: [FieldValue]

  public init(id: String, title: String, fields: [FieldValue]) {
    self.id = id
    self.title = title
    self.fields = fields
  }
}

public struct ItemURL: Identifiable, Equatable, Sendable {
  public var id: String
  public var url: String
  public var mode: String
  public var kind: String

  public init(id: String, url: String, mode: String = "domain", kind: String = "login") {
    self.id = id
    self.url = url
    self.mode = mode
    self.kind = kind
  }
}

public struct AttachmentSummary: Identifiable, Equatable, Sendable {
  public var id: String
  public var name: String
  public var mime: String
  public var size: Int

  public init(id: String, name: String, mime: String, size: Int) {
    self.id = id
    self.name = name
    self.mime = mime
    self.size = size
  }
}

public struct ItemDetail: Equatable, Sendable {
  public var summary: ItemSummary
  public var sections: [SectionValue]
  public var notes: String?
  public var urls: [ItemURL]
  public var attachments: [AttachmentSummary]
  public var passkeys: Int
  public var passwordHistory: Int

  public init(
    summary: ItemSummary,
    sections: [SectionValue] = [],
    notes: String? = nil,
    urls: [ItemURL] = [],
    attachments: [AttachmentSummary] = [],
    passkeys: Int = 0,
    passwordHistory: Int = 0,
  ) {
    self.summary = summary
    self.sections = sections
    self.notes = notes
    self.urls = urls
    self.attachments = attachments
    self.passkeys = passkeys
    self.passwordHistory = passwordHistory
  }
}

public struct HistoryEntry: Identifiable, Equatable, Sendable {
  public var version: Int
  public var epoch: Int
  public var title: String
  public var modified: Date

  public var id: Int { version }

  public init(version: Int, epoch: Int, title: String, modified: Date) {
    self.version = version
    self.epoch = epoch
    self.title = title
    self.modified = modified
  }
}

public struct TOTPSnapshot: Equatable, Sendable {
  public var code: String
  public var remaining: Int
  public var period: Int
  public var digits: Int

  public init(code: String, remaining: Int, period: Int, digits: Int) {
    self.code = code
    self.remaining = remaining
    self.period = period
    self.digits = digits
  }
}

public struct SearchFilter: Equatable, Sendable {
  public var text: String
  public var vault: VaultID?
  public var kind: String?
  public var tag: String?
  public var favouritesOnly: Bool
  public var status: ItemStatus?
  public var limit: Int

  public init(
    text: String = "",
    vault: VaultID? = nil,
    kind: String? = nil,
    tag: String? = nil,
    favouritesOnly: Bool = false,
    status: ItemStatus? = .active,
    limit: Int = 1000,
  ) {
    self.text = text
    self.vault = vault
    self.kind = kind
    self.tag = tag
    self.favouritesOnly = favouritesOnly
    self.status = status
    self.limit = limit
  }
}

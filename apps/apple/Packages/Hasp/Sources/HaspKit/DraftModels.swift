public import Foundation

public struct DraftField: Identifiable, Equatable, Sendable {
  public var id: String
  public var existingID: String?
  public var label: String
  public var kind: String
  public var purpose: String?
  public var concealed: Bool
  public var expiresAlert: Bool
  public var value: String
  public var keepValue: Bool

  public init(
    id: String = UUID().uuidString,
    existingID: String? = nil,
    label: String,
    kind: String,
    purpose: String? = nil,
    concealed: Bool = false,
    expiresAlert: Bool = false,
    value: String = "",
    keepValue: Bool = false,
  ) {
    self.id = id
    self.existingID = existingID
    self.label = label
    self.kind = kind
    self.purpose = purpose
    self.concealed = concealed
    self.expiresAlert = expiresAlert
    self.value = value
    self.keepValue = keepValue
  }
}

public struct DraftSection: Identifiable, Equatable, Sendable {
  public var id: String
  public var existingID: String?
  public var title: String
  public var fields: [DraftField]

  public init(
    id: String = UUID().uuidString,
    existingID: String? = nil,
    title: String,
    fields: [DraftField],
  ) {
    self.id = id
    self.existingID = existingID
    self.title = title
    self.fields = fields
  }
}

public struct DraftURL: Identifiable, Equatable, Sendable {
  public var id: String
  public var existingID: String?
  public var url: String
  public var mode: String
  public var kind: String

  public init(
    id: String = UUID().uuidString,
    existingID: String? = nil,
    url: String,
    mode: String = "domain",
    kind: String = "login",
  ) {
    self.id = id
    self.existingID = existingID
    self.url = url
    self.mode = mode
    self.kind = kind
  }
}

public struct ItemDraft: Equatable, Sendable {
  public var kind: String
  public var title: String
  public var subtitle: String
  public var tags: [String]
  public var favourite: Bool
  public var notes: String
  public var expiresAt: Date?
  public var sections: [DraftSection]
  public var urls: [DraftURL]

  public init(
    kind: String,
    title: String = "",
    subtitle: String = "",
    tags: [String] = [],
    favourite: Bool = false,
    notes: String = "",
    expiresAt: Date? = nil,
    sections: [DraftSection] = [],
    urls: [DraftURL] = [],
  ) {
    self.kind = kind
    self.title = title
    self.subtitle = subtitle
    self.tags = tags
    self.favourite = favourite
    self.notes = notes
    self.expiresAt = expiresAt
    self.sections = sections
    self.urls = urls
  }
}

public enum GeneratorStyle: Equatable, Sendable {
  case random
  case memorable
  case pin
  case koreanSafe
}

public struct GeneratorOptions: Equatable, Sendable {
  public var style: GeneratorStyle
  public var length: Int
  public var words: Int
  public var origin: String?

  public init(
    style: GeneratorStyle = .random,
    length: Int = 20,
    words: Int = 4,
    origin: String? = nil,
  ) {
    self.style = style
    self.length = length
    self.words = words
    self.origin = origin
  }
}

public struct GeneratedSecret: Sendable {
  public var secret: RevealedSecret
  public var bits: Double
  public var length: Int

  public init(secret: RevealedSecret, bits: Double, length: Int) {
    self.secret = secret
    self.bits = bits
    self.length = length
  }
}

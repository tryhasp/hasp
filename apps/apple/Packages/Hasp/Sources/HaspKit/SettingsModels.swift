public import Foundation

public struct LockPolicy: Equatable, Sendable {
  public var idle: Duration
  public var lockOnSleep: Bool
  public var lockOnScreenLock: Bool
  public var lockOnUserSwitch: Bool
  public var lockOnQuit: Bool
  public var background: Duration
  public var passwordEveryDays: Int
  public var clipboardClear: Duration

  public init(
    idle: Duration = .seconds(600),
    lockOnSleep: Bool = true,
    lockOnScreenLock: Bool = true,
    lockOnUserSwitch: Bool = true,
    lockOnQuit: Bool = true,
    background: Duration = .seconds(60),
    passwordEveryDays: Int = 14,
    clipboardClear: Duration = .seconds(90),
  ) {
    self.idle = idle
    self.lockOnSleep = lockOnSleep
    self.lockOnScreenLock = lockOnScreenLock
    self.lockOnUserSwitch = lockOnUserSwitch
    self.lockOnQuit = lockOnQuit
    self.background = background
    self.passwordEveryDays = passwordEveryDays
    self.clipboardClear = clipboardClear
  }
}

public struct SecretTag: Equatable, Sendable {
  public static let maxWordLength = 12
  public static let glyphCount = 12

  public var word: String
  public var glyph: Int

  public init(word: String, glyph: Int) {
    self.word = word
    self.glyph = glyph
  }
}

public struct AppSettings: Equatable, Sendable {
  public var lock: LockPolicy
  public var secretTag: SecretTag?
  public var language: String
  public var inlineMenu: Bool
  public var autoSubmit: Bool
  public var askBeforeFilling: Bool
  public var hardenedMode: Bool
  public var copyTotpAfterFill: Bool
  public var breachCheck: Bool

  public init(
    lock: LockPolicy = LockPolicy(),
    secretTag: SecretTag? = nil,
    language: String = "ko",
    inlineMenu: Bool = true,
    autoSubmit: Bool = true,
    askBeforeFilling: Bool = false,
    hardenedMode: Bool = false,
    copyTotpAfterFill: Bool = false,
    breachCheck: Bool = false,
  ) {
    self.lock = lock
    self.secretTag = secretTag
    self.language = language
    self.inlineMenu = inlineMenu
    self.autoSubmit = autoSubmit
    self.askBeforeFilling = askBeforeFilling
    self.hardenedMode = hardenedMode
    self.copyTotpAfterFill = copyTotpAfterFill
    self.breachCheck = breachCheck
  }
}

public enum LockTrigger: Equatable, Sendable {
  case sleep
  case screenLock
  case userSwitch
  case idle
  case quit
  case background
  case manual
}

public enum WatchKind: Equatable, Sendable {
  case vulnerable
  case reused
  case weak
  case insecureURL
  case expiring
}

public struct WatchFinding: Identifiable, Equatable, Sendable {
  public var kind: WatchKind
  public var key: ItemKey
  public var title: String
  public var detail: String?
  public var group: Int?

  public var id: String { "\(kind)-\(key.vault.rawValue)-\(key.item)" }

  public init(
    kind: WatchKind,
    key: ItemKey,
    title: String,
    detail: String? = nil,
    group: Int? = nil,
  ) {
    self.kind = kind
    self.key = key
    self.title = title
    self.detail = detail
    self.group = group
  }
}

public struct WatchtowerSummary: Equatable, Sendable {
  public var findings: [WatchFinding]
  public var checked: Int
  public var breachCheckRan: Bool
  public var generatedAt: Date

  public init(findings: [WatchFinding], checked: Int, breachCheckRan: Bool, generatedAt: Date) {
    self.findings = findings
    self.checked = checked
    self.breachCheckRan = breachCheckRan
    self.generatedAt = generatedAt
  }
}

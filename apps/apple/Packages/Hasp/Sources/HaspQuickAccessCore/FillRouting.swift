import Foundation

public struct TargetApp: Equatable, Sendable {
  public let bundleID: String
  public let name: String
  public let processID: Int32

  public init(bundleID: String, name: String, processID: Int32) {
    self.bundleID = bundleID
    self.name = name
    self.processID = processID
  }

  public var isBrowser: Bool { KnownBrowsers.bundleIDs.contains(bundleID) }
}

public enum KnownBrowsers {
  public static let bundleIDs: Set<String> = [
    "com.apple.Safari",
    "com.google.Chrome",
    "com.google.Chrome.beta",
    "com.google.Chrome.canary",
    "com.microsoft.edgemac",
    "com.brave.Browser",
    "org.mozilla.firefox",
    "company.thebrowser.Browser",
    "com.vivaldi.Vivaldi",
    "com.operasoftware.Opera",
  ]
}

public enum FillRoute: Equatable, Sendable {
  case browserExtension(bundleID: String)
  case type(into: TargetApp)
  case needsAccessibility
  case copyOnly(CopyOnlyReason)
}

public enum CopyOnlyReason: Equatable, Sendable {
  case noTarget
  case unsupportedKind
}

public struct FillContext: Equatable, Sendable {
  public let target: TargetApp?
  public let hasPairedExtension: Bool
  public let accessibilityTrusted: Bool
  public let kind: QuickItemKind

  public init(
    target: TargetApp?,
    hasPairedExtension: Bool,
    accessibilityTrusted: Bool,
    kind: QuickItemKind,
  ) {
    self.target = target
    self.hasPairedExtension = hasPairedExtension
    self.accessibilityTrusted = accessibilityTrusted
    self.kind = kind
  }
}

public enum FillRouter {
  public static func route(_ context: FillContext) -> FillRoute {
    guard context.kind == .login else { return .copyOnly(.unsupportedKind) }
    guard let target = context.target else { return .copyOnly(.noTarget) }
    if target.isBrowser, context.hasPairedExtension {
      return .browserExtension(bundleID: target.bundleID)
    }
    return context.accessibilityTrusted ? .type(into: target) : .needsAccessibility
  }
}

public struct TargetKey: Hashable, Sendable {
  let item: QuickItemID
  let bundleID: String
}

public enum FillConfirmation: Equatable, Sendable {
  case proceed
  case confirm(ConfirmReason)
}

public enum ConfirmReason: Equatable, Sendable {
  case unverifiedBrowserPage(appName: String, savedHosts: [String])
  case nativeApp(appName: String, savedHosts: [String])
}

public struct TypingApprovals: Sendable {
  private var approved: Set<TargetKey> = []

  public init() {}

  public mutating func approve(_ item: QuickItemID, in target: TargetApp) {
    approved.insert(TargetKey(item: item, bundleID: target.bundleID))
  }

  public mutating func reset() {
    approved.removeAll()
  }

  public func decision(for item: QuickItem, into target: TargetApp) -> FillConfirmation {
    let key = TargetKey(item: item.id, bundleID: target.bundleID)
    if target.isBrowser {
      return .confirm(.unverifiedBrowserPage(appName: target.name, savedHosts: item.hosts))
    }
    if approved.contains(key) { return .proceed }
    return .confirm(.nativeApp(appName: target.name, savedHosts: item.hosts))
  }
}

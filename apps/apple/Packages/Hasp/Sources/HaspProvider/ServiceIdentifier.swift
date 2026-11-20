import Foundation

/// A service the system asks credentials for. Apps carry an identifier that never matches a vault URL.
public struct ServiceIdentifier: Sendable, Equatable {
  public enum Kind: Sendable, Equatable {
    case domain, url, app
  }

  public let kind: Kind
  public let value: String

  public init(kind: Kind, value: String) {
    self.kind = kind
    self.value = value
  }
}

/// Turns the system's service identifiers into the strings the shared matcher ranks by.
/// Order is kept: the first identifier is the most specific one (AuthenticationServices header).
public enum ServiceMatching {
  public static func identifiers(for services: [ServiceIdentifier]) -> [String] {
    var seen = Set<String>()
    var result: [String] = []
    for service in services where service.kind != .app {
      let value = service.value.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !value.isEmpty, seen.insert(value).inserted else { continue }
      result.append(value)
    }
    return result
  }
}

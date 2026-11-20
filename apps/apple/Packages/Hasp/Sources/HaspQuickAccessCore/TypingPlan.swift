import Foundation

public enum FocusedFieldKind: Equatable, Sendable {
  case secure
  case plain
  case unknown
}

public enum TypingStep: Equatable, Sendable {
  case text(String)
  case tab
}

public struct TypingPlan: Equatable, Sendable {
  public let steps: [TypingStep]

  public static func login(
    username: String,
    password: String,
    focus: FocusedFieldKind,
    secureInputActive: Bool,
  ) -> TypingPlan {
    let passwordOnly = focus == .secure || (focus == .unknown && secureInputActive)
    if passwordOnly || username.isEmpty { return TypingPlan(steps: [.text(password)]) }
    return TypingPlan(steps: [.text(username), .tab, .text(password)])
  }

  public static func single(_ text: String) -> TypingPlan {
    TypingPlan(steps: [.text(text)])
  }
}

public enum UnicodeChunker {
  public static let maxUTF16Units = 20

  public static func chunks(_ text: String, limit: Int = maxUTF16Units) -> [[UInt16]] {
    var result: [[UInt16]] = []
    var current: [UInt16] = []
    for cluster in text {
      let units = Array(String(cluster).utf16)
      if units.count > limit {
        flush(&current, into: &result)
        result.append(contentsOf: splitByScalar(cluster, limit: limit))
        continue
      }
      if current.count + units.count > limit { flush(&current, into: &result) }
      current.append(contentsOf: units)
    }
    flush(&current, into: &result)
    return result
  }

  private static func flush(_ current: inout [UInt16], into result: inout [[UInt16]]) {
    guard !current.isEmpty else { return }
    result.append(current)
    current = []
  }

  private static func splitByScalar(_ cluster: Character, limit: Int) -> [[UInt16]] {
    var result: [[UInt16]] = []
    var current: [UInt16] = []
    for scalar in cluster.unicodeScalars {
      let units = Array(String(scalar).utf16)
      if current.count + units.count > limit { flush(&current, into: &result) }
      current.append(contentsOf: units)
    }
    flush(&current, into: &result)
    return result
  }
}

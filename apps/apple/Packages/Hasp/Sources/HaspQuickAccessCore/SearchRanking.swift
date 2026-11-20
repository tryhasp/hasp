public import Foundation

public struct SearchContext: Equatable, Sendable {
  public let frontmostHost: String?
  public let now: Date

  public init(frontmostHost: String?, now: Date) {
    self.frontmostHost = frontmostHost
    self.now = now
  }
}

public enum SearchRanking {
  public static func rank(
    _ items: [QuickItem],
    query: String,
    context: SearchContext,
  ) -> [QuickItem] {
    let needle = fold(query)
    let scored: [(item: QuickItem, score: Double)] = items.compactMap { item in
      guard let match = matchScore(item, needle: needle) else { return nil }
      return (item, match + boost(item, context: context))
    }
    return scored.sorted(by: ordered).map(\.item)
  }

  static func fold(_ text: String) -> String {
    text.precomposedStringWithCanonicalMapping
      .folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: nil)
  }

  static func matchScore(_ item: QuickItem, needle: String) -> Double? {
    if needle.isEmpty { return 0 }
    let fields: [(text: String, weight: Double)] =
      [(item.title, 1.0), (item.hosts.joined(separator: " "), 0.8), (item.username, 0.6)]
    let best = fields.compactMap { field in
      fuzzyScore(needle: needle, haystack: fold(field.text)).map { $0 * field.weight }
    }.max()
    return best
  }

  static func fuzzyScore(needle: String, haystack: String) -> Double? {
    if haystack == needle { return 100 }
    if haystack.hasPrefix(needle) { return 80 }
    if haystack.contains(needle) { return 60 }
    if let initials = initialsScore(needle: needle, haystack: haystack) { return initials }
    return subsequenceScore(needle: needle, haystack: haystack)
  }

  static func subsequenceScore(needle: String, haystack: String) -> Double? {
    var remaining = haystack[...]
    var gaps = 0
    var started = false
    for character in needle {
      guard let found = remaining.firstIndex(of: character) else { return nil }
      if started { gaps += remaining.distance(from: remaining.startIndex, to: found) }
      started = true
      remaining = remaining[remaining.index(after: found)...]
    }
    return max(10, 40 - Double(gaps))
  }

  static func initialsScore(needle: String, haystack: String) -> Double? {
    let initials = haystack.map { HangulInitials.initial(of: $0) }
    guard needle.allSatisfy({ HangulInitials.isInitial($0) }) else { return nil }
    let joined = String(initials)
    if joined.hasPrefix(needle) { return 50 }
    return joined.contains(needle) ? 35 : nil
  }

  static func boost(_ item: QuickItem, context: SearchContext) -> Double {
    var total = 0.0
    if let host = context.frontmostHost, item.hosts.contains(where: { hostMatches($0, host) }) {
      total += 200
    }
    if item.favourite { total += 8 }
    total += recency(item.modified, now: context.now)
    return total
  }

  static func hostMatches(_ saved: String, _ page: String) -> Bool {
    let lhs = saved.lowercased()
    let rhs = page.lowercased()
    return lhs == rhs || rhs.hasSuffix("." + lhs) || lhs.hasSuffix("." + rhs)
  }

  static func recency(_ modified: Date, now: Date) -> Double {
    let days = max(0, now.timeIntervalSince(modified) / 86_400)
    return 6 / (1 + days / 30)
  }

  static func ordered(
    _ lhs: (item: QuickItem, score: Double),
    _ rhs: (item: QuickItem, score: Double),
  ) -> Bool {
    if lhs.score != rhs.score { return lhs.score > rhs.score }
    return lhs.item.title.localizedStandardCompare(rhs.item.title) == .orderedAscending
  }
}

enum HangulInitials {
  private static let table: [Character] = Array("ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ")

  static func isInitial(_ character: Character) -> Bool {
    table.contains(character)
  }

  static func initial(of character: Character) -> Character {
    guard let scalar = character.unicodeScalars.first, character.unicodeScalars.count == 1,
      (0xAC00...0xD7A3).contains(scalar.value)
    else { return character }
    return table[Int(scalar.value - 0xAC00) / 588]
  }
}

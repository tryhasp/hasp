import Foundation
import HaspFFI
import Testing

private struct TextCase: Decodable {
  let name: String
  let scalars: [UInt32]
  let utf8: String?
  let err: String?

  var input: String {
    var view = String.UnicodeScalarView()
    for scalar in scalars.compactMap(Unicode.Scalar.init) {
      view.append(scalar)
    }
    return String(view)
  }
}

private struct TextVectors: Decodable {
  let cases: [TextCase]
}

private func hex(_ text: String) -> String {
  text.utf8.map { String(format: "%02x", $0) }.joined()
}

private func load(_ group: String) throws -> [TextCase] {
  let data = try Data(contentsOf: Vectors.root.appending(path: "\(group).json"))
  return try JSONDecoder().decode(TextVectors.self, from: data).cases
}

private func swiftPassword(_ input: String) -> String {
  input.trimmingCharacters(in: .whitespacesAndNewlines).decomposedStringWithCompatibilityMapping
}

private func swiftLogin(_ input: String) -> String {
  input.trimmingCharacters(in: .whitespacesAndNewlines).precomposedStringWithCompatibilityMapping
    .lowercased()
}

private func swiftLoginFolded(_ input: String) -> String {
  input.trimmingCharacters(in: .whitespacesAndNewlines).precomposedStringWithCompatibilityMapping
    .folding(options: [.caseInsensitive], locale: nil)
}

@Suite struct TextRulesTests {
  @Test func ffiPasswordMatchesTheVectors() throws {
    for textCase in try load("text/password") {
      #expect(textCase.err == nil, "\(textCase.name)")
      #expect(hex(normalisePassword(input: textCase.input)) == textCase.utf8, "\(textCase.name)")
    }
  }

  @Test func ffiLoginMatchesTheVectors() throws {
    var rejected = 0
    for textCase in try load("text/login") {
      do {
        let output = try normaliseLogin(input: textCase.input)
        #expect(hex(output) == textCase.utf8, "\(textCase.name)")
      } catch HaspError.Format {
        rejected += 1
        #expect(textCase.err == "Format", "\(textCase.name)")
      }
    }
    #expect(rejected == (try load("text/login").filter { $0.err != nil }.count))
    #expect(rejected > 0)
  }

  @Test func foundationPasswordRuleDivergesFromRust() throws {
    let diverging = try load("text/password").filter {
      $0.utf8 != nil && hex(swiftPassword($0.input)) != $0.utf8
    }
    #expect(diverging.map(\.name) == ["trim-zero-width-space", "unicode-18-armenian"])
  }

  @Test func foundationLoginRuleDivergesFromRust() throws {
    let diverging = try load("text/login").filter {
      $0.utf8 != nil && hex(swiftLogin($0.input)) != $0.utf8
    }
    #expect(
      diverging.map(\.name) == [
        "trim-bom",
        "korean-compat-jamo",
        "korean-halfwidth-jamo",
        "german-sharp-s",
        "german-capital-sharp-s",
        "german-strasse",
        "greek-small-final-sigma",
        "cherokee",
        "emoji-zwj-family",
        "unicode-18-armenian",
        "zero-width-space-inside",
        "soft-hyphen-inside",
        "greek-iota-subscript",
        "greek-iota-subscript-then-mark",
        "halfwidth-katakana",
      ]
    )
  }

  @Test func foundationCaseFoldingDivergesFromRust() throws {
    let diverging = try load("text/login").filter {
      $0.utf8 != nil && hex(swiftLoginFolded($0.input)) != $0.utf8
    }
    #expect(
      diverging.map(\.name) == [
        "trim-bom",
        "korean-compat-jamo",
        "korean-halfwidth-jamo",
        "cherokee",
        "emoji-zwj-family",
        "unicode-18-armenian",
        "zero-width-space-inside",
        "soft-hyphen-inside",
        "halfwidth-katakana",
      ]
    )
  }
}

import HaspFFI
import Testing

@Suite struct ReplayTests {
  @Test(arguments: vectorGroups())
  func replaysIdenticallyToRust(group: String) throws {
    let outcomes = try replayVectors(group: group, vectors: Vectors.read(group))
    #expect(!outcomes.isEmpty)
    let mismatches = outcomes.filter { $0.expected != $0.actual }.map(\.name)
    #expect(mismatches.isEmpty, "\(mismatches)")
  }

  @Test func groupsCoverEveryVectorFamily() {
    let groups = Set(vectorGroups())
    #expect(groups.contains("proto/verify"))
    #expect(groups.contains("crypto/argon2id"))
    #expect(groups.contains("text/login"))
  }

  @Test func unknownGroupIsATypedError() {
    #expect(throws: HaspError.Internal) {
      try replayVectors(group: "crypto/unknown", vectors: "{}")
    }
  }
}

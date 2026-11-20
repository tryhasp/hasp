import AuthenticationServices
import Foundation
import HaspKit
import Testing

@testable import HaspProvider

struct CredentialExchangeTests {
  @available(macOS 26.0, iOS 26.0, *)
  private func sample() -> ASExportedCredentialData {
    let item = ASImportableItem(
      id: Data([1, 2, 3]),
      created: Date(timeIntervalSince1970: 1_700_000_000),
      lastModified: Date(timeIntervalSince1970: 1_700_000_100),
      title: "Example",
      credentials: [
        .basicAuthentication(
          .init(
            userName: .init(id: nil, fieldType: .string, value: "alice"),
            password: .init(id: nil, fieldType: .concealedString, value: "pw"),
          )
        )
      ],
    )
    let account = ASImportableAccount(
      id: Data([9]),
      userName: "u",
      email: "e@example.com",
      collections: [],
      items: [item],
    )
    return ASExportedCredentialData(
      accounts: [account],
      formatVersion: .v1,
      exporterRelyingPartyIdentifier: "com.apple.Passwords",
      exporterDisplayName: "Passwords",
      timestamp: Date(timeIntervalSince1970: 1_700_000_200),
    )
  }

  private func object(_ data: Data) throws -> [String: Any] {
    try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
  }

  @Test func theSDKPropertiesBecomeTheCXFMembersTheEngineReads() throws {
    guard #available(macOS 26.0, iOS 26.0, *) else { return }
    let json = try object(SystemCredentialExchange.cxfJSON(sample()))
    #expect(json["exporterRpId"] as? String == "com.apple.Passwords")
    #expect(json["exporterDisplayName"] as? String == "Passwords")
    let version = try #require(json["version"] as? [String: Int])
    #expect(version == ["major": 1, "minor": 0])
    let accounts = try #require(json["accounts"] as? [[String: Any]])
    let items = try #require(accounts.first?["items"] as? [[String: Any]])
    #expect(accounts.first?["username"] as? String == "u")
    #expect(items.first?["id"] as? String == "AQID")
    let credentials = try #require(items.first?["credentials"] as? [[String: Any]])
    #expect(credentials.first?["type"] as? String == "basic-auth")
  }

  @Test func datesAreUnixSecondsNotSecondsSince2001() throws {
    guard #available(macOS 26.0, iOS 26.0, *) else { return }
    let json = try object(SystemCredentialExchange.cxfJSON(sample()))
    #expect(json["timestamp"] as? Int == 1_700_000_200)
    let accounts = try #require(json["accounts"] as? [[String: Any]])
    let items = try #require(accounts.first?["items"] as? [[String: Any]])
    #expect(items.first?["creationAt"] as? Int == 1_700_000_000)
    #expect(items.first?["modifiedAt"] as? Int == 1_700_000_100)

    let plain = JSONEncoder()
    let shifted = try object(plain.encode(sample()))
    #expect(shifted["timestamp"] as? Int == 1_700_000_200 - 978_307_200)
  }

  @Test func theActivityAndTokenLiteralsAreTheSDKConstants() {
    guard #available(macOS 26.0, iOS 26.0, *) else { return }
    #expect(CredentialExchangeActivity.activityType == ASCredentialExchangeActivity)
    #expect(CredentialExchangeActivity.tokenKey == ASCredentialImportToken)
  }

  @Test func theTokenIsReadFromTheActivityUserInfo() {
    guard #available(macOS 26.0, iOS 26.0, *) else { return }
    let token = UUID()
    #expect(CredentialExchangeActivity.token(from: [ASCredentialImportToken: token]) == token)
    #expect(CredentialExchangeActivity.token(from: ["other": token]) == nil)
    #expect(CredentialExchangeActivity.token(from: nil) == nil)
  }

  @Test func theImporterPassesTheStagedDocumentToTheEngine() async throws {
    struct Staged: CredentialExchangeSource {
      let document: Data
      func document(token: UUID) async throws -> Data { document }
    }
    let engine = FakeProvider()
    let document = Data("{}".utf8)
    let summary = try await CredentialExchangeImporter(
      source: Staged(document: document),
      engine: engine,
    ).receive(token: UUID())
    #expect(summary.imported == 3)
    #expect(await engine.importedDocuments == [document])
  }
}

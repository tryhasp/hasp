import Foundation
import HaspKit
import Testing

@testable import HaspProvider

struct MatchingTests {
  @Test func identifiersKeepOrderAndDropDuplicatesAndAppsAndBlanks() {
    let services = [
      ServiceIdentifier(kind: .url, value: "https://m.example.com/login"),
      ServiceIdentifier(kind: .domain, value: "example.com"),
      ServiceIdentifier(kind: .domain, value: " example.com "),
      ServiceIdentifier(kind: .app, value: "com.example.app"),
      ServiceIdentifier(kind: .domain, value: "  "),
    ]
    #expect(
      ServiceMatching.identifiers(for: services) == ["https://m.example.com/login", "example.com"]
    )
  }

  @Test func noServicesMeansTheWholeLoginList() {
    #expect(ServiceMatching.identifiers(for: []).isEmpty)
  }

  @Test(arguments: [
    ("p:ab:cd:example.com", CredentialRecord.Kind.password, "example.com"),
    ("o:ab:cd:example.com", .oneTimeCode, "example.com"),
    ("k:ab:cd:AQID_w", .passkey, "AQID_w"),
    ("p:ab:cd:host:8443", .password, "host:8443"),
  ])
  func recordsNameKindItemAndTail(identifier: String, kind: CredentialRecord.Kind, tail: String) {
    let record = CredentialRecord(identifier)
    #expect(record?.kind == kind)
    #expect(record?.key == ItemKey(vault: VaultID("ab"), item: "cd"))
    #expect(record?.tail == tail)
  }

  @Test(arguments: [nil, "", "p:ab:cd", "x:ab:cd:host", "p::cd:host", "p:ab::host", "p:ab:cd:"])
  func malformedRecordsAreRefused(identifier: String?) {
    #expect(CredentialRecord(identifier) == nil)
  }

  @Test func base64URLRoundTripsWithoutPadding() throws {
    let data = Data([0xfb, 0xff, 0x01, 0x02])
    let text = data.base64URLString()
    #expect(text == "-_8BAg")
    #expect(Data(base64URLString: text) == data)
    #expect(Data(base64URLString: "!!") == nil)
  }
}

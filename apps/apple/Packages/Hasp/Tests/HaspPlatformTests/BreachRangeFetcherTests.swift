import Foundation
import Synchronization
import Testing

@testable import HaspPlatform

@Suite struct BreachRangeFetcherTests {
  @Test func configurationKeepsNothingOnDisk() {
    let configuration = BreachRangeFetcher.configuration()
    #expect(configuration.urlCache == nil)
    #expect(configuration.requestCachePolicy == .reloadIgnoringLocalAndRemoteCacheData)
    #expect(configuration.httpCookieStorage == nil)
    #expect(!configuration.httpShouldSetCookies)
    #expect(configuration.urlCredentialStorage == nil)
    #expect(configuration.identifier == nil)
  }

  @Test func noSessionExistsUntilTheFirstRange() {
    let created = Mutex(0)
    let fetcher = BreachRangeFetcher(makeSession: {
      created.withLock { $0 += 1 }
      return URLSession(configuration: BreachRangeFetcher.configuration())
    })
    #expect(created.withLock { $0 } == 0)
    #expect(throws: (any Error).self) { try fetcher.range(prefix: "zz") }
    #expect(created.withLock { $0 } == 0)
  }
}

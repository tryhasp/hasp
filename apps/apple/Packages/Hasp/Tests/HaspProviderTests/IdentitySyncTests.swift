import HaspKit
import Testing

@testable import HaspProvider

struct IdentitySyncTests {
  private let all = [
    identity(.password, record: "p:v:i:example.com"),
    identity(.oneTimeCode, record: "o:v:i:example.com"),
    identity(.passkey, record: "k:v:i:AQID"),
  ]

  private func change(_ fingerprint: String, changed: Bool = true) -> IdentityChange {
    IdentityChange(changed: changed, fingerprint: fingerprint, identities: changed ? all : [])
  }

  @Test func aChangedVaultReplacesTheStoreWithEveryKindThenAcknowledges() async throws {
    let source = FakeProvider()
    await source.set(changes: [change("f1")])
    let store = FakeIdentityStore()
    let outcome = try await IdentitySync(source: source, store: store).refresh()
    #expect(outcome == .replaced(count: 3))
    #expect(await store.sets == [all])
    #expect(await source.calls.acknowledged == ["f1"])
    #expect(Set(all.map(\.kind)) == [.password, .oneTimeCode, .passkey])
  }

  @Test func anUnchangedVaultTouchesNothing() async throws {
    let source = FakeProvider()
    await source.set(changes: [change("f1", changed: false)])
    let store = FakeIdentityStore()
    let outcome = try await IdentitySync(source: source, store: store).refresh()
    #expect(outcome == .unchanged)
    #expect(await store.sets.isEmpty)
    #expect(await source.calls.acknowledged.isEmpty)
  }

  @Test func aDisabledStoreIsNotFilledAndNothingIsAcknowledged() async throws {
    let source = FakeProvider()
    await source.set(changes: [change("f1")])
    let store = FakeIdentityStore()
    await store.set(enabled: false)
    let outcome = try await IdentitySync(source: source, store: store).refresh()
    #expect(outcome == .disabled)
    #expect(await source.calls.acknowledged.isEmpty)
  }

  @Test func aFailedReplaceSendsNoAcknowledgement() async {
    let source = FakeProvider()
    await source.set(changes: [change("f1")])
    let store = FakeIdentityStore()
    await store.set(failure: HaspError.internal)
    await #expect(throws: HaspError.internal) {
      try await IdentitySync(source: source, store: store).refresh()
    }
    #expect(await source.calls.acknowledged.isEmpty)
  }

  @Test func oneBadIdentityIsSkippedAndTheRestIsStoredAndAcknowledged() async throws {
    let source = FakeProvider()
    await source.set(changes: [change("f1")])
    let store = FakeIdentityStore()
    await store.reject(records: ["o:v:i:example.com"])
    let outcome = try await IdentitySync(source: source, store: store).refresh()
    #expect(outcome == .replaced(count: 2, skipped: 1))
    #expect(await store.saved.map(\.record) == ["p:v:i:example.com", "k:v:i:AQID"])
    #expect(await source.calls.acknowledged == ["f1"])
  }

  @Test func aStoreThatRejectsEverythingSendsNoAcknowledgement() async {
    let source = FakeProvider()
    await source.set(changes: [change("f1")])
    let store = FakeIdentityStore()
    await store.reject(records: Set(all.map(\.record)))
    await #expect(throws: HaspError.self) {
      try await IdentitySync(source: source, store: store).refresh()
    }
    #expect(await source.calls.acknowledged.isEmpty)
  }

  @Test func aConflictingAcknowledgementAsksForTheDiffAgain() async throws {
    let source = FakeProvider()
    await source.set(changes: [change("f1"), change("f2")])
    await source.set(acknowledgeErrors: [.conflict])
    let store = FakeIdentityStore()
    let outcome = try await IdentitySync(source: source, store: store).refresh()
    #expect(outcome == .replaced(count: 3))
    #expect(await source.calls.acknowledged == ["f1", "f2"])
    #expect(await store.sets.count == 2)
  }

  @Test func theAppHookSkipsSessionsThatAreNotProviders() async {
    let store = FakeIdentityStore()
    let outcome = await IdentityRefresh.run(after: NotAProvider(), into: store)
    #expect(outcome == nil)
    #expect(await store.sets.isEmpty)
  }
}

struct IdentityClearingTests {
  @Test func clearingEmptiesTheStoreOnce() async {
    let store = FakeIdentityStore()
    await IdentityRefresh.clear(store)
    #expect(await store.removals == 1)
  }

  @Test func aFailingStoreDoesNotCrashTheClear() async {
    let store = FakeIdentityStore()
    await store.set(failure: HaspError.internal)
    await IdentityRefresh.clear(store)
    #expect(await store.removals == 0)
  }
}

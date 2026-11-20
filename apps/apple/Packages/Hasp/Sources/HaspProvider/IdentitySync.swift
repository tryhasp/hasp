public import HaspKit

/// The system's QuickType store, reduced to what the sync needs. The fake in tests records the sets.
public protocol CredentialIdentityStoring: Sendable {
  func isEnabled() async -> Bool
  func replaceAll(with identities: [CredentialIdentity]) async throws
  func removeAll() async throws
  func save(_ identity: CredentialIdentity) async throws
}

/// Keeps `ASCredentialIdentityStore` equal to the vault: engine diff, replace, acknowledge.
/// A failed bulk replace falls back to saving one by one, so a single bad identity cannot block
/// every later update. A failure that leaves the store unusable sends no acknowledgement.
public actor IdentitySync {
  public enum Outcome: Sendable, Equatable {
    case unchanged
    case replaced(count: Int, skipped: Int = 0)
    case disabled
  }

  private static let attempts = 3

  private let source: any ProviderServing
  private let store: any CredentialIdentityStoring

  public init(source: any ProviderServing, store: any CredentialIdentityStoring) {
    self.source = source
    self.store = store
  }

  public func refresh() async throws -> Outcome {
    guard await store.isEnabled() else { return .disabled }
    for _ in 0..<Self.attempts {
      let change = try await source.identityChange()
      guard change.changed else { return .unchanged }
      let skipped = try await replace(change.identities)
      do {
        try await source.acknowledgeIdentities(fingerprint: change.fingerprint)
        return .replaced(count: change.identities.count - skipped, skipped: skipped)
      } catch HaspError.conflict {
        continue
      }
    }
    throw HaspError.conflict
  }

  private func replace(_ identities: [CredentialIdentity]) async throws -> Int {
    do {
      try await store.replaceAll(with: identities)
      return 0
    } catch {
      do {
        try await store.removeAll()
      } catch {
        throw error
      }
      var skipped = 0
      for identity in identities {
        do {
          try await store.save(identity)
        } catch {
          skipped += 1
        }
      }
      if skipped == identities.count && !identities.isEmpty { throw error }
      return skipped
    }
  }
}

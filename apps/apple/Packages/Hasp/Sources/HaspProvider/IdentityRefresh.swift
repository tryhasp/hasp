public import HaspKit
import OSLog

private let log = Logger(subsystem: "kr.jmo.hasp", category: "quicktype")

/// The app's hook: after a sync, a lock-policy change or the extension being enabled, bring the
/// system's QuickType store in line with the unlocked vault. A locked or failing engine only logs.
public enum IdentityRefresh {
  /// Sign-out, a revoked device, a new account or no account at all: the next person must not see
  /// this account's sites and user names above the keyboard.
  public static func clear(_ store: any CredentialIdentityStoring) async {
    do {
      try await store.removeAll()
    } catch {
      log.error("the quicktype store was not cleared")
    }
  }

  @discardableResult
  public static func run(
    after session: any VaultServing,
    into store: any CredentialIdentityStoring,
  ) async -> IdentitySync.Outcome? {
    guard let source = session as? any ProviderServing else { return nil }
    do {
      return try await IdentitySync(source: source, store: store).refresh()
    } catch HaspError.locked {
      return nil
    } catch {
      log.error("the quicktype store was not refreshed")
      return nil
    }
  }
}

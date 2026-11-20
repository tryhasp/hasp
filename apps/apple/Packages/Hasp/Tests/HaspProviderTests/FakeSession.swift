import Foundation
import HaspKit

struct NotAProvider: VaultServing {
  var events: AsyncStream<SessionEvent> { AsyncStream { $0.finish() } }
  func status() async throws -> AccountStatus { throw HaspError.internal }
  func serverFingerprint() async throws -> String { throw HaspError.internal }
  func signIn(login: String, secretKey: String, password: String, serverFingerprint: String)
    async throws
  { throw HaspError.internal }
  func signUp(login: String, code: String, password: String, serverFingerprint: String)
    async throws -> EmergencyKit
  { throw HaspError.internal }
  func signInWithKit(blob: Data, password: String) async throws { throw HaspError.internal }
  func unlockPassword(_ password: String) async throws { throw HaspError.internal }
  func unlockBiometric() async throws { throw HaspError.internal }
  func enableHardwareUnlock(password: String) async throws { throw HaspError.internal }
  func lock() async {}
  func applyLockTrigger(_ trigger: LockTrigger, elapsed: Duration) async throws -> Bool {
    throw HaspError.internal
  }
  func settings() async throws -> AppSettings { throw HaspError.internal }
  func setSettings(_ settings: AppSettings) async throws { throw HaspError.internal }
  func sync() async throws -> SyncOutcome { throw HaspError.internal }
  func startHints() async throws {}
  func stopHints() async {}
  func vaults() async throws -> [VaultSummary] { [] }
  func categories() async -> [ItemCategory] { [] }
  func items(in vault: VaultID) async throws -> [ItemSummary] { [] }
  func search(_ filter: SearchFilter) async throws -> [ItemSummary] { [] }
  func detail(_ key: ItemKey) async throws -> ItemDetail { throw HaspError.internal }
  func blankDraft(kind: String) async throws -> ItemDraft { throw HaspError.internal }
  func editDraft(_ key: ItemKey) async throws -> ItemDraft { throw HaspError.internal }
  func createItem(in vault: VaultID, draft: ItemDraft) async throws -> ItemKey {
    throw HaspError.internal
  }
  func editItem(_ key: ItemKey, draft: ItemDraft) async throws { throw HaspError.internal }
  func setStatus(_ key: ItemKey, status: ItemStatus) async throws { throw HaspError.internal }
  func setFavourite(_ key: ItemKey, favourite: Bool) async throws { throw HaspError.internal }
  func deleteItem(_ key: ItemKey) async throws { throw HaspError.internal }
  func history(_ key: ItemKey) async throws -> [HistoryEntry] { [] }
  func restoreVersion(_ key: ItemKey, version: Int) async throws { throw HaspError.internal }
  func revealField(_ key: ItemKey, field: String) async throws -> RevealedSecret {
    throw HaspError.internal
  }
  func totp(_ key: ItemKey, field: String?) async throws -> TOTPSnapshot {
    throw HaspError.internal
  }
  func generate(_ options: GeneratorOptions) async throws -> GeneratedSecret {
    throw HaspError.internal
  }
  func attachFile(_ key: ItemKey, name: String, mime: String, data: Data) async throws
    -> AttachmentSummary
  { throw HaspError.internal }
  func downloadAttachment(_ key: ItemKey, attachment: String) async throws -> Data {
    throw HaspError.internal
  }
  func removeAttachment(_ key: ItemKey, attachment: String) async throws {
    throw HaspError.internal
  }
  func watchtower() async throws -> WatchtowerSummary { throw HaspError.internal }
  func checkBreaches(using source: any BreachRangeSource) async throws -> WatchtowerSummary {
    throw HaspError.internal
  }
  func devices() async throws -> [DeviceSummary] { [] }
  func revokeDevice(_ device: DeviceSummary) async throws {}
}

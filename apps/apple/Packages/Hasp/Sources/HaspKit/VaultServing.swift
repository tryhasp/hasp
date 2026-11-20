public import Foundation

/// What the interface needs from an account. `AccountSession` is the engine-backed one.
public protocol VaultServing: Sendable {
  var events: AsyncStream<SessionEvent> { get }

  func status() async throws -> AccountStatus
  func serverFingerprint() async throws -> String
  func signIn(login: String, secretKey: String, password: String, serverFingerprint: String)
    async throws
  func signUp(login: String, code: String, password: String, serverFingerprint: String)
    async throws -> EmergencyKit
  func signInWithKit(blob: Data, password: String) async throws
  func unlockPassword(_ password: String) async throws
  func unlockBiometric() async throws
  func enableHardwareUnlock(password: String) async throws
  func lock() async
  func applyLockTrigger(_ trigger: LockTrigger, elapsed: Duration) async throws -> Bool

  func settings() async throws -> AppSettings
  func setSettings(_ settings: AppSettings) async throws

  func sync() async throws -> SyncOutcome
  func startHints() async throws
  func stopHints() async

  func vaults() async throws -> [VaultSummary]
  func categories() async -> [ItemCategory]
  func items(in vault: VaultID) async throws -> [ItemSummary]
  func search(_ filter: SearchFilter) async throws -> [ItemSummary]
  func detail(_ key: ItemKey) async throws -> ItemDetail
  func blankDraft(kind: String) async throws -> ItemDraft
  func editDraft(_ key: ItemKey) async throws -> ItemDraft
  func createItem(in vault: VaultID, draft: ItemDraft) async throws -> ItemKey
  func editItem(_ key: ItemKey, draft: ItemDraft) async throws
  func setStatus(_ key: ItemKey, status: ItemStatus) async throws
  func setFavourite(_ key: ItemKey, favourite: Bool) async throws
  func deleteItem(_ key: ItemKey) async throws
  func history(_ key: ItemKey) async throws -> [HistoryEntry]
  func restoreVersion(_ key: ItemKey, version: Int) async throws

  func revealField(_ key: ItemKey, field: String) async throws -> RevealedSecret
  func totp(_ key: ItemKey, field: String?) async throws -> TOTPSnapshot
  func generate(_ options: GeneratorOptions) async throws -> GeneratedSecret
  func attachFile(_ key: ItemKey, name: String, mime: String, data: Data) async throws
    -> AttachmentSummary
  func downloadAttachment(_ key: ItemKey, attachment: String) async throws -> Data
  func removeAttachment(_ key: ItemKey, attachment: String) async throws

  func watchtower() async throws -> WatchtowerSummary
  func checkBreaches(using source: any BreachRangeSource) async throws -> WatchtowerSummary

  func devices() async throws -> [DeviceSummary]
  func revokeDevice(_ device: DeviceSummary) async throws
}

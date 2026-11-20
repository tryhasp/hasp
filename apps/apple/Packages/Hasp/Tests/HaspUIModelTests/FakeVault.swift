import Foundation
import HaspKit

final class FakeVault: VaultServing, @unchecked Sendable {
  // Why: tests drive it from one task at a time.
  var state = LockState.locked
  var items: [ItemSummary]
  var settingsValue = AppSettings()
  var triggers: [LockTrigger] = []
  var breachChecks = 0
  var locksOnTrigger = true
  var lastElapsed: Duration?
  var syncs = 0
  var hardwareEnabled = false
  var signInError: HaspError?
  var hangsOnStatus = false
  let events = AsyncStream<SessionEvent>.makeStream().stream

  init(items: [ItemSummary] = []) {
    self.items = items
  }

  func status() async throws -> AccountStatus {
    if hangsOnStatus { try await Task.sleep(for: .seconds(3600)) }
    return AccountStatus(
      state: state,
      login: "me@example.com",
      origin: "http://127.0.0.1:1",
      unlockMode: hardwareEnabled ? .hardware : .passwordOnly,
    )
  }
  func serverFingerprint() async throws -> String { "AAAA-BBBB" }
  func signIn(login: String, secretKey: String, password: String, serverFingerprint: String)
    async throws
  {
    if let signInError { throw signInError }
    guard password == "pw", serverFingerprint == "AAAA-BBBB" else { throw HaspError.auth }
    state = .unlocked
  }
  func signUp(login: String, code: String, password: String, serverFingerprint: String)
    async throws -> EmergencyKit
  {
    guard serverFingerprint == "AAAA-BBBB" else { throw HaspError.auth }
    state = .unlocked
    return EmergencyKit(
      origin: "http://127.0.0.1:1",
      login: login,
      serverFingerprint: serverFingerprint,
      secretKey: "V1-TEST",
      documentText: "kit",
      documentPdf: Data(),
    )
  }
  func signInWithKit(blob: Data, password: String) async throws { state = .unlocked }
  func unlockPassword(_ password: String) async throws {
    guard password == "pw" else { throw HaspError.auth }
    state = .unlocked
  }
  func unlockBiometric() async throws { state = .unlocked }
  func enableHardwareUnlock(password: String) async throws {
    guard password == "pw" else { throw HaspError.auth }
    hardwareEnabled = true
  }
  func lock() async { state = .locked }
  func applyLockTrigger(_ trigger: LockTrigger, elapsed: Duration) async throws -> Bool {
    triggers.append(trigger)
    lastElapsed = elapsed
    guard locksOnTrigger else { return false }
    state = .locked
    return true
  }
  func settings() async throws -> AppSettings { settingsValue }
  func setSettings(_ settings: AppSettings) async throws { settingsValue = settings }
  func sync() async throws -> SyncOutcome {
    syncs += 1
    return SyncOutcome(vaults: 1, changed: 0, needsAttention: 0)
  }
  func startHints() async throws {}
  func stopHints() async {}
  func vaults() async throws -> [VaultSummary] {
    [VaultSummary(id: VaultID("v1"), name: "개인", kind: "personal", role: "owner")]
  }
  func categories() async -> [ItemCategory] {
    [ItemCategory(id: "login", nameEn: "Login", nameKo: "로그인", icon: "key")]
  }
  func items(in vault: VaultID) async throws -> [ItemSummary] { items }
  func search(_ filter: SearchFilter) async throws -> [ItemSummary] {
    items.filter { filter.text.isEmpty || $0.title.contains(filter.text) }
  }
  func detail(_ key: ItemKey) async throws -> ItemDetail {
    ItemDetail(summary: items.first { $0.key == key } ?? items[0])
  }
  func blankDraft(kind: String) async throws -> ItemDraft { ItemDraft(kind: kind) }
  func editDraft(_ key: ItemKey) async throws -> ItemDraft { ItemDraft(kind: "login") }
  func createItem(in vault: VaultID, draft: ItemDraft) async throws -> ItemKey {
    let key = ItemKey(vault: vault, item: "new")
    items.append(ItemSummary(key: key, kind: draft.kind, title: draft.title))
    return key
  }
  func editItem(_ key: ItemKey, draft: ItemDraft) async throws {}
  func setStatus(_ key: ItemKey, status: ItemStatus) async throws {
    if let index = items.firstIndex(where: { $0.key == key }) { items[index].status = status }
  }
  func setFavourite(_ key: ItemKey, favourite: Bool) async throws {}
  func deleteItem(_ key: ItemKey) async throws { items.removeAll { $0.key == key } }
  func history(_ key: ItemKey) async throws -> [HistoryEntry] { [] }
  func restoreVersion(_ key: ItemKey, version: Int) async throws {}
  func revealField(_ key: ItemKey, field: String) async throws -> RevealedSecret {
    RevealedSecret(text: "secret")
  }
  func totp(_ key: ItemKey, field: String?) async throws -> TOTPSnapshot {
    TOTPSnapshot(code: "123456", remaining: 18, period: 30, digits: 6)
  }
  func generate(_ options: GeneratorOptions) async throws -> GeneratedSecret {
    GeneratedSecret(secret: RevealedSecret(text: "generated"), bits: 100, length: 9)
  }
  func attachFile(_ key: ItemKey, name: String, mime: String, data: Data) async throws
    -> AttachmentSummary
  { AttachmentSummary(id: "a", name: name, mime: mime, size: data.count) }
  func downloadAttachment(_ key: ItemKey, attachment: String) async throws -> Data { Data() }
  func removeAttachment(_ key: ItemKey, attachment: String) async throws {}
  func watchtower() async throws -> WatchtowerSummary {
    WatchtowerSummary(findings: [], checked: items.count, breachCheckRan: false, generatedAt: .now)
  }
  func checkBreaches(using source: any BreachRangeSource) async throws -> WatchtowerSummary {
    breachChecks += 1
    return try await watchtower()
  }
  func devices() async throws -> [DeviceSummary] { [] }
  func revokeDevice(_ device: DeviceSummary) async throws {}
}

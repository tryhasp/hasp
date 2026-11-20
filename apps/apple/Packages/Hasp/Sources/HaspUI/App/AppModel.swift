public import Foundation
public import HaspKit
public import HaspQuickAccessCore
import Observation

@Observable
public final class AppModel {
  public enum Phase: Equatable {
    case starting
    case onboarding
    case locked
    case unlocked
  }

  public enum LockReason: Equatable {
    case manual
    case idle(minutes: Int)
    case sleep
    case screenLock
    case userSwitch
    case policy
  }

  public internal(set) var phase = Phase.starting
  public internal(set) var status: AccountStatus?
  public internal(set) var settings = AppSettings()
  public internal(set) var lockReason: LockReason?
  public internal(set) var toast: String?
  var library: LibraryModel?
  public internal(set) var notice: String?
  public internal(set) var busy = false
  public internal(set) var emergencyKit: EmergencyKit?
  public var settingsTab = SettingsTab.security
  public var quickAccess: (any QuickAccessControl)?
  public internal(set) var showsQuickAccessIntro = false
  public internal(set) var unlockAdvice: UnlockAdvice?
  public var showsUnlockAdvice = false

  let environment: AppEnvironment
  var session: (any VaultServing)?
  var eventLoop: Task<Void, Never>?
  var loops: [Task<Void, Never>] = []
  var toastTask: Task<Void, Never>?
  public internal(set) var isDecidingLock = false
  var backgroundedAt: ContinuousClock.Instant?
  var onLocked: @Sendable () async -> Void = {}
  var launchDeadline = Duration.seconds(20)

  public init(environment: AppEnvironment) {
    self.environment = environment
  }

  public var isHardwareBacked: Bool { environment.isHardwareBacked }

  public func setLockObserver(_ observer: @escaping @Sendable () async -> Void) {
    onLocked = observer
  }

  public func launch() async {
    guard phase == .starting else { return }
    guard let origin = environment.storedOrigin() else {
      await environment.accountDidEnd()
      phase = .onboarding
      return
    }
    do {
      let opened = try environment.makeSession(origin)
      let current = try await Self.within(launchDeadline) { try await opened.status() }
      status = current
      refreshUnlockAdvice(offering: false)
      guard current.state != .empty else {
        await environment.accountDidEnd()
        phase = .onboarding
        return
      }
      session = opened
      phase = .locked
      startEventLoop(for: opened)
    } catch is LaunchTimeout {
      notice = String(localized: "error.startTimeout")
      phase = .onboarding
    } catch {
      notice = UserMessage.text(for: error)
      phase = .onboarding
    }
  }

  private struct LaunchTimeout: Error {}

  private static func within<T: Sendable>(
    _ limit: Duration,
    _ work: @escaping @Sendable () async throws -> T,
  ) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
      group.addTask { try await work() }
      group.addTask {
        try await Task.sleep(for: limit)
        throw LaunchTimeout()
      }
      defer { group.cancelAll() }
      guard let first = try await group.next() else { throw LaunchTimeout() }
      return first
    }
  }

  /// Only an open vault is hidden; onboarding and the lock screen hold nothing to hide and must never be covered.
  public func showsPrivacyShield(sceneActive: Bool) -> Bool {
    phase == .unlocked && (!sceneActive || isDecidingLock)
  }

  public func openItem(vault: String, item: String) {
    guard let library else { return }
    library.selection = .all
    library.searchText = ""
    library.selectedKey = ItemKey(vault: VaultID(vault), item: item)
  }

  public func dismissQuickAccessIntro() {
    showsQuickAccessIntro = false
    UserDefaults.standard.set(true, forKey: Self.introSeenKey)
  }

  static let introSeenKey = "hasp.quickAccessIntroSeen"

  public var clipboard: ClipboardClearer { environment.clipboard }

  public var activeSession: (any VaultServing)? { session }

  var breachSource: any BreachRangeSource { environment.breachSource }

  func show(error: any Error) {
    notice = UserMessage.text(for: error, store: environment.storeFailure())
  }

  func refreshStatus() async {
    guard let session else { return }
    if let current = try? await session.status() { status = current }
  }
}

import Foundation
import HaspKit
import Synchronization
import Testing

@testable import HaspUI

@MainActor
private func unlockedModel(
  vault: FakeVault,
  afterSync: @escaping @Sendable (any VaultServing) async -> Void = { _ in },
) async -> AppModel {
  let model = makeModel(origin: nil, vault: vault, afterSync: afterSync)
  await model.launch()
  await model.signIn(
    origin: "http://127.0.0.1:1",
    login: "me",
    secretKey: "k",
    password: "pw",
    fingerprint: "AAAA-BBBB",
  )
  return model
}

@MainActor
struct BackgroundLockTests {
  @Test func returningAfterTheBackgroundLimitLocks() async {
    let vault = FakeVault()
    let model = await unlockedModel(vault: vault)
    let start = ContinuousClock.now
    model.sceneDidBackground(at: start)
    await model.sceneDidActivate(at: start + .seconds(90))
    #expect(vault.triggers == [.background])
    #expect(vault.lastElapsed == .seconds(90))
    #expect(model.phase == .locked)
    #expect(model.lockReason == .policy)
  }

  @Test func returningInsideTheLimitStaysUnlockedAndSyncs() async {
    let vault = FakeVault()
    vault.locksOnTrigger = false
    let model = await unlockedModel(vault: vault)
    let before = vault.syncs
    let start = ContinuousClock.now
    model.sceneDidBackground(at: start)
    await model.sceneDidActivate(at: start + .seconds(5))
    #expect(model.phase == .unlocked)
    #expect(vault.syncs == before + 1)
  }

  @Test func aLockedAppIgnoresBackgroundTransitions() async {
    let vault = FakeVault()
    let model = makeModel(origin: URL(string: "http://127.0.0.1:1"), vault: vault)
    await model.launch()
    model.sceneDidBackground(at: .now)
    await model.sceneDidActivate(at: .now + .seconds(300))
    #expect(vault.triggers.isEmpty)
    #expect(model.phase == .locked)
  }

  @Test func theShieldDecisionIsPendingFromTheSceneChangeUntilTheRuleRan() async {
    let vault = FakeVault()
    let model = await unlockedModel(vault: vault)
    let start = ContinuousClock.now
    model.sceneDidBackground(at: start)
    model.sceneWillActivate()
    #expect(model.isDecidingLock)
    await model.sceneDidActivate(at: start + .seconds(90))
    #expect(model.isDecidingLock == false)
    #expect(model.phase == .locked)
  }

  @Test func activatingWithoutHavingLeftNeedsNoShield() async {
    let model = await unlockedModel(vault: FakeVault())
    model.sceneWillActivate()
    #expect(model.isDecidingLock == false)
  }

  @Test func leavingTheScreenAppliesTheRuleAtOnceForAnImmediatePolicy() async {
    let vault = FakeVault()
    let model = await unlockedModel(vault: vault)
    model.sceneDidBackground(at: .now)
    await model.lockForBackground()
    #expect(vault.triggers == [.background])
    #expect(vault.lastElapsed == .zero)
    #expect(model.phase == .locked)
  }

  @Test func activatingTwiceAppliesTheRuleOnce() async {
    let vault = FakeVault()
    vault.locksOnTrigger = false
    let model = await unlockedModel(vault: vault)
    let start = ContinuousClock.now
    model.sceneDidBackground(at: start)
    await model.sceneDidActivate(at: start + .seconds(5))
    await model.sceneDidActivate(at: start + .seconds(500))
    #expect(vault.triggers == [.background])
  }
}

@MainActor
struct SyncHookTests {
  @Test func everySyncTellsTheIdentityRefresh() async {
    let calls = Mutex(0)
    let model = await unlockedModel(vault: FakeVault()) { _ in calls.withLock { $0 += 1 } }
    let before = calls.withLock { $0 }
    await model.syncNow()
    #expect(calls.withLock { $0 } == before + 1)
  }

  @Test func backgroundRefreshSyncsOnlyWhileUnlocked() async {
    let vault = FakeVault()
    let model = makeModel(origin: URL(string: "http://127.0.0.1:1"), vault: vault)
    await model.launch()
    #expect(await model.refreshInBackground() == false)
    #expect(vault.syncs == 0)
    await model.unlock(password: "pw")
    let before = vault.syncs
    #expect(await model.refreshInBackground())
    #expect(vault.syncs == before + 1)
  }

  @Test func backgroundRefreshAfterTheLimitLocksInsteadOfSyncing() async {
    let vault = FakeVault()
    let model = await unlockedModel(vault: vault)
    try? await Task.sleep(for: .milliseconds(100))
    let before = vault.syncs
    let start = ContinuousClock.now
    model.sceneDidBackground(at: start)
    #expect(await model.refreshInBackground(at: start + .seconds(3600)) == false)
    #expect(vault.triggers == [.background])
    #expect(vault.lastElapsed == .seconds(3600))
    #expect(model.phase == .locked)
    #expect(vault.syncs == before)
  }

  @Test func backgroundRefreshInsideTheLimitStillSyncs() async {
    let vault = FakeVault()
    vault.locksOnTrigger = false
    let model = await unlockedModel(vault: vault)
    let before = vault.syncs
    let start = ContinuousClock.now
    model.sceneDidBackground(at: start)
    #expect(await model.refreshInBackground(at: start + .seconds(5)))
    #expect(vault.syncs == before + 1)
  }

  @Test func passwordComesFirstWithoutHardwareCustody() async {
    let model = await unlockedModel(vault: FakeVault())
    #expect(model.asksForPasswordFirst)
    #expect(model.biometricsAvailable == false)
  }
}

@MainActor
struct NoBlankScreenTests {
  @Test func onboardingAndTheLockScreenAreNeverCovered() async {
    let fresh = makeModel(origin: nil, vault: FakeVault())
    await fresh.launch()
    fresh.sceneWillActivate()
    #expect(fresh.phase == .onboarding)
    #expect(fresh.showsPrivacyShield(sceneActive: false) == false)

    let locked = makeModel(origin: URL(string: "http://127.0.0.1:1"), vault: FakeVault())
    await locked.launch()
    #expect(locked.phase == .locked)
    #expect(locked.showsPrivacyShield(sceneActive: false) == false)
  }

  @Test func anOpenVaultIsCoveredOnlyWhileTheSceneIsAwayOrTheLockIsUndecided() async {
    let model = await unlockedModel(vault: FakeVault())
    #expect(model.showsPrivacyShield(sceneActive: true) == false)
    #expect(model.showsPrivacyShield(sceneActive: false))
  }

  @Test func anExistingOriginWithAMissingAccountShowsOnboarding() async {
    let vault = FakeVault()
    vault.state = .empty
    let model = makeModel(origin: URL(string: "http://127.0.0.1:1"), vault: vault)
    await model.launch()
    #expect(model.phase == .onboarding)
    #expect(model.showsPrivacyShield(sceneActive: false) == false)
  }

  @Test func aStatusCallThatNeverReturnsEndsInOnboardingWithAMessage() async {
    let vault = FakeVault()
    vault.hangsOnStatus = true
    let model = makeModel(origin: URL(string: "http://127.0.0.1:1"), vault: vault)
    model.launchDeadline = .milliseconds(50)
    await model.launch()
    #expect(model.phase == .onboarding)
    #expect(model.notice != nil)
  }
}

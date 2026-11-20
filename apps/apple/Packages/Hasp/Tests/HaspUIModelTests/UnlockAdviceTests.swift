import Foundation
import HaspKit
import Synchronization
import Testing

@testable import HaspUI

@MainActor
@Suite(.serialized) struct UnlockAdviceTests {
  init() {
    UserDefaults.standard.removeObject(forKey: AppModel.passcodeAdviceKey)
    UserDefaults.standard.removeObject(forKey: AppModel.biometricOfferKey)
  }

  private func signedIn(
    _ vault: FakeVault,
    capability: @escaping @Sendable () -> UnlockCapability,
  ) async -> AppModel {
    let model = makeModel(origin: nil, vault: vault, capability: capability)
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

  @Test func aKeychainRefusalReachesTheUserAsItsOwnMessage() async {
    let vault = FakeVault()
    vault.signInError = .internal
    let model = makeModel(
      origin: nil,
      vault: vault,
      storeFailure: { .passcodeNotSet },
    )
    await model.launch()
    await model.signIn(
      origin: "http://127.0.0.1:1",
      login: "me",
      secretKey: "k",
      password: "pw",
      fingerprint: "AAAA-BBBB",
    )
    #expect(model.phase == .onboarding)
    #expect(model.notice == UserMessage.text(for: StoreFailure.passcodeNotSet))
    #expect(model.notice != UserMessage.text(for: HaspError.internal))
  }

  @Test func everyStoreFailureHasItsOwnText() {
    let failures: [StoreFailure] = [
      .passcodeNotSet, .missingEntitlement, .deviceLocked, .authenticationFailed, .status(-1),
    ]
    let texts = Set(failures.map { UserMessage.text(for: $0) })
    #expect(texts.count == failures.count)
    #expect(!texts.contains(UserMessage.text(for: HaspError.internal)))
  }

  @Test func withoutAPasscodeSignInWorksAndExplainsOnce() async {
    let model = await signedIn(FakeVault(), capability: { .needsPasscode })
    #expect(model.phase == .unlocked)
    #expect(model.unlockAdvice == .setPasscode)
    #expect(model.showsUnlockAdvice)
    model.showsUnlockAdvice = false
    model.refreshUnlockAdvice()
    #expect(model.unlockAdvice == .setPasscode)
    #expect(!model.showsUnlockAdvice)
  }

  @Test func aDeviceThatCannotGateGetsNoAdvice() async {
    let model = await signedIn(FakeVault(), capability: { .softwareOnly })
    #expect(model.unlockAdvice == nil)
    #expect(!model.showsUnlockAdvice)
  }

  @Test func settingAPasscodeLaterOffersBiometricUnlockAndTheOfferWorks() async {
    let capability = Mutex(UnlockCapability.needsPasscode)
    let vault = FakeVault()
    let model = await signedIn(vault, capability: { capability.withLock { $0 } })
    model.showsUnlockAdvice = false
    capability.withLock { $0 = .hardwareReady }
    model.refreshUnlockAdvice()
    #expect(model.unlockAdvice == .enableBiometrics)
    #expect(model.showsUnlockAdvice)

    await model.enableHardwareUnlock(password: "wrong")
    #expect(!vault.hardwareEnabled)
    #expect(model.notice != nil)

    await model.enableHardwareUnlock(password: "pw")
    #expect(vault.hardwareEnabled)
    #expect(model.phase == .unlocked)
    #expect(!model.showsUnlockAdvice)
  }
}

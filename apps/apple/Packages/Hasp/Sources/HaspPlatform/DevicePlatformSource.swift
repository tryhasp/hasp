public import HaspKit
import Synchronization

/// Builds the platform again for each session, so a device passcode set while the app runs gives
/// the next session the hardware-gated store, and remembers the latest store's refusal for the interface.
public final class DevicePlatformSource: Sendable {
  private let memoryOnly: Bool
  private let latest = Mutex<DevicePlatform?>(nil)

  public init(memoryOnly: Bool) {
    self.memoryOnly = memoryOnly
  }

  public func make() -> DevicePlatform {
    let platform = DevicePlatformFactory.make(memoryOnly: memoryOnly)
    latest.withLock { $0 = platform }
    return platform
  }

  public var capability: UnlockCapability {
    memoryOnly ? .softwareOnly : DevicePlatformFactory.unlockCapability()
  }

  public var isHardwareBacked: Bool { capability == .hardwareReady }

  public var lastFailure: StoreFailure? { latest.withLock { $0 }?.store.lastFailure }
}

#if os(iOS)
  import UIKit
  public import HaspKit

  /// The device lock makes protected data unavailable, which is the phone's screen lock.
  public enum SystemLockEvents {
    public static func triggers() -> AsyncStream<LockTrigger> {
      AsyncStream { continuation in
        let watcher = Task {
          let name = UIApplication.protectedDataWillBecomeUnavailableNotification
          for await _ in NotificationCenter.default.notifications(named: name) {
            continuation.yield(.screenLock)
          }
        }
        continuation.onTermination = { _ in watcher.cancel() }
      }
    }
  }

  public enum SystemIdle {
    /// The phone has no global input clock; the background timer replaces the idle timer.
    public static func sinceLastInput() -> Duration { .zero }
  }
#endif

#if os(macOS)
  import AppKit
  public import HaspKit

  /// Sleep, screen lock and fast user switch, as lock triggers.
  public enum SystemLockEvents {
    public static func triggers() -> AsyncStream<LockTrigger> {
      AsyncStream { continuation in
        let observers = Observers()
        observers.add(
          center: NSWorkspace.shared.notificationCenter,
          name: NSWorkspace.willSleepNotification,
        ) { continuation.yield(.sleep) }
        observers.add(
          center: NSWorkspace.shared.notificationCenter,
          name: NSWorkspace.sessionDidResignActiveNotification,
        ) { continuation.yield(.userSwitch) }
        observers.add(
          center: DistributedNotificationCenter.default(),
          name: Notification.Name("com.apple.screenIsLocked"),
        ) { continuation.yield(.screenLock) }
        continuation.onTermination = { _ in observers.removeAll() }
      }
    }
  }

  private final class Observers: @unchecked Sendable {
    // Why: tokens are only touched on the creating call and in onTermination, never concurrently.
    private var tokens: [(center: NotificationCenter, token: any NSObjectProtocol)] = []

    func add(
      center: NotificationCenter,
      name: Notification.Name,
      handler: @escaping @Sendable () -> Void,
    ) {
      let token = center.addObserver(forName: name, object: nil, queue: nil) { _ in handler() }
      tokens.append((center, token))
    }

    func removeAll() {
      for entry in tokens { entry.center.removeObserver(entry.token) }
      tokens.removeAll()
    }
  }

  public enum SystemIdle {
    public static func sinceLastInput() -> Duration {
      let types: [CGEventType] = [
        .keyDown, .mouseMoved, .leftMouseDown, .rightMouseDown, .scrollWheel,
      ]
      let seconds = types.map {
        CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: $0)
      }.min()
      return .seconds(seconds ?? 0)
    }
  }
#endif

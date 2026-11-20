import AppKit
import HaspDesign
import SwiftUI

final class ToastPresenter {
  private let clock: any Clock<Duration>
  private let lifetime: Duration
  private var panel: NSPanel?
  private var hideTask: Task<Void, Never>?

  init(clock: any Clock<Duration>, lifetime: Duration = .seconds(2)) {
    self.clock = clock
    self.lifetime = lifetime
  }

  func show(_ message: String) {
    hideTask?.cancel()
    let host = NSHostingView(rootView: ToastView(message: message))
    let size = host.fittingSize
    let panel = self.panel ?? makePanel()
    panel.contentView = host
    panel.setContentSize(size)
    panel.setFrameOrigin(origin(for: size))
    panel.orderFrontRegardless()
    self.panel = panel
    NSAccessibility.post(
      element: panel,
      notification: .announcementRequested,
      userInfo: [.announcement: message],
    )
    hideTask = Task { [weak self] in
      guard let self else { return }
      do { try await clock.sleep(for: lifetime) } catch { return }
      hide()
    }
  }

  func hide() {
    hideTask?.cancel()
    panel?.orderOut(nil)
  }

  private func makePanel() -> NSPanel {
    let panel = NSPanel(
      contentRect: .zero,
      styleMask: [.borderless, .nonactivatingPanel],
      backing: .buffered,
      defer: true,
    )
    panel.level = .statusBar
    panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient, .ignoresCycle]
    panel.isOpaque = false
    panel.backgroundColor = .clear
    panel.hasShadow = false
    panel.ignoresMouseEvents = true
    panel.sharingType = .none
    panel.animationBehavior = .none
    panel.isReleasedWhenClosed = false
    return panel
  }

  private func origin(for size: NSSize) -> NSPoint {
    let screen = ScreenPlacement.activeScreen()
    let frame = screen?.visibleFrame ?? .zero
    return NSPoint(x: frame.midX - size.width / 2, y: frame.minY + HaspSpace.s32 * 2)
  }
}

enum ScreenPlacement {
  static func activeScreen() -> NSScreen? {
    let mouse = NSEvent.mouseLocation
    return NSScreen.screens.first { NSMouseInRect(mouse, $0.frame, false) } ?? NSScreen.main
  }
}

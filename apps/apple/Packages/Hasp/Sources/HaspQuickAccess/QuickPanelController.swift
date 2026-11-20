import AppKit
import HaspDesign

final class QuickPanelController {
  private let model: QuickAccessModel
  private let panel: QuickPanel
  private let environment: any SystemEnvironment
  private var previousApp: NSRunningApplication?
  private var presenting: Task<Void, Never>?

  var isVisible: Bool { panel.isVisible }

  init(model: QuickAccessModel, environment: any SystemEnvironment) {
    self.model = model
    self.environment = environment
    panel = QuickPanel(content: QuickAccessView(model: model))
    panel.chordHandler = { [weak model] chord in model?.handle(chord) ?? false }
    panel.onResignKey = { [weak self] in self?.hide() }
  }

  func toggle() {
    if panel.isVisible { hide() } else { show() }
  }

  func show() {
    previousApp = NSWorkspace.shared.frontmostApplication
    position()
    panel.makeKeyAndOrderFront(nil)
    presenting?.cancel()
    presenting = Task { await model.present() }
  }

  func hide() {
    guard panel.isVisible else { return }
    presenting?.cancel()
    panel.orderOut(nil)
    model.dismissed()
    restoreFocus()
  }

  private func restoreFocus() {
    guard let previousApp, !previousApp.isTerminated else { return }
    if NSWorkspace.shared.frontmostApplication != previousApp { previousApp.activate() }
    self.previousApp = nil
  }

  private func position() {
    let frame = ScreenPlacement.activeScreen()?.visibleFrame ?? .zero
    let size = panel.frame.size
    panel.setFrameOrigin(
      NSPoint(x: frame.midX - size.width / 2, y: frame.maxY - frame.height * 0.28 - size.height)
    )
  }
}

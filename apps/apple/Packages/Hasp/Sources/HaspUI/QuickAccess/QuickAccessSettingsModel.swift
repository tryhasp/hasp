#if os(macOS)
  import AppKit
  import HaspQuickAccessCore
  import Observation

  @Observable
  final class QuickAccessSettingsModel {
    private(set) var hotKeyText = ""
    private(set) var recording = false
    private(set) var failure: HotKeyFailure?
    private(set) var trusted = false

    private let app: AppModel
    private var monitor: Any?

    init(app: AppModel) {
      self.app = app
      refresh()
    }

    func startRecording() {
      failure = nil
      recording = true
      monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
        self?.capture(event)
        return nil
      }
    }

    func stopRecording() {
      recording = false
      if let monitor { NSEvent.removeMonitor(monitor) }
      monitor = nil
    }

    func allowAccessibility() {
      app.quickAccess?.requestAccessibility()
      app.quickAccess?.openAccessibilitySettings()
    }

    func watchAccessibility() async {
      while !Task.isCancelled {
        refresh()
        try? await Task.sleep(for: .seconds(1))
      }
    }

    private func refresh() {
      guard let control = app.quickAccess else { return }
      hotKeyText = HotKeyDisplay.text(for: control.hotKey)
      trusted = control.accessibilityTrusted
    }

    private func capture(_ event: NSEvent) {
      guard event.keyCode != 53 else {
        stopRecording()
        return
      }
      let binding = HotKeyDisplay.binding(from: event)
      do {
        try app.quickAccess?.setHotKey(binding)
        failure = nil
        stopRecording()
        refresh()
      } catch {
        failure = error
      }
    }
  }
#endif

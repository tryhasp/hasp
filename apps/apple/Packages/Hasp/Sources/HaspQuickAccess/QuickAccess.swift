public import Foundation
public import HaspQuickAccessCore

public final class QuickAccess {
  public struct Callbacks {
    public var openInMainWindow: (QuickItemID) -> Void
    public var requestUnlock: () -> Void

    public init(
      openInMainWindow: @escaping (QuickItemID) -> Void,
      requestUnlock: @escaping () -> Void,
    ) {
      self.openInMainWindow = openInMainWindow
      self.requestUnlock = requestUnlock
    }
  }

  private let controller: QuickPanelController
  private let toast: ToastPresenter
  private let model: QuickAccessModel
  private let clipboard: ClipboardClearer
  private let registrar: HotKeyRegistrar
  private let preferences: HotKeyPreferences
  public private(set) var hotKey: HotKeyBinding

  private init(
    engine: any QuickAccessEngine,
    clipboard: ClipboardClearer,
    browserChannel: (any BrowserFillChannel)?,
    callbacks: Callbacks,
    defaults: UserDefaults,
  ) {
    let clock = ContinuousClock()
    let environment = LiveSystemEnvironment()
    self.clipboard = clipboard
    toast = ToastPresenter(clock: clock)
    model = QuickAccessModel(
      dependencies: QuickAccessModel.Dependencies(
        engine: engine,
        clipboard: clipboard,
        typer: KeystrokeTyper(
          poster: ProcessEventPoster(),
          surroundings: environment,
          clock: clock,
          focusTimeout: .seconds(1),
        ),
        environment: environment,
        browserChannel: browserChannel,
        clock: clock,
        now: { Date() },
      )
    )
    controller = QuickPanelController(model: model, environment: environment)
    registrar = HotKeyRegistrar()
    preferences = HotKeyPreferences(defaults: defaults)
    hotKey = preferences.load()
    wire(callbacks)
  }

  public static func install(
    engine: any QuickAccessEngine,
    clipboard: ClipboardClearer,
    browserChannel: (any BrowserFillChannel)? = nil,
    callbacks: Callbacks,
    defaults: UserDefaults = .standard,
  ) throws -> QuickAccess {
    let quickAccess = QuickAccess(
      engine: engine,
      clipboard: clipboard,
      browserChannel: browserChannel,
      callbacks: callbacks,
      defaults: defaults,
    )
    try quickAccess.registerHotKey(quickAccess.hotKey)
    return quickAccess
  }

  public func show() { controller.show() }

  public func hide() { controller.hide() }

  public func toggle() { controller.toggle() }

  public func setHotKey(_ binding: HotKeyBinding) throws {
    try registerHotKey(binding)
    try preferences.save(binding)
    hotKey = binding
  }

  public func lock() async {
    controller.hide()
    toast.hide()
    model.lock()
    await clipboard.clearIfOurs()
  }

  private func registerHotKey(_ binding: HotKeyBinding) throws {
    try registrar.register(binding) { [weak self] in self?.controller.toggle() }
  }

  private func wire(_ callbacks: Callbacks) {
    model.setHooks(
      QuickAccessModel.Hooks(
        closePanel: { [weak self] in self?.controller.hide() },
        showToast: { [weak self] in self?.toast.show($0) },
        openInMainWindow: callbacks.openInMainWindow,
        requestUnlock: { [weak self] in
          self?.controller.hide()
          callbacks.requestUnlock()
        },
      )
    )
  }
}

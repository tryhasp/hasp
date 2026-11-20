import Foundation
import HaspQuickAccessCore
import Observation

@Observable
final class QuickAccessModel {
  enum Mode: Equatable {
    case locked
    case search
    case confirmTyping(ConfirmReason, QuickItem)
    case needsAccessibility(QuickItem)
  }

  struct Dependencies {
    let engine: any QuickAccessEngine
    let clipboard: ClipboardClearer
    let typer: KeystrokeTyper
    let environment: any SystemEnvironment
    let browserChannel: (any BrowserFillChannel)?
    let clock: any Clock<Duration>
    let now: @Sendable () -> Date
  }

  struct Hooks {
    var closePanel: () -> Void = {}
    var showToast: (String) -> Void = { _ in }
    var openInMainWindow: (QuickItemID) -> Void = { _ in }
    var requestUnlock: () -> Void = {}
  }

  var query = "" {
    didSet { if query != oldValue { rerank() } }
  }
  private(set) var mode = Mode.search
  private(set) var results: [QuickItem] = []
  private(set) var selection: QuickItemID?
  private(set) var otp: OTPPreview?
  private(set) var showsActions = false
  private(set) var focusToken = 0

  private let dependencies: Dependencies
  private var hooks: Hooks
  private var allItems: [QuickItem] = []
  private var frontmostHost: String?
  private var target: TargetApp?
  private var clipboardClear = Duration.seconds(30)
  private var approvals = TypingApprovals()
  private var otpTicker: Task<Void, Never>?

  init(dependencies: Dependencies, hooks: Hooks = Hooks()) {
    self.dependencies = dependencies
    self.hooks = hooks
  }

  var selectedItem: QuickItem? { results.first { $0.id == selection } }

  func setHooks(_ hooks: Hooks) {
    self.hooks = hooks
  }

  func present() async {
    target = dependencies.environment.frontmostApp()
    query = ""
    showsActions = false
    mode = .search
    focusToken += 1
    guard await loadLockState() else { return }
    await loadItems()
    frontmostHost = await currentPageHost()
    rerank()
  }

  func dismissed() {
    otpTicker?.cancel()
    otpTicker = nil
    allItems = []
    results = []
    selection = nil
    otp = nil
    query = ""
    showsActions = false
    mode = .search
  }

  func lock() {
    approvals.reset()
    dismissed()
  }

  func moveSelection(by offset: Int) {
    guard !results.isEmpty else { return }
    let current = results.firstIndex { $0.id == selection } ?? 0
    let next = min(max(current + offset, 0), results.count - 1)
    select(results[next].id)
  }

  func select(_ id: QuickItemID?) {
    guard id != selection else { return }
    selection = id
    refreshOTP()
  }

  func handle(_ chord: KeyChord) -> Bool {
    guard let action = QuickAction.route(chord) else { return false }
    Task { await perform(action) }
    return true
  }

  func perform(_ action: QuickAction) async {
    switch mode {
    case .locked:
      if action == .close { hooks.closePanel() }
      if action == .fill { hooks.requestUnlock() }
    case .confirmTyping(_, let item):
      await performConfirm(action, item: item)
    case .needsAccessibility(let item):
      await performAccessibility(action, item: item)
    case .search:
      await performSearch(action)
    }
  }

  func confirmTyping() async { if case .confirmTyping(_, let item) = mode { await type(item) } }

  func cancelPrompt() { mode = .search }

  func openAccessibilitySettings() {
    dependencies.environment.requestAccessibility()
    dependencies.environment.openAccessibilitySettings()
  }

  func copyPasswordFromPrompt() async {
    guard case .needsAccessibility(let item) = mode else { return }
    mode = .search
    await copy(item, secret: .password)
  }

  func requestUnlock() { hooks.requestUnlock() }
}

extension QuickAccessModel {
  private func loadLockState() async -> Bool {
    do {
      switch try await dependencies.engine.lockState() {
      case .unlocked(let clear):
        clipboardClear = clear
        return true
      case .locked:
        mode = .locked
        return false
      }
    } catch {
      mode = .locked
      return false
    }
  }

  private func loadItems() async {
    do {
      allItems = try await dependencies.engine.items()
    } catch {
      allItems = []
      hooks.showToast(Strings.toastFailed)
    }
  }

  private func currentPageHost() async -> String? {
    guard let target, target.isBrowser, let channel = dependencies.browserChannel,
      await channel.hasPairedExtension(browserBundleID: target.bundleID)
    else { return nil }
    return await channel.pageHost(browserBundleID: target.bundleID)
  }

  private func rerank() {
    let context = SearchContext(frontmostHost: frontmostHost, now: dependencies.now())
    results = SearchRanking.rank(allItems, query: query, context: context)
    if !results.contains(where: { $0.id == selection }) {
      selection = results.first?.id
      refreshOTP()
    }
  }

  private func refreshOTP() {
    otpTicker?.cancel()
    otp = nil
    guard let item = selectedItem, item.hasOTP else { return }
    otpTicker = Task { [weak self] in await self?.runOTP(for: item.id) }
  }

  private func runOTP(for id: QuickItemID) async {
    while !Task.isCancelled {
      let preview: OTPPreview
      do { preview = try await dependencies.engine.otpPreview(for: id) } catch { return }
      otp = preview
      var remaining = max(preview.secondsRemaining, 1)
      while remaining > 0 {
        do { try await dependencies.clock.sleep(for: .seconds(1)) } catch { return }
        remaining -= 1
        otp = OTPPreview(code: preview.code, secondsRemaining: remaining)
      }
    }
  }

  private func performSearch(_ action: QuickAction) async {
    switch action {
    case .close:
      if showsActions { showsActions = false } else { hooks.closePanel() }
    case .showAllActions:
      showsActions.toggle()
    case .fill:
      showsActions = false
      if let item = selectedItem { await fill(item) }
    case .copyPassword:
      if let item = selectedItem { await copy(item, secret: .password) }
    case .copyOTP:
      if let item = selectedItem { await copy(item, secret: .otp) }
    case .copyUsername:
      if let item = selectedItem { await copy(item, secret: .username) }
    case .openInMainWindow:
      if let item = selectedItem {
        hooks.closePanel()
        hooks.openInMainWindow(item.id)
      }
    }
  }

  private func performConfirm(_ action: QuickAction, item: QuickItem) async {
    switch action {
    case .fill: await type(item)
    case .close: mode = .search
    default: break
    }
  }

  private func performAccessibility(_ action: QuickAction, item: QuickItem) async {
    switch action {
    case .fill: openAccessibilitySettings()
    case .close: mode = .search
    default: break
    }
  }
}

extension QuickAccessModel {
  enum Secret { case password, otp, username }

  func copy(_ item: QuickItem, secret: Secret) async {
    if secret == .otp, !item.hasOTP {
      hooks.showToast(Strings.toastNoOTP)
      return
    }
    do {
      let data: Data
      switch secret {
      case .password: data = try await dependencies.engine.password(for: item.id)
      case .otp: data = try await dependencies.engine.otpCode(for: item.id)
      case .username: data = try await dependencies.engine.username(for: item.id)
      }
      let sensitive = secret != .username
      await dependencies.clipboard.copy(data, clearAfter: sensitive ? clipboardClear : nil)
      hooks.closePanel()
      hooks.showToast(copiedMessage(sensitive: sensitive))
    } catch {
      hooks.showToast(Strings.toastFailed)
    }
  }

  private func copiedMessage(sensitive: Bool) -> String {
    sensitive
      ? Strings.copied(clearAfterSeconds: Int(clipboardClear.components.seconds))
      : Strings.copiedWithoutTimer
  }

  func fill(_ item: QuickItem) async {
    let paired = await pairedExtension()
    let route = FillRouter.route(
      FillContext(
        target: target,
        hasPairedExtension: paired,
        accessibilityTrusted: dependencies.environment.accessibilityTrusted,
        kind: item.kind,
      )
    )
    switch route {
    case .browserExtension(let bundleID): await fillThroughExtension(item, bundleID: bundleID)
    case .type(let app): await beginTyping(item, into: app)
    case .needsAccessibility: mode = .needsAccessibility(item)
    case .copyOnly(.unsupportedKind): hooks.showToast(Strings.toastLoginOnly)
    case .copyOnly(.noTarget):
      await copy(item, secret: .password)
      hooks.showToast(Strings.toastCopiedInstead)
    }
  }

  private func pairedExtension() async -> Bool {
    guard let target, target.isBrowser, let channel = dependencies.browserChannel else {
      return false
    }
    return await channel.hasPairedExtension(browserBundleID: target.bundleID)
  }

  private func fillThroughExtension(_ item: QuickItem, bundleID: String) async {
    guard let channel = dependencies.browserChannel else { return }
    switch await channel.requestFill(browserBundleID: bundleID, item: item.id) {
    case .filled: hooks.closePanel()
    case .needsConfirmationInBrowser:
      hooks.closePanel()
      hooks.showToast(Strings.toastConfirmInBrowser)
    case .noMatchingPage: hooks.showToast(Strings.toastNoMatchingPage)
    case .extensionLocked: hooks.showToast(Strings.toastExtensionLocked)
    case .unavailable: hooks.showToast(Strings.toastBrowserUnavailable)
    }
  }

  private func beginTyping(_ item: QuickItem, into app: TargetApp) async {
    switch approvals.decision(for: item, into: app) {
    case .proceed: await type(item)
    case .confirm(let reason): mode = .confirmTyping(reason, item)
    }
  }

  private func type(_ item: QuickItem) async {
    guard let app = target else { return }
    approvals.approve(item.id, in: app)
    mode = .search
    hooks.closePanel()
    do {
      let values = try await dependencies.engine.loginValues(for: item.id)
      let focus = try await dependencies.typer.captureFocus(of: app.processID)
      let plan = TypingPlan.login(
        username: String(decoding: values.username, as: UTF8.self),
        password: String(decoding: values.password, as: UTF8.self),
        focus: focus.kind,
        secureInputActive: dependencies.environment.secureInputActive,
      )
      try await dependencies.typer.type(plan, expecting: focus)
    } catch is CancellationError {
      return
    } catch {
      hooks.showToast(Strings.toastFailed)
    }
  }
}

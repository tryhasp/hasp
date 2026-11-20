import Carbon.HIToolbox
import HaspQuickAccessCore

public enum HotKeyError: Error, Equatable {
  case needsModifier
  case conflictsWithSystemShortcut
  case registrationFailed(Int32)
}

final class HotKeyRegistrar {
  private static let signature: OSType = 0x4841_5350
  private static let exclusive = OptionBits(kEventHotKeyExclusive)

  private let shortcuts: () -> [SystemShortcut]
  private var handlerRef: EventHandlerRef?
  private var hotKeyRef: EventHotKeyRef?
  private var onPress: () -> Void = {}

  init(shortcuts: @escaping () -> [SystemShortcut] = { SymbolicHotKeys.current() }) {
    self.shortcuts = shortcuts
  }

  isolated deinit {
    unregister()
    if let handlerRef { RemoveEventHandler(handlerRef) }
  }

  func register(_ binding: HotKeyBinding, onPress: @escaping () -> Void) throws {
    guard binding.hasModifier else { throw HotKeyError.needsModifier }
    if HotKeyConflicts.conflicts(binding, with: shortcuts()) {
      throw HotKeyError.conflictsWithSystemShortcut
    }
    try installHandlerIfNeeded()
    let previous = hotKeyRef
    var fresh: EventHotKeyRef?
    let id = EventHotKeyID(signature: Self.signature, id: 1)
    let status = RegisterEventHotKey(
      binding.keyCode,
      binding.modifiers,
      id,
      GetApplicationEventTarget(),
      Self.exclusive,
      &fresh,
    )
    guard status == noErr else { throw HotKeyError.registrationFailed(status) }
    if let previous { UnregisterEventHotKey(previous) }
    hotKeyRef = fresh
    self.onPress = onPress
  }

  func unregister() {
    if let hotKeyRef { UnregisterEventHotKey(hotKeyRef) }
    hotKeyRef = nil
  }

  fileprivate func fire() {
    onPress()
  }

  private func installHandlerIfNeeded() throws {
    guard handlerRef == nil else { return }
    var spec = EventTypeSpec(
      eventClass: OSType(kEventClassKeyboard),
      eventKind: UInt32(kEventHotKeyPressed),
    )
    let status = InstallEventHandler(
      GetApplicationEventTarget(),
      hotKeyCallback,
      1,
      &spec,
      Unmanaged.passUnretained(self).toOpaque(),
      &handlerRef,
    )
    guard status == noErr else { throw HotKeyError.registrationFailed(status) }
  }
}

private nonisolated func hotKeyCallback(
  _ next: EventHandlerCallRef?,
  _ event: EventRef?,
  _ userData: UnsafeMutableRawPointer?,
) -> OSStatus {
  guard let userData else { return OSStatus(eventNotHandledErr) }
  let registrar = Unmanaged<HotKeyRegistrar>.fromOpaque(userData)
  MainActor.assumeIsolated { registrar.takeUnretainedValue().fire() }
  return noErr
}

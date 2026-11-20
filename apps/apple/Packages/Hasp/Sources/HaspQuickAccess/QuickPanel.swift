import AppKit
import HaspDesign
import HaspQuickAccessCore
import SwiftUI

final class QuickPanel: NSPanel {
  var chordHandler: (KeyChord) -> Bool = { _ in false }
  var onResignKey: () -> Void = {}

  override var canBecomeKey: Bool { true }
  override var canBecomeMain: Bool { false }

  init(content: some View) {
    super.init(
      contentRect: NSRect(
        x: 0,
        y: 0,
        width: HaspSize.quickAccessWidth,
        height: HaspSize.quickAccessHeight,
      ),
      styleMask: [.borderless, .nonactivatingPanel],
      backing: .buffered,
      defer: true,
    )
    isFloatingPanel = true
    level = .modalPanel
    collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient, .ignoresCycle]
    hidesOnDeactivate = false
    becomesKeyOnlyIfNeeded = false
    isOpaque = false
    backgroundColor = .clear
    hasShadow = true
    animationBehavior = .none
    sharingType = .none
    isReleasedWhenClosed = false
    contentView = NSHostingView(rootView: content)
  }

  override func performKeyEquivalent(with event: NSEvent) -> Bool {
    if let chord = KeyChord(event), chord.command, chordHandler(chord) { return true }
    return super.performKeyEquivalent(with: event)
  }

  override func keyDown(with event: NSEvent) {
    if let chord = KeyChord(event), chordHandler(chord) { return }
    super.keyDown(with: event)
  }

  override func resignKey() {
    super.resignKey()
    onResignKey()
  }
}

extension KeyChord {
  init?(_ event: NSEvent) {
    let flags = event.modifierFlags
    let key: Key
    switch event.keyCode {
    case 36, 76: key = .returnKey
    case 53: key = .escape
    default:
      guard let character = event.charactersIgnoringModifiers?.first else { return nil }
      key = .character(character)
    }
    self.init(
      key,
      command: flags.contains(.command),
      shift: flags.contains(.shift),
      option: flags.contains(.option),
      control: flags.contains(.control),
    )
  }
}

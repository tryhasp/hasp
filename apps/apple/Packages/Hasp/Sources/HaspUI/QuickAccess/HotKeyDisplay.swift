#if os(macOS)
  import AppKit
  import Carbon.HIToolbox
  import HaspQuickAccessCore

  enum HotKeyDisplay {
    static func text(for binding: HotKeyBinding) -> String {
      modifierGlyphs(binding.modifiers) + keyName(binding.keyCode)
    }

    static func binding(from event: NSEvent) -> HotKeyBinding {
      var modifiers: UInt32 = 0
      let flags = event.modifierFlags
      if flags.contains(.command) { modifiers |= HotKeyBinding.carbonCommand }
      if flags.contains(.shift) { modifiers |= HotKeyBinding.carbonShift }
      if flags.contains(.option) { modifiers |= HotKeyBinding.carbonOption }
      if flags.contains(.control) { modifiers |= HotKeyBinding.carbonControl }
      return HotKeyBinding(keyCode: UInt32(event.keyCode), modifiers: modifiers)
    }

    private static func modifierGlyphs(_ modifiers: UInt32) -> String {
      var glyphs = ""
      if modifiers & HotKeyBinding.carbonControl != 0 { glyphs += "⌃" }
      if modifiers & HotKeyBinding.carbonOption != 0 { glyphs += "⌥" }
      if modifiers & HotKeyBinding.carbonShift != 0 { glyphs += "⇧" }
      if modifiers & HotKeyBinding.carbonCommand != 0 { glyphs += "⌘" }
      return glyphs
    }

    private static let named: [UInt32: String] = [
      UInt32(kVK_Space): "Space", UInt32(kVK_Return): "↩", UInt32(kVK_Tab): "⇥",
      UInt32(kVK_Delete): "⌫", UInt32(kVK_LeftArrow): "←", UInt32(kVK_RightArrow): "→",
      UInt32(kVK_UpArrow): "↑", UInt32(kVK_DownArrow): "↓", UInt32(kVK_F1): "F1",
      UInt32(kVK_F2): "F2", UInt32(kVK_F3): "F3", UInt32(kVK_F4): "F4", UInt32(kVK_F5): "F5",
      UInt32(kVK_F6): "F6", UInt32(kVK_F7): "F7", UInt32(kVK_F8): "F8", UInt32(kVK_F9): "F9",
      UInt32(kVK_F10): "F10", UInt32(kVK_F11): "F11", UInt32(kVK_F12): "F12",
    ]

    private static func keyName(_ keyCode: UInt32) -> String {
      if let name = named[keyCode] { return name }
      guard let source = TISCopyCurrentASCIICapableKeyboardLayoutInputSource()?.takeRetainedValue(),
        let raw = TISGetInputSourceProperty(source, kTISPropertyUnicodeKeyLayoutData)
      else { return "#\(keyCode)" }
      let layout = unsafeBitCast(raw, to: CFData.self)
      var dead: UInt32 = 0
      var length = 0
      var characters = [UniChar](repeating: 0, count: 4)
      let status = CFDataGetBytePtr(layout).withMemoryRebound(
        to: UCKeyboardLayout.self,
        capacity: 1,
      ) {
        UCKeyTranslate(
          $0,
          UInt16(keyCode),
          UInt16(kUCKeyActionDisplay),
          0,
          UInt32(LMGetKbdType()),
          OptionBits(kUCKeyTranslateNoDeadKeysBit),
          &dead,
          characters.count,
          &length,
          &characters,
        )
      }
      guard status == noErr, length > 0 else { return "#\(keyCode)" }
      return String(utf16CodeUnits: characters, count: length).uppercased()
    }
  }
#endif

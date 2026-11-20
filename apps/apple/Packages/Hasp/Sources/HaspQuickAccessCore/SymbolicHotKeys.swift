#if os(macOS)
  import Carbon

  public enum SymbolicHotKeys {
    public static func current() -> [SystemShortcut] {
      var array: Unmanaged<CFArray>?
      guard CopySymbolicHotKeys(&array) == noErr, let entries = array?.takeRetainedValue() else {
        return []
      }
      return (entries as? [[String: Any]] ?? []).compactMap { entry in
        guard let code = entry["kHISymbolicHotKeyCode"] as? Int,
          let modifiers = entry["kHISymbolicHotKeyModifiers"] as? Int
        else { return nil }
        let enabled = (entry["kHISymbolicHotKeyEnabled"] as? Int ?? 0) != 0
        return SystemShortcut(
          keyCode: UInt32(code),
          modifiers: UInt32(modifiers),
          enabled: enabled,
        )
      }
    }
  }
#endif

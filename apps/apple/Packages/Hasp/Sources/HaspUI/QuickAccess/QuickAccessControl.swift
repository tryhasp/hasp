public import HaspQuickAccessCore

public enum HotKeyFailure: Error, Equatable {
  case needsModifier
  case conflictsWithSystem
  case unavailable
}

/// What the settings screen and the first-run guide need from Quick Access. The app target implements it.
public protocol QuickAccessControl: AnyObject {
  var hotKey: HotKeyBinding { get }
  var accessibilityTrusted: Bool { get }
  func setHotKey(_ binding: HotKeyBinding) throws(HotKeyFailure)
  func requestAccessibility()
  func openAccessibilitySettings()
  func show()
}

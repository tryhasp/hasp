import AppKit
import ApplicationServices
import Carbon.HIToolbox
import HaspQuickAccessCore

protocol SystemEnvironment: TypingSurroundings {
  func frontmostApp() -> TargetApp?
  var accessibilityTrusted: Bool { get }
  var secureInputActive: Bool { get }
  func requestAccessibility()
  func openAccessibilitySettings()
}

struct LiveSystemEnvironment: SystemEnvironment {
  private static let settingsURL = URL(
    string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"
  )

  func frontmostApp() -> TargetApp? {
    guard let app = NSWorkspace.shared.frontmostApplication,
      let bundleID = app.bundleIdentifier,
      app.processIdentifier != ProcessInfo.processInfo.processIdentifier
    else { return nil }
    return TargetApp(
      bundleID: bundleID,
      name: app.localizedName ?? bundleID,
      processID: app.processIdentifier,
    )
  }

  var accessibilityTrusted: Bool { AXIsProcessTrusted() }

  var secureInputActive: Bool { IsSecureEventInputEnabled() }

  func frontmostProcessID() -> Int32? {
    NSWorkspace.shared.frontmostApplication?.processIdentifier
  }

  func hasKeyWindow() -> Bool { NSApp.keyWindow != nil }

  func secureInputEnabled() -> Bool { IsSecureEventInputEnabled() }

  func focus(in processID: Int32) -> FocusSnapshot? {
    guard accessibilityTrusted else { return nil }
    let application = AXUIElementCreateApplication(processID)
    var focused: CFTypeRef?
    guard
      AXUIElementCopyAttributeValue(
        application,
        kAXFocusedUIElementAttribute as CFString,
        &focused,
      )
        == .success,
      let focused, CFGetTypeID(focused) == AXUIElementGetTypeID()
    else { return nil }
    let element = unsafeDowncast(focused, to: AXUIElement.self)
    var owner: pid_t = 0
    guard AXUIElementGetPid(element, &owner) == .success, owner == processID else { return nil }
    return FocusSnapshot(processID: owner, kind: Self.kind(of: element), element: CFHash(element))
  }

  func requestAccessibility() {
    let options = ["AXTrustedCheckOptionPrompt": true] as CFDictionary
    _ = AXIsProcessTrustedWithOptions(options)
  }

  func openAccessibilitySettings() {
    guard let url = Self.settingsURL else { return }
    NSWorkspace.shared.open(url)
  }

  private static func kind(of element: AXUIElement) -> FocusedFieldKind {
    var subrole: CFTypeRef?
    AXUIElementCopyAttributeValue(element, kAXSubroleAttribute as CFString, &subrole)
    if (subrole as? String) == "AXSecureTextField" { return .secure }
    var role: CFTypeRef?
    AXUIElementCopyAttributeValue(element, kAXRoleAttribute as CFString, &role)
    return (role as? String) == kAXTextFieldRole || (role as? String) == kAXTextAreaRole
      ? .plain : .unknown
  }
}

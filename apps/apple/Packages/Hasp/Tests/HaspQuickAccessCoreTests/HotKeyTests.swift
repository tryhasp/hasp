import Foundation
import Testing

@testable import HaspQuickAccessCore

struct HotKeyTests {
  @Test func defaultIsOptionCommandBackslash() {
    #expect(HotKeyBinding.standard.keyCode == 0x2A)
    #expect(HotKeyBinding.standard.modifiers == 0x100 | 0x800)
  }

  @Test func detectsAnEnabledSystemShortcutOnTheSameChord() {
    let spotlight = SystemShortcut(keyCode: 49, modifiers: 0x100, enabled: true)
    let spotlightChord = HotKeyBinding(keyCode: 49, modifiers: 0x100)
    #expect(HotKeyConflicts.conflicts(spotlightChord, with: [spotlight]))
    #expect(!HotKeyConflicts.conflicts(.standard, with: [spotlight]))
  }

  @Test func ignoresDisabledSystemShortcuts() {
    let off = SystemShortcut(keyCode: 0x2A, modifiers: 0x100 | 0x800, enabled: false)
    #expect(!HotKeyConflicts.conflicts(.standard, with: [off]))
  }

  @Test func theDefaultDoesNotCollideWithThisMachinesSystemShortcuts() {
    #expect(!HotKeyConflicts.conflicts(.standard, with: SymbolicHotKeys.current()))
  }

  @Test func preferencesRoundTripAndFallBack() throws {
    let suite = "hasp.test.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let preferences = HotKeyPreferences(defaults: defaults)
    #expect(preferences.load() == .standard)
    let custom = HotKeyBinding(
      keyCode: 49,
      modifiers: HotKeyBinding.carbonControl | HotKeyBinding.carbonOption,
    )
    try preferences.save(custom)
    #expect(preferences.load() == custom)
    try preferences.save(HotKeyBinding(keyCode: 49, modifiers: 0))
    #expect(preferences.load() == .standard)
  }

  @Test func tileHueIsStableAndInRange() {
    #expect(TileHue.hue(for: "쿠팡") == TileHue.hue(for: "쿠팡"))
    #expect((0..<360).contains(TileHue.hue(for: "GitHub")))
    #expect(TileHue.letter(for: "쿠팡") == "쿠")
    #expect(TileHue.letter(for: "") == "?")
  }
}

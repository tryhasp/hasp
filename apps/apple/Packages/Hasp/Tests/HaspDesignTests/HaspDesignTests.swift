import CoreGraphics
import Foundation
import Testing

@testable import HaspDesign

@Test func rowHeightMatchesTheDesign() {
  #expect(HaspSize.rowHeight == 44)
  #expect(HaspSize.targetMin == 28)
}

@Test func textColorDiffersBetweenLightAndDark() {
  #expect(HaspColorValues.text.light != HaspColorValues.text.dark)
}

@Test func tileColorsFollowTheThemeAndTheHue() {
  let pair = HaspTile.background(hue: 150)
  #expect(pair.light != pair.dark)
  #expect(pair.light != HaspTile.background(hue: 12).light)
  #expect(pair.light.green > pair.light.red)
}

private func linear(_ channel: Double) -> Double {
  channel <= 0.04045 ? channel / 12.92 : pow((channel + 0.055) / 1.055, 2.4)
}

private func luminance(_ color: HaspRGBA) -> Double {
  0.2126 * linear(color.red) + 0.7152 * linear(color.green) + 0.0722 * linear(color.blue)
}

private func contrast(_ first: HaspRGBA, _ second: HaspRGBA) -> Double {
  let (high, low) = (
    max(luminance(first), luminance(second)), min(luminance(first), luminance(second)),
  )
  return (high + 0.05) / (low + 0.05)
}

private let smallTextContrast = 7.0

@Test func smallTextRolesReachSevenOnEverySurface() {
  let surfaces = [
    HaspColorValues.list, HaspColorValues.window, HaspColorValues.group,
    HaspColorValues.sidebar, HaspColorValues.selectedSidebar, HaspColorValues.selectedRow,
    HaspColorValues.chip, HaspColorValues.field,
  ]
  let roles = [HaspColorValues.text, HaspColorValues.textSecondary, HaspColorValues.accentText]
  for surface in surfaces {
    for text in roles {
      #expect(contrast(text.light, surface.light) >= smallTextContrast)
      #expect(contrast(text.dark, surface.dark) >= smallTextContrast)
    }
  }
}

@Test func lettersOnFilledSurfacesReachSeven() {
  #expect(
    contrast(HaspColorValues.onAccent.light, HaspColorValues.accent.light) >= smallTextContrast
  )
  #expect(
    contrast(HaspColorValues.onAccent.dark, HaspColorValues.accent.dark) >= smallTextContrast
  )
  #expect(
    contrast(HaspColorValues.onWarning.light, HaspColorValues.warning.light) >= smallTextContrast
  )
  #expect(
    contrast(HaspColorValues.onWarning.dark, HaspColorValues.warning.dark) >= smallTextContrast
  )
  #expect(contrast(HaspColorValues.onInk.light, HaspColorValues.ink.light) >= smallTextContrast)
  #expect(contrast(HaspColorValues.onInk.dark, HaspColorValues.ink.dark) >= smallTextContrast)
}

@Test func tileLettersReachSevenForEveryHue() {
  for hue in stride(from: 0.0, to: 360.0, by: 1.0) {
    let background = HaspTile.background(hue: hue)
    let foreground = HaspTile.foreground(hue: hue)
    #expect(contrast(foreground.light, background.light) >= smallTextContrast, "light hue \(hue)")
    #expect(contrast(foreground.dark, background.dark) >= smallTextContrast, "dark hue \(hue)")
  }
}

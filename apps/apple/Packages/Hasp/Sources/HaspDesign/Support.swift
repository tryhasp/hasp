public import SwiftUI

#if canImport(AppKit)
  import AppKit
#elseif canImport(UIKit)
  import UIKit
#endif

public struct HaspRGBA: Sendable, Equatable {
  public let red: Double
  public let green: Double
  public let blue: Double
  public let alpha: Double

  public init(red: Double, green: Double, blue: Double, alpha: Double = 1) {
    self.red = red
    self.green = green
    self.blue = blue
    self.alpha = alpha
  }

  public init(_ hex: UInt32, alpha: Double = 1) {
    self.init(
      red: Double((hex >> 16) & 0xff) / 255,
      green: Double((hex >> 8) & 0xff) / 255,
      blue: Double(hex & 0xff) / 255,
      alpha: alpha,
    )
  }
}

public struct HaspColorPair: Sendable, Equatable {
  public let light: HaspRGBA
  public let dark: HaspRGBA

  public init(light: HaspRGBA, dark: HaspRGBA) {
    self.light = light
    self.dark = dark
  }
}

public struct HaspTileTone: Sendable, Equatable {
  public let backgroundSaturation: Double
  public let backgroundLightness: Double
  public let foregroundSaturation: Double
  public let foregroundLightness: Double

  public init(
    backgroundSaturation: Double,
    backgroundLightness: Double,
    foregroundSaturation: Double,
    foregroundLightness: Double,
  ) {
    self.backgroundSaturation = backgroundSaturation
    self.backgroundLightness = backgroundLightness
    self.foregroundSaturation = foregroundSaturation
    self.foregroundLightness = foregroundLightness
  }
}

public struct HaspTextStyle: Sendable, Equatable {
  public let size: CGFloat
  public let weight: Font.Weight
  public let lineHeight: CGFloat
  public let letterSpacing: CGFloat
  public let monospaced: Bool
  public let tabularNums: Bool

  public init(
    size: CGFloat,
    weight: Font.Weight,
    lineHeight: CGFloat,
    letterSpacing: CGFloat,
    monospaced: Bool,
    tabularNums: Bool,
  ) {
    self.size = size
    self.weight = weight
    self.lineHeight = lineHeight
    self.letterSpacing = letterSpacing
    self.monospaced = monospaced
    self.tabularNums = tabularNums
  }

  public var font: Font {
    let base = Font.system(size: size, weight: weight, design: monospaced ? .monospaced : .default)
    return tabularNums ? base.monospacedDigit() : base
  }

  public var tracking: CGFloat { letterSpacing * size }

  public var lineSpacing: CGFloat { (lineHeight - 1.2) * size }
}

struct HaspTextModifier: ViewModifier {
  private let style: HaspTextStyle
  @ScaledMetric private var size: CGFloat

  init(style: HaspTextStyle) {
    self.style = style
    _size = ScaledMetric(wrappedValue: style.size, relativeTo: .body)
  }

  func body(content: Content) -> some View {
    let base = Font.system(
      size: size,
      weight: style.weight,
      design: style.monospaced ? .monospaced : .default,
    )
    content
      .font(style.tabularNums ? base.monospacedDigit() : base)
      .tracking(style.letterSpacing * size)
      .lineSpacing((style.lineHeight - 1.2) * size)
  }
}

extension View {
  /// Applies the token style; the size follows Dynamic Type where the platform has it.
  public func haspText(_ style: HaspTextStyle) -> some View {
    modifier(HaspTextModifier(style: style))
  }
}

extension HaspTile {
  public static func background(hue: Double) -> HaspColorPair {
    HaspColorPair(
      light: rgba(
        hue: hue,
        saturation: light.backgroundSaturation,
        lightness: light.backgroundLightness,
      ),
      dark: rgba(
        hue: hue,
        saturation: dark.backgroundSaturation,
        lightness: dark.backgroundLightness,
      ),
    )
  }

  public static func foreground(hue: Double) -> HaspColorPair {
    HaspColorPair(
      light: rgba(
        hue: hue,
        saturation: light.foregroundSaturation,
        lightness: light.foregroundLightness,
      ),
      dark: rgba(
        hue: hue,
        saturation: dark.foregroundSaturation,
        lightness: dark.foregroundLightness,
      ),
    )
  }

  public static func backgroundColor(hue: Double) -> Color { Color(background(hue: hue)) }

  public static func foregroundColor(hue: Double) -> Color { Color(foreground(hue: hue)) }

  private static func rgba(hue: Double, saturation: Double, lightness: Double) -> HaspRGBA {
    let chroma = (1 - abs(2 * lightness - 1)) * saturation
    let sector = hue.truncatingRemainder(dividingBy: 360) / 60
    let second = chroma * (1 - abs(sector.truncatingRemainder(dividingBy: 2) - 1))
    let offset = lightness - chroma / 2
    let (red, green, blue): (Double, Double, Double) =
      switch Int(sector) {
      case 0: (chroma, second, 0)
      case 1: (second, chroma, 0)
      case 2: (0, chroma, second)
      case 3: (0, second, chroma)
      case 4: (second, 0, chroma)
      default: (chroma, 0, second)
      }
    return HaspRGBA(red: red + offset, green: green + offset, blue: blue + offset)
  }
}

extension Color {
  public init(_ rgba: HaspRGBA) {
    self.init(.sRGB, red: rgba.red, green: rgba.green, blue: rgba.blue, opacity: rgba.alpha)
  }

  public init(_ pair: HaspColorPair) {
    #if canImport(AppKit)
      self.init(
        nsColor: NSColor(name: nil) { appearance in
          let isDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
          return NSColor(isDark ? pair.dark : pair.light)
        }
      )
    #else
      self.init(
        uiColor: UIColor { traits in
          UIColor(traits.userInterfaceStyle == .dark ? pair.dark : pair.light)
        }
      )
    #endif
  }
}

#if canImport(AppKit)
  extension NSColor {
    fileprivate convenience init(_ rgba: HaspRGBA) {
      self.init(srgbRed: rgba.red, green: rgba.green, blue: rgba.blue, alpha: rgba.alpha)
    }
  }
#else
  extension UIColor {
    fileprivate convenience init(_ rgba: HaspRGBA) {
      self.init(red: rgba.red, green: rgba.green, blue: rgba.blue, alpha: rgba.alpha)
    }
  }
#endif

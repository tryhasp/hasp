public import SwiftUI

public enum HaspColorValues {
  public static let text = HaspColorPair(light: HaspRGBA(0x1d1d1f), dark: HaspRGBA(0xf5f5f7))
  public static let textSecondary = HaspColorPair(
    light: HaspRGBA(0x404043),
    dark: HaspRGBA(0xcfcfd1),
  )
  public static let window = HaspColorPair(light: HaspRGBA(0xffffff), dark: HaspRGBA(0x1e1e20))
  public static let sidebar = HaspColorPair(light: HaspRGBA(0xe7e9ec), dark: HaspRGBA(0x25272a))
  public static let list = HaspColorPair(light: HaspRGBA(0xffffff), dark: HaspRGBA(0x1e1e20))
  public static let group = HaspColorPair(light: HaspRGBA(0xf5f5f7), dark: HaspRGBA(0x2a2a2d))
  public static let separator = HaspColorPair(light: HaspRGBA(0xe0e0e4), dark: HaspRGBA(0x38383c))
  public static let controlBorder = HaspColorPair(
    light: HaspRGBA(0x8a8a90),
    dark: HaspRGBA(0x8a8a90),
  )
  public static let selectedSidebar = HaspColorPair(
    light: HaspRGBA(0xd3d8de),
    dark: HaspRGBA(0x3a3d42),
  )
  public static let selectedRow = HaspColorPair(
    light: HaspRGBA(0xdbe5ea),
    dark: HaspRGBA(0x2d3a42),
  )
  public static let accent = HaspColorPair(light: HaspRGBA(0x435c6b), dark: HaspRGBA(0x435c6b))
  public static let accentText = HaspColorPair(light: HaspRGBA(0x2f4350), dark: HaspRGBA(0xc8d4dc))
  public static let onAccent = HaspColorPair(light: HaspRGBA(0xffffff), dark: HaspRGBA(0xffffff))
  public static let chip = HaspColorPair(light: HaspRGBA(0xe7e7ea), dark: HaspRGBA(0x3a3a3e))
  public static let field = HaspColorPair(light: HaspRGBA(0xffffff), dark: HaspRGBA(0x1e1e20))
  public static let tickOff = HaspColorPair(light: HaspRGBA(0x84848a), dark: HaspRGBA(0x76767b))
  public static let ink = HaspColorPair(light: HaspRGBA(0x1d1d1f), dark: HaspRGBA(0xf5f5f7))
  public static let onInk = HaspColorPair(light: HaspRGBA(0xffffff), dark: HaspRGBA(0x1d1d1f))
  public static let warning = HaspColorPair(light: HaspRGBA(0x7b5000), dark: HaspRGBA(0x7b5000))
  public static let onWarning = HaspColorPair(light: HaspRGBA(0xffffff), dark: HaspRGBA(0xffffff))
  public static let keycapOnInk = HaspColorPair(
    light: HaspRGBA(0xffffff, alpha: 0.2),
    dark: HaspRGBA(0xffffff, alpha: 0.2),
  )
}

public enum HaspColor {
  public static let text = Color(HaspColorValues.text)
  public static let textSecondary = Color(HaspColorValues.textSecondary)
  public static let window = Color(HaspColorValues.window)
  public static let sidebar = Color(HaspColorValues.sidebar)
  public static let list = Color(HaspColorValues.list)
  public static let group = Color(HaspColorValues.group)
  public static let separator = Color(HaspColorValues.separator)
  public static let controlBorder = Color(HaspColorValues.controlBorder)
  public static let selectedSidebar = Color(HaspColorValues.selectedSidebar)
  public static let selectedRow = Color(HaspColorValues.selectedRow)
  public static let accent = Color(HaspColorValues.accent)
  public static let accentText = Color(HaspColorValues.accentText)
  public static let onAccent = Color(HaspColorValues.onAccent)
  public static let chip = Color(HaspColorValues.chip)
  public static let field = Color(HaspColorValues.field)
  public static let tickOff = Color(HaspColorValues.tickOff)
  public static let ink = Color(HaspColorValues.ink)
  public static let onInk = Color(HaspColorValues.onInk)
  public static let warning = Color(HaspColorValues.warning)
  public static let onWarning = Color(HaspColorValues.onWarning)
  public static let keycapOnInk = Color(HaspColorValues.keycapOnInk)
  public static let trafficLightClose = Color(HaspRGBA(0xff5f57))
  public static let trafficLightMinimize = Color(HaspRGBA(0xfebc2e))
  public static let trafficLightZoom = Color(HaspRGBA(0x28c840))
  public static let trafficLightRing = Color(HaspRGBA(0x000000, alpha: 0.18))
  public static let quickPanelBorder = Color(HaspRGBA(0x5f6c75))
  public static let inlineMenuBackground = Color(HaspRGBA(0xffffff))
  public static let inlineMenuBorder = Color(HaspRGBA(0x6f7b86))
  public static let inlineMenuHeader = Color(HaspRGBA(0xf1f3f5))
  public static let inlineMenuDivider = Color(HaspRGBA(0xcfd6dc))
  public static let inlineMenuText = Color(HaspRGBA(0x1c2630))
  public static let inlineMenuTextSecondary = Color(HaspRGBA(0x38424b))
  public static let inlineMenuSelectedRow = Color(HaspRGBA(0xdbe5ea))
  public static let inlineMenuTile = Color(HaspRGBA(0xe4e9ec))
  public static let inlineMenuTileText = Color(HaspRGBA(0x2f4654))
  public static let inlineMenuSelectedTile = Color(HaspRGBA(0x435c6b))
  public static let inlineMenuSelectedTileText = Color(HaspRGBA(0xffffff))
  public static let inlineMenuKeycap = Color(HaspRGBA(0xe4e9ec))
  public static let inlineMenuKeycapText = Color(HaspRGBA(0x1c2630))
}

public enum HaspTile {
  public static let light = HaspTileTone(
    backgroundSaturation: 0.2,
    backgroundLightness: 0.92,
    foregroundSaturation: 0.34,
    foregroundLightness: 0.23,
  )
  public static let dark = HaspTileTone(
    backgroundSaturation: 0.16,
    backgroundLightness: 0.27,
    foregroundSaturation: 0.34,
    foregroundLightness: 0.9,
  )
}

public enum HaspFont {
  public static let caption = HaspTextStyle(
    size: 12,
    weight: .regular,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let captionMedium = HaspTextStyle(
    size: 12,
    weight: .medium,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let captionStrong = HaspTextStyle(
    size: 12,
    weight: .semibold,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let captionTabular = HaspTextStyle(
    size: 12,
    weight: .regular,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: true,
  )
  public static let captionRelaxed = HaspTextStyle(
    size: 12,
    weight: .regular,
    lineHeight: 1.55,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let hostInline = HaspTextStyle(
    size: 12,
    weight: .semibold,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: true,
    tabularNums: false,
  )
  public static let body = HaspTextStyle(
    size: 13,
    weight: .regular,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let bodyMedium = HaspTextStyle(
    size: 13,
    weight: .medium,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let bodyStrong = HaspTextStyle(
    size: 13,
    weight: .semibold,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let bodyRelaxed = HaspTextStyle(
    size: 13,
    weight: .regular,
    lineHeight: 1.5,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let origin = HaspTextStyle(
    size: 13,
    weight: .regular,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: true,
    tabularNums: false,
  )
  public static let originStrong = HaspTextStyle(
    size: 13,
    weight: .bold,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: true,
    tabularNums: false,
  )
  public static let originLarge = HaspTextStyle(
    size: 16,
    weight: .regular,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: true,
    tabularNums: false,
  )
  public static let originLargeStrong = HaspTextStyle(
    size: 16,
    weight: .bold,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: true,
    tabularNums: false,
  )
  public static let bodyLarge = HaspTextStyle(
    size: 14,
    weight: .regular,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let bodyLargeMedium = HaspTextStyle(
    size: 14,
    weight: .medium,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let bodyLargeRelaxed = HaspTextStyle(
    size: 14,
    weight: .regular,
    lineHeight: 1.6,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let secretCompact = HaspTextStyle(
    size: 14,
    weight: .regular,
    lineHeight: 1.4,
    letterSpacing: 0.08,
    monospaced: true,
    tabularNums: false,
  )
  public static let secret = HaspTextStyle(
    size: 15,
    weight: .regular,
    lineHeight: 1.2,
    letterSpacing: 0.08,
    monospaced: true,
    tabularNums: false,
  )
  public static let titleSmall = HaspTextStyle(
    size: 17,
    weight: .semibold,
    lineHeight: 1.2,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let titleSettings = HaspTextStyle(
    size: 17,
    weight: .semibold,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let queryField = HaspTextStyle(
    size: 18,
    weight: .regular,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let unlockField = HaspTextStyle(
    size: 18,
    weight: .regular,
    lineHeight: 1.4,
    letterSpacing: 0.14,
    monospaced: true,
    tabularNums: false,
  )
  public static let titleConfirm = HaspTextStyle(
    size: 19,
    weight: .bold,
    lineHeight: 1.3,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let otpCompact = HaspTextStyle(
    size: 20,
    weight: .regular,
    lineHeight: 1.4,
    letterSpacing: 0.06,
    monospaced: false,
    tabularNums: true,
  )
  public static let title = HaspTextStyle(
    size: 22,
    weight: .semibold,
    lineHeight: 1.2,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let headline = HaspTextStyle(
    size: 24,
    weight: .semibold,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let titleLocked = HaspTextStyle(
    size: 26,
    weight: .semibold,
    lineHeight: 1.25,
    letterSpacing: -0.01,
    monospaced: false,
    tabularNums: false,
  )
  public static let otpDigits = HaspTextStyle(
    size: 30,
    weight: .regular,
    lineHeight: 1.15,
    letterSpacing: 0.06,
    monospaced: false,
    tabularNums: true,
  )
  public static let tileLetter = HaspTextStyle(
    size: 13,
    weight: .semibold,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let tileLetterPreview = HaspTextStyle(
    size: 18,
    weight: .semibold,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
  public static let tileLetterHeader = HaspTextStyle(
    size: 24,
    weight: .semibold,
    lineHeight: 1.4,
    letterSpacing: 0,
    monospaced: false,
    tabularNums: false,
  )
}

public enum HaspSpace {
  public static let s2: CGFloat = 2
  public static let s4: CGFloat = 4
  public static let s6: CGFloat = 6
  public static let s8: CGFloat = 8
  public static let s10: CGFloat = 10
  public static let s12: CGFloat = 12
  public static let s14: CGFloat = 14
  public static let s16: CGFloat = 16
  public static let s18: CGFloat = 18
  public static let s20: CGFloat = 20
  public static let s24: CGFloat = 24
  public static let s28: CGFloat = 28
  public static let s32: CGFloat = 32
  public static let s36: CGFloat = 36
  public static let s40: CGFloat = 40
}

public enum HaspRadius {
  public static let keycap: CGFloat = 4
  public static let chip: CGFloat = 5
  public static let tag: CGFloat = 6
  public static let control: CGFloat = 7
  public static let tile: CGFloat = 7
  public static let row: CGFloat = 8
  public static let toast: CGFloat = 8
  public static let menu: CGFloat = 8
  public static let field: CGFloat = 9
  public static let card: CGFloat = 9
  public static let group: CGFloat = 10
  public static let tilePreview: CGFloat = 10
  public static let tileHeader: CGFloat = 13
  public static let panel: CGFloat = 16
  public static let mark: CGFloat = 20
  public static let tick: CGFloat = 1
  public static let full: CGFloat = 9999
}

public enum HaspBorder {
  public static let hairline: CGFloat = 1
  public static let emphasis: CGFloat = 2
  public static let trafficLightRing: CGFloat = 0.5
  public static let focusGap: CGFloat = 2
  public static let focusRing: CGFloat = 2
  public static let underlineOffset: CGFloat = 2
  public static let underlineOffsetEmphasis: CGFloat = 3
  public static let underlineThicknessEmphasis: CGFloat = 2
}

public enum HaspSize {
  public static let windowWidth: CGFloat = 1280
  public static let windowHeight: CGFloat = 800
  public static let sidebarWidth: CGFloat = 224
  public static let listWidth: CGFloat = 340
  public static let toolbarHeight: CGFloat = 52
  public static let rowHeight: CGFloat = 44
  public static let rowHeightQuickAccess: CGFloat = 52
  public static let menuWidth: CGFloat = 340
  public static let menuRowHeight: CGFloat = 48
  public static let menuHeaderHeight: CGFloat = 40
  public static let menuActionHeight: CGFloat = 44
  public static let tile: CGFloat = 28
  public static let tileQuickAccess: CGFloat = 32
  public static let tilePreview: CGFloat = 40
  public static let tileHeader: CGFloat = 56
  public static let controlHeight: CGFloat = 28
  public static let controlHeightCompact: CGFloat = 24
  public static let controlHeightPopup: CGFloat = 32
  public static let controlHeightSettings: CGFloat = 30
  public static let controlHeightConfirm: CGFloat = 34
  public static let controlHeightLarge: CGFloat = 40
  public static let targetMin: CGFloat = 28
  public static let iconButton: CGFloat = 28
  public static let iconButtonPopup: CGFloat = 32
  public static let iconButtonLarge: CGFloat = 40
  public static let glyphButton: CGFloat = 36
  public static let glyphBadge: CGFloat = 16
  public static let glyph: CGFloat = 16
  public static let icon: CGFloat = 16
  public static let iconSmall: CGFloat = 12
  public static let iconSearch: CGFloat = 14
  public static let iconToolbar: CGFloat = 18
  public static let iconQuickSearch: CGFloat = 18
  public static let iconBiometric: CGFloat = 22
  public static let iconWarning: CGFloat = 22
  public static let iconMark: CGFloat = 44
  public static let keycapMinWidth: CGFloat = 20
  public static let keycapMinWidthWide: CGFloat = 22
  public static let keycapLineHeight: CGFloat = 18
  public static let tickWidth: CGFloat = 3
  public static let tickHeight: CGFloat = 16
  public static let tickHeightOff: CGFloat = 8
  public static let tickGap: CGFloat = 2
  public static let tickCount: CGFloat = 30
  public static let trafficLight: CGFloat = 12
  public static let trafficLightGap: CGFloat = 8
  public static let trafficLightInsetLeading: CGFloat = 19
  public static let trafficLightInsetTop: CGFloat = 20
  public static let searchWidth: CGFloat = 200
  public static let settingsFieldWidth: CGFloat = 200
  public static let unlockFieldWidth: CGFloat = 352
  public static let markSize: CGFloat = 88
  public static let paneWidth: CGFloat = 620
  public static let formFieldMinHeight: CGFloat = 52
  public static let formFieldMinHeightOtp: CGFloat = 84
  public static let toastHeight: CGFloat = 34
  public static let quickAccessWidth: CGFloat = 700
  public static let quickAccessHeight: CGFloat = 380
  public static let quickAccessQueryHeight: CGFloat = 56
  public static let quickAccessListWidth: CGFloat = 300
  public static let quickAccessHintHeight: CGFloat = 44
  public static let popupWidth: CGFloat = 360
  public static let popupHeight: CGFloat = 560
  public static let popupHeaderHeight: CGFloat = 40
  public static let popupBarHeight: CGFloat = 52
  public static let confirmWidth: CGFloat = 420
  public static let confirmHeight: CGFloat = 520
  public static let confirmTitleBarHeight: CGFloat = 36
  public static let settingsWidth: CGFloat = 640
  public static let settingsHeight: CGFloat = 420
  public static let settingsTitleBarHeight: CGFloat = 44
}

public enum HaspMotion {
  public static let dwell: Duration = .milliseconds(400)
  public static let revealTimeout: Duration = .seconds(15)
  public static let clipboardClear: Duration = .seconds(30)
}

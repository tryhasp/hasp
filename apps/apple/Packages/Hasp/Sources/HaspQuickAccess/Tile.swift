import HaspDesign
import HaspQuickAccessCore
import SwiftUI

struct Tile: View {
  let title: String
  let size: CGFloat
  let selected: Bool

  var body: some View {
    let hue = TileHue.hue(for: title)
    Text(TileHue.letter(for: title))
      .haspText(HaspFont.bodyStrong)
      .foregroundStyle(selected ? HaspColor.onAccent : HaspTile.foregroundColor(hue: hue))
      .frame(width: size, height: size)
      .background(
        selected ? HaspColor.accent : HaspTile.backgroundColor(hue: hue),
        in: RoundedRectangle(cornerRadius: HaspRadius.tile),
      )
      .accessibilityHidden(true)
  }
}

struct Keycap: View {
  let label: String

  var body: some View {
    Text(label)
      .haspText(HaspFont.caption)
      .foregroundStyle(HaspColor.text)
      .frame(minWidth: HaspSize.keycapMinWidth)
      .padding(.horizontal, HaspSpace.s4)
      .background(HaspColor.chip, in: RoundedRectangle(cornerRadius: HaspRadius.keycap))
  }
}

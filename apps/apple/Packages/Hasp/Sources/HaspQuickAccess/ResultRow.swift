import HaspDesign
import HaspQuickAccessCore
import SwiftUI

struct ResultRow: View {
  let item: QuickItem
  let selected: Bool
  let onSelect: () -> Void

  var body: some View {
    Button(action: onSelect) {
      HStack(spacing: HaspSpace.s10) {
        Tile(title: item.title, size: HaspSize.tileQuickAccess, selected: selected)
        VStack(alignment: .leading, spacing: 0) {
          Text(item.title)
            .haspText(selected ? HaspFont.bodyStrong : HaspFont.bodyMedium)
            .foregroundStyle(HaspColor.text)
          Text(item.username)
            .haspText(HaspFont.caption)
            .foregroundStyle(HaspColor.textSecondary)
        }
        .lineLimit(1)
        Spacer(minLength: 0)
        if item.isShared {
          Label(item.vaultName, systemImage: "person.2")
            .haspText(HaspFont.caption)
            .foregroundStyle(HaspColor.textSecondary)
        }
      }
      .padding(.horizontal, HaspSpace.s8)
      .frame(height: HaspSize.rowHeightQuickAccess)
      .background(
        selected ? HaspColor.selectedRow : Color.clear,
        in: RoundedRectangle(cornerRadius: HaspRadius.row),
      )
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
    .accessibilityAddTraits(selected ? .isSelected : [])
  }
}

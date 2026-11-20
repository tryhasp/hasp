import HaspDesign
import HaspKit
import SwiftUI

struct DetailGroup<Content: View>: View {
  @ViewBuilder let content: Content

  var body: some View {
    VStack(spacing: 0) { content }
      .frame(maxWidth: .infinity, alignment: .leading)
      .background(HaspColor.group, in: RoundedRectangle(cornerRadius: HaspRadius.group))
  }
}

struct DetailHeader: View {
  let summary: ItemSummary
  let kindName: String

  var body: some View {
    HStack(spacing: HaspSpace.s14) {
      MonogramTile(title: summary.title, size: HaspSize.tileHeader)
      VStack(alignment: .leading, spacing: HaspSpace.s2) {
        Text(summary.title)
          .haspText(HaspFont.title)
          .foregroundStyle(HaspColor.text)
          .accessibilityAddTraits(.isHeader)
        Text(kindName)
          .haspText(HaspFont.body)
          .foregroundStyle(HaspColor.textSecondary)
      }
    }
    .accessibilityElement(children: .combine)
  }
}

struct NotesGroup: View {
  let summary: ItemSummary
  let notes: String?

  var body: some View {
    if !summary.tags.isEmpty || notes != nil {
      DetailGroup {
        if !summary.tags.isEmpty {
          VStack(alignment: .leading, spacing: HaspSpace.s6) {
            Text("detail.tags")
              .haspText(HaspFont.caption)
              .foregroundStyle(HaspColor.textSecondary)
            HStack {
              ForEach(summary.tags, id: \.self) { tag in
                Text(tag)
                  .haspText(HaspFont.caption)
                  .padding(.horizontal, HaspSpace.s8)
                  .padding(.vertical, HaspSpace.s2)
                  .background(HaspColor.chip, in: RoundedRectangle(cornerRadius: HaspRadius.tag))
              }
            }
          }
          .padding(HaspSpace.s14)
          .frame(maxWidth: .infinity, alignment: .leading)
        }
        if !summary.tags.isEmpty && notes != nil { Divider().overlay(HaspColor.separator) }
        if let notes {
          VStack(alignment: .leading, spacing: HaspSpace.s2) {
            Text("detail.notes")
              .haspText(HaspFont.caption)
              .foregroundStyle(HaspColor.textSecondary)
            Text(notes).haspText(HaspFont.bodyLarge).textSelection(.enabled)
          }
          .padding(HaspSpace.s14)
          .frame(maxWidth: .infinity, alignment: .leading)
        }
      }
    }
  }
}

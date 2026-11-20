import HaspDesign
import HaspKit
import SwiftUI

struct SecretTagSettings: View {
  @Bindable var model: SettingsModel

  private static let glyphs = [
    "circle.fill", "square.fill", "triangle.fill", "diamond.fill", "star.fill", "moon.fill",
    "water.waves", "leaf.fill", "plus", "hexagon.fill", "drop.fill", "circle.circle",
  ]

  var body: some View {
    VStack(alignment: .leading, spacing: HaspSpace.s16) {
      Text("tag.title").haspText(HaspFont.titleSettings)
        .accessibilityAddTraits(.isHeader)
      Text("tag.subtitle").haspText(HaspFont.body).foregroundStyle(HaspColor.textSecondary)
      HStack {
        Text("tag.word").haspText(HaspFont.bodyMedium)
        TextField("tag.word", text: $model.tagWord)
          .haspField()
          .frame(width: HaspSize.settingsFieldWidth)
          .onChange(of: model.tagWord) {
            model.tagWord = String(model.tagWord.prefix(SecretTag.maxWordLength))
          }
          .accessibilityIdentifier("tag.word")
        Text("\(model.tagWord.count)/\(SecretTag.maxWordLength)")
          .haspText(HaspFont.captionTabular)
          .foregroundStyle(HaspColor.textSecondary)
      }
      HStack(alignment: .top) {
        Text("tag.glyph").haspText(HaspFont.bodyMedium)
        glyphGrid
      }
      HStack {
        Text("tag.preview").haspText(HaspFont.caption).foregroundStyle(HaspColor.textSecondary)
        TagChip(word: model.tagWord, glyph: model.tagGlyph)
        Spacer()
        Button("common.save") { Task { await model.saveTag() } }
          .buttonStyle(HaspBorderedButtonStyle())
          .disabled(!model.tagIsValid)
          .accessibilityIdentifier("tag.save")
      }
      .padding(HaspSpace.s12)
      .background(HaspColor.group, in: RoundedRectangle(cornerRadius: HaspRadius.group))
      Text("tag.warning").haspText(HaspFont.caption).foregroundStyle(HaspColor.textSecondary)
    }
    .padding(HaspSpace.s24)
  }

  private var glyphGrid: some View {
    LazyVGrid(columns: Array(repeating: GridItem(.fixed(HaspSize.glyphButton)), count: 6)) {
      ForEach(Self.glyphs.indices, id: \.self) { index in
        Button {
          model.tagGlyph = index
        } label: {
          Image(systemName: Self.glyphs[index])
            .frame(width: HaspSize.glyphButton, height: HaspSize.glyphButton)
            .foregroundStyle(model.tagGlyph == index ? HaspColor.onAccent : HaspColor.text)
            .background(
              model.tagGlyph == index ? HaspColor.accent : HaspColor.field,
              in: RoundedRectangle(cornerRadius: HaspRadius.control),
            )
            .overlay(
              RoundedRectangle(cornerRadius: HaspRadius.control)
                .stroke(HaspColor.controlBorder, lineWidth: HaspBorder.hairline)
            )
        }
        .buttonStyle(.plain)
        .accessibilityLabel(LocalizedStringKey("tag.glyph." + String(index)))
        .accessibilityAddTraits(model.tagGlyph == index ? .isSelected : [])
      }
    }
  }

  static func symbol(_ glyph: Int) -> String {
    glyphs[glyph % glyphs.count]
  }
}

struct TagChip: View {
  let word: String
  let glyph: Int

  var body: some View {
    HStack(spacing: HaspSpace.s4) {
      Image(systemName: SecretTagSettings.symbol(glyph))
      Text(word).haspText(HaspFont.captionStrong)
    }
    .padding(.horizontal, HaspSpace.s8)
    .frame(minHeight: HaspSize.controlHeightCompact)
    .overlay(
      RoundedRectangle(cornerRadius: HaspRadius.control)
        .stroke(HaspColor.controlBorder, lineWidth: HaspBorder.hairline)
    )
    .accessibilityElement(children: .combine)
  }
}

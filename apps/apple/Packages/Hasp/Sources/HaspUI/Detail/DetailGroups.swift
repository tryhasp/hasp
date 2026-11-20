#if os(macOS)
  import HaspDesign
  import HaspKit
  import HaspPlatform
  import SwiftUI
  import UniformTypeIdentifiers

  struct URLGroup: View {
    let urls: [ItemURL]
    @Environment(\.openURL) private var openURL

    var body: some View {
      if !urls.isEmpty {
        DetailGroup {
          ForEach(urls) { entry in
            HStack {
              VStack(alignment: .leading, spacing: HaspSpace.s2) {
                Text("detail.website")
                  .haspText(HaspFont.caption)
                  .foregroundStyle(HaspColor.textSecondary)
                Text(entry.url)
                  .haspText(HaspFont.bodyLarge)
                  .foregroundStyle(HaspColor.accentText)
                  .underline()
                  .textSelection(.enabled)
              }
              Spacer()
              IconButton(systemName: "arrow.up.right.square", label: "detail.openURL") {
                if let url = URL(string: entry.url) { openURL(url) }
              }
            }
            .padding(.horizontal, HaspSpace.s14)
            .frame(minHeight: HaspSize.formFieldMinHeight)
          }
        }
      }
    }
  }

  struct AttachmentGroup: View {
    let model: ItemDetailModel
    let attachments: [AttachmentSummary]
    @State private var picking = false

    var body: some View {
      DetailGroup {
        ForEach(attachments) { attachment in
          AttachmentRow(model: model, attachment: attachment)
          Divider().overlay(HaspColor.separator)
        }
        Button("attachments.add") { picking = true }
          .buttonStyle(.plain)
          .foregroundStyle(HaspColor.accentText)
          .haspText(HaspFont.bodyMedium)
          .padding(HaspSpace.s14)
          .frame(maxWidth: .infinity, alignment: .leading)
          .accessibilityIdentifier("attachments.add")
      }
      .fileImporter(isPresented: $picking, allowedContentTypes: [.item]) { result in
        guard case .success(let url) = result else { return }
        Task {
          let granted = url.startAccessingSecurityScopedResource()
          defer { if granted { url.stopAccessingSecurityScopedResource() } }
          await model.attach(fileAt: url)
        }
      }
    }
  }

  struct AttachmentRow: View {
    let model: ItemDetailModel
    let attachment: AttachmentSummary
    @Environment(\.openURL) private var openURL

    var body: some View {
      HStack {
        VStack(alignment: .leading, spacing: HaspSpace.s2) {
          Text(attachment.name).haspText(HaspFont.bodyMedium)
          Text(ByteCountFormatter.string(fromByteCount: Int64(attachment.size), countStyle: .file))
            .haspText(HaspFont.caption)
            .foregroundStyle(HaspColor.textSecondary)
        }
        Spacer()
        IconButton(systemName: "arrow.up.forward.app", label: "attachments.open") {
          Task { if let file = await model.openableFile(for: attachment) { openURL(file) } }
        }
        IconButton(systemName: "square.and.arrow.down", label: "attachments.save") {
          Task {
            guard let target = await FilePanels.saveLocation(suggestedName: attachment.name) else {
              return
            }
            await model.save(attachment, to: target)
          }
        }
        IconButton(systemName: "trash", label: "attachments.remove") {
          Task { await model.removeAttachment(attachment) }
        }
      }
      .padding(.horizontal, HaspSpace.s14)
      .frame(minHeight: HaspSize.formFieldMinHeight)
      .accessibilityElement(children: .contain)
    }
  }
#endif

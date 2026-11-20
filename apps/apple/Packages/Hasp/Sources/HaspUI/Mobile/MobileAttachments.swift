#if os(iOS)
  import HaspDesign
  import HaspKit
  import SwiftUI
  import UniformTypeIdentifiers

  struct AttachmentDocument: FileDocument {
    static let readableContentTypes: [UTType] = [.item]
    let data: Data

    init(data: Data) {
      self.data = data
    }

    init(configuration: ReadConfiguration) throws {
      data = configuration.file.regularFileContents ?? Data()
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
      FileWrapper(regularFileWithContents: data)
    }
  }

  struct MobileAttachmentGroup: View {
    let model: ItemDetailModel
    let attachments: [AttachmentSummary]
    @State private var picking = false

    var body: some View {
      DetailGroup {
        ForEach(attachments) { attachment in
          MobileAttachmentRow(model: model, attachment: attachment)
          Divider().overlay(HaspColor.separator)
        }
        Button("attachments.add") { picking = true }
          .buttonStyle(.plain)
          .foregroundStyle(HaspColor.accentText)
          .haspText(HaspFont.bodyMedium)
          .frame(maxWidth: .infinity, minHeight: MobileMetrics.touchTarget, alignment: .leading)
          .padding(.horizontal, HaspSpace.s14)
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

  struct MobileAttachmentRow: View {
    let model: ItemDetailModel
    let attachment: AttachmentSummary
    @State private var exporting: AttachmentDocument?

    var body: some View {
      HStack(spacing: 0) {
        VStack(alignment: .leading, spacing: HaspSpace.s2) {
          Text(attachment.name).haspText(HaspFont.bodyMedium)
          Text(ByteCountFormatter.string(fromByteCount: Int64(attachment.size), countStyle: .file))
            .haspText(HaspFont.caption)
            .foregroundStyle(HaspColor.textSecondary)
        }
        Spacer()
        MobileIconButton(systemName: "square.and.arrow.down", label: "attachments.save") {
          Task {
            if let data = await model.data(for: attachment) {
              exporting = AttachmentDocument(data: data)
            }
          }
        }
        MobileIconButton(systemName: "trash", label: "attachments.remove") {
          Task { await model.removeAttachment(attachment) }
        }
      }
      .padding(.leading, HaspSpace.s14)
      .padding(.trailing, HaspSpace.s4)
      .frame(minHeight: HaspSize.formFieldMinHeight)
      .accessibilityElement(children: .contain)
      .fileExporter(
        isPresented: Binding(get: { exporting != nil }, set: { if !$0 { exporting = nil } }),
        document: exporting,
        contentType: .item,
        defaultFilename: attachment.name,
      ) { _ in exporting = nil }
    }
  }
#endif

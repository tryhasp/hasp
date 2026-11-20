#if os(macOS)
  import HaspDesign
  import HaspKit
  import HaspPlatform
  import SwiftUI

  struct EmergencyKitSheet: View {
    let app: AppModel
    let kit: EmergencyKit
    @State private var saved = false
    @State private var typedGroup = ""

    var body: some View {
      VStack(alignment: .leading, spacing: HaspSpace.s16) {
        Text("kit.title")
          .haspText(HaspFont.titleConfirm)
          .accessibilityAddTraits(.isHeader)
        Text("kit.body")
          .haspText(HaspFont.bodyRelaxed)
          .foregroundStyle(HaspColor.textSecondary)
        Text("kit.secretKey").haspText(HaspFont.caption)
          .foregroundStyle(HaspColor.textSecondary)
        Text(kit.secretKey)
          .haspText(HaspFont.hostInline)
          .textSelection(.enabled)
          .accessibilityIdentifier("kit.secretKey")
        Text("kit.fingerprint").haspText(HaspFont.caption)
          .foregroundStyle(HaspColor.textSecondary)
        Text(kit.serverFingerprint).haspText(HaspFont.hostInline).textSelection(.enabled)
        HStack {
          Button("kit.save") { Task { await save() } }
            .buttonStyle(HaspBorderedButtonStyle())
            .accessibilityIdentifier("kit.save")
          if saved { Text("kit.saved").haspText(HaspFont.caption) }
        }
        TextField("kit.lastGroup", text: $typedGroup)
          .haspField()
          .accessibilityIdentifier("kit.lastGroup")
        HStack {
          Spacer()
          Button("kit.continue") { app.finishEmergencyKit() }
            .buttonStyle(HaspBorderedButtonStyle())
            .keyboardShortcut(.defaultAction)
            .disabled(!matches)
            .accessibilityIdentifier("kit.continue")
        }
      }
      .padding(HaspSpace.s24)
      .frame(width: HaspSize.confirmWidth)
      .interactiveDismissDisabled()
    }

    private var matches: Bool {
      guard let last = kit.secretKey.split(separator: "-").last else { return false }
      return typedGroup.trimmingCharacters(in: .whitespaces).caseInsensitiveCompare(String(last))
        == .orderedSame
    }

    private func save() async {
      guard let url = await FilePanels.saveLocation(suggestedName: "Hasp Emergency Kit.pdf") else {
        return
      }
      do {
        try kit.documentPdf.write(to: url, options: .completeFileProtection)
        saved = true
      } catch {
        app.show(error: error)
      }
    }
  }
#endif

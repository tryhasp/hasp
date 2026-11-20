#if os(iOS)
  import HaspDesign
  import HaspKit
  import HaspPlatform
  import SwiftUI

  struct MobileScanSheet: View {
    let model: OnboardingModel
    @Binding var isPresented: Bool

    var body: some View {
      ZStack(alignment: .topTrailing) {
        KitScannerView(
          onPayload: { payload in
            model.importKit(payload: payload)
            isPresented = false
          },
          onUnavailable: {
            model.scanUnavailable()
            isPresented = false
          },
        )
        .ignoresSafeArea()
        Button("common.close") { isPresented = false }
          .buttonStyle(MobileSecondaryButtonStyle())
          .frame(width: 120)
          .padding(HaspSpace.s16)
          .accessibilityIdentifier("scan.close")
      }
      .overlay(alignment: .bottom) {
        Text("m.scan.hint")
          .haspText(HaspFont.bodyMedium)
          .foregroundStyle(HaspColor.onInk)
          .padding(HaspSpace.s12)
          .background(
            HaspColor.ink.opacity(0.8),
            in: RoundedRectangle(cornerRadius: HaspRadius.toast),
          )
          .padding(.bottom, HaspSpace.s40)
      }
    }
  }

  struct MobileKitSheet: View {
    let app: AppModel
    let kit: EmergencyKit
    @State private var typedGroup = ""

    var body: some View {
      ScrollView {
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
          ShareLink(
            item: KitDocument(data: kit.documentPdf),
            preview: SharePreview("Hasp Emergency Kit.pdf"),
          ) {
            Label("m.kit.share", systemImage: "square.and.arrow.up")
          }
          .buttonStyle(MobileSecondaryButtonStyle())
          .accessibilityIdentifier("kit.save")
          TextField("kit.lastGroup", text: $typedGroup)
            .mobileField()
            .textInputAutocapitalization(.characters)
            .autocorrectionDisabled()
            .accessibilityIdentifier("kit.lastGroup")
          Button("kit.continue") { app.finishEmergencyKit() }
            .buttonStyle(MobilePrimaryButtonStyle())
            .disabled(!matches)
            .accessibilityIdentifier("kit.continue")
        }
        .padding(HaspSpace.s24)
      }
      .interactiveDismissDisabled()
      .background(HaspColor.window.ignoresSafeArea())
    }

    private var matches: Bool {
      guard let last = kit.secretKey.split(separator: "-").last else { return false }
      return typedGroup.trimmingCharacters(in: .whitespaces).caseInsensitiveCompare(String(last))
        == .orderedSame
    }
  }
#endif

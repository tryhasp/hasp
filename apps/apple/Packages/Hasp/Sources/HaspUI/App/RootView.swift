#if os(macOS)
  import HaspDesign
  import HaspPlatform
  import HaspKit
  public import SwiftUI

  public struct RootView: View {
    let app: AppModel

    public init(app: AppModel) {
      self.app = app
    }

    public var body: some View {
      Group {
        switch app.phase {
        case .starting:
          HaspColor.window
        case .onboarding:
          OnboardingView(app: app)
        case .locked:
          LockedView(app: app)
        case .unlocked:
          if let library = app.library { MainView(app: app, library: library) }
        }
      }
      .frame(minWidth: HaspSize.windowWidth * 0.7, minHeight: HaspSize.windowHeight * 0.7)
      .task { await app.launch() }
      .sheet(item: kitBinding) { kit in EmergencyKitSheet(app: app, kit: kit) }
      .sheet(isPresented: introBinding) { QuickAccessIntroSheet(app: app) }
    }

    private var kitBinding: Binding<EmergencyKit?> {
      Binding(
        get: { app.emergencyKit },
        set: { _ in },
      )
    }

    private var introBinding: Binding<Bool> {
      Binding(
        get: { app.showsQuickAccessIntro && app.emergencyKit == nil },
        set: { if !$0 { app.dismissQuickAccessIntro() } },
      )
    }

  }
#endif

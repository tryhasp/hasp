#if os(iOS)
  import HaspDesign
  import HaspKit
  public import SwiftUI

  public struct MobileRootView: View {
    let app: AppModel
    @Environment(\.scenePhase) private var scenePhase

    public init(app: AppModel) {
      self.app = app
    }

    public var body: some View {
      ZStack {
        content
        if app.showsPrivacyShield(sceneActive: scenePhase == .active) {
          PrivacyShield()
        }
      }
      .task { await app.launch() }
      .onChange(of: scenePhase) { _, phase in
        switch phase {
        case .background:
          app.sceneDidBackground(at: .now)
          Task { await app.lockForBackground() }
        case .active:
          app.sceneWillActivate()
          app.refreshUnlockAdvice()
          Task { await app.sceneDidActivate(at: .now) }
        case .inactive: break
        @unknown default: break
        }
      }
      .sheet(item: kitBinding) { kit in MobileKitSheet(app: app, kit: kit) }
      .sheet(isPresented: adviceBinding) { MobileUnlockAdviceSheet(app: app) }
      .overlay(alignment: .bottom) {
        if let toast = app.toast {
          ToastView(message: toast)
            .padding(.bottom, HaspSpace.s36 + HaspSpace.s32)
            .transition(.opacity)
        }
      }
      .animation(.default, value: app.toast)
      .dynamicTypeSize(...DynamicTypeSize.accessibility3)
    }

    @ViewBuilder private var content: some View {
      switch app.phase {
      case .starting:
        HaspColor.window.ignoresSafeArea()
      case .onboarding:
        MobileOnboardingView(app: app)
      case .locked:
        MobileLockedView(app: app)
      case .unlocked:
        if let library = app.library { MobileMainView(app: app, library: library) }
      }
    }

    private var adviceBinding: Binding<Bool> {
      Binding(get: { app.showsUnlockAdvice }, set: { app.showsUnlockAdvice = $0 })
    }

    private var kitBinding: Binding<EmergencyKit?> {
      Binding(get: { app.emergencyKit }, set: { _ in })
    }
  }
#endif

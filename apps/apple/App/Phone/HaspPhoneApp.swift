import HaspKit
import HaspProvider
import HaspUI
import SwiftUI

@main
struct HaspPhoneApp: App {
  @State private var model: AppModel
  private let refresh: BackgroundRefresh

  init() {
    ExecutionGuard.install(ApplicationBackgroundGrant())
    let made = PhoneBootstrap.make()
    _model = State(initialValue: made)
    refresh = BackgroundRefresh(model: made)
    refresh.register()
  }

  var body: some Scene {
    WindowGroup {
      MobileRootView(app: model)
        .onAppear { refresh.schedule() }
        .onContinueUserActivity(CredentialExchangeActivity.activityType) { activity in
          Task { await CredentialExchangeReceiver.receive(activity, into: model) }
        }
    }
  }
}

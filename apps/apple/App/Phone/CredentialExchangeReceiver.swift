import AuthenticationServices
import Foundation
import HaspKit
import HaspProvider
import HaspUI

/// The system opens the app with `ASCredentialExchangeActivity` when the user moves passwords and passkeys
/// here from another manager (iOS 26). The data never reaches disk: it goes straight to the engine.
@MainActor
enum CredentialExchangeReceiver {
  static func receive(_ activity: NSUserActivity, into model: AppModel) async {
    guard let token = CredentialExchangeActivity.token(from: activity.userInfo),
      let engine = model.activeSession as? any ProviderServing
    else { return }
    guard #available(iOS 26.0, *) else { return }
    let importer = CredentialExchangeImporter(source: SystemCredentialExchange(), engine: engine)
    do {
      let summary = try await importer.receive(token: token)
      model.announce(
        String(localized: "m.cxf.imported \(summary.imported + summary.mergedPasskeys)")
      )
    } catch {
      model.announce(error: error)
    }
  }
}

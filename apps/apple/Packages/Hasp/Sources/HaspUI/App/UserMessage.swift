import Foundation
import HaspKit

enum UserMessage {
  static func text(for error: any Error, store: StoreFailure? = nil) -> String {
    guard let error = error as? HaspError else { return String(localized: "error.internal") }
    if error == .internal, let store { return text(for: store) }
    return switch error {
    case .auth: String(localized: "error.auth")
    case .locked: String(localized: "error.locked")
    case .offline: String(localized: "error.offline")
    case .rateLimited: String(localized: "error.rateLimited")
    case .cancelled: String(localized: "error.cancelled")
    case .deviceRevoked: String(localized: "error.deviceRevoked")
    case .readOnly: String(localized: "error.readOnly")
    case .refused, .invite: String(localized: "error.refused")
    case .authz: String(localized: "error.authz")
    case .notFound: String(localized: "error.notFound")
    case .serverKey, .pin: String(localized: "error.serverKey")
    case .conflict, .pending, .quarantined, .unconfirmed: String(localized: "error.syncState")
    case .format: String(localized: "error.format")
    default: String(localized: "error.internal")
    }
  }

  static func text(for failure: StoreFailure) -> String {
    switch failure {
    case .passcodeNotSet: return String(localized: "error.store.passcode")
    case .missingEntitlement: return String(localized: "error.store.entitlement")
    case .deviceLocked: return String(localized: "error.store.locked")
    case .authenticationFailed: return String(localized: "error.store.auth")
    case .status(let code):
      let number = Int(code)
      return String(localized: "error.store.status \(number)")
    }
  }
}

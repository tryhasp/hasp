import Foundation
import HaspKit
import HaspPlatform
import Observation

@Observable
final class OnboardingModel {
  enum Method: Hashable {
    case secretKey
    case signUp
    case kit
  }

  var method = Method.secretKey
  var origin = "" {
    didSet { if origin != oldValue { resetFingerprint() } }
  }
  var code = ""
  var fingerprint: String?
  var fingerprintConfirmed = false
  var login = ""
  var secretKey = ""
  var password = ""
  private(set) var kitPreview: KitPreview?
  private(set) var kitBlob: Data?
  private(set) var kitFailed = false

  private let app: AppModel

  init(app: AppModel) {
    self.app = app
  }

  var canSubmit: Bool {
    guard !password.isEmpty, !app.busy else { return false }
    return switch method {
    case .secretKey:
      fingerprintConfirmed && !login.isEmpty && !secretKey.isEmpty
    case .signUp:
      fingerprintConfirmed && !login.isEmpty && !code.isEmpty
    case .kit: kitBlob != nil
    }
  }

  var needsServerCheck: Bool { method != .kit }

  func checkServer() async {
    resetFingerprint()
    fingerprint = await app.fetchFingerprint(origin: origin)
  }

  private func resetFingerprint() {
    fingerprint = nil
    fingerprintConfirmed = false
  }

  func importKit(from url: URL) {
    adopt(KitQRReader.payload(inImageAt: url))
  }

  func importKit(imageData: Data) {
    adopt(KitQRReader.payload(inImageData: imageData))
  }

  func importKit(payload: Data) {
    adopt(payload)
  }

  func scanUnavailable() {
    kitFailed = true
  }

  private func adopt(_ blob: Data?) {
    kitFailed = false
    guard let blob, let preview = try? AccountSession.previewKit(blob: blob) else {
      kitBlob = nil
      kitPreview = nil
      kitFailed = true
      return
    }
    kitBlob = blob
    kitPreview = preview
  }

  func submit() async {
    let typedPassword = password
    let typedKey = secretKey
    let typedCode = code
    password = ""
    secretKey = ""
    code = ""
    let trimmedLogin = login.trimmingCharacters(in: .whitespaces)
    switch method {
    case .secretKey:
      guard let fingerprint else { return }
      await app.signIn(
        origin: origin,
        login: trimmedLogin,
        secretKey: typedKey,
        password: typedPassword,
        fingerprint: fingerprint,
      )
    case .signUp:
      guard let fingerprint else { return }
      await app.signUp(
        origin: origin,
        login: trimmedLogin,
        code: typedCode,
        password: typedPassword,
        fingerprint: fingerprint,
      )
    case .kit:
      guard let kitBlob else { return }
      await app.signIn(kit: kitBlob, password: typedPassword)
    }
  }
}

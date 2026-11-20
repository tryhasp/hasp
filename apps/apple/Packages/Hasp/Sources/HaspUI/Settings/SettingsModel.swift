import Foundation
import HaspKit
import Observation

@Observable
final class SettingsModel {
  private(set) var devices: [DeviceSummary] = []
  private(set) var saved = false
  var tagWord: String
  var tagGlyph: Int

  private let app: AppModel

  init(app: AppModel) {
    self.app = app
    tagWord = app.settings.secretTag?.word ?? ""
    tagGlyph = app.settings.secretTag?.glyph ?? 0
  }

  var settings: AppSettings { app.settings }

  var tagIsValid: Bool {
    let count = tagWord.trimmingCharacters(in: .whitespaces).count
    return count >= 1 && count <= SecretTag.maxWordLength
  }

  func update(_ change: (inout AppSettings) -> Void) async {
    guard let session = app.activeSession else { return }
    var next = app.settings
    change(&next)
    do {
      try await session.setSettings(next)
      app.settings = next
      await app.settingsDidChange(session)
    } catch {
      app.show(error: error)
    }
  }

  func saveTag() async {
    guard tagIsValid else { return }
    let tag = SecretTag(word: tagWord.trimmingCharacters(in: .whitespaces), glyph: tagGlyph)
    await update { $0.secretTag = tag }
    saved = true
  }

  func loadDevices() async {
    guard let session = app.activeSession else { return }
    do {
      devices = try await session.devices()
    } catch {
      app.show(error: error)
    }
  }

  func revoke(_ device: DeviceSummary) async {
    guard let session = app.activeSession else { return }
    do {
      try await session.revokeDevice(device)
      if device.current { await app.accountEnded() }
      await loadDevices()
    } catch {
      app.show(error: error)
    }
  }
}

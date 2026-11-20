import Foundation
import HaspKit
import Observation

@Observable
final class WatchtowerModel {
  private(set) var summary: WatchtowerSummary?
  private(set) var checking = false

  private let library: LibraryModel
  private let app: AppModel
  private let session: any VaultServing

  init(library: LibraryModel, app: AppModel, session: any VaultServing) {
    self.library = library
    self.app = app
    self.session = session
    summary = library.watchtower
  }

  var breachCheckEnabled: Bool { app.settings.breachCheck }

  func count(_ kind: WatchKind) -> Int {
    summary?.findings.filter { $0.kind == kind }.count ?? 0
  }

  func optIn() async {
    guard let session = app.activeSession else { return }
    var next = app.settings
    next.breachCheck = true
    do {
      try await session.setSettings(next)
      app.settings = next
      await runBreachCheck()
    } catch {
      app.show(error: error)
    }
  }

  func runBreachCheck() async {
    guard app.settings.breachCheck else { return }
    checking = true
    defer { checking = false }
    do {
      summary = try await session.checkBreaches(using: app.breachSource)
      await library.refresh()
    } catch {
      app.show(error: error)
    }
  }
}

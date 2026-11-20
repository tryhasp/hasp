// Why: BGTask is not Sendable; the system hands it to the launch handler and expects completion from any thread.
@preconcurrency import BackgroundTasks
import Foundation
import HaspUI
import OSLog

private let log = Logger(subsystem: "kr.jmo.hasp", category: "refresh")

/// Opportunistic sync: the system decides when. It only runs while the keys are
/// still open, because a background task cannot ask for Face ID.
struct BackgroundRefresh: Sendable {
  static let identifier = "kr.jmo.hasp.refresh"

  let model: AppModel

  func register() {
    let model = model
    BGTaskScheduler.shared.register(forTaskWithIdentifier: Self.identifier, using: nil) { task in
      guard let task = task as? BGAppRefreshTask else { return }
      let work = Task { @MainActor in
        let synced = await model.refreshInBackground()
        BackgroundRefresh(model: model).schedule()
        task.setTaskCompleted(success: synced)
      }
      task.expirationHandler = { work.cancel() }
    }
  }

  func schedule() {
    let request = BGAppRefreshTaskRequest(identifier: Self.identifier)
    request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
    do {
      try BGTaskScheduler.shared.submit(request)
    } catch {
      log.info("background refresh was not scheduled")
    }
  }
}

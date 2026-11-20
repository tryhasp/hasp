import Synchronization

final class ManualClock: Clock, Sendable {
  struct Instant: InstantProtocol {
    var offset: Duration

    func advanced(by duration: Duration) -> Instant { Instant(offset: offset + duration) }
    func duration(to other: Instant) -> Duration { other.offset - offset }
    static func < (lhs: Instant, rhs: Instant) -> Bool { lhs.offset < rhs.offset }
  }

  private struct Sleeper {
    let deadline: Instant
    let continuation: CheckedContinuation<Void, any Error>
    let id: Int
  }

  private struct State {
    var now = Instant(offset: .zero)
    var sleepers: [Sleeper] = []
    var nextID = 0
  }

  private let state = Mutex(State())

  var now: Instant { state.withLock { $0.now } }
  var minimumResolution: Duration { .zero }

  var pendingSleepers: Int { state.withLock { $0.sleepers.count } }

  func sleep(until deadline: Instant, tolerance: Duration?) async throws {
    let id = state.withLock { state -> Int in
      state.nextID += 1
      return state.nextID
    }
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        let resumeNow = state.withLock { state -> Bool in
          if deadline <= state.now { return true }
          state.sleepers.append(Sleeper(deadline: deadline, continuation: continuation, id: id))
          return false
        }
        if resumeNow { continuation.resume() }
      }
    } onCancel: {
      let cancelled = state.withLock { state -> Sleeper? in
        guard let index = state.sleepers.firstIndex(where: { $0.id == id }) else { return nil }
        return state.sleepers.remove(at: index)
      }
      cancelled?.continuation.resume(throwing: CancellationError())
    }
  }

  func advance(by duration: Duration) {
    let due = state.withLock { state -> [Sleeper] in
      state.now = state.now.advanced(by: duration)
      let ready = state.sleepers.filter { $0.deadline <= state.now }
      state.sleepers.removeAll { $0.deadline <= state.now }
      return ready
    }
    for sleeper in due { sleeper.continuation.resume() }
  }
}

final class ImmediateClock: Clock, Sendable {
  typealias Instant = ManualClock.Instant
  var now: Instant { Instant(offset: .zero) }
  var minimumResolution: Duration { .zero }
  func sleep(until deadline: Instant, tolerance: Duration?) async throws {}
}

import Synchronization
import Testing

@testable import HaspKit

private final class Recorder: ExecutionGrant {
  let events = Mutex<[String]>([])

  func begin() -> @Sendable () -> Void {
    events.withLock { $0.append("begin") }
    return { [self] in events.withLock { $0.append("end") } }
  }
}

struct ExecutionGuardTests {
  @Test func everyEngineCallRunsInsideAGrantAndReleasesItAfterAFailure() throws {
    let recorder = Recorder()
    ExecutionGuard.install(recorder)
    defer { ExecutionGuard.install(ProcessActivityGrant()) }
    _ = try mapped { recorder.events.withLock { $0.append("call") } }
    #expect(throws: HaspError.internal) { try mapped { throw HaspError.internal } }
    #expect(recorder.events.withLock { $0 } == ["begin", "call", "end", "begin", "end"])
  }
}

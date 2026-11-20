import Dispatch
import Foundation
public import HaspKit
import Synchronization

/// `GET https://api.pwnedpasswords.com/range/<prefix>` with padding. Only the five-character prefix leaves the device.
public final class BreachRangeFetcher: BreachRangeSource {
  private let makeSession: @Sendable () -> URLSession
  private let session = Mutex<URLSession?>(nil)

  public init() {
    makeSession = { URLSession(configuration: Self.configuration()) }
  }

  init(makeSession: @escaping @Sendable () -> URLSession) {
    self.makeSession = makeSession
  }

  static func configuration() -> URLSessionConfiguration {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.urlCache = nil
    configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
    configuration.httpCookieStorage = nil
    configuration.httpShouldSetCookies = false
    configuration.urlCredentialStorage = nil
    return configuration
  }

  private func activeSession() -> URLSession {
    session.withLock { current in
      if let current { return current }
      let created = makeSession()
      current = created
      return created
    }
  }

  public func range(prefix: String) throws -> String {
    guard prefix.count == 5, prefix.allSatisfy(\.isHexDigit),
      let url = URL(string: "https://api.pwnedpasswords.com/range/\(prefix)")
    else { throw HaspError.refused }
    var request = URLRequest(url: url, timeoutInterval: 15)
    request.setValue("true", forHTTPHeaderField: "Add-Padding")
    let box = ResponseBox()
    // Why: the engine calls from a Rust thread and waits for the body.
    let finished = DispatchSemaphore(value: 0)
    activeSession().dataTask(with: request) { data, response, _ in
      box.set(data: data, status: (response as? HTTPURLResponse)?.statusCode ?? 0)
      finished.signal()
    }.resume()
    finished.wait()
    guard let body = box.body() else { throw HaspError.offline }
    return body
  }
}

private final class ResponseBox: @unchecked Sendable {
  // Why: written once in the completion handler before the semaphore is signalled, read after it.
  private var data: Data?
  private var status = 0

  func set(data: Data?, status: Int) {
    self.data = data
    self.status = status
  }

  func body() -> String? {
    guard status == 200, let data else { return nil }
    return String(data: data, encoding: .utf8)
  }
}

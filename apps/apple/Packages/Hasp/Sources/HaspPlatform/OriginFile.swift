public import Foundation

public struct OriginFile: Sendable {
  public let directory: URL

  public init(directory: URL) {
    self.directory = directory
  }

  private var file: URL { directory.appending(path: "server-url") }

  public func read() -> URL? {
    // Why: a missing file only means no server was chosen yet.
    guard let text = try? String(contentsOf: file, encoding: .utf8) else { return nil }
    return URL(string: text.trimmingCharacters(in: .whitespacesAndNewlines))
  }

  public func write(_ origin: URL) throws {
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    try origin.absoluteString.write(to: file, atomically: true, encoding: .utf8)
  }
}

import Foundation

/// Test-only switches. A release build ignores every one of them.
struct LaunchOptions {
  var dataDirectory: String?
  var memoryStore = false
  var fixture: URL?
  var shotsDirectory: URL?

  static func read(_ environment: [String: String]) -> LaunchOptions {
    var options = LaunchOptions()
    #if DEBUG
      options.dataDirectory = environment["HASP_DATA_DIR"]
      options.memoryStore = environment["HASP_MEMORY_STORE"] == "1"
      options.fixture = environment["HASP_FIXTURE"].map { URL(filePath: $0) }
      options.shotsDirectory = environment["HASP_SHOTS_DIR"].map {
        URL(filePath: $0, directoryHint: .isDirectory)
      }
    #endif
    return options
  }
}

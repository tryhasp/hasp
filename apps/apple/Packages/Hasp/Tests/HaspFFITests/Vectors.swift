import Foundation

enum Vectors {
  static let root: URL = {
    var url = URL(filePath: #filePath)
    for _ in 0..<7 {
      url.deleteLastPathComponent()
    }
    return url.appending(path: "testvectors", directoryHint: .isDirectory)
  }()

  static func read(_ group: String) throws -> String {
    try String(contentsOf: root.appending(path: "\(group).json"), encoding: .utf8)
  }
}

#if os(macOS)
  import AppKit
  public import Foundation

  @MainActor
  public enum FilePanels {
    public static func saveLocation(suggestedName: String) async -> URL? {
      let panel = NSSavePanel()
      panel.nameFieldStringValue = suggestedName
      panel.canCreateDirectories = true
      return await withCheckedContinuation { continuation in
        panel.begin { response in
          continuation.resume(returning: response == .OK ? panel.url : nil)
        }
      }
    }
  }
#endif

import Foundation
import HaspDesign
import HaspKit
import Observation
import UniformTypeIdentifiers

@Observable
final class ItemDetailModel {
  private(set) var detail: ItemDetail?
  private(set) var revealed: [String: String] = [:]
  private(set) var codes: [String: TOTPSnapshot] = [:]
  private(set) var now = Date()
  private(set) var history: [HistoryEntry] = []
  var showsHistory = false
  private(set) var largeType: String?

  let key: ItemKey
  private let session: any VaultServing
  private weak var app: AppModel?
  private weak var library: LibraryModel?
  private var fetchedAt: [String: Date] = [:]
  private var hideTasks: [String: Task<Void, Never>] = [:]
  private var ticker: Task<Void, Never>?
  private var openedFiles: [URL] = []

  init(session: any VaultServing, key: ItemKey, app: AppModel?, library: LibraryModel?) {
    self.session = session
    self.key = key
    self.app = app
    self.library = library
  }

  var otpFields: [FieldValue] {
    detail?.sections.flatMap(\.fields).filter { $0.kind == "otp" } ?? []
  }

  func reload() async {
    do {
      detail = try await session.detail(key)
      await refreshCodes()
      startTicker()
    } catch {
      app?.show(error: error)
    }
  }

  func remaining(for field: String) -> Int {
    guard let code = codes[field], let fetched = fetchedAt[field] else { return 0 }
    return max(0, code.remaining - Int(now.timeIntervalSince(fetched)))
  }

  func discard() {
    ticker?.cancel()
    hideTasks.values.forEach { $0.cancel() }
    hideTasks.removeAll()
    revealed.removeAll()
    codes.removeAll()
    largeType = nil
    removeOpenedFiles()
  }

  func toggleReveal(_ field: FieldValue) async {
    if revealed[field.id] != nil {
      hide(field.id)
      return
    }
    do {
      revealed[field.id] = try await session.revealField(key, field: field.id).text()
      hideTasks[field.id]?.cancel()
      hideTasks[field.id] = Task { [weak self] in
        try? await Task.sleep(for: HaspMotion.revealTimeout)
        if !Task.isCancelled { self?.hide(field.id) }
      }
    } catch {
      app?.show(error: error)
    }
  }

  func copy(_ field: FieldValue) async {
    do {
      if field.concealed {
        await app?.copy(try await session.revealField(key, field: field.id))
      } else if let value = field.value {
        await app?.copyPlain(value)
      }
    } catch {
      app?.show(error: error)
    }
  }

  func copyCode(_ field: FieldValue) async {
    guard let code = codes[field.id] else { return }
    await app?.copy(RevealedSecret(text: code.code))
  }

  func showLargeType(_ field: FieldValue) async {
    guard let text = revealed[field.id] ?? field.value else { return }
    largeType = text
  }

  func dismissLargeType() {
    largeType = nil
  }

  private func hide(_ id: String) {
    revealed[id] = nil
    hideTasks[id]?.cancel()
    hideTasks[id] = nil
  }
}

extension ItemDetailModel {
  private func refreshCodes() async {
    for field in otpFields {
      do {
        codes[field.id] = try await session.totp(key, field: field.id)
        fetchedAt[field.id] = Date()
      } catch {
        codes[field.id] = nil
      }
    }
  }

  private func startTicker() {
    guard ticker == nil, !otpFields.isEmpty else { return }
    ticker = Task { [weak self] in
      while !Task.isCancelled {
        try? await Task.sleep(for: .seconds(1))
        guard let self else { return }
        now = Date()
        if otpFields.contains(where: { remaining(for: $0.id) == 0 }) { await refreshCodes() }
      }
    }
  }

  func loadHistory() async {
    do {
      history = try await session.history(key)
      showsHistory = true
    } catch {
      app?.show(error: error)
    }
  }

  func restore(_ entry: HistoryEntry) async {
    do {
      try await session.restoreVersion(key, version: entry.version)
      showsHistory = false
      await library?.refresh()
    } catch {
      app?.show(error: error)
    }
  }

  func attach(fileAt url: URL) async {
    do {
      let data = try Data(contentsOf: url)
      let mime =
        UTType(filenameExtension: url.pathExtension)?.preferredMIMEType
        ?? "application/octet-stream"
      _ = try await session.attachFile(key, name: url.lastPathComponent, mime: mime, data: data)
      await reload()
    } catch {
      app?.show(error: error)
    }
  }

  func removeAttachment(_ attachment: AttachmentSummary) async {
    do {
      try await session.removeAttachment(key, attachment: attachment.id)
      await reload()
    } catch {
      app?.show(error: error)
    }
  }

  func save(_ attachment: AttachmentSummary, to destination: URL) async {
    do {
      let data = try await session.downloadAttachment(key, attachment: attachment.id)
      try data.write(to: destination, options: [.atomic, .completeFileProtection])
    } catch {
      app?.show(error: error)
    }
  }

  func data(for attachment: AttachmentSummary) async -> Data? {
    do {
      return try await session.downloadAttachment(key, attachment: attachment.id)
    } catch {
      app?.show(error: error)
      return nil
    }
  }

  func openableFile(for attachment: AttachmentSummary) async -> URL? {
    do {
      let data = try await session.downloadAttachment(key, attachment: attachment.id)
      let folder = FileManager.default.temporaryDirectory.appending(
        path: "hasp-\(UUID().uuidString)"
      )
      try FileManager.default.createDirectory(
        at: folder,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700],
      )
      let file = folder.appending(path: attachment.name)
      try data.write(to: file, options: .atomic)
      openedFiles.append(folder)
      return file
    } catch {
      app?.show(error: error)
      return nil
    }
  }

  private func removeOpenedFiles() {
    for folder in openedFiles { try? FileManager.default.removeItem(at: folder) }
    openedFiles.removeAll()
  }
}

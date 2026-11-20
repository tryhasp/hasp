import Foundation
import HaspKit
import Observation

@Observable
final class ItemEditorModel {
  enum Mode: Equatable {
    case create(kind: String, vault: VaultID)
    case edit(ItemKey)
  }

  var draft: ItemDraft?
  var tagsText = ""
  var kind: String
  private(set) var saving = false
  private(set) var failure: String?
  private(set) var generatedBits: Double?

  let mode: Mode
  private let session: any VaultServing
  private weak var library: LibraryModel?

  init(session: any VaultServing, library: LibraryModel?, mode: Mode) {
    self.session = session
    self.library = library
    self.mode = mode
    kind =
      switch mode {
      case .create(let kind, _): kind
      case .edit: ""
      }
  }

  var isCreating: Bool {
    if case .create = mode { return true }
    return false
  }

  var canSave: Bool {
    guard let draft else { return false }
    return !saving && !draft.title.trimmingCharacters(in: .whitespaces).isEmpty
  }

  func load() async {
    do {
      switch mode {
      case .create(let kind, _):
        draft = try await session.blankDraft(kind: kind)
      case .edit(let key):
        draft = try await session.editDraft(key)
      }
      tagsText = draft?.tags.joined(separator: ", ") ?? ""
    } catch {
      failure = UserMessage.text(for: error)
    }
  }

  func changeKind(to newKind: String) async {
    guard isCreating, newKind != kind, var current = draft else { return }
    do {
      var fresh = try await session.blankDraft(kind: newKind)
      fresh.title = current.title
      fresh.notes = current.notes
      current = fresh
      draft = current
      kind = newKind
    } catch {
      failure = UserMessage.text(for: error)
    }
  }

  func generate(into fieldID: String) async {
    guard var current = draft else { return }
    do {
      let generated = try await session.generate(GeneratorOptions(origin: current.urls.first?.url))
      for section in current.sections.indices {
        guard let index = current.sections[section].fields.firstIndex(where: { $0.id == fieldID })
        else { continue }
        current.sections[section].fields[index].value = generated.secret.text()
        current.sections[section].fields[index].keepValue = false
      }
      generatedBits = generated.bits
      draft = current
    } catch {
      failure = UserMessage.text(for: error)
    }
  }

  func addURL() {
    draft?.urls.append(DraftURL(url: ""))
  }

  func removeURL(_ id: String) {
    draft?.urls.removeAll { $0.id == id }
  }

  func save() async {
    guard var current = draft else { return }
    saving = true
    defer { saving = false }
    current.tags = tagsText.split(separator: ",").map {
      $0.trimmingCharacters(in: .whitespaces)
    }.filter { !$0.isEmpty }
    do {
      switch mode {
      case .create(_, let vault):
        let key = try await session.createItem(in: vault, draft: current)
        await library?.finishEditing(saved: key)
      case .edit(let key):
        try await session.editItem(key, draft: current)
        await library?.finishEditing(saved: key)
      }
    } catch {
      failure = UserMessage.text(for: error)
    }
  }

  func cancel() {
    library?.editor = nil
  }
}

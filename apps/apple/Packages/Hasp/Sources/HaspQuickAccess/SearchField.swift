import AppKit
import SwiftUI

struct SearchField: NSViewRepresentable {
  @Binding var text: String
  let placeholder: String
  let focusToken: Int
  let onMove: (Int) -> Void
  let onReturn: () -> Void
  let onEscape: () -> Void

  func makeCoordinator() -> Coordinator {
    Coordinator(self)
  }

  func makeNSView(context: Context) -> NSTextField {
    let field = FocusingTextField()
    field.delegate = context.coordinator
    field.isBordered = false
    field.drawsBackground = false
    field.focusRingType = .none
    field.font = .systemFont(ofSize: 18)
    field.placeholderString = placeholder
    field.setAccessibilityLabel(placeholder)
    field.cell?.usesSingleLineMode = true
    return field
  }

  func updateNSView(_ field: NSTextField, context: Context) {
    context.coordinator.parent = self
    if field.stringValue != text,
      !((field.currentEditor() as? NSTextView)?.hasMarkedText() ?? false)
    {
      field.stringValue = text
    }
    if context.coordinator.focusToken != focusToken {
      context.coordinator.focusToken = focusToken
      field.window?.makeFirstResponder(field)
    }
  }

  final class Coordinator: NSObject, NSTextFieldDelegate {
    var parent: SearchField
    var focusToken = -1

    init(_ parent: SearchField) {
      self.parent = parent
    }

    func controlTextDidChange(_ notification: Notification) {
      guard let field = notification.object as? NSTextField else { return }
      parent.text = field.stringValue
    }

    func control(
      _ control: NSControl,
      textView: NSTextView,
      doCommandBy selector: Selector,
    ) -> Bool {
      if textView.hasMarkedText() { return false }
      switch selector {
      case #selector(NSResponder.moveUp(_:)): parent.onMove(-1)
      case #selector(NSResponder.moveDown(_:)): parent.onMove(1)
      case #selector(NSResponder.insertNewline(_:)): parent.onReturn()
      case #selector(NSResponder.cancelOperation(_:)): parent.onEscape()
      default: return false
      }
      return true
    }
  }
}

final class FocusingTextField: NSTextField {
  override func viewDidMoveToWindow() {
    super.viewDidMoveToWindow()
    window?.makeFirstResponder(self)
  }
}

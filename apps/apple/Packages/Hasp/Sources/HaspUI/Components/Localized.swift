import Foundation
import HaspKit

enum TemplateText {
  static func fieldLabel(kind: String, label: String) -> String {
    let key = "\(kind)/\(label)"
    let text = Bundle.main.localizedString(forKey: key, value: key, table: "TemplateLabels")
    return text == key ? label : text
  }
}

enum HaspDate {
  static func day(_ date: Date) -> String {
    let parts = Calendar.current.dateComponents([.year, .month, .day], from: date)
    return String(format: "%04d.%02d.%02d", parts.year ?? 0, parts.month ?? 0, parts.day ?? 0)
  }

  static func dayAndTime(_ date: Date) -> String {
    let parts = Calendar.current.dateComponents([.hour, .minute], from: date)
    return "\(day(date)) " + String(format: "%02d:%02d", parts.hour ?? 0, parts.minute ?? 0)
  }
}

extension VaultSummary {
  var displayName: String {
    kind == "private" && name == "Private" ? String(localized: "vault.personal") : name
  }
}

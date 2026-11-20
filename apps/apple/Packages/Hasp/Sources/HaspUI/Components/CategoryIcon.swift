enum CategoryIcon {
  static func symbol(_ name: String) -> String {
    switch name {
    case "key": "key"
    case "credit-card": "creditcard"
    case "wifi": "wifi"
    case "passport": "person.text.rectangle"
    case "terminal": "terminal"
    case "note": "note.text"
    case "mail": "envelope"
    case "bank": "building.columns"
    case "server": "server.rack"
    case "database": "cylinder"
    case "lock": "lock"
    case "id-card", "badge": "person.crop.rectangle"
    case "car": "car"
    case "cloud": "cloud"
    case "wallet": "wallet.bifold"
    case "heart": "heart"
    case "gift": "gift"
    case "shield": "shield"
    case "tree": "tree"
    default: "doc"
    }
  }
}

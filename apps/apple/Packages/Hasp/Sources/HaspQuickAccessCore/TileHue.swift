public enum TileHue {
  public static func hue(for title: String) -> Double {
    let sum = title.unicodeScalars.reduce(UInt32(0)) { ($0 &* 31) &+ $1.value }
    return Double(sum % 360)
  }

  public static func letter(for title: String) -> String {
    title.first.map { String($0).uppercased() } ?? "?"
  }
}

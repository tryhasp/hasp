import HaspDesign
import HaspQuickAccessCore
import SwiftUI

struct PreviewPane: View {
  let item: QuickItem
  let otp: OTPPreview?

  var body: some View {
    VStack(alignment: .leading, spacing: HaspSpace.s12) {
      header
      field(Strings.username) { Text(item.username).haspText(HaspFont.body) }
      if item.kind == .login {
        field(Strings.password) {
          Text(String(repeating: "•", count: 12)).haspText(HaspFont.secretCompact)
        }
      }
      if item.hasOTP { otpField }
      if let host = item.hosts.first {
        field(Strings.website) { Text(host).haspText(HaspFont.body) }
      }
      Spacer(minLength: 0)
    }
    .padding(.horizontal, HaspSpace.s24)
    .padding(.vertical, HaspSpace.s20)
    .frame(maxWidth: .infinity, alignment: .leading)
    .foregroundStyle(HaspColor.text)
  }

  private var header: some View {
    HStack(spacing: HaspSpace.s12) {
      Tile(title: item.title, size: HaspSize.tilePreview, selected: false)
      VStack(alignment: .leading, spacing: 0) {
        Text(item.title).haspText(HaspFont.titleSmall)
        Text(Strings.kindLine(item)).haspText(HaspFont.caption)
          .foregroundStyle(HaspColor.textSecondary)
      }
    }
    .padding(.bottom, HaspSpace.s4)
  }

  private var otpField: some View {
    field(Strings.oneTimeCode) {
      HStack(alignment: .firstTextBaseline, spacing: HaspSpace.s10) {
        Text(otp.map { Self.grouped($0.code) } ?? "")
          .haspText(HaspFont.otpCompact)
        if let otp {
          Text(Strings.secondsRemaining(otp.secondsRemaining))
            .haspText(HaspFont.captionTabular)
            .foregroundStyle(HaspColor.textSecondary)
        }
      }
    }
  }

  private func field<Value: View>(_ label: String, @ViewBuilder value: () -> Value) -> some View {
    VStack(alignment: .leading, spacing: 0) {
      Text(label).haspText(HaspFont.caption).foregroundStyle(HaspColor.textSecondary)
      value()
    }
    .accessibilityElement(children: .combine)
  }

  static func grouped(_ code: String) -> String {
    let half = code.count / 2
    return code.count >= 6 ? "\(code.prefix(half)) \(code.dropFirst(half))" : code
  }
}

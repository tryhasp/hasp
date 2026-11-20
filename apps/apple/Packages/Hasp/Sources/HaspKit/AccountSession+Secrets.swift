public import Foundation
import HaspFFI

extension AccountSession {
  public func revealField(_ key: ItemKey, field: String) throws -> RevealedSecret {
    let secret = try mapped {
      try client.revealField(vault: key.vault.rawValue, item: key.item, field: field)
    }
    return RevealedSecret(secret)
  }

  public func totp(_ key: ItemKey, field: String?) throws -> TOTPSnapshot {
    let code = try mapped {
      try client.totp(vault: key.vault.rawValue, item: key.item, field: field)
    }
    return TOTPSnapshot(
      code: RevealedSecret(code.code).text(),
      remaining: Int(code.remaining),
      period: Int(code.period),
      digits: Int(code.digits),
    )
  }

  public func generate(_ options: GeneratorOptions) throws -> GeneratedSecret {
    let request = GeneratorRequest(
      kind: options.style.ffi,
      length: UInt32(options.length),
      lower: true,
      upper: true,
      digits: true,
      symbols: nil,
      excludeAmbiguous: false,
      words: UInt32(options.words),
      separator: "-",
      capitalize: true,
      appendDigit: true,
      origin: options.origin,
      siteRules: nil,
      fieldMinLength: nil,
      fieldMaxLength: nil,
    )
    let generated = try mapped { try client.generate(request: request) }
    return GeneratedSecret(
      secret: RevealedSecret(generated.value),
      bits: generated.bits,
      length: Int(generated.length),
    )
  }

  public func attachFile(_ key: ItemKey, name: String, mime: String, data: Data) throws
    -> AttachmentSummary
  {
    let upload = AttachmentUpload(name: name, mime: mime, data: data)
    let view = try mapped {
      try client.attachFile(vault: key.vault.rawValue, item: key.item, upload: upload)
    }
    return AttachmentSummary(view)
  }

  public func downloadAttachment(_ key: ItemKey, attachment: String) throws -> Data {
    try mapped {
      try client.downloadAttachment(
        vault: key.vault.rawValue,
        item: key.item,
        attachment: attachment,
      )
    }
  }

  public func removeAttachment(_ key: ItemKey, attachment: String) throws {
    try mapped {
      try client.removeAttachment(
        vault: key.vault.rawValue,
        item: key.item,
        attachment: attachment,
      )
    }
  }

  public func watchtower() throws -> WatchtowerSummary {
    WatchtowerSummary(try mapped { try client.watchtowerReport() })
  }

  public func checkBreaches(using source: any BreachRangeSource) throws -> WatchtowerSummary {
    let report = try mapped {
      try client.watchtowerCheckBreaches(range: BreachRangeAdapter(source))
    }
    return WatchtowerSummary(report)
  }
}

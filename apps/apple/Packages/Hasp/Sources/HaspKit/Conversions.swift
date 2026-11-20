import Foundation
import HaspFFI

private func date(_ seconds: UInt64) -> Date {
  Date(timeIntervalSince1970: TimeInterval(seconds))
}

private func seconds(_ date: Date) -> UInt64 {
  UInt64(max(0, date.timeIntervalSince1970))
}

extension AccountStatus {
  init(_ status: HaspFFI.AccountStatus) {
    self.init(
      state: LockState(status.state),
      login: status.login,
      origin: status.origin,
      unlockMode: status.unlockMode.map(UnlockMode.init),
      biometricReady: status.biometricReady,
      retryAfter: .seconds(status.retryAfter),
      deviceConfirmed: status.deviceConfirmed,
      fingerprint: status.fingerprint,
      passwordRequired: status.passwordRequired,
    )
  }
}

extension LockState {
  init(_ state: HaspFFI.LockState) {
    self =
      switch state {
      case .empty: .empty
      case .locked: .locked
      case .unlocked: .unlocked
      }
  }
}

extension UnlockMode {
  init(_ mode: HaspFFI.UnlockMode) {
    self =
      switch mode {
      case .hardware: .hardware
      case .passwordOnly: .passwordOnly
      case .extension: .desktopExtension
      }
  }
}

extension SessionEvent {
  init(_ event: EngineEvent) {
    switch event.kind {
    case .locked: self = .locked
    case .unlocked: self = .unlocked
    case .syncStarted: self = .syncStarted
    case .syncFinished: self = .syncFinished
    case .vaultChanged: self = .vaultChanged(event.vault.map(VaultID.init))
    case .conflict: self = .conflict
    case .needsAttention: self = .needsAttention
    case .sessionRevoked: self = .sessionRevoked
    case .deviceRevoked: self = .deviceRevoked
    case .settingsChanged: self = .settingsChanged
    case .offline: self = .offline
    }
  }
}

extension ItemStatus {
  init(_ status: HaspFFI.ItemStatus) {
    self =
      switch status {
      case .active: .active
      case .archived: .archived
      case .trashed: .trashed
      }
  }

  var ffi: HaspFFI.ItemStatus {
    switch self {
    case .active: .active
    case .archived: .archived
    case .trashed: .trashed
    }
  }
}

extension VaultSummary {
  init(_ vault: HaspFFI.VaultInfo) {
    self.init(
      id: VaultID(vault.id),
      name: vault.name,
      kind: vault.kind,
      role: vault.role,
      confirmed: vault.confirmed,
      quarantined: vault.quarantined,
      members: Int(vault.members),
      writable: vault.writable,
    )
  }
}

extension ItemSummary {
  init(_ row: ItemRow) {
    self.init(
      key: ItemKey(vault: VaultID(row.vault), item: row.id),
      kind: row.kind,
      title: row.title,
      subtitle: row.subtitle,
      hosts: row.hosts,
      tags: row.tags,
      favourite: row.favourite,
      status: ItemStatus(row.status),
      hasTotp: row.hasTotp,
      hasPasskey: row.hasPasskey,
      hasAttachments: row.hasAttachments,
      modified: date(row.modified),
      pending: row.pending,
    )
  }
}

extension ItemCategory {
  init(_ category: HaspFFI.Category) {
    self.init(
      id: category.id,
      nameEn: category.nameEn,
      nameKo: category.nameKo,
      icon: category.icon,
    )
  }
}

extension ItemDetail {
  init(_ detail: HaspFFI.ItemDetail) {
    self.init(
      summary: ItemSummary(detail.row),
      sections: detail.sections.map(SectionValue.init),
      notes: detail.notes,
      urls: detail.urls.map { ItemURL(id: $0.id, url: $0.url, mode: $0.mode, kind: $0.kind) },
      attachments: detail.attachments.map(AttachmentSummary.init),
      passkeys: Int(detail.passkeys),
      passwordHistory: Int(detail.passwordHistory),
    )
  }
}

extension SectionValue {
  init(_ section: SectionView) {
    self.init(
      id: section.id,
      title: section.title,
      fields: section.fields.map {
        FieldValue(
          id: $0.id,
          label: $0.label,
          kind: $0.kind,
          purpose: $0.purpose,
          concealed: $0.concealed,
          value: $0.value,
          expiresAlert: $0.expiresAlert,
        )
      },
    )
  }
}

extension AttachmentSummary {
  init(_ view: AttachmentView) {
    self.init(id: view.id, name: view.name, mime: view.mime, size: Int(view.size))
  }
}

extension ItemDraft {
  init(_ draft: HaspFFI.ItemDraft) {
    self.init(
      kind: draft.kind,
      title: draft.title,
      subtitle: draft.subtitle,
      tags: draft.tags,
      favourite: draft.favourite,
      notes: draft.notes ?? "",
      expiresAt: draft.expiresAt.map(date),
      sections: draft.sections.map(DraftSection.init),
      urls: draft.urls.map {
        DraftURL(existingID: $0.id, url: $0.url, mode: $0.mode, kind: $0.kind)
      },
    )
  }

  var ffi: HaspFFI.ItemDraft {
    HaspFFI.ItemDraft(
      kind: kind,
      title: title,
      subtitle: subtitle,
      tags: tags,
      favourite: favourite,
      notes: notes.isEmpty ? nil : notes,
      expiresAt: expiresAt.map(seconds),
      sections: sections.map(\.ffi),
      urls: urls.filter { !$0.url.isEmpty }.map {
        UrlDraft(id: $0.existingID, url: $0.url, mode: $0.mode, kind: $0.kind)
      },
    )
  }
}

extension DraftSection {
  init(_ section: SectionDraft) {
    self.init(
      existingID: section.id,
      title: section.title,
      fields: section.fields.map {
        DraftField(
          existingID: $0.id,
          label: $0.label,
          kind: $0.kind,
          purpose: $0.purpose,
          concealed: $0.concealed,
          expiresAlert: $0.expiresAlert,
          value: String(decoding: $0.value, as: UTF8.self),
          keepValue: $0.keepValue,
        )
      },
    )
  }

  var ffi: SectionDraft {
    SectionDraft(
      id: existingID,
      title: title,
      fields: fields.map {
        FieldDraft(
          id: $0.existingID,
          label: $0.label,
          kind: $0.kind,
          purpose: $0.purpose,
          concealed: $0.concealed,
          expiresAlert: $0.expiresAlert,
          value: Data($0.value.utf8),
          keepValue: $0.keepValue,
        )
      },
    )
  }
}

extension HistoryEntry {
  init(_ row: HistoryRow) {
    self.init(
      version: Int(row.version),
      epoch: Int(row.epoch),
      title: row.title,
      modified: date(row.modified),
    )
  }
}

extension AppSettings {
  init(_ settings: HaspFFI.Settings) {
    let lock = settings.lock
    self.init(
      lock: LockPolicy(
        idle: .seconds(Int(lock.idleMinutes) * 60),
        lockOnSleep: lock.lockOnSleep,
        lockOnScreenLock: lock.lockOnScreenLock,
        lockOnUserSwitch: lock.lockOnUserSwitch,
        lockOnQuit: lock.lockOnQuit,
        background: .seconds(lock.backgroundSeconds),
        passwordEveryDays: Int(lock.passwordEveryDays),
        clipboardClear: .seconds(lock.clipboardClearSeconds),
      ),
      secretTag: settings.secretTag.map { SecretTag(word: $0.word, glyph: Int($0.glyph)) },
      language: settings.language,
      inlineMenu: settings.inlineMenu,
      autoSubmit: settings.autoSubmit,
      askBeforeFilling: settings.askBeforeFilling,
      hardenedMode: settings.hardenedMode,
      copyTotpAfterFill: settings.copyTotpAfterFill,
      breachCheck: settings.breachCheck,
    )
  }

  var ffi: HaspFFI.Settings {
    HaspFFI.Settings(
      lock: HaspFFI.LockPolicy(
        idleMinutes: UInt32(max(0, lock.idle.components.seconds / 60)),
        lockOnSleep: lock.lockOnSleep,
        lockOnScreenLock: lock.lockOnScreenLock,
        lockOnUserSwitch: lock.lockOnUserSwitch,
        lockOnQuit: lock.lockOnQuit,
        backgroundSeconds: UInt32(max(0, lock.background.components.seconds)),
        passwordEveryDays: UInt32(max(0, lock.passwordEveryDays)),
        clipboardClearSeconds: UInt32(max(0, lock.clipboardClear.components.seconds)),
      ),
      secretTag: secretTag.map { HaspFFI.SecretTag(word: $0.word, glyph: UInt32($0.glyph)) },
      language: language,
      inlineMenu: inlineMenu,
      autoSubmit: autoSubmit,
      askBeforeFilling: askBeforeFilling,
      hardenedMode: hardenedMode,
      copyTotpAfterFill: copyTotpAfterFill,
      breachCheck: breachCheck,
    )
  }
}

extension LockTrigger {
  var ffi: HaspFFI.LockTrigger {
    switch self {
    case .sleep: .sleep
    case .screenLock: .screenLock
    case .userSwitch: .userSwitch
    case .idle: .idle
    case .quit: .quit
    case .background: .background
    case .manual: .manual
    }
  }
}

extension WatchtowerSummary {
  init(_ report: WatchtowerReport) {
    self.init(
      findings: report.findings.map {
        WatchFinding(
          kind: WatchKind($0.kind),
          key: ItemKey(vault: VaultID($0.vault), item: $0.item),
          title: $0.title,
          detail: $0.detail,
          group: $0.group.map(Int.init),
        )
      },
      checked: Int(report.checked),
      breachCheckRan: report.breachCheckRan,
      generatedAt: date(report.generatedAt),
    )
  }
}

extension WatchKind {
  init(_ kind: HaspFFI.WatchKind) {
    self =
      switch kind {
      case .vulnerable: .vulnerable
      case .reused: .reused
      case .weak: .weak
      case .insecureUrl: .insecureURL
      case .expiring: .expiring
      }
  }
}

extension GeneratorStyle {
  var ffi: GeneratorKind {
    switch self {
    case .random: .random
    case .memorable: .memorable
    case .pin: .pin
    case .koreanSafe: .koreanSafe
    }
  }
}

extension SearchFilter {
  var ffi: SearchQuery {
    SearchQuery(
      text: text,
      vault: vault?.rawValue,
      kind: kind,
      tag: tag,
      favouritesOnly: favouritesOnly,
      status: status?.ffi,
      boostUrl: nil,
      limit: UInt32(max(1, limit)),
    )
  }
}

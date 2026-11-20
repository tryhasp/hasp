use std::collections::BTreeMap;

use hasp_proto::{AccountId, ItemId, ItemWire, Leaf, ProtoError, Reader, VaultId, Wire, Writer};

use super::{
    AccountLocal, Event, EventKind, Head, LocalVaultStatus, Marks, PendingKind, PendingOp,
    PendingRepair, QuarantineInfo, StoreError, UnlockClass, VaultLocal,
};

pub(super) fn encode_account(a: &AccountLocal) -> Result<Vec<u8>, StoreError> {
    let mut w = Writer::new();
    w.array(14)?;
    w.text(&a.origin)?;
    w.text(&a.login)?;
    a.account_id.encode(&mut w)?;
    a.device_id.encode(&mut w)?;
    w.bytes(&a.server_fp)?;
    a.record.encode(&mut w)?;
    a.keyset.encode(&mut w)?;
    w.uint(a.max_seen_v)?;
    w.uint(a.min_v)?;
    w.uint(match a.class {
        UnlockClass::Hardware => 1,
        UnlockClass::PasswordOnly => 2,
        UnlockClass::Extension => 3,
    })?;
    w.bytes(&a.local_salt)?;
    w.uint(a.local_gen)?;
    w.uint(a.notices_after)?;
    w.text(&a.platform)?;
    Ok(w.into_bytes())
}

pub(super) fn decode_account(bytes: &[u8]) -> Result<AccountLocal, StoreError> {
    let mut r = Reader::new(bytes);
    let account = r.array(|r, n| {
        if n != 14 {
            return Err(ProtoError::Format);
        }
        Ok(AccountLocal {
            origin: r.text()?.to_owned(),
            login: r.text()?.to_owned(),
            account_id: r.value()?,
            device_id: r.value()?,
            server_fp: r.fixed()?,
            record: r.value()?,
            keyset: r.value()?,
            max_seen_v: r.uint()?.get(),
            min_v: r.uint()?.get(),
            class: match r.uint()?.get() {
                1 => UnlockClass::Hardware,
                2 => UnlockClass::PasswordOnly,
                3 => UnlockClass::Extension,
                _ => return Err(ProtoError::Format),
            },
            local_salt: r.fixed()?,
            local_gen: r.uint()?.get(),
            notices_after: r.uint()?.get(),
            platform: r.text()?.to_owned(),
        })
    })?;
    r.finish()?;
    Ok(account)
}

pub(super) fn encode_marks(w: &mut Writer, marks: Option<&Marks>) -> Result<(), ProtoError> {
    match marks {
        None => {
            w.null();
            Ok(())
        }
        Some(marks) => {
            w.array(5)?;
            marks.seq.encode(w)?;
            marks.hash.encode(w)?;
            marks.rver.encode(w)?;
            marks.roster_hash.encode(w)?;
            marks.epoch.encode(w)
        }
    }
}

pub(super) fn decode_marks(r: &mut Reader<'_>) -> Result<Option<Marks>, ProtoError> {
    if r.is_null() {
        r.null()?;
        return Ok(None);
    }
    r.array(|r, n| {
        if n != 5 {
            return Err(ProtoError::Format);
        }
        Ok(Some(Marks {
            seq: r.value()?,
            hash: r.value()?,
            rver: r.value()?,
            roster_hash: r.value()?,
            epoch: r.value()?,
        }))
    })
}

pub(super) fn encode_vault(v: &VaultLocal) -> Result<Vec<u8>, StoreError> {
    let mut w = Writer::new();
    w.array(8)?;
    v.vault_id.encode(&mut w)?;
    v.kind.encode(&mut w)?;
    v.role.encode(&mut w)?;
    w.uint(match v.status {
        LocalVaultStatus::Active => 1,
        LocalVaultStatus::Left => 2,
        LocalVaultStatus::Dissolved => 3,
        LocalVaultStatus::Removed => 4,
    })?;
    w.bool(v.confirmed);
    encode_marks(&mut w, v.marks.as_ref())?;
    match &v.head {
        None => w.null(),
        Some(head) => {
            w.array(5)?;
            head.seq.encode(&mut w)?;
            head.hash.encode(&mut w)?;
            head.manifest.encode(&mut w)?;
            head.roster.encode(&mut w)?;
            w.array(head.leaves.len())?;
            for leaf in &head.leaves {
                leaf.encode(&mut w)?;
            }
        }
    }
    w.array(v.vk_commits.len())?;
    for (epoch, commit) in &v.vk_commits {
        w.array(2)?;
        w.uint(*epoch)?;
        commit.encode(&mut w)?;
    }
    Ok(w.into_bytes())
}

pub(super) fn decode_vault(bytes: &[u8]) -> Result<VaultLocal, StoreError> {
    let mut r = Reader::new(bytes);
    let vault = r.array(|r, n| {
        if n != 8 {
            return Err(ProtoError::Format);
        }
        let vault_id = r.value()?;
        let kind = r.value()?;
        let role = r.value()?;
        let status = match r.uint()?.get() {
            1 => LocalVaultStatus::Active,
            2 => LocalVaultStatus::Left,
            3 => LocalVaultStatus::Dissolved,
            4 => LocalVaultStatus::Removed,
            _ => return Err(ProtoError::Format),
        };
        let confirmed = r.bool()?;
        let marks = decode_marks(r)?;
        let head = if r.is_null() {
            r.null()?;
            None
        } else {
            Some(r.array(|r, n| {
                if n != 5 {
                    return Err(ProtoError::Format);
                }
                let seq = r.value()?;
                let hash = r.value()?;
                let manifest = r.value()?;
                let roster = r.value()?;
                let leaves = r.array(|r, n| {
                    let mut leaves = Vec::with_capacity(n);
                    for _ in 0..n {
                        leaves.push(r.value::<Leaf>()?);
                    }
                    Ok(leaves)
                })?;
                Ok(Head {
                    seq,
                    hash,
                    manifest,
                    roster,
                    leaves,
                })
            })?)
        };
        let vk_commits = r.array(|r, n| {
            let mut out = BTreeMap::new();
            for _ in 0..n {
                r.array(|r, n| {
                    if n != 2 {
                        return Err(ProtoError::Format);
                    }
                    out.insert(r.uint()?.get(), r.value()?);
                    Ok(())
                })?;
            }
            Ok(out)
        })?;
        Ok(VaultLocal {
            vault_id,
            kind,
            role,
            status,
            confirmed,
            marks,
            head,
            vk_commits,
        })
    })?;
    r.finish()?;
    Ok(vault)
}

pub(super) fn encode_pending(op: &PendingOp) -> Result<Vec<u8>, StoreError> {
    let mut w = Writer::new();
    w.array(5)?;
    op.vault_id.encode(&mut w)?;
    op.item_id.encode(&mut w)?;
    w.uint(match op.kind {
        PendingKind::Put => 1,
        PendingKind::Delete => 2,
    })?;
    op.base_ver.encode(&mut w)?;
    w.bytes(&op.wire.to_cbor()?)?;
    Ok(w.into_bytes())
}

pub(super) fn decode_pending(bytes: &[u8]) -> Result<PendingOp, StoreError> {
    let mut r = Reader::new(bytes);
    let op = r.array(|r, n| {
        if n != 5 {
            return Err(ProtoError::Format);
        }
        Ok(PendingOp {
            vault_id: r.value()?,
            item_id: r.value()?,
            kind: match r.uint()?.get() {
                1 => PendingKind::Put,
                2 => PendingKind::Delete,
                _ => return Err(ProtoError::Format),
            },
            base_ver: r.value()?,
            wire: ItemWire::from_cbor(r.bytes()?)?,
        })
    })?;
    r.finish()?;
    Ok(op)
}

pub(super) fn encode_quarantine(q: &QuarantineInfo) -> Result<Vec<u8>, StoreError> {
    let mut w = Writer::new();
    w.array(9)?;
    q.vault_id.encode(&mut w)?;
    w.text(&q.check)?;
    w.uint(q.seq)?;
    q.author.encode(&mut w)?;
    q.bad_hash.encode(&mut w)?;
    w.uint(q.last_good_seq)?;
    q.last_good_hash.encode(&mut w)?;
    w.uint(q.at)?;
    w.bytes(&q.bad_bundle)?;
    Ok(w.into_bytes())
}

pub(super) fn decode_quarantine(bytes: &[u8]) -> Result<QuarantineInfo, StoreError> {
    let mut r = Reader::new(bytes);
    let info = r.array(|r, n| {
        if n != 9 {
            return Err(ProtoError::Format);
        }
        Ok(QuarantineInfo {
            vault_id: r.value()?,
            check: r.text()?.to_owned(),
            seq: r.uint()?.get(),
            author: r.value()?,
            bad_hash: r.value()?,
            last_good_seq: r.uint()?.get(),
            last_good_hash: r.value()?,
            at: r.uint()?.get(),
            bad_bundle: r.bytes()?.to_vec(),
        })
    })?;
    r.finish()?;
    Ok(info)
}

pub(super) fn encode_repair(repair: &PendingRepair) -> Result<Vec<u8>, StoreError> {
    let mut w = Writer::new();
    w.array(6)?;
    repair.vault_id.encode(&mut w)?;
    w.uint(repair.seq)?;
    repair.hash.encode(&mut w)?;
    repair.author.encode(&mut w)?;
    w.uint(repair.at)?;
    w.bytes(&repair.bundle)?;
    Ok(w.into_bytes())
}

pub(super) fn decode_repair(bytes: &[u8]) -> Result<PendingRepair, StoreError> {
    let mut r = Reader::new(bytes);
    let repair = r.array(|r, n| {
        if n != 6 {
            return Err(ProtoError::Format);
        }
        Ok(PendingRepair {
            vault_id: r.value()?,
            seq: r.uint()?.get(),
            hash: r.value()?,
            author: r.value()?,
            at: r.uint()?.get(),
            bundle: r.bytes()?.to_vec(),
        })
    })?;
    r.finish()?;
    Ok(repair)
}

pub(super) fn encode_event(event: &Event) -> Result<Vec<u8>, StoreError> {
    struct Row<'a> {
        code: u64,
        vault: Option<VaultId>,
        item: Option<ItemId>,
        number: u64,
        text: &'a str,
        account: Option<AccountId>,
        flag: bool,
        extra: u64,
    }
    let blank = |code, vault| Row {
        code,
        vault,
        item: None,
        number: 0,
        text: "",
        account: None,
        flag: false,
        extra: 0,
    };
    let row = match &event.kind {
        EventKind::Conflict {
            vault_id,
            item_id,
            replaced_ver,
            resurrected,
        } => Row {
            item: Some(*item_id),
            number: *replaced_ver,
            flag: *resurrected,
            ..blank(1, Some(*vault_id))
        },
        EventKind::Removed { vault_id } => blank(2, Some(*vault_id)),
        EventKind::Dissolved { vault_id } => blank(3, Some(*vault_id)),
        EventKind::Left { vault_id } => blank(4, Some(*vault_id)),
        EventKind::LeaveRequested { vault_id, account } => Row {
            account: Some(*account),
            ..blank(5, Some(*vault_id))
        },
        EventKind::Quarantined { vault_id, check } => Row {
            text: check,
            ..blank(6, Some(*vault_id))
        },
        EventKind::NeedsAttention { vault_id, reason } => Row {
            text: reason,
            ..blank(7, Some(*vault_id))
        },
        EventKind::RetentionFallback {
            vault_id,
            from_seq,
            to_seq,
        } => Row {
            number: *from_seq,
            extra: *to_seq,
            ..blank(9, Some(*vault_id))
        },
        EventKind::ServerBehind {
            vault_id,
            server_seq,
            local_seq,
        } => Row {
            number: *server_seq,
            extra: *local_seq,
            ..blank(10, Some(*vault_id))
        },
        EventKind::RollbackAccepted {
            vault_id,
            from_seq,
            to_seq,
        } => Row {
            number: *from_seq,
            extra: *to_seq,
            ..blank(11, Some(*vault_id))
        },
        EventKind::Server { kind, vault_id, at } => Row {
            number: *kind,
            flag: at.is_some(),
            extra: at.unwrap_or(0),
            ..blank(8, *vault_id)
        },
    };
    let mut w = Writer::new();
    w.array(4)?;
    w.uint(event.id)?;
    w.uint(event.at)?;
    w.uint(row.code)?;
    w.array(7)?;
    row.vault.encode(&mut w)?;
    row.item.encode(&mut w)?;
    w.uint(row.number)?;
    w.text(row.text)?;
    row.account.encode(&mut w)?;
    w.bool(row.flag);
    w.uint(row.extra)?;
    Ok(w.into_bytes())
}

pub(super) fn decode_event(bytes: &[u8]) -> Result<Event, StoreError> {
    let mut r = Reader::new(bytes);
    let event = r.array(|r, n| {
        if n != 4 {
            return Err(ProtoError::Format);
        }
        let id = r.uint()?.get();
        let at = r.uint()?.get();
        let code = r.uint()?.get();
        r.array(|r, n| {
            if n != 7 {
                return Err(ProtoError::Format);
            }
            let vault: Option<VaultId> = r.value()?;
            let item: Option<ItemId> = r.value()?;
            let number = r.uint()?.get();
            let text = r.text()?.to_owned();
            let account: Option<AccountId> = r.value()?;
            let flag = r.bool()?;
            let extra = r.uint()?.get();
            let need_vault = vault.ok_or(ProtoError::Format);
            let kind = match code {
                1 => EventKind::Conflict {
                    vault_id: need_vault?,
                    item_id: item.ok_or(ProtoError::Format)?,
                    replaced_ver: number,
                    resurrected: flag,
                },
                2 => EventKind::Removed {
                    vault_id: need_vault?,
                },
                3 => EventKind::Dissolved {
                    vault_id: need_vault?,
                },
                4 => EventKind::Left {
                    vault_id: need_vault?,
                },
                5 => EventKind::LeaveRequested {
                    vault_id: need_vault?,
                    account: account.ok_or(ProtoError::Format)?,
                },
                6 => EventKind::Quarantined {
                    vault_id: need_vault?,
                    check: text,
                },
                7 => EventKind::NeedsAttention {
                    vault_id: need_vault?,
                    reason: text,
                },
                9 => EventKind::RetentionFallback {
                    vault_id: need_vault?,
                    from_seq: number,
                    to_seq: extra,
                },
                10 => EventKind::ServerBehind {
                    vault_id: need_vault?,
                    server_seq: number,
                    local_seq: extra,
                },
                11 => EventKind::RollbackAccepted {
                    vault_id: need_vault?,
                    from_seq: number,
                    to_seq: extra,
                },
                8 => EventKind::Server {
                    kind: number,
                    vault_id: vault,
                    at: flag.then_some(extra),
                },
                _ => return Err(ProtoError::Format),
            };
            Ok(Event { id, at, kind })
        })
    })?;
    r.finish()?;
    Ok(event)
}

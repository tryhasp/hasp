use std::sync::Arc;

use hasp_proto::{
    AccountId, Epoch, Hash32, InviteId, ItemId, ItemWire, Rver, SealedRaw, Seq, VaultId,
};

use crate::store::sqlite::codec::{
    array, dec, dec_opt, enc, enc_opt, epoch, flag, hash, int, invite_state, key_int,
    member_status, member_status_code, phase, phase_code, role, role_code, rver, seq, uint,
    vault_kind, vault_kind_code, version,
};
use crate::store::sqlite::db::Db;
use crate::store::{
    InviteRow, ItemKey, ItemRow, ManifestRow, MemberRow, RosterRow, ServerError, ShareRow,
    StoreResult, Table, VaultRow,
};

sql_table! {
    VaultsTable, VaultId, VaultRow;
    table "vaults";
    cols "vault_id, kind, owner, head_seq, head_hash, rver, epoch, state, dissolve, created";
    key_eq "vault_id = ?";
    key_row "(vault_id)";
    key_holes "(?)";
    order "vault_id";
    order_desc "vault_id DESC";
    holes "?, ?, ?, ?, ?, ?, ?, ?, ?, ?";
    conflict "ON CONFLICT (vault_id) DO UPDATE SET kind = excluded.kind, owner = excluded.owner, head_seq = excluded.head_seq, head_hash = excluded.head_hash, rver = excluded.rver, epoch = excluded.epoch, state = excluded.state, dissolve = excluded.dissolve, created = excluded.created";
    key(k) [k.as_bytes().as_slice()];
    value(v) [
        vault_kind_code(v.kind),
        v.owner.as_bytes().as_slice(),
        key_int(v.head_seq.get()),
        v.head_hash.as_bytes().as_slice(),
        key_int(v.rver.get()),
        key_int(v.epoch.get()),
        phase_code(v.state),
        enc_opt(v.dissolve.as_ref())?,
        int(v.created)?,
    ];
    decode(r) {
        Ok((VaultId::from_bytes(array(&r.vault_id)?), VaultRow {
            kind: vault_kind(r.kind)?,
            owner: AccountId::from_bytes(array(&r.owner)?),
            head_seq: seq(r.head_seq)?,
            head_hash: hash(&r.head_hash)?,
            rver: rver(r.rver)?,
            epoch: epoch(r.epoch)?,
            state: phase(r.state)?,
            dissolve: dec_opt(r.dissolve.as_deref())?,
            created: uint(r.created)?,
        }))
    };
}

sql_table! {
    RostersTable, (VaultId, Rver), RosterRow;
    table "rosters";
    cols "vault_id, rver, roster, seq";
    key_eq "vault_id = ? AND rver = ?";
    key_row "(vault_id, rver)";
    key_holes "(?, ?)";
    order "vault_id, rver";
    order_desc "vault_id DESC, rver DESC";
    holes "?, ?, ?, ?";
    conflict "ON CONFLICT (vault_id, rver) DO UPDATE SET roster = excluded.roster, seq = excluded.seq";
    key(k) [k.0.as_bytes().as_slice(), key_int(k.1.get())];
    value(v) [enc(&v.roster)?, key_int(v.seq.get())];
    decode(r) {
        Ok(((VaultId::from_bytes(array(&r.vault_id)?), rver(r.rver)?), RosterRow {
            roster: dec(&r.roster)?,
            seq: seq(r.seq)?,
        }))
    };
}

sql_table! {
    ManifestsTable, (VaultId, Seq), ManifestRow;
    table "manifests";
    cols "vault_id, seq, manifest, author";
    key_eq "vault_id = ? AND seq = ?";
    key_row "(vault_id, seq)";
    key_holes "(?, ?)";
    order "vault_id, seq";
    order_desc "vault_id DESC, seq DESC";
    holes "?, ?, ?, ?";
    conflict "ON CONFLICT (vault_id, seq) DO UPDATE SET manifest = excluded.manifest, author = excluded.author";
    key(k) [k.0.as_bytes().as_slice(), key_int(k.1.get())];
    value(v) [enc(&v.manifest)?, v.author.as_bytes().as_slice()];
    decode(r) {
        Ok(((VaultId::from_bytes(array(&r.vault_id)?), seq(r.seq)?), ManifestRow {
            manifest: dec(&r.manifest)?,
            author: AccountId::from_bytes(array(&r.author)?),
        }))
    };
}

sql_table! {
    MembersTable, (VaultId, AccountId), MemberRow;
    table "members";
    cols "vault_id, account_id, role, state, rver, leave";
    key_eq "vault_id = ? AND account_id = ?";
    key_row "(vault_id, account_id)";
    key_holes "(?, ?)";
    order "vault_id, account_id";
    order_desc "vault_id DESC, account_id DESC";
    holes "?, ?, ?, ?, ?, ?";
    conflict "ON CONFLICT (vault_id, account_id) DO UPDATE SET role = excluded.role, state = excluded.state, rver = excluded.rver, leave = excluded.leave";
    key(k) [k.0.as_bytes().as_slice(), k.1.as_bytes().as_slice()];
    value(v) [
        role_code(v.role),
        member_status_code(v.state),
        key_int(v.rver.get()),
        enc_opt(v.leave.as_ref())?,
    ];
    decode(r) {
        Ok(((VaultId::from_bytes(array(&r.vault_id)?), AccountId::from_bytes(array(&r.account_id)?)), MemberRow {
            role: role(r.role)?,
            state: member_status(r.state)?,
            rver: rver(r.rver)?,
            leave: dec_opt(r.leave.as_deref())?,
        }))
    };
}

sql_table! {
    MembershipsTable, (AccountId, VaultId), ();
    table "memberships";
    cols "account_id, vault_id";
    key_eq "account_id = ? AND vault_id = ?";
    key_row "(account_id, vault_id)";
    key_holes "(?, ?)";
    order "account_id, vault_id";
    order_desc "account_id DESC, vault_id DESC";
    holes "?, ?";
    conflict "ON CONFLICT (account_id, vault_id) DO NOTHING";
    key(k) [k.0.as_bytes().as_slice(), k.1.as_bytes().as_slice()];
    value(v) [];
    decode(r) {
        Ok(((AccountId::from_bytes(array(&r.account_id)?), VaultId::from_bytes(array(&r.vault_id)?)), ()))
    };
}

sql_table! {
    SharesTable, (VaultId, Epoch, AccountId), ShareRow;
    table "shares";
    cols "vault_id, epoch, account_id, share, seq";
    key_eq "vault_id = ? AND epoch = ? AND account_id = ?";
    key_row "(vault_id, epoch, account_id)";
    key_holes "(?, ?, ?)";
    order "vault_id, epoch, account_id";
    order_desc "vault_id DESC, epoch DESC, account_id DESC";
    holes "?, ?, ?, ?, ?";
    conflict "ON CONFLICT (vault_id, epoch, account_id) DO UPDATE SET share = excluded.share, seq = excluded.seq";
    key(k) [k.0.as_bytes().as_slice(), key_int(k.1.get()), k.2.as_bytes().as_slice()];
    value(v) [enc(&v.share)?, key_int(v.seq.get())];
    decode(r) {
        Ok(((VaultId::from_bytes(array(&r.vault_id)?), epoch(r.epoch)?, AccountId::from_bytes(array(&r.account_id)?)), ShareRow {
            share: dec(&r.share)?,
            seq: seq(r.seq)?,
        }))
    };
}

sql_table! {
    SelfWrapsTable, (AccountId, VaultId, Epoch), SealedRaw;
    table "self_wraps";
    cols "account_id, vault_id, epoch, wrap";
    key_eq "account_id = ? AND vault_id = ? AND epoch = ?";
    key_row "(account_id, vault_id, epoch)";
    key_holes "(?, ?, ?)";
    order "account_id, vault_id, epoch";
    order_desc "account_id DESC, vault_id DESC, epoch DESC";
    holes "?, ?, ?, ?";
    conflict "ON CONFLICT (account_id, vault_id, epoch) DO UPDATE SET wrap = excluded.wrap";
    key(k) [k.0.as_bytes().as_slice(), k.1.as_bytes().as_slice(), key_int(k.2.get())];
    value(v) [enc(v)?];
    decode(r) {
        Ok(((AccountId::from_bytes(array(&r.account_id)?), VaultId::from_bytes(array(&r.vault_id)?), epoch(r.epoch)?), dec(&r.wrap)?))
    };
}

sql_table! {
    ItemsTable, ItemKey, ItemRow;
    table "items";
    cols "vault_id, item_id, ver, epoch, wire, h_item, tomb, size, seq, current";
    key_eq "vault_id = ? AND item_id = ? AND ver = ? AND epoch = ?";
    key_row "(vault_id, item_id, ver, epoch)";
    key_holes "(?, ?, ?, ?)";
    order "vault_id, item_id, ver, epoch";
    order_desc "vault_id DESC, item_id DESC, ver DESC, epoch DESC";
    holes "?, ?, ?, ?, ?, ?, ?, ?, ?, ?";
    conflict "ON CONFLICT (vault_id, item_id, ver, epoch) DO UPDATE SET wire = excluded.wire, h_item = excluded.h_item, tomb = excluded.tomb, size = excluded.size, seq = excluded.seq, current = excluded.current";
    key(k) [k.0.as_bytes().as_slice(), k.1.as_bytes().as_slice(), key_int(k.2.get()), key_int(k.3.get())];
    value(v) [
        enc(&v.wire)?,
        v.h_item.as_bytes().as_slice(),
        i64::from(v.tomb),
        int(v.size)?,
        key_int(v.seq.get()),
        i64::from(v.current),
    ];
    decode(r) {
        Ok((
            (
                VaultId::from_bytes(array(&r.vault_id)?),
                ItemId::from_bytes(array(&r.item_id)?),
                version(r.ver)?,
                epoch(r.epoch)?,
            ),
            ItemRow {
                wire: dec::<ItemWire>(&r.wire)?,
                h_item: hash(&r.h_item)?,
                tomb: flag(r.tomb),
                size: uint(r.size)?,
                seq: seq(r.seq)?,
                current: flag(r.current),
            },
        ))
    };
}

sql_table! {
    InvitesTable, InviteId, InviteRow;
    table "invites";
    cols "invite_id, vault_id, inviter, role, expires, state, invitee, accept";
    key_eq "invite_id = ?";
    key_row "(invite_id)";
    key_holes "(?)";
    order "invite_id";
    order_desc "invite_id DESC";
    holes "?, ?, ?, ?, ?, ?, ?, ?";
    conflict "ON CONFLICT (invite_id) DO UPDATE SET vault_id = excluded.vault_id, inviter = excluded.inviter, role = excluded.role, expires = excluded.expires, state = excluded.state, invitee = excluded.invitee, accept = excluded.accept";
    key(k) [k.as_bytes().as_slice()];
    value(v) [
        v.vault_id.as_bytes().as_slice(),
        v.inviter.as_bytes().as_slice(),
        role_code(v.role),
        int(v.expires)?,
        int(v.state.code())?,
        v.invitee.as_ref().map(|id| id.as_bytes().as_slice()),
        v.accept.as_deref(),
    ];
    decode(r) {
        Ok((InviteId::from_bytes(array(&r.invite_id)?), InviteRow {
            vault_id: VaultId::from_bytes(array(&r.vault_id)?),
            inviter: AccountId::from_bytes(array(&r.inviter)?),
            role: role(r.role)?,
            expires: uint(r.expires)?,
            state: invite_state(r.state)?,
            invitee: r.invitee.as_deref().map(|b| array(b).map(AccountId::from_bytes)).transpose()?,
            accept: r.accept,
        }))
    };
}

sql_table! {
    CommitLogTable, (VaultId, Seq), Hash32;
    table "commit_log";
    cols "vault_id, base_seq, manifest_hash";
    key_eq "vault_id = ? AND base_seq = ?";
    key_row "(vault_id, base_seq)";
    key_holes "(?, ?)";
    order "vault_id, base_seq";
    order_desc "vault_id DESC, base_seq DESC";
    holes "?, ?, ?";
    conflict "ON CONFLICT (vault_id, base_seq) DO UPDATE SET manifest_hash = excluded.manifest_hash";
    key(k) [k.0.as_bytes().as_slice(), key_int(k.1.get())];
    value(v) [v.as_bytes().as_slice()];
    decode(r) {
        Ok(((VaultId::from_bytes(array(&r.vault_id)?), seq(r.base_seq)?), hash(&r.manifest_hash)?))
    };
}

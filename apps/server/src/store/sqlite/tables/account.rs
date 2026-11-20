use std::sync::Arc;

use hasp_proto::wire::{RecoveryId, SessionId};
use hasp_proto::{AccountId, AccountRecord, Esid, Hash32, Keyset, SealedRaw, Seq, Signed, VaultId};

use crate::store::sqlite::codec::{
    account_state, account_state_code, array, dec, dec_opt, dec_slots, enc, enc_opt, enc_slots,
    enrol_state, enrol_state_code, flag, hash, int, key_int, notice_kind, recovery_state,
    recovery_state_code, seq, text, token_kind, uint,
};
use crate::store::sqlite::db::Db;
use crate::store::{
    AccountRow, EnrolRow, NoticeRow, OpaqueRow, RecoveryRow, RecoverySessionRow, ServerError,
    SessionRow, StoreResult, Table, TokenRow,
};

sql_table! {
    AccountsTable, AccountId, AccountRow;
    table "accounts";
    cols "account_id, login, notify_email, is_admin, state, cred_gen, created";
    key_eq "account_id = ?";
    key_row "(account_id)";
    key_holes "(?)";
    order "account_id";
    order_desc "account_id DESC";
    holes "?, ?, ?, ?, ?, ?, ?";
    conflict "ON CONFLICT (account_id) DO UPDATE SET login = excluded.login, notify_email = excluded.notify_email, is_admin = excluded.is_admin, state = excluded.state, cred_gen = excluded.cred_gen, created = excluded.created";
    key(k) [k.as_bytes().as_slice()];
    value(v) [
        v.login.as_str(),
        v.notify_email.as_deref(),
        i64::from(v.is_admin),
        account_state_code(v.state),
        int(v.cred_gen)?,
        int(v.created)?,
    ];
    decode(r) {
        let id = AccountId::from_bytes(array(&r.account_id)?);
        Ok((id, AccountRow {
            account_id: id,
            login: r.login,
            notify_email: r.notify_email,
            is_admin: flag(r.is_admin),
            state: account_state(r.state)?,
            cred_gen: uint(r.cred_gen)?,
            created: uint(r.created)?,
        }))
    };
}

sql_table! {
    LoginsTable, String, AccountId;
    table "logins";
    cols "login, account_id";
    key_eq "login = ?";
    key_row "(login)";
    key_holes "(?)";
    order "login";
    order_desc "login DESC";
    holes "?, ?";
    conflict "ON CONFLICT (login) DO UPDATE SET account_id = excluded.account_id";
    key(k) [k.as_bytes()];
    value(v) [v.as_bytes().as_slice()];
    decode(r) {
        Ok((text(r.login)?, AccountId::from_bytes(array(&r.account_id)?)))
    };
}

sql_table! {
    AccountRecordsTable, (AccountId, Seq), Signed<AccountRecord>;
    table "account_records";
    cols "account_id, seq, record";
    key_eq "account_id = ? AND seq = ?";
    key_row "(account_id, seq)";
    key_holes "(?, ?)";
    order "account_id, seq";
    order_desc "account_id DESC, seq DESC";
    holes "?, ?, ?";
    conflict "ON CONFLICT (account_id, seq) DO UPDATE SET record = excluded.record";
    key(k) [k.0.as_bytes().as_slice(), key_int(k.1.get())];
    value(v) [enc(v)?];
    decode(r) {
        Ok(((AccountId::from_bytes(array(&r.account_id)?), seq(r.seq)?), dec(&r.record)?))
    };
}

sql_table! {
    OpaqueRecordsTable, AccountId, OpaqueRow;
    table "opaque_records";
    cols "account_id, record, cred_gen";
    key_eq "account_id = ?";
    key_row "(account_id)";
    key_holes "(?)";
    order "account_id";
    order_desc "account_id DESC";
    holes "?, ?, ?";
    conflict "ON CONFLICT (account_id) DO UPDATE SET record = excluded.record, cred_gen = excluded.cred_gen";
    key(k) [k.as_bytes().as_slice()];
    value(v) [v.record.as_slice(), int(v.cred_gen)?];
    decode(r) {
        Ok((
            AccountId::from_bytes(array(&r.account_id)?),
            OpaqueRow { record: r.record, cred_gen: uint(r.cred_gen)? },
        ))
    };
}

sql_table! {
    KeysetsTable, AccountId, Keyset;
    table "keysets";
    cols "account_id, keyset";
    key_eq "account_id = ?";
    key_row "(account_id)";
    key_holes "(?)";
    order "account_id";
    order_desc "account_id DESC";
    holes "?, ?";
    conflict "ON CONFLICT (account_id) DO UPDATE SET keyset = excluded.keyset";
    key(k) [k.as_bytes().as_slice()];
    value(v) [enc(v)?];
    decode(r) {
        Ok((AccountId::from_bytes(array(&r.account_id)?), dec(&r.keyset)?))
    };
}

sql_table! {
    SignupTokensTable, Hash32, TokenRow;
    table "signup_tokens";
    cols "token_hash, creator, target, expires, used_by, kind, makes_admin";
    key_eq "token_hash = ?";
    key_row "(token_hash)";
    key_holes "(?)";
    order "token_hash";
    order_desc "token_hash DESC";
    holes "?, ?, ?, ?, ?, ?, ?";
    conflict "ON CONFLICT (token_hash) DO UPDATE SET creator = excluded.creator, target = excluded.target, expires = excluded.expires, used_by = excluded.used_by, kind = excluded.kind, makes_admin = excluded.makes_admin";
    key(k) [k.as_bytes().as_slice()];
    value(v) [
        v.creator.as_ref().map(|id| id.as_bytes().as_slice()),
        v.target.as_ref().map(|id| id.as_bytes().as_slice()),
        int(v.expires)?,
        v.used_by.as_ref().map(|id| id.as_bytes().as_slice()),
        int(v.kind.code())?,
        i64::from(v.makes_admin),
    ];
    decode(r) {
        Ok((hash(&r.token_hash)?, TokenRow {
            creator: r.creator.as_deref().map(|b| array(b).map(AccountId::from_bytes)).transpose()?,
            target: r.target.as_deref().map(|b| array(b).map(AccountId::from_bytes)).transpose()?,
            expires: uint(r.expires)?,
            used_by: r.used_by.as_deref().map(|b| array(b).map(AccountId::from_bytes)).transpose()?,
            kind: token_kind(r.kind)?,
            makes_admin: flag(r.makes_admin),
        }))
    };
}

sql_table! {
    SessionsTable, SessionId, SessionRow;
    table "sessions";
    cols "session_id, account_id, token_hash, device_id, platform, label, created, last_seen, idle_expires, abs_expires, reauth_until";
    key_eq "session_id = ?";
    key_row "(session_id)";
    key_holes "(?)";
    order "session_id";
    order_desc "session_id DESC";
    holes "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?";
    conflict "ON CONFLICT (session_id) DO UPDATE SET account_id = excluded.account_id, token_hash = excluded.token_hash, device_id = excluded.device_id, platform = excluded.platform, label = excluded.label, created = excluded.created, last_seen = excluded.last_seen, idle_expires = excluded.idle_expires, abs_expires = excluded.abs_expires, reauth_until = excluded.reauth_until";
    key(k) [k.as_bytes().as_slice()];
    value(v) [
        v.account_id.as_bytes().as_slice(),
        v.token_hash.as_bytes().as_slice(),
        v.device_id.as_bytes().as_slice(),
        v.platform.as_str(),
        enc_opt(v.label.as_ref())?,
        int(v.created)?,
        int(v.last_seen)?,
        int(v.idle_expires)?,
        int(v.abs_expires)?,
        int(v.reauth_until)?,
    ];
    decode(r) {
        let id = SessionId::from_bytes(array(&r.session_id)?);
        Ok((id, SessionRow {
            session_id: id,
            account_id: AccountId::from_bytes(array(&r.account_id)?),
            token_hash: hash(&r.token_hash)?,
            device_id: hasp_proto::DeviceId::from_bytes(array(&r.device_id)?),
            platform: r.platform,
            label: dec_opt::<SealedRaw>(r.label.as_deref())?,
            created: uint(r.created)?,
            last_seen: uint(r.last_seen)?,
            idle_expires: uint(r.idle_expires)?,
            abs_expires: uint(r.abs_expires)?,
            reauth_until: uint(r.reauth_until)?,
        }))
    };
}

sql_table! {
    SessionTokensTable, Hash32, SessionId;
    table "session_tokens";
    cols "token_hash, session_id";
    key_eq "token_hash = ?";
    key_row "(token_hash)";
    key_holes "(?)";
    order "token_hash";
    order_desc "token_hash DESC";
    holes "?, ?";
    conflict "ON CONFLICT (token_hash) DO UPDATE SET session_id = excluded.session_id";
    key(k) [k.as_bytes().as_slice()];
    value(v) [v.as_bytes().as_slice()];
    decode(r) {
        Ok((hash(&r.token_hash)?, SessionId::from_bytes(array(&r.session_id)?)))
    };
}

sql_table! {
    EnrolChannelsTable, Esid, EnrolRow;
    table "enrol_channels";
    cols "esid, account_id, session_id, expires, state, slots, attempts";
    key_eq "esid = ?";
    key_row "(esid)";
    key_holes "(?)";
    order "esid";
    order_desc "esid DESC";
    holes "?, ?, ?, ?, ?, ?, ?";
    conflict "ON CONFLICT (esid) DO UPDATE SET account_id = excluded.account_id, session_id = excluded.session_id, expires = excluded.expires, state = excluded.state, slots = excluded.slots, attempts = excluded.attempts";
    key(k) [k.as_bytes().as_slice()];
    value(v) [
        v.account_id.as_bytes().as_slice(),
        v.session_id.as_bytes().as_slice(),
        int(v.expires)?,
        enrol_state_code(v.state),
        enc_slots(&v.slots)?,
        i64::from(v.attempts),
    ];
    decode(r) {
        Ok((Esid::from_bytes(array(&r.esid)?), EnrolRow {
            account_id: AccountId::from_bytes(array(&r.account_id)?),
            session_id: SessionId::from_bytes(array(&r.session_id)?),
            expires: uint(r.expires)?,
            state: enrol_state(r.state)?,
            slots: dec_slots(&r.slots)?,
            attempts: u32::try_from(r.attempts).map_err(|_| ServerError::Store)?,
        }))
    };
}

sql_table! {
    RecoveryEnrolmentsTable, (AccountId, u64), RecoveryRow;
    table "recovery_enrolments";
    cols "account_id, rgen, enrolment, rc_wrap, h_auth";
    key_eq "account_id = ? AND rgen = ?";
    key_row "(account_id, rgen)";
    key_holes "(?, ?)";
    order "account_id, rgen";
    order_desc "account_id DESC, rgen DESC";
    holes "?, ?, ?, ?, ?";
    conflict "ON CONFLICT (account_id, rgen) DO UPDATE SET enrolment = excluded.enrolment, rc_wrap = excluded.rc_wrap, h_auth = excluded.h_auth";
    key(k) [k.0.as_bytes().as_slice(), key_int(k.1)];
    value(v) [enc(&v.enrolment)?, enc(&v.rc_wrap)?, v.h_auth.as_bytes().as_slice()];
    decode(r) {
        Ok(((AccountId::from_bytes(array(&r.account_id)?), uint(r.rgen)?), RecoveryRow {
            enrolment: dec(&r.enrolment)?,
            rc_wrap: dec(&r.rc_wrap)?,
            h_auth: hash(&r.h_auth)?,
        }))
    };
}

sql_table! {
    RecoverySessionsTable, RecoveryId, RecoverySessionRow;
    table "recovery_sessions";
    cols "recovery_id, account_id, rgen, started, release_at, state, source, token_hash";
    key_eq "recovery_id = ?";
    key_row "(recovery_id)";
    key_holes "(?)";
    order "recovery_id";
    order_desc "recovery_id DESC";
    holes "?, ?, ?, ?, ?, ?, ?, ?";
    conflict "ON CONFLICT (recovery_id) DO UPDATE SET account_id = excluded.account_id, rgen = excluded.rgen, started = excluded.started, release_at = excluded.release_at, state = excluded.state, source = excluded.source, token_hash = excluded.token_hash";
    key(k) [k.as_bytes().as_slice()];
    value(v) [
        v.account_id.as_bytes().as_slice(),
        int(v.rgen)?,
        int(v.started)?,
        int(v.release_at)?,
        recovery_state_code(v.state),
        v.source.as_deref(),
        v.token_hash.as_ref().map(|h| h.as_bytes().as_slice()),
    ];
    decode(r) {
        Ok((RecoveryId::from_bytes(array(&r.recovery_id)?), RecoverySessionRow {
            account_id: AccountId::from_bytes(array(&r.account_id)?),
            rgen: uint(r.rgen)?,
            started: uint(r.started)?,
            release_at: uint(r.release_at)?,
            state: recovery_state(r.state)?,
            source: r.source,
            token_hash: r.token_hash.as_deref().map(hash).transpose()?,
        }))
    };
}

impl SessionsTable {
    pub(in crate::store::sqlite) fn of_account(
        &self,
        account: &AccountId,
    ) -> StoreResult<Vec<(SessionId, SessionRow)>> {
        let ids = self.db.exec(async |tx| {
            let rows = sqlx::query!(
                "SELECT session_id FROM sessions WHERE account_id = ?",
                account.as_bytes().as_slice()
            )
            .fetch_all(&mut tx.conn)
            .await?;
            rows.into_iter()
                .map(|r| array(&r.session_id).map(SessionId::from_bytes))
                .collect::<StoreResult<Vec<_>>>()
        })?;
        ids.into_iter()
            .filter_map(|id| {
                self.get(&id)
                    .transpose()
                    .map(|row| row.map(|row| (id, row)))
            })
            .collect()
    }
}

impl RecoverySessionsTable {
    pub(in crate::store::sqlite) fn of_account(
        &self,
        account: &AccountId,
    ) -> StoreResult<Vec<(RecoveryId, RecoverySessionRow)>> {
        let ids = self.db.exec(async |tx| {
            let rows = sqlx::query!(
                "SELECT recovery_id FROM recovery_sessions WHERE account_id = ?",
                account.as_bytes().as_slice()
            )
            .fetch_all(&mut tx.conn)
            .await?;
            rows.into_iter()
                .map(|r| array(&r.recovery_id).map(RecoveryId::from_bytes))
                .collect::<StoreResult<Vec<_>>>()
        })?;
        ids.into_iter()
            .filter_map(|id| {
                self.get(&id)
                    .transpose()
                    .map(|row| row.map(|row| (id, row)))
            })
            .collect()
    }
}

sql_table! {
    NoticesTable, (AccountId, u64), NoticeRow;
    table "notices";
    cols "account_id, notice_id, kind, created, vault_id, at";
    key_eq "account_id = ? AND notice_id = ?";
    key_row "(account_id, notice_id)";
    key_holes "(?, ?)";
    order "account_id, notice_id";
    order_desc "account_id DESC, notice_id DESC";
    holes "?, ?, ?, ?, ?, ?";
    conflict "ON CONFLICT (account_id, notice_id) DO UPDATE SET kind = excluded.kind, created = excluded.created, vault_id = excluded.vault_id, at = excluded.at";
    key(k) [k.0.as_bytes().as_slice(), key_int(k.1)];
    value(v) [
        int(v.kind.code())?,
        int(v.created)?,
        v.vault_id.as_ref().map(|id| id.as_bytes().as_slice()),
        v.at.map(int).transpose()?,
    ];
    decode(r) {
        Ok(((AccountId::from_bytes(array(&r.account_id)?), uint(r.notice_id)?), NoticeRow {
            kind: notice_kind(r.kind)?,
            created: uint(r.created)?,
            vault_id: r.vault_id.as_deref().map(|b| array(b).map(VaultId::from_bytes)).transpose()?,
            at: r.at.map(uint).transpose()?,
        }))
    };
}

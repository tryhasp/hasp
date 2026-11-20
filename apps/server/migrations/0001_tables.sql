CREATE TABLE accounts (
    account_id BLOB NOT NULL PRIMARY KEY CHECK (length(account_id) = 16),
    login TEXT NOT NULL,
    notify_email TEXT,
    is_admin INTEGER NOT NULL CHECK (is_admin IN (0, 1)),
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    cred_gen INTEGER NOT NULL,
    created INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE logins (
    login BLOB NOT NULL PRIMARY KEY,
    account_id BLOB NOT NULL REFERENCES accounts (account_id) DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE account_records (
    account_id BLOB NOT NULL,
    seq INTEGER NOT NULL,
    record BLOB NOT NULL,
    PRIMARY KEY (account_id, seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE opaque_records (
    account_id BLOB NOT NULL PRIMARY KEY REFERENCES accounts (account_id) DEFERRABLE INITIALLY DEFERRED,
    record BLOB NOT NULL,
    cred_gen INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE keysets (
    account_id BLOB NOT NULL PRIMARY KEY REFERENCES accounts (account_id) DEFERRABLE INITIALLY DEFERRED,
    keyset BLOB NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE signup_tokens (
    token_hash BLOB NOT NULL PRIMARY KEY CHECK (length(token_hash) = 32),
    creator BLOB,
    expires INTEGER NOT NULL,
    used_by BLOB,
    kind INTEGER NOT NULL CHECK (kind IN (1, 2, 3)),
    makes_admin INTEGER NOT NULL CHECK (makes_admin IN (0, 1))
) STRICT, WITHOUT ROWID;

CREATE TABLE sessions (
    session_id BLOB NOT NULL PRIMARY KEY CHECK (length(session_id) = 16),
    account_id BLOB NOT NULL REFERENCES accounts (account_id) DEFERRABLE INITIALLY DEFERRED,
    token_hash BLOB NOT NULL,
    device_id BLOB NOT NULL,
    platform TEXT NOT NULL,
    label BLOB,
    created INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    idle_expires INTEGER NOT NULL,
    abs_expires INTEGER NOT NULL,
    reauth_until INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE session_tokens (
    token_hash BLOB NOT NULL PRIMARY KEY CHECK (length(token_hash) = 32),
    session_id BLOB NOT NULL REFERENCES sessions (session_id) DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE enrol_channels (
    esid BLOB NOT NULL PRIMARY KEY CHECK (length(esid) = 16),
    account_id BLOB NOT NULL,
    session_id BLOB NOT NULL,
    expires INTEGER NOT NULL,
    state INTEGER NOT NULL CHECK (state IN (1, 2, 3)),
    slots BLOB NOT NULL,
    attempts INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE recovery_enrolments (
    account_id BLOB NOT NULL REFERENCES accounts (account_id) DEFERRABLE INITIALLY DEFERRED,
    rgen INTEGER NOT NULL,
    enrolment BLOB NOT NULL,
    rc_wrap BLOB NOT NULL,
    h_auth BLOB NOT NULL CHECK (length(h_auth) = 32),
    PRIMARY KEY (account_id, rgen)
) STRICT, WITHOUT ROWID;

CREATE TABLE recovery_sessions (
    recovery_id BLOB NOT NULL PRIMARY KEY CHECK (length(recovery_id) = 16),
    account_id BLOB NOT NULL,
    rgen INTEGER NOT NULL,
    started INTEGER NOT NULL,
    release_at INTEGER NOT NULL,
    state INTEGER NOT NULL CHECK (state IN (1, 2, 3, 4)),
    source TEXT,
    token_hash BLOB
) STRICT, WITHOUT ROWID;

CREATE TABLE notices (
    account_id BLOB NOT NULL,
    notice_id INTEGER NOT NULL,
    kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 8),
    created INTEGER NOT NULL,
    vault_id BLOB,
    at INTEGER,
    PRIMARY KEY (account_id, notice_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE vaults (
    vault_id BLOB NOT NULL PRIMARY KEY CHECK (length(vault_id) = 16),
    kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
    owner BLOB NOT NULL,
    head_seq INTEGER NOT NULL,
    head_hash BLOB NOT NULL CHECK (length(head_hash) = 32),
    rver INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    dissolve BLOB,
    created INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE rosters (
    vault_id BLOB NOT NULL REFERENCES vaults (vault_id) DEFERRABLE INITIALLY DEFERRED,
    rver INTEGER NOT NULL,
    roster BLOB NOT NULL,
    seq INTEGER NOT NULL,
    PRIMARY KEY (vault_id, rver)
) STRICT, WITHOUT ROWID;

CREATE TABLE manifests (
    vault_id BLOB NOT NULL REFERENCES vaults (vault_id) DEFERRABLE INITIALLY DEFERRED,
    seq INTEGER NOT NULL,
    manifest BLOB NOT NULL,
    author BLOB NOT NULL,
    PRIMARY KEY (vault_id, seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE members (
    vault_id BLOB NOT NULL REFERENCES vaults (vault_id) DEFERRABLE INITIALLY DEFERRED,
    account_id BLOB NOT NULL,
    role INTEGER NOT NULL CHECK (role IN (1, 2, 3)),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 5),
    rver INTEGER NOT NULL,
    leave BLOB,
    PRIMARY KEY (vault_id, account_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE memberships (
    account_id BLOB NOT NULL,
    vault_id BLOB NOT NULL,
    PRIMARY KEY (account_id, vault_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE shares (
    vault_id BLOB NOT NULL REFERENCES vaults (vault_id) DEFERRABLE INITIALLY DEFERRED,
    epoch INTEGER NOT NULL,
    account_id BLOB NOT NULL,
    share BLOB NOT NULL,
    seq INTEGER NOT NULL,
    PRIMARY KEY (vault_id, epoch, account_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE self_wraps (
    account_id BLOB NOT NULL,
    vault_id BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    wrap BLOB NOT NULL,
    PRIMARY KEY (account_id, vault_id, epoch)
) STRICT, WITHOUT ROWID;

CREATE TABLE items (
    vault_id BLOB NOT NULL REFERENCES vaults (vault_id) DEFERRABLE INITIALLY DEFERRED,
    item_id BLOB NOT NULL,
    ver INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    wire BLOB NOT NULL,
    h_item BLOB NOT NULL CHECK (length(h_item) = 32),
    tomb INTEGER NOT NULL CHECK (tomb IN (0, 1)),
    size INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    current INTEGER NOT NULL CHECK (current IN (0, 1)),
    PRIMARY KEY (vault_id, item_id, ver, epoch)
) STRICT, WITHOUT ROWID;

CREATE TABLE invites (
    invite_id BLOB NOT NULL PRIMARY KEY CHECK (length(invite_id) = 16),
    vault_id BLOB NOT NULL,
    inviter BLOB NOT NULL,
    role INTEGER NOT NULL CHECK (role IN (1, 2, 3)),
    expires INTEGER NOT NULL,
    state INTEGER NOT NULL,
    invitee BLOB,
    accept BLOB
) STRICT, WITHOUT ROWID;

CREATE TABLE attachments (
    att_id BLOB NOT NULL PRIMARY KEY CHECK (length(att_id) = 16),
    vault_id BLOB NOT NULL,
    size INTEGER NOT NULL,
    chunks INTEGER NOT NULL,
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    created INTEGER NOT NULL,
    refs INTEGER NOT NULL CHECK (refs >= 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE attachment_chunks (
    att_id BLOB NOT NULL REFERENCES attachments (att_id) DEFERRABLE INITIALLY DEFERRED,
    idx INTEGER NOT NULL,
    len INTEGER NOT NULL,
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    PRIMARY KEY (att_id, idx)
) STRICT, WITHOUT ROWID;

CREATE TABLE commit_log (
    vault_id BLOB NOT NULL REFERENCES vaults (vault_id) DEFERRABLE INITIALLY DEFERRED,
    base_seq INTEGER NOT NULL,
    manifest_hash BLOB NOT NULL CHECK (length(manifest_hash) = 32),
    PRIMARY KEY (vault_id, base_seq)
) STRICT, WITHOUT ROWID;

CREATE INDEX sessions_by_account ON sessions (account_id);
CREATE INDEX logins_by_account ON logins (account_id);
CREATE INDEX attachments_by_vault ON attachments (vault_id);
CREATE INDEX invites_by_vault ON invites (vault_id);

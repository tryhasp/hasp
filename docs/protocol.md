# Hasp protocol specification, format version 1 (draft v2.8)

Status: draft v2.8, 2026-11-19. Normative language: MUST, MUST NOT, SHOULD as in RFC 2119.
Authority: this file is authoritative for sessions, identity (login id, prelogin), roles, recovery, extension pairing and unlock, vault dissolve and leave, attachments, export, server records and backups.
Marking: **[unverified]** = not confirmed from a primary source. The product, CLI and URL scheme are `hasp` (named 2026-11-18; trademark search pending before public release).

Contents: 1 Threat model, 2 Suite and PQ, 3 Encoding, 4 Keys, 5 Records, 6 OPAQUE, sessions, prelogin, 7 Flows, 8 Versioning, 9 Server state and operations, 10 Attack mapping, 11 Tests, 12 Residual risks, Appendix A labels, Appendix B changelog.

---

## 1. Threat model and goals

### 1.1 Adversaries

| Id | Adversary | Capabilities |
|---|---|---|
| A1 | Malicious server (host, operator, DBA, backup thief) | Serves any bytes to any client at any time; forks, rolls back, replays, drops, reorders; fabricates users and keys; runs a second server for one victim; reads and edits storage. Does not control a signed client binary. The self-hosting operator is inside A1. |
| A2 | Network attacker | Full MITM including TLS with a rogue CA; replay; downgrade. |
| A3 | Stolen or lost device | Disk contents of an enrolled, locked device; maybe the account password, not the Secret Key. |
| A4 | Compromised member | Legitimate member later removed or hostile; keeps everything it decrypted. |
| A5 | Stolen server DB without client secrets | Offline attack on verifier and ciphertexts. |
| A6 | Phisher or shoulder surfer | Sees a QR code, invite code or Emergency Kit once. |

### 1.2 Out of scope

- Compromised client OS or binary, malicious extension reading the page, keylogger, screen capture, memory scraping of an unlocked client.
- A removed member keeps every secret it saw (UI says so, offers per-item rotation).
- Server availability and deletion (remedy: backups, multi-device copies, rehost).
- Traffic analysis (section 12.3). Coercion. Quantum break of signatures and OPAQUE (2.3). Formal verification.

### 1.3 Goals

| Id | Goal | Condition |
|---|---|---|
| G1 | Confidentiality of item contents, names, URLs, types, tags, times, attachment names against A1, A2, A5. | |
| G2 | Integrity and authenticity of items, item set, vault settings, roster, KDF parameters against A1. | Server may withhold, or roll back to a state the client has not seen. Clients with local state, or with a confirmed head (7.3), detect rollback. |
| G3 | A vault key accepted by a client came from the vault owner key the client was told out of band. | Invitee side: invite code carries `fp(owner)` (H3). Inviter side: verified only if the owner checks `fp(invitee)`; else pin level `tofu`. |
| G4 | The server cannot lower KDF strength below the client floor. | |
| G5 | No downgrade: one suite per format version, unknown version refused. | |
| G6 | Server compromise alone gives no offline password-guessing target (128-bit Secret Key in every credential). | |
| G7 | Stolen locked device: attacker needs the hardware-gated key plus user presence. | Hardware platforms only. Password-only platforms: attacker must brute-force the password at the local Argon2id profile; UI says so. |
| G8 | Removal creates a new epoch; the removed member cannot read data written after removal or unwrap re-wrapped items. | Clients with local state or a confirmed head. A stateless unconfirmed device may be held in a pre-removal epoch, so it cannot write to shared vaults (H2). |
| G9 | The protocol creates no escrow. Family recovery is an ordinary shared item the member chooses to create (7.12). | |
| G10 | Writes are signed; reads are ciphertext. Session = TLS plus an OPAQUE-derived bearer token. Per-request transport MAC is deferred (ruling 9). | A rogue-CA MITM can steal a session token (read ciphertext, spam writes that clients reject, deny service). |

### 1.4 Hardening index (crypto review H1, H2, H3)

| Id | Mechanism | Client verification steps |
|---|---|---|
| H1 stale roster signer | Manifest binds latest roster version, roster hash and epoch; all monotonic (5.6) | Steps 2-5 of the 5.6 loop; negative test E21 |
| H2 stateless freshness | QR and desktop-mediated extension enrolment transfer per-vault high-water marks (7.2 B, 7.2 C); kit sign-in and restore are "unconfirmed": read-only for shared vaults until head confirmed (7.3) | Compare stored marks to server heads before "up to date"; confirm head code; E23 |
| H3 first-contact TOFU | Invite code carries `fp(owner)`; share from any other key refused (7.7) | Steps 1-3 of the 7.7 invitee procedure; E27 |

---

## 2. Suite

### 2.1 Suite table (suite 1 = format version 1; no negotiation)

| Purpose | Algorithm | Parameters | Reference |
|---|---|---|---|
| Password hash | Argon2id v1.3 | floor and default m=65536 KiB, t=3, p=4, tag 32 B, salt 16 B; ceiling m=524288, t=12, p=4. A client also refuses parameters above its own capability with an explicit error and never lowers them. | RFC 9106 §4 |
| KDF | HKDF-SHA-256, labels Appendix A | | RFC 5869 |
| AEAD | XChaCha20-Poly1305, 24 B random nonce, 32 B key, 16 B tag | | RFC 8439 + draft-irtf-cfrg-xchacha-03 (expired draft) **[unverified: status]** |
| Signature | Ed25519, strict verification (reject non-canonical S, small-order A/R) | | RFC 8032 |
| Passkey signature | ECDSA P-256 with SHA-256 (WebAuthn ES256, COSE -7), RFC 6979 deterministic nonces, ASN.1 DER signatures. Only for credentials the user keeps for web relying parties; never for a protocol record. Private key 32-byte scalar stored as PKCS#8, public point 65 bytes uncompressed |  | FIPS 186-5, RFC 6979, W3C WebAuthn Level 3 |
| KEM | X-Wing (ML-KEM-768 + X25519) inside HPKE Base: KEM 0x647a, KDF 0x0001, AEAD 0x0003. Ed25519 signature over (enc, ct, info) for sender authentication. | pk 1216 B, enc 1120 B, seed 32 B | draft-connolly-cfrg-xwing-kem-11, RFC 9180 §9.1.1, FIPS 203 |
| PAKE | OPAQUE-3DH ristretto255-SHA512, KSF = Identity (Argon2id runs before the OPRF, 6.1) | | RFC 9807, RFC 9497 |
| Hash / MAC | SHA-256; HMAC-SHA-256 (prelogin pseudo-records, enrolment MAC); SHA-512 only inside OPAQUE; HMAC-SHA-1, HMAC-SHA-256 and HMAC-SHA-512 with keys of any length for TOTP and HOTP codes only (an `HmacAlg` enum in the crypto crate; never used for protocol keys) | | RFC 2104, RFC 4226, RFC 6238 |
| Encoding | Deterministic CBOR (section 3) | | RFC 8949 §4.2.1 |
| RNG | OS CSPRNG only | | |
| Text | Password: trim (Unicode `White_Space`), then NFKD; every code point accepted. Login id: trim (`White_Space`), reject any unassigned code point (`E_FORMAT`), then `toNFKC_Casefold` (UAX #15 and `DerivedNormalizationProps.txt`: case folding C+F, default-ignorable removal, NFKC). Tables pinned to Unicode 18.0.0 and compiled into `hasp-core` (ICU4X 2.4). Only `hasp-core` normalises; Swift and TypeScript pass the raw typed string. | | UAX #15, UAX #44 |

HPKE construction (ruling 10): HPKE Base with X-Wing plus an Ed25519 signature over `(enc, ct, info)`. RFC 9180 §9.1.1 recommends exactly this for Base mode; draft-ietf-hpke-pq-05 §7.2 offers no Auth mode for PQ KEMs and recommends signatures. The client MUST NOT call HPKE `DeriveKeyPair` (X-Wing -11 and hpke-pq-05 differ); keys come from a stored 32-byte seed through the X-Wing keygen-from-seed function, pinned by a vector.

Login id on the server: the server has no Unicode tables. It treats the login as an opaque string (non-empty, at most 256 bytes, trimmed) and keys uniqueness on the exact bytes. Clients MUST send the NFKC, case-folded form; two clients that normalise differently reach different accounts, which vectors 11.1 prevent. Login ids are account keys: a later change to the fold or the Unicode version needs a new format version. `normalise_login` and `normalise_password` are exported to Swift and TypeScript for display checks only; their output is never sent.

Not key-committing: XChaCha20-Poly1305 and HPKE ChaCha20-Poly1305. Acceptable because every Sealed value is opened with one key derived from state the opener already trusts and no counter-party picks a key for a ciphertext it did not author; the leaf hash over item wire bytes removes malleability. Re-check if a feature ever lets two keys open one blob (per-member item keys, share links).

### 2.2 Implementation versions (crates.io, 2026-11-18)

| Crate | Version | Note |
|---|---|---|
| `ml-kem` | 0.3.4 | RustCrypto, unaudited, FIPS 203 final |
| `x-wing` | 0.1.1 | description says draft 06; its three Appendix C vectors equal -11 (verified, M0); `hpke` 0.15.1 passes the hpke-pq KEM 0x647a vector |
| `hpke` (rozbb) | 0.15.1 | X-Wing via `mlkem` feature, unaudited |
| `opaque-ke` | 4.0.1 stable; 5.0.0-pre.0 | "synced with RFC 9807"; replays RFC 9807 Appendix C.1.1 and C.1.2 byte for byte (verified, M0) |
| `argon2` 0.6.0, `chacha20poly1305` 0.11.0, `ed25519-dalek`/`x25519-dalek` 3.0.0, `hkdf` 0.13.0, `sha2` 0.11.1 | | audit status **[unverified]** |
| `minicbor` | 2.3.1 | strict decoder candidate |
| `p256`, `ecdsa` | 0.14.0 (2026-07-03), 0.17.0 (2026-07-02) | RustCrypto, ES256 passkeys only (`hasp-crypto`); RFC 6979 vector replayed in tests; audit status **[unverified]**; pulls `elliptic-curve` 0.14 beside the 0.13 of `opaque-ke` 4.0.1 (deny.toml skips, end with `opaque-ke` 5) |

The core MUST pin exact versions with `Cargo.lock`; `cargo-deny` runs in CI (advisories included).

### 2.3 Post-quantum decision

| Item | Status |
|---|---|
| draft-connolly-cfrg-xwing-kem | -11, 2026-09-23, Independent Submission, no RFC number; sizes unchanged since -06; editorial defects in -11 |
| draft-irtf-cfrg-concrete-hybrid-kems | -04; MLKEM768-X25519 "identical to the X-Wing construction" |
| draft-ietf-hpke-pq | -05; KEM id 0x647a; no Auth mode for PQ KEMs |
| ML-KEM | FIPS 203 final |

Decision: X-Wing inside HPKE Base for every public-key encryption (vault key shares). Harvest-now-decrypt-later applies to what the server stores long-term and a passive attacker copies: share ciphertexts. Everything else long-lived is symmetric or signature-only. The condition "stable spec" in decisions.md is met in substance (frozen wire format, final component standard, two maintained crates), not formally. Freeze rule: suite constants freeze at the v1.0 tag; later changes are suite 2 (section 8).
Mitigations: CI passes the draft -11 vectors and the hpke-pq vector against the pinned crates (verified in M0; no vendored combiner); check the encapsulation key per FIPS 203 §7.2 on every Encap (invalid-ek vector, E30); crypto review of the glue is a release gate.
Classical on purpose: Ed25519 and OPAQUE ristretto255. A CRQC forges future rosters and manifests and recovers the OPAQUE password input (still needing the Secret Key). Hybrid signatures are reserved for suite 2.

---

## 3. Encoding, AAD, signatures

### 3.1 Deterministic CBOR profile (every signed, hashed or AAD-bound structure)

- RFC 8949 §4.2.1: shortest-form integers and lengths, definite lengths, map keys sorted bytewise by encoded form.
- Allowed: unsigned int (at most 2^53-1), byte string, UTF-8 text string, array, map, `true`, `false`, `null`. Forbidden: negative ints, floats, tags (including 55799), indefinite lengths, `undefined`, other simple values, bignums.
- Map keys are unsigned ints below 256. Unknown keys, duplicate keys, missing required keys, wrong types, `null` where not allowed: rejected. Compatibility is by format version only.
- Decoder (MUST): reject duplicate keys while parsing; parse into the typed struct; re-encode; compare bytes; reject on any difference. Limits: nesting 8 (binds every signed, hashed or AAD-bound structure; transport messages such as pull replies and request bodies are not signed, hashed or bound and have their own nesting limit of 16, with the same length limits otherwise), array length 65536, text 4096 bytes (applies to every text string, including the invite origin; all length limits count bytes), record 16 MiB (applies to every `from_cbor` input).
- A commit bundle carries each item op as a byte string holding the item's canonical CBOR (the exact bytes `h_item` hashes), so the bundle stays within the transport limit and the item wire is never re-encoded.
- Timestamps: uint seconds, informational; never used for a security decision.
- Ids (`account_id`, `vault_id`, `item_id`, `device_id`, `att_id`, `invite_id`, `esid`): 16 random bytes, no structure. Reserved `item_id` of 16 zero bytes = vault settings item.
- Hash-sorted structures sort by the raw bytes of the key, never by CBOR text.

### 3.2 Common types

```
Sealed = [ nonce: bstr(24), ct: bstr ]      ; XChaCha20-Poly1305(key, nonce, padded plaintext, AAD = cbor(Ctx))
Signed = [ body: bstr, signer: bstr(32), sig: bstr(64) ]
H(x)   = SHA-256(x);   H(record) = SHA-256(body)
X(k, name, ctx...) = HKDF-Expand(k, cbor(["hasp/v1/" || name, ctx...]), 32)      ; name from Appendix A
```

### 3.3 AAD

`Ctx = { 0: v (1), 1: rtype, 2: account_id?, 3: vault_id?, 4: item_id?, 5: field?, 6: epoch?, 7: ver?, 8: extra? }`; absent keys are omitted. Decryption MUST rebuild `Ctx` from locally verified state, never from server-supplied bytes.

| rtype | Name | Ctx keys | `field` / extra |
|---|---|---|---|
| 1 | account record | signed | |
| 2 | keyset | 1,2,5,8 | 1 ak_wrap (extra [gen,m,t,p]); 2 keys (extra [gen]) |
| 3 | roster | signed | |
| 4 | manifest | signed | |
| 5 | item payload | 1,3,4,5,7 | 1 overview, 2 details |
| 6 | item key wrap | 1,3,4,5=3,6,7 | |
| 7 | attachment chunk | 1,3,4,5=4,8 | extra [att_id, chunk_size] |
| 8 | share | HPKE info/aad (5.8) | |
| 9 | recovery | 1,2,5,6 | 1 rc_wrap, 6 = rgen |
| 10 | self-wrap | 1,2,3,6 | |
| 11 | device-local blob | 1,2,5,8 | 1 ak_bio, 2 sk, 3 session, 4 ak_pw, 5 session_pw, 6 ext_ak, 7 ext_session (sealed under `K_ext`, 7.16), 8 ext_key (desktop copy of `K_ext`); extra [device_id, local_gen] (device_id of the extension for 6 to 8) |
| 12 | enrolment channel | 1,8 | extra = transcript hash |
| 13 | export stream | 1,8 | extra [H(header), chunk_size] |
| 14 | account meta | 1,2,5,8 | 1 session label; extra [device_id] |
| 15 | vault dissolve | signed (5.13) | |
| 16 | leave request | signed (5.13) | |

### 3.4 Padding

Overview, details and keys plaintext: ISO 7816-4 (0x80, zeros) to buckets 256 B, 512 B, ... 64 KiB (powers of two), then multiples of 64 KiB; decoders verify the pad exactly. Wraps of 32-byte keys (`ak_wrap`, item `wrap`, `self_wrap`, `rc_wrap`) are not padded; the plaintext keyset `keys` is. Attachment and export chunks: see 5.7.

### 3.5 Signatures

`sig = Ed25519(sk, "hasp/v1/sig/<name>" || 0x00 || body)`. The verifier checks `signer` against the expected key (pinned, roster or own) before verifying, with strict verification.

---

## 4. Keys

### 4.1 Hierarchy

```
 password p (NFKD)                    Secret Key SK (26 symbols, 128.8 bits)
        |  Argon2id(m,t,p; salt S_kdf)       |
        +----------- K_pw || SK -------------+
                       |  HKDF-Extract(salt = H(cbor["hasp/v1/2skd", account_id, m, t, p]))
              AUK = X(prk,"auk",account_id)    OPK = X(prk,"opaque-input",account_id)
                 |                                  |
       ak_wrap = Sealed(AUK, AK)             OPAQUE account credential (the only OPAQUE credential)
 AK (32 random, never derived from a password)
  |- K_keyset = X(AK,"keyset-seal")   seals {IK_seed, KEM_seed, SK, retired}  ; IK = Ed25519, DK = X-Wing
  |- K_self   = X(AK,"self-wrap")     seals own copies of VK_e
  |- K_meta   = X(AK,"account-meta")  seals session labels
 per vault, epoch e: VK_e (32 random)
  |- K_iw = X(VK_e,"item-wrap",vault_id,e)     seals item keys
  |- vk_commit = X(VK_e,"vk-commit",vault_id,e)  in the signed roster
 per item version: item_key (32 random) -> K_ov = X(item_key,"field",vault_id,item_id,ver,1); K_det = (..., 2)
 per attachment: file_key (32 random, fresh per att_id) -> K_chunk = X(file_key,"att-chunk",vault_id,item_id,att_id)
 recovery: RC (same format as SK) -> K_rc = X(RC-prk,"rc-wrap"), K_rc_auth = X(RC-prk,"rc-auth")
 device: DUK (32 random, hardware-gated where available) seals local blobs (4.6)
```

There are no per-device OPAQUE credentials and no pin-store key (ruling 6, 7). Pins live as items in the Private vault.

### 4.2 Derivations

```
S_kdf = HKDF-Expand(HKDF-Extract(salt="hasp/v1/argon-salt", ikm = SK_ascii(26) || account_id), cbor(["hasp/v1/argon-salt"]), 16)
K_pw  = Argon2id(NFKD(trim(p)), S_kdf, m, t, 4, 32, 0x13)
prk   = HKDF-Extract(salt = H(cbor(["hasp/v1/2skd", account_id, m, t, p_par])), ikm = K_pw || SK_ascii)
RC-prk = HKDF-Extract(salt = "hasp/v1/rc-prk", ikm = RC_ascii || account_id)
```

`m,t,p` and `account_id` arrive from prelogin as untrusted hints; wrong values change K_pw and fail closed at the first AEAD or OPAQUE check. AUK and OPK have different labels, so the server learns nothing about AUK (G6).

### 4.3 Secret Key and Recovery Code format

`V1-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF` (SK) and `R1-...` (RC). Alphabet (31): `23456789ABCDEFGHJKLMNPQRSTVWXYZ`. 26 secret symbols by rejection sampling (31^26 = 2^128.8) plus 4 check symbols: `c = H("hasp/v1/sk-check" || tag || secret_ascii)[0..4]` as u32 BE, with `tag` the ASCII prefix (`V1` for SK, `R1` for RC) and `secret_ascii` the 26 secret symbols; the check symbols are the base-31 digits of `c mod 31^4`, most significant first. The 26 secret symbols are the uniform base-31 symbols themselves (no packing into 128 bits). Undetected random typo 1/923521. The check adds no exposure when the full string is exposed; a partial view (blurred kit) leaks up to 19.8 bits. Parse failure is `E_FORMAT`, local only.

### 4.4 Emergency Kit (local PDF, never uploaded)

| Field | Content |
|---|---|
| Header | product, date, kit version 1 |
| Server | canonical origin |
| Login id | normalised |
| Secret Key | `V1-...` |
| Server key fingerprint `sf` | first 15 bytes of SHA-256(server OPAQUE public key), 24 Crockford base32 chars (format as 4.5) |
| Account password | blank for handwriting |
| QR | opaque base32 blob `cbor{0 v, 1 origin, 2 login, 3 SK, 4 sf}`, scanned only by the in-app scanner. No URL scheme, no link form (a custom scheme is not exclusive; browsers log URLs). |
| Warnings | kit plus password unlock the account; keep the recovery code away from the kit |

Generation requires re-entry of the last SK group. The RC is shown on its own page with the same step.

Rendering (v2.7): the kit is produced from an unlocked device as exact text and as a one-page PDF (PDF 1.4, A4, the standard Helvetica and Courier fonts, no embedded fonts, no metadata, no JavaScript, no external references). A PDF carries Latin-1 only, so a login id with other characters prints them as `?` there; the text and the QR carry it exactly. The QR holds the Crockford base32 of the `cbor{...}` blob above. A regenerated kit has no RC page: the RC is not retained after it is shown once. PDF over printable HTML: the spec already says PDF, a PDF needs no browser (a browser caches and syncs what it prints) and the writer is about 150 lines with no dependency beyond the QR encoder.

### 4.5 Fingerprints

`fp(account) = H(cbor(["hasp/v1/fp", ik_pk, kem_pk]))[0..15]` (120 bits), 24 Crockford base32 chars (uppercase, no padding) in groups of 4 separated by `-`, and a QR that is an opaque in-app blob. One definition everywhere. UI shows login id plus `fp`; never a self-asserted label. Login ids can be homoglyphs (Cyrillic "a"); invites rely on `fp`, not the typed id.

### 4.6 Device state

| Item | Hardware platform | Password-only platform |
|---|---|---|
| `local_ak_bio = Sealed(DUK, AK)`, `local_sk = Sealed(DUK, SK)`, `local_session = Sealed(DUK, token)` | yes | no |
| `local_ak_pw = Sealed(K_loc, AK)`, `local_session_pw = Sealed(K_loc, token)`, `K_loc = Argon2id(p, local_salt, local profile)` | NO (no hardware-gate bypass) | yes; local profile m = 256 MiB where memory allows (local cost only), else the account profile |
| Secret Key | in the gated store (`local_sk`), as 1Password keeps it in platform secure storage | not stored; inside the keyset, reachable with AK |
| Password unlock | release DUK (user presence), open `local_sk`, Argon2id(p, S_kdf(SK)), open cached `ak_wrap` | open `local_ak_pw` |
| Anti-rollback state (local DB) | per-vault `(rver, roster hash, epoch, seq, manifest hash)`, account record `seq`, keyset `gen`, server key pin and origin, `max_seen_v`, `min_v` | same |

Session key (v2.9, password-only class: the standalone browser extension): after a password unlock the client MAY hand the host `K_loc` as an opaque session blob, `0x01 || K_loc` (33 bytes). `K_loc` is derived from the password but does not reveal it, and it cannot log in: the OPAQUE exchange needs the password and the Secret Key. It opens only the device-local blobs (`local_ak_pw`, `local_session_pw`), so the host resumes after a service-worker eviction without asking again. The host MUST keep the blob in session-scoped storage only (for a browser, `storage.session` with trusted-context access), MUST discard it on lock and at browser exit, and MUST NOT store the account password anywhere in any form. The blob is as strong as `K_ext` (7.16): whoever holds it and the persisted blobs holds AK. A session token that has expired cannot be renewed from the blob; the user types the password again. A hardware-class device has no session blob (a refusal, not a protocol error code). A resume with a wrong or damaged blob fails like a wrong password, without a lockout step: the blob is 32 random bytes, so there is nothing to guess.

Pending recovery (v2.7): a device with no account may keep a started recovery (7.11) as one local record, the recovery ticket: CBOR `[recovery_id, release_at, account_id, login, origin, RC]` sealed with XChaCha20-Poly1305 under `Argon2id(NFKD(new password), salt, local profile)` (fresh 16-byte salt and 24-byte nonce; the profile is stored beside the salt and bounded like any untrusted KDF header), AAD `hasp/v1/local/recovery-ticket`. The password is the new password the user chose when starting, asked again to resume; a wrong one is an authentication failure. The record is deleted when the recovery completes or the user restarts it.

`local_salt` = 16 random bytes per device; `local_gen` = counter of the local blob set, bumped on every rewrite (a replayed older blob fails AAD only if the DB counter moved; stateless devices cannot tell).

Platform semantics (what actually holds the key):

| Platform | DUK holder | Gate |
|---|---|---|
| iOS | Keychain item, `WhenPasscodeSetThisDeviceOnly`, access control user-presence; class keys are Secure Enclave protected. The Enclave holds only P-256 keys, so DUK is not an Enclave key. | Face/Touch ID or passcode |
| macOS | data-protection Keychain item, user-presence; where available an Enclave P-256 key ECIES-wraps DUK | Touch ID or password |
| Android (v1.1) | Keystore AES-256-GCM key (StrongBox if present), user authentication required, wraps DUK | BiometricPrompt |
| Windows (later) | Windows Hello (TPM) key wraps DUK. DPAPI alone isolates other users only, not same-user malware: password-only class. | Hello |
| Linux, extension-only | none (libsecret is open to every process of the user) | password-only; UI MUST say so at unlock |

User-presence (not biometry-current-set) is the default so a biometric change does not destroy DUK; a stricter option exists. The AutoFill extension reads DUK from the shared keychain group, runs no Argon2, and has local state only if it shares the app database; otherwise it is a stateless device (H2). Where DUK is lost the user signs in again with the kit.

Browser extension: its own enrolled device (own `device_id`, session, local state). With the desktop app present it is unlocked by the desktop (7.16) and keeps only `ext_ak` and `ext_session` at rest, sealed under a key the desktop holds. It also keeps the password-only blobs (`local_ak_pw`, `local_session_pw`) as the fallback when the desktop is absent; it is password-only class and the UI says so.

---

## 5. Records

Common rules: (1) strict decode; (2) `v == 1` else `E_VERSION`; (3) rtype; (4) verify signature or AEAD with the expected key; (5) semantic rules; (6) apply. Any failure rejects the whole unit atomically, quarantines the vault or operation, logs a local security event and names the check. The client MUST NOT retry with server-supplied alternatives.

Error codes: `E_FORMAT`, `E_VERSION`, `E_SIG`, `E_AEAD`, `E_PIN`, `E_ROLLBACK`, `E_FORK`, `E_ROSTER`, `E_KDF_PARAMS`, `E_EPOCH`, `E_ROOT`, `E_AUTH`, `E_SERVER_KEY`, `E_AUTHZ`, `E_INVITE` (invite fingerprint mismatch).

### 5.1 Account record (public, self-signed)

Keys: `0 v, 1 rtype=1, 2 account_id, 3 seq, 4 prev (hash or null), 5 ik_pk, 6 kem_pk, 7 kdf {0 m,1 t,2 p}, 8 status (1 active, 2 deleted), 9 rc_gen (0 none), 10 min_v, 11 rot (MUST be null in v1; reserved for identity-key rotation, v1.5), 12 created`. Signer `ik_pk`.
KDF acceptance: m in [65536, 524288], t in [3, 12], p = 4, else `E_KDF_PARAMS` before any Argon2. The record is trusted only after `ak_wrap` opens with an AUK derived from exactly these parameters (they are in the AAD) and the key derived from `IK_seed` equals `ik_pk`. Others verify signature, `seq` greater than any seen, `prev` chain, pin check (5.10). `E_PIN` blocks every operation naming the account.
Seq rule: a record whose `seq` is more than one above the seen `seq` cannot have `prev` checked; it is accepted after the signature, KDF and pin checks. Equal `seq` with equal hash is accepted (idempotent re-fetch); lower `seq` is `E_ROLLBACK`; equal `seq` with another hash is `E_FORK`.
Re-fetch: a device that holds a record fetches the chain again at every sync and requires the newest `seq` to be at least its own (`E_ROLLBACK` below, `E_FORK` for the same `seq` with another hash), the same `account_id`, `ik_pk` and `kem_pk`, and a keyset whose `gen` is at least its own and which opens under its AK; only then does it adopt the newer record. Stateless sign-in trusts an unauthenticated older record (`rc_gen`, `status`, `kdf`, `min_v` may be stale); only `rc_gen` and `status` matter in v1.

### 5.2 Keyset (secret, server-stored)

`0 v, 1 rtype=2, 2 account_id, 3 gen (1 in v1; reserved), 4 ak_wrap, 5 keys`.
`ak_wrap = Sealed(AUK, AK, Ctx{1:2,2:acct,5:1,8:[gen,m,t,p]})`; `keys = Sealed(K_keyset, cbor({0 ik_seed, 1 kem_seed, 2 sk_ascii, 3 retired: []}), Ctx{1:2,2:acct,5:2,8:[gen]})`. `E_AEAD` shows as "wrong password, Secret Key or tampered data" (indistinguishable). `gen` below the stored value is `E_ROLLBACK` for stateful clients.

### 5.3 Roster (owner-signed membership; also the vault record)

Body: `0 v, 1 rtype=3, 2 vault_id, 3 rver (starts 1), 4 epoch, 5 prev (hash, null at 1), 6 kind (1 private, 2 shared; immutable), 7 members sorted by account_id of {0 account_id, 1 ik_pk, 2 kem_pk, 3 role (1 viewer, 2 editor, 3 owner), 4 added_rver}, 8 vk_commit (for epoch)`. Signer: the owner.
Rules: exactly one `role=3` member, who is the creator and signer; `kind=1` has exactly one member and accepts no share; `rver = prev + 1`; `epoch` never decreases, and rises if and only if `vk_commit` changes; `added_rver <= rver` for every member; member keys pass the pin check (`New` is acceptable, `KeyChanged` is `E_PIN`); the verifier's own entry equals its own keys exactly (`E_ROSTER`, detects key substitution); the creator at `rver 1` is own or a pinned/invited key at first sight. Between rosters of one vault the signer, the owner, `kind` and `vault_id` are immutable. Ownership transfer is deferred (12.4); an owner who leaves must dissolve the vault. Role change is a new roster (`rver+1`); a downgrade to viewer does not change `epoch`. A roster that removes a member (removal or leave, 7.8, 7.18) MUST set `epoch = prior epoch + 1` with a new `vk_commit`; the verifier enforces it (5.6 step 3).
State per vault: highest `(rver, hash)`; lower `rver` = `E_ROLLBACK`, equal with another hash = `E_FORK` (also for a roster met in 5.6 step 2, instead of `E_ROSTER`).

### 5.4 Roles

| Role | Read | Write items | Change roster, rotate, repair |
|---|---|---|---|
| owner (one per vault) | yes | yes | yes; also dissolve (7.17) |
| editor | yes | yes | no |
| viewer | yes | no | no |

Roles are enforced by clients: a manifest signed by a non-writer is `E_AUTHZ`. The server also checks the role from the latest roster as policy (availability, not trust). Viewers hold VK and can export (client-only control). Instance admin is a separate server flag (9.1) with no vault access.

### 5.5 Manifest (signed, hash-chained vault state)

Body: `0 v, 1 rtype=4, 2 vault_id, 3 seq (starts 1), 4 prev, 5 epoch, 6 rver, 7 roster_hash, 8 root, 9 author account_id, 10 repair (null or 1)`. Signer: the author's IK, role >= editor; role owner for any commit that carries a roster, shares, an epoch change or `repair`.

Leaf set (ruling 8): one leaf per live item (its current version) and per tombstone, sorted bytewise by `item_id`:

```
leaf_bytes = cbor([item_id, ver, epoch, h_item, flag])     ; h_item = SHA-256(item wire bytes, 5.6); flag 0 live, 1 tombstone (h_item = H(tombstone wire))
root = SHA-256("hasp/v1/leafset" || u32_be(count) || SHA-256(leaf_1) || ... || SHA-256(leaf_n))      ; empty set: count 0
```

History versions are not leaves; their integrity is AEAD (AAD binds vault, item, ver). The server may drop history (availability only). Tombstones are never compacted.

### 5.6 Manifest verification (H1, M5, M7)

State `S = (seq, hash, rver, roster_hash, epoch, roster, leafset)`. A pulled batch is verified all-or-nothing in one local transaction:

```
for each commit k = 1..n (manifest M_k, optional bundled roster R_k, item ops):
  1. M_k.seq == S.seq+1 else E_ROLLBACK (lower, a gap that skips a commit, or an exact replay of the head) / E_FORK (equal, other hash); M_k.prev == S.hash else E_FORK
  2. if R_k present: verify R_k (5.3), signed by owner of S.roster (or genesis), R_k.rver == S.rver+1, R_k.prev == hash(S.roster); S.roster := R_k      else E_ROSTER
     else R = S.roster
  3. M_k.rver == R.rver, M_k.roster_hash == H(R) (always, not only on change), M_k.epoch == R.epoch, M_k.epoch >= S.epoch,
     M_k.rver >= S.rver; if R_k removes a member of S.roster, M_k.epoch == S.epoch+1                           else E_ROSTER / E_EPOCH
  4. signature valid; author in R with role >= editor (owner if R_k, shares, epoch change or repair present)       else E_SIG (signature invalid) / E_AUTHZ (author not in R, which includes an unknown author, or role too low)
  5. apply ops to the leaf set: ver == current+1 (tombstone included), except the epoch-bump re-wrap: an op with ver == current, epoch greater than the leaf's epoch, live to live, is accepted; every op carries epoch == M_k.epoch; every live leaf has epoch == M_k.epoch afterwards (tombstone leaves keep their epoch)    else E_EPOCH
  6. recompute root over the leaf set; == M_k.root                                                                 else E_ROOT   (every commit, not only the last)
  7. S := (M_k, ...)
persist batch and S; open items lazily (AEAD at read time)
```

Each share bundled in a commit (owner authority, step 4) must be signed by the author (the owner), name this vault, carry the manifest's `rver` and `epoch`, have `from` equal to the author and `to` another member of the roster; else `E_ROSTER` (`E_EPOCH` for an epoch mismatch).
This is the ruling-1 rule: the signer's roster version and epoch equal the latest roster the client holds, and `rver` and `epoch` never decrease. Attribution: a failing commit's author is shown in the quarantine UI. Stateless clients verify the chain but cannot detect a rolled-back head (G2, H2).

Page handling (C1): a client never decides the head of a pull from the server's `has_more`. It keeps requesting from the last `seq` it holds until the last commit it has received has `seq` and manifest hash equal to the page's `head_seq` and `head_hash`; a page with no commits that does not meet that test, a head below the commits, or more than 4096 pages is an error (`E_FORMAT`, or `E_FORK` for a conflicting head). Nothing is persisted until the whole run has verified: unverified pages are staged in memory only. A pull of zero commits is accepted only as "up to date" if the stored head still hashes to its manifest root: the client recomputes the leaf-set root of its stored head (`leafset_root(leaves) == manifest.root`) every time it loads a head, and a mismatch is a damaged store, not a state.

Strict, stateless and retention replay (ruling 2, H1): a device with state runs the steps above on every commit, including the root at each one. It does not fall back to a weaker rule on failure. It falls back only when the run itself shows pruning, which is: some item has ops in the run whose versions skip some versions above its stored leaf version, and every skipped version is at least the retention window (10, 5.7) below the highest version of that item in the run. The fallback then checks, for every commit, steps 1 to 4, the signature, chain, roster, epoch (including `wire.epoch == M_k.epoch` for every op) and share rules, and recomputes the leaf-set root only at the last commit of the run, over the highest `(ver, epoch)` seen per item; it is recorded as a visible event (`retention fallback`, vault, from `seq`, to `seq`). Any other failure quarantines the vault with the strict error. A client with no local state (path A, restore, a new device without a snapshot) verifies the whole signature chain from genesis: account records, rosters and manifests, meaning signatures, monotonic `rver`, `epoch` and `seq`, `prev` hashes, and roster equality (`M_k.roster_hash == H(R)`, H1); it recomputes the leaf-set root only at the head it adopts and applies the same per-op epoch check. Head confirmation (H2, 7.3) still applies to the adopted head. This weakens detection of a past leaf-set fault to the head for devices in the fallback or without state; every device in the strict path keeps the per-commit root. Reviewed in phase F (run/review/m0-crypto-review.md M1): sound given the page handling above.

Repair (M5): a validly signed but invalid commit wedges every honest client at its `seq`. The owner publishes a repair manifest: same `seq` as the bad commit, `prev` = the last good hash, `repair = 1`, signed by the owner; its leaf set is the last good leaf set plus the repair commit's ops. A client holding the quarantined bad commit (or none) shows author, both hashes and the dropped suffix, and applies the repair only after explicit user confirmation on that client. Later commits built on the bad commit are discarded (their authors re-base). A repair manifest on a client that never saw the bad commit also needs confirmation. The server removes the suffix (policy). Test E22.

### 5.7 Item and attachments

Item wire: `0 v, 1 rtype=5, 2 vault_id, 3 item_id, 4 ver (author sets base_ver+1), 5 epoch, 6 wrap, 7 ov, 8 det, 9 tomb, 10 att_ids (array of att_id referenced by this version, plaintext), 11 prev_h (hash of the previous version's wire bytes, null for `ver` 1)`; a tombstone has `9 = true`, key 10 present and empty, key 11 present, and no 6-8. `prev_h = SHA-256(previous version's wire bytes)` is exactly the previous leaf's `h_item` at the time of the edit; an epoch re-wrap of a version keeps its `prev_h`. Because `h_item` of the current version is in the signed root, `prev_h` authenticates the chain of older versions back to the retention window: a viewer or a removed member holds `VK_e` and can seal a version that opens, but cannot make it the predecessor named by a hash.

- `item_key` 32 random, new for every version.
- `wrap = Sealed(K_iw, item_key, Ctx{1:6,3:vault,4:item,5:3,6:epoch,7:ver})`; `ov = Sealed(K_ov, pad(cbor(overview)), Ctx{1:5,3,4,5:1,7})`; `det` likewise with field 2. Payload AAD excludes epoch so rotation re-wraps `item_key` without re-encrypting.
- Payload codec (`hasp-proto` module `payload`: overview, details, attachment descriptors, history; used by the store and by export; no other codec exists). `pv` is inside the ciphertext; unknown `pv` is refused by a compiled table. Item templates are data inside the payload (ruling 20). Short text values (kind, title, subtitle, tags, text, url, email, phone, menu and sign-in-with values, address parts, security-question questions, passkey `rp_id`, `user_name` and `display_name`, url, app and attachment names) are CBOR text strings of valid UTF-8, at most 4096 bytes, checked on write and on read. Long and secret values are byte strings: `notes` (details key 2, its own limit of 256 KiB), concealed field values, security-question answers and password-history values (at most 64 KiB each). The limits are checked on write and on read. Enumerations are unsigned indexes into compiled tables, except the overview `kind`, which is a text string naming the template (`login`, `pin`, `device`, `vault-settings`, `recovery-code`, ...). Key numbers (fixed; every map is complete, no optional keys, absent optionals are `null`):

| Structure | Keys |
|---|---|
| Overview (11) | 0 pv, 1 kind, 2 title, 3 subtitle, 4 tags (array), 5 favourite (uint or null), 6 state (0 active, 1 archived, 2 trashed), 7 state_at (null iff active), 8 client_modified, 9 created, 10 expires_at (uint or null) |
| Details (8) | 0 pv, 1 sections, 2 notes (bytes or null), 3 urls, 4 apps, 5 passkeys, 6 history, 7 attachments |
| Section (3) | 0 id, 1 title, 2 fields |
| Field (7) | 0 id, 1 label, 2 kind, 3 value, 4 purpose (uint or null), 5 concealed, 6 expires_alert |
| Field kind | 0 text, 1 concealed, 2 url, 3 email, 4 phone, 5 date, 6 month-year, 7 otp, 8 address, 9 menu, 10 security-question, 11 sign-in-with |
| Field value by kind | text, url, email, phone, menu, sign-in-with: bytes; concealed: bytes; date: `[y,m,d]`; month-year: `[y,m]`; address: `[street, city, region, postal_code, country]`; security-question: `[question, answer]` |
| OTP value (8) | 0 secret (bytes), 1 algorithm (0 sha1, 1 sha256, 2 sha512), 2 digits, 3 kind (0 totp, 1 hotp), 4 period_s or counter, 5 issuer (bytes or null), 6 account (bytes or null), 7 steam |
| Url (5) | 0 id, 1 url, 2 match mode (0 domain, 1 host, 2 never), 3 confirmed_hosts, 4 kind (0 website, 1 sign-in, 2 api) |
| App (4) | 0 platform (0 ios, 1 android, 2 macos, 3 windows), 1 id, 2 cert_sha256 (32 B or null), 3 source (0 user, 1 dataset) |
| Passkey (11) | 0 credential_id, 1 rp_id, 2 user_handle, 3 user_name, 4 display_name, 5 algorithm (COSE id, zigzag-encoded: n >= 0 as 2n, n < 0 as -2n-1), 6 private_key (PKCS#8), 7 created, 8 last_used (uint or null), 9 backup_eligible, 10 backed_up |
| History entry (3) | 0 value (bytes), 1 replaced_at, 2 field id |
| Attachment descriptor (7) | 0 att_id, 1 file_key, 2 nonce_prefix (15 B), 3 size, 4 chunk_size, 5 name, 6 mime |
| Purpose table (field key 4) | 0 username, 1 password, 2 totp, 3 new-password, 4 card-holder, 5 card-number, 6 card-expiry, 7 card-expiry-month, 8 card-expiry-year, 9 card-cvc, 10 card-type, 11 name, 12 given-name, 13 family-name, 14 email, 15 phone, 16 birthday, 17 street-address, 18 address-line1, 19 address-line2, 20 city, 21 region, 22 postal-code, 23 country, 24 organization, 25 api-key, 26 hostname, 27 ssh-private-key, 28 ssh-public-key |

Passkey `algorithm` is `-7` (ES256) in v1 and any other value is refused when the passkey is used; the signature counter is not stored. The numbers above are those of `hasp_proto::payload`, the only payload codec; hidden items (`pin`, `device`, vault settings) use its `Hidden` form in the details slot. The overview carries no URL summaries or flags; lists derive `has_totp`, `has_passkey` and `has_attachments` after opening details or cache them locally.

- Pins and devices are items (5.10, 5.11).
- Opening: leaf `(item_id, ver)` exists in the verified leaf set and `H(received bytes) == h_item`; rebuild AAD locally; AEAD opens; schema valid. A failing item is shown damaged and excluded; no network request is ever derived from a decrypted field.
- History: the server keeps the 10 newest versions per item (constant, not configurable). A client lists, restores and exports only the versions that chain back from the current leaf by `prev_h`; a stored version the chain does not reach is not history. A device that holds only the current version (stateless sign-in, pruning) shows no older versions. On an epoch bump only current versions are re-wrapped (7.8); older retained versions stay under their original epoch key and are not leaves. A retained version may also be pruned (5.6, stateless replay).

Attachment cipher (STREAM, XChaCha20-Poly1305): chunk size 2^20. `ct_i = AEAD(K_chunk, nonce_i, pad_i, AAD = cbor(Ctx{1:7,3:vault,4:item,5:4,8:[att_id, chunk_size]}))`, `nonce_i = nonce_prefix(15, random per attachment) || u64_be(i) || last_flag`. The last chunk always exists and carries 0..chunk_size-1 plaintext bytes plus ISO 7816-4 padding to a multiple of 4 KiB (an exact multiple of the chunk size emits an empty final chunk). The reader checks the total against `size`. Vectors for 0, 1, chunk_size-1, chunk_size, chunk_size+1 bytes.
Upload rules (M2): `att_id`, `file_key` and `nonce_prefix` are fresh per attachment and per restart. Encrypted chunks are staged and uploaded from the stage; a resume re-sends staged bytes and MUST NOT re-encrypt. M1 stages in memory, so a resume works within one process; staging on disk is deferred (12.4). If the source changes mid-upload the client aborts and restarts with a new `att_id`, `file_key`, `nonce_prefix`. Limits: chunk ciphertext at most 2^20 + 16 bytes, total ciphertext at most 100 MiB (server default), chunks written in order and idempotent (a repeat of chunk `n` with identical bytes succeeds), `attachment_complete` requires the exact chunk count the client sends. Reference counts are per retained item row that lists the `att_id`; a blob is deleted when its count reaches zero, and an upload with no reference after 24 h is swept. There is no per-vault quota in v1. Integrity: AEAD plus `size`; attachments are not manifest leaves, but `att_ids` is in the item wire and so in `h_item`. A chunk failure aborts the download; no partial plaintext reaches user storage.
Cross-vault move: `K_chunk` and AAD bind vault and item, so a move is a copy (new item, new `att_id`, re-encrypted chunks) plus a tombstone at the source.

### 5.8 Share (vault key transport)

`Signed` body `{0 v, 1 rtype=8, 2 vault_id, 3 epoch, 4 rver, 5 from, 6 to, 7 kem_pk_hash (SHA-256 of the 1216-byte KEM public key), 8 enc (1120 B), 9 ct (48 B)}`, signer = the vault owner. HPKE Base (X-Wing): `info = cbor(["hasp/v1/share", vault_id, epoch, rver, from, to, from_ik_pk, to_ik_pk, kem_pk_hash])`, `aad = cbor(["hasp/v1/share-aad", roster_hash])`, plaintext `VK_e`. The signature covers `enc, ct` and the identities.
Recipient verification, in order: (1) body decodes, `to` is own, `kem_pk_hash` equals own current or retired KEM key; (2) owner key passes the pin check, or this is the first share of an invite and `fp(from)` equals the `fp` in the invite code (else `E_INVITE`); (3) signature verifies with that key; (4) the roster `rver` verifies (5.3), lists the recipient with the recipient's real keys, and carries the same `epoch` and `vk_commit`; (5) HPKE opens with `info` and `aad` rebuilt locally; (6) `X(VK,"vk-commit",vault_id,epoch) == roster.vk_commit` else `E_ROSTER`; (7) first share only: the user accepts the invitation; (8) store `self_wrap = Sealed(K_self, VK, Ctx{1:10,2:acct,3:vault,6:epoch})` and upload it before discarding anything.
Error mapping: `to` not the verifier is `E_AUTHZ`; `kem_pk_hash` that is neither the own current nor a retired key is `E_ROSTER` (key substitution); with a matching pin and an invite present, the invite fingerprint must still match (`E_INVITE`, H3); any HPKE open failure is `E_AEAD`.
Self-wrap opening re-checks `vk_commit` against the verified roster. Failure keeps the prior epoch.

### 5.9 Recovery enrolment

`Signed` body `{0 v, 1 rtype=9, 2 account_id, 3 rgen, 4 h_wrap}`; `rc_wrap = Sealed(K_rc, AK, Ctx{1:9,2:acct,5:1,6:rgen})`; verifier `h_auth = H(K_rc_auth)` stored on the server. `account.rc_gen == rgen` or the enrolment is stale (`E_ROLLBACK`). There is no OPAQUE credential for recovery: RC has 128 bits, so a hash verifier is not guessable offline, and `K_rc_auth` is independent of `K_rc`. No organizer or server escrow exists in the protocol.

### 5.10 Pins (stored as items in the Private vault)

One hidden item per known account: `item_id = H("hasp/v1/pin-id" || account_id)[0..16]`, kind `pin`, payload `{account_id, ik_pk, kem_pk_hash, level (1 tofu, 2 verified), first_seen}`. Pins inherit manifest integrity, rollback detection and history; no separate store, key or merge rule. A concurrent edit is whole-item last-writer-wins; two different keys for one account surface as `E_PIN`. While a device is unconfirmed (7.3) every pin it holds is loaded at level `unverified`: `pin_check` returns `UNVERIFIED` for a matching key, a changed key is still `KEY_CHANGED`, and no flow accepts an unverified pin as `OK` (an incoming share then needs its invite fingerprint, as for a new contact). The level returns to the stored one when the device confirms.

```
pin_check(account_id, ik_pk, kem_pk):  none -> NEW (first-contact UI; level verified only via invite fp or a scanned fp, else tofu)
                                      match -> OK;  else KEY_CHANGED (blocking; both fingerprints; acceptance sets level tofu)
```

Wrap targets for rotation and removal come only from the owner's own signed roster, never from pins or the server (BW02). v1 has no key rotation, so a roster key differing from the account record key is an alarm needing explicit accept.

### 5.11 Device pins

One hidden Private-vault item per device: `item_id = device_id`, kind `device`, payload `{label, platform, first_seen, status (1 active, 2 revoked)}`. The device list = server sessions (9.1) matched to device items by `device_id`; a session without an item is shown "unrecognised session" until the signed-in device writes its item. There is no device record, no device credential and no `dseq`.

### 5.12 Invite code

Not signed, not secret-bearing beyond expiry: `INV1-` + Crockford base32 (uppercase, no padding, trailing bits zero; parsing is case-insensitive) of cbor{0 v, 1 invite_id, 2 fp_owner (15 B), 3 origin}); the same blob as an in-app QR. Server record: invite id, vault, role, expiry (7 days), state.

### 5.13 Dissolve record and leave request

Both are `Signed` bodies verified like any signed record (3.5).

- Dissolve: `{0 v, 1 rtype=15, 2 vault_id, 3 rver, 4 epoch, 5 seq, 6 head (manifest hash)}`, signer = the vault owner, signature label `hasp/v1/sig/dissolve`. Valid only for `kind = 2`. On a member that holds state, `rver`, `epoch` or `seq` below the stored marks is `E_ROLLBACK`; equal `seq` with a different head is `E_FORK`. It is terminal: `vault_id` is never reused. It does not change `epoch` (no further data is written).
- Leave request: `{0 v, 1 rtype=16, 2 vault_id, 3 account_id, 4 rver, 5 epoch}`, signer = the leaving member's IK, label `hasp/v1/sig/leave`. Valid only for a non-owner member and only while `rver` and `epoch` equal the latest roster the verifier holds (a stale request is ignored: `rver` different from the held one is `E_ROSTER`, `epoch` different is `E_EPOCH`). It grants nothing by itself: membership changes only through the owner-signed roster (7.18).

---

## 6. OPAQUE, sessions, prelogin

### 6.1 OPAQUE configuration (one credential per account)

| Item | Value |
|---|---|
| Protocol | OPAQUE-3DH RFC 9807, ristretto255-SHA512 |
| KSF | Identity: the password input is `OPK`, a 256-bit Argon2id-derived value mixed with the Secret Key. RFC 9807 §10.8 says applications SHOULD apply a KSF; nothing forbids this one (checked). Soundness: record stolen without SK = 2^128.8; with SK each guess costs one Argon2id plus a local OPRF, equal to a post-OPRF KSF. Changing the KSF later needs re-registration. If a reviewer rejects Identity, switch to the Argon2id KSF and halve the 2SKD floor; the interface does not change. |
| `credential_identifier` | `cbor(["acct", account_id])` |
| `server_identity` / `client_identity` | the UTF-8 bytes of the canonical origin the user pinned / the 16 `account_id` bytes |
| Context | `cbor({0 v, 1 suite, 2 purpose, 3 account_id, 4 [m,t,p], 5 api})`; purposes 1 register, 2 login, 3 reauth, 4 change. `v` = 1, `suite` = 1, `api` = 1; `[m,t,p]` is the KDF of the server's latest account record for `account_id`, so a login that used a stale prelogin fails with the uniform error. RFC 9807 mixes context only into the AKE preamble, so `[m,t,p]` is not a downgrade defence (the client already commits to it through OPK). |
| `export_key` | discarded; vault keys never derive from OPAQUE output |
| Server key | pinned at first sign-in (kit `sf` or operator comparison); a different key later is `E_SERVER_KEY` with an explicit reset action |

Server setup (ruling 29): one 32-byte `server_master`, generated at first start and stored in a file outside the database (`secrets/server.key`, mode 0600, or an env path). `oprf_seed` (64 B), the AKE key pair seed and the prelogin HMAC key `K_pre` are derived from it with HKDF labels `hasp/v1/srv/oprf`, `.../ake`, `.../prelogin`. Each stream is `HKDF-Expand(server_master as PRK, cbor(["hasp/v1/srv/<name>"]), 256)`. `oprf_seed` = bytes 0..64 of the `oprf` stream; the AKE private key is the wide reduction (mod the group order) of bytes 0..64 of the `ake` stream; the OPAQUE fake-record key material is bytes 64..128 of the `oprf` stream. The setup is pinned by `testvectors/crypto/opaque-server-setup.json`, a vector produced by this implementation (no external reference exists). It is not in the DB so a plain DB leak does not hand over the seed; a leak of both is still safe against password guessing because the Secret Key stays unknown (G6). `haspd backup` MUST include the file (7.14).

### 6.2 Messages and purposes

Registration (purposes 1, 4): request, response, record uploaded with the other records of the flow in one atomic request. Login (2): KE1, KE2, KE3 per RFC 9807 §6.4; success returns a session. Reauth (3): the same login, yields a reauth mark valid 5 minutes on that session.

### 6.3 Prelogin and anti-enumeration (M10)

`prelogin(login)` is pre-auth and returns `{account_id, kdf {m,t,p}, cred_gen, v}`. For an unknown login the server returns a pseudo-record derived from `h = HMAC(K_pre, login)` alone, with no read of the account table: `account_id' = h[0..15]`, the suite-floor KDF parameters (`m` 65536, `t` 3, `p` 4), `cred_gen = 1 + (h[15] mod 3)`, and for recovery prelogin `rgen = h[15] mod 2`. The response is stable per login and cannot drift as accounts sign up. `K_pre` is the first 32 bytes of the 256-byte `srv/prelogin` stream (6.1). Status codes, shape, size and timing are identical (constant-time fake path). Residual risk (12.1 item 9): an account whose KDF parameters are not the floor, or whose `cred_gen` is above 3, is distinguishable from a login that does not exist. Recovery prelogin returns `{account_id, rgen}` by the same rule. Login for an unknown credential uses the RFC 9807 §6.3.2.2 fake response; one `oprf_seed` for all clients; one client error message for wrong login, password, Secret Key or tampered data. Registration needs a signup token and is rate limited (registration is an oracle by nature).
Rate-limit classes (in memory): login, register and recovery, everything else.

### 6.4 Sessions and transport (ruling 9)

- A session is created by OPAQUE login, by QR enrolment approval (7.2 B), by desktop-mediated extension enrolment (7.2 C) or by recovery completion. Token `T = X(HKDF-Extract(salt = empty, ikm = session_key), "session-token", sid)` (32 B); `session_key` is the 64-byte OPAQUE session key and `X` takes a 32-byte PRK, so the Extract step comes first (QR and recovery sessions have no OPAQUE key: the server mints `T` as 32 random bytes); the server stores `H(T)`; the client sends `Authorization: Bearer T`. TLS is required (HSTS). There is no request MAC, counter or response MAC.
- Lifetime: idle expiry 30 days sliding, absolute 90 days; at expiry the user types the password (Argon2) to log in again. Renewal of a live session needs no Argon2, so the AutoFill extension works from `local_session`.
- Authority matrix:

| Session may | Needs reauth (5 min mark) |
|---|---|
| read its account's ciphertext; push commits (clients reject anything not validly signed); list, revoke sessions; open enrolment; create invites; upload attachments; send a leave request (7.18) | change credential, create or replace recovery code, delete account, dissolve a vault (7.17), export, `rehost`, repair-affecting admin actions |

- Revocation = delete the session row. A device that still holds AK, SK and the password can sign in again, so "lost device" guidance is revoke plus change password (7.4) plus epoch bumps (7.8); full key rotation is v1.5.
- Pre-auth operations: prelogin, register, login KE1/KE2, enrolment relay, recovery. Their content is an untrusted hint and every use is verified cryptographically.
- Idempotent retry of a write is by `(vault, base_seq, manifest hash)`, not a header (ruling 14).

---

## 7. Flows

`C` client, `S` server (untrusted), `D1` an enrolled device, `D2` a new device.

### 7.1 Sign-up

1. User gives origin, signup token, login id, password. C checks strength locally.
2. C generates `account_id, AK, IK_seed, KEM_seed, SK, device_id, VK_0, vault_id`; KDF parameters = floor or a device-benchmarked value within bounds.
3. C derives K_pw, prk, AUK, OPK and registers the OPAQUE credential (purpose 1); pins the server key.
4. C builds and signs: account record seq 1, keyset gen 1, Private-vault roster rver 1 (kind 1), settings item, device item, manifest seq 1, self-wrap for VK_0.
5. One atomic upload with the token; S creates the account or rejects. C downloads and verifies its own records, then logs in (session).
6. C shows the Emergency Kit (confirmation required) and offers a recovery code (7.11).

### 7.2 Sign-in on a new device

Path A, Emergency Kit or typed (stateless; device is **unconfirmed**, 7.3): inputs origin, login id, SK, password.

1. Parse SK (`E_FORMAT` locally). Prelogin gives `(account_id, m, t, p)`; outside the allow-list or above this device's capability: `E_KDF_PARAMS`, no Argon2.
1a. When the kit gives `sf`, the device calls `server_key` (no session) before anything else and compares `fp(public_key)` and the origin with the kit; a mismatch is `E_SERVER_KEY` and no login, prelogin or Argon2 runs. `server_key` returns only public material the OPAQUE login would reveal anyway; it is never trusted on its own. A first sign-in without a kit `sf` is not offered: the client asks the user to type the fingerprint from the kit, and sign-up asks for the one `haspd init` printed, compared the same way before `register_start` (v2.8).
2. Argon2id once; derive AUK, OPK; OPAQUE login (purpose 2); failure is the uniform error. The login's authenticated server key is compared with kit `sf` again (first sign-in) or the pin, and binds it.
3. Fetch account record, keyset. Open `ak_wrap` with AAD `[gen,m,t,p]` from the record; open `keys`; require derived `ik_pk` equal the record; verify signature and `prev` chain.
4. Create local unlock material (4.6). Write the device item (Private vault commit). First full sync with the 5.6 verification; open self-wraps (`E_ROSTER` on `vk_commit` mismatch). Pins are unverified until head confirmation.

Path B, QR from enrolled `D1` (no password, no Argon2; D2 starts **confirmed**):

1. D1 (unlocked) makes `e` (32 B), `esid`, 5-minute expiry, single use; shows an opaque in-app QR `cbor{0 v, 1 origin, 2 account_id, 3 esid, 4 e, 5 fp(account), 6 sf}`; opens the channel at S with its session.
2. D2 scans in-app, calls `server_key` and compares it with `sf` (`E_SERVER_KEY`, before any other call), makes ephemeral X25519 `b`, and sends the request `body = cbor{0 cB, 1 platform, 2 device_id}` with `cB = H(cbor(["hasp/v1/enrol-commit", B, esid]))`, plus `MAC_e(body || esid)` (the MAC covers the whole body, so the relay cannot swap the platform or device id), `MAC_e = HMAC-SHA-256(HKDF-Extract("hasp/v1/enrol-mac", e), .)`.
3. D1 shows "new device <platform> wants access" (enforces the 5-minute expiry itself), makes `a`, sends `A` with `MAC_e(A || esid || cB)`.
4. D2 reveals `B` with `MAC_e(B || esid)`; D1 checks `H(cbor([..., B, esid])) == cB` and the MAC.
5. Both compute `ss = X25519`, `kc = HKDF-Extract(salt = e, ikm = ss)`, `transcript = H(cbor([origin, account_id, esid, cB, A, B]))`, `K_ch = X(kc,"enrol-key",transcript)`, `code = u32(X(kc,"enrol-code",transcript)[0..4]) mod 10^6`. D2 shows `code`; the user types it into D1 (3 attempts; any failure or expiry invalidates `esid`).
6. D1 asks S to approve `esid` once with its session (the creating session is the only approver; a second approve is refused); S mints a session for D2 and returns the token to D1. D1 sends `Sealed(K_ch, cbor{AK, token, snapshot}, Ctx{1:12, 8:transcript})`. `snapshot` = per-vault `(rver, roster_hash, epoch, seq, manifest_hash)`, account record `seq`, keyset `gen`, `max_seen_v`.
7. D2 opens it, loads the snapshot as its local state (H2), fetches the records, verifies `fp(record) == fp` from the QR (anchor is the QR, not the server), derives `ik_pk` from `IK_seed` and compares, then runs Path A step 4; any server head older than the snapshot is `E_ROLLBACK`.
Channel relay (`enrol_msg`): a channel has four write-once slots, in order request (`cB` message), offer (`A`), reveal (`B`) and payload (sealed payload), each at most 1 MiB, at most 16 writes per channel (a second write to a filled slot with different bytes is refused; identical bytes are idempotent, and order is not enforced by the server: the commit-reveal rule is checked by D1). The typed-code attempt limit (step 5) is enforced by D1 only; the server holds no attempt counter. Whoever knows the `esid` (the creating session, either enrolment party) ends a channel with `enrol_abort` (state `aborted`; slots deleted); the server rate-limits it per `esid`. Expiry (5 minutes) and single use are enforced by the server as policy and by D1 cryptographically.
Path C, extension through the desktop app (enrolled, unlocked desktop `D1`; the extension `D2` is its own device; starts **confirmed**). The Path B payload is delivered over a local channel that OS-level peer verification authenticates, replacing the QR scan, the relay, the commitment and the typed code:
1. Peer verification, before the app reads any message, on every connection: (a) the browser starts the native host only for an extension id listed in the host manifest (`allowed_origins` for Chromium, `allowed_extensions` for Firefox), set to exactly the published ids; (b) `hasp-nmh` verifies the code signature of its parent process, the browser binary, against an allowlist of browser signing identities; (c) the app verifies `hasp-nmh`'s code signature (our team id) and the socket peer. Safari has no host process: the native handler lives inside the app bundle and that containment is the verification. Any failure refuses the connection and shows no prompt.
2. `D2` sends `enrol_request {device_id, platform = extension, browser}`. `D1` shows "Connect <browser> extension?" and requires biometric approval (password where no biometrics exist).
3. `D1` makes `esid`, calls `enrol_open` and `enrol_approve` with its own session (no `enrol_msg`); S mints a session for `D2` bound to `device_id` and returns the token to `D1`.
4. `D1` makes `K_ext` (32 random, 7.16) and sends `{AK, token, snapshot, fp(account), K_ext}` over the channel: the Path B payload (`AK` opens the keyset that holds the Secret Key, so the Secret Key needs no separate transfer; `snapshot` = per-vault high-water marks, account record `seq`, keyset `gen`, `max_seen_v`).
5. `D2` stores the marks as its local state (H2), fetches the records, verifies `fp(record)` against the `fp` received, derives `ik_pk` from `IK_seed` and compares, runs Path A step 4, then seals `ext_ak` and `ext_session` under `K_ext` (7.16). It then asks for the account password once to create `local_ak_pw` and `local_session_pw` (4.6), checked by opening the cached `ak_wrap`; this is the fallback of 7.16. A server head older than the snapshot is `E_ROLLBACK`.
The channel is not cryptographic: the pipe and socket are local, authenticated only by the checks in step 1 and the user's biometric approval. Because the host checks its parent by pid, a same-user process can start the signed helper while posing as the browser (E33); so the approval prompt shows a code `NNN NNN` derived from the `device_id` the extension put in `enrol_request` (label `hasp/v1/ext-pair-code`, same derivation as 7.16), and the extension shows the same code in a window of its own. The user approves only if the two match. Test E33.
Commit-reveal in Path B blocks the relay attack: D2 commits `B` before seeing `A`, so a relay that knows `e` cannot grind keys toward a matching code (E24). X25519 here is classical and short-lived; the payload is additionally protected by possession of `e`.

### 7.3 Head confirmation, unlock (H2)

| State | Reads | Writes to Private vault | Writes to shared vaults |
|---|---|---|---|
| confirmed (stateful, QR snapshot, or after confirmation) | yes | yes | yes |
| unconfirmed (Path A, restore from kit) | yes (banner "state not confirmed") | yes | blocked |

Confirmation UX: (1) banner on the unconfirmed device: "This device has not confirmed the latest state of your shared vaults. You can read; editing shared vaults is paused. Confirm now."; (2) "Confirm now" lists each vault with `seq` and a head code; (3) the user opens the same screen on a confirmed device of the account, or asks any member of that vault, and compares each code; the user taps "codes match" per vault; (4) equal `seq` and different code = `E_FORK` alarm; different `seq` = "sync both devices and compare again"; (5) a user with no other device and no member can confirm the Private vault only by accepting the risk, and shared writes stay blocked until a member's code is compared; (6) on success the device stores the marks and becomes stateful.
`head_code(vault) = base32_crockford(H(cbor(["hasp/v1/head-code", vault_id, rver, epoch, seq, manifest_hash]))[0..5])`, 8 chars as `XXXX-XXXX`, shown with `seq`.

Unlock: hardware platform, biometric: user presence releases DUK, open `local_ak_bio`; password: DUK, `local_sk`, Argon2id, cached `ak_wrap`. Password-only: open `local_ak_pw`. A session whose token is valid is reused (`local_session`). After unlock the client verifies stored marks before showing "up to date". The AutoFill extension follows the biometric path and runs no Argon2.

### 7.4 Password change and compromise response

Change (reauth): user enters current and new password, optionally a new Secret Key. C checks `ak_wrap` opens, derives AUK', OPK', builds `ak_wrap'` over the same AK, OPAQUE registration (purpose 4), uploads atomically; S bumps `cred_gen`, revokes every session except the current one. KDF parameter change = account record `seq+1`. New SK = regenerate the kit.
UI statement (required): "This re-wraps your key. Anyone who holds your old password, Secret Key and a copy of the old keyset can still read data."
v1.0 compromise response (no key rotation): revoke sessions, change password and Secret Key, bump the epoch of every owned vault (7.8 with no removal), rotate shared secrets item by item, new recovery code. AK, IK and the KEM key do not change in v1: if a device that held AK was compromised, the account is exposed until the user creates a new account and imports an export. Identity-key rotation is v1.5; the format reserves `rot`, `gen` and the roster key-replacement path.

### 7.5 Create vault

C generates `vault_id`, `VK_0`; signs roster (owner only, kind 2), settings item (name inside), manifest seq 1; seals the self-wrap; uploads atomically. No escrow wrap exists.

### 7.6 Pull

Client sends `(vault, seq)` per vault; S returns manifests and bundled rosters since `seq`, item ops, shares and self-wraps addressed to the account, and unauthenticated notices. Everything is verified by 5.6; the cursor is never trusted.

### 7.7 Invite and add member (H3)

Owner O, invitee M with an account on the same server.

1. O creates an invite (vault, role); O's client records `(invite_id, role)` locally and S stores the invite; the role in the roster is the one O recorded (or chose on the confirming device), never the role field of S's reply (an owner approving on another device chooses the role there); O's client builds the code with `fp(O)` and gives it to M out of band (copy-paste or QR in-app; no web landing page).
2. M's client (invitee procedure): (a) fetch O's account record by the invite's `invite_id`; (b) require `fp(record) == fp_owner` from the code, else `E_INVITE` and refuse; (c) record O as a `verified` pin; (d) post the accept with M's account id; M's screen shows `fp(M)` and a QR.
3. O's client receives the accept, fetches M's record, verifies it, runs `pin_check`. If O scans or compares `fp(M)` the pin is `verified`, else `tofu` with a visible badge (a server that fabricates M for O is undetected otherwise; this is the one residual first-contact window, 12.1).
4. O builds roster `rver+1` adding M (role chosen by O), same epoch and `vk_commit`, an HPKE share of `VK_e` to M's `kem_pk`, new manifest; one commit.
5. M runs 5.8 verification, accepts, stores the self-wrap, verifies the first manifest batch.
A share with no matching invite is refused. Invite links grant nothing without the signed share.

### 7.8 Remove member, epoch bump (ruling 11)

1. O (owner only) builds roster `rver+1` without the member (or unchanged for a bump), `epoch = e+1`, new `vk_commit`, `VK_{e+1}`. Targets come from O's own previous signed roster.
2. Shares for every remaining member; O's self-wrap, carried in the commit (any member may also upload a self-wrap for an epoch not above the vault epoch with `self_wrap_put`, 5.8 step 8).
3. O re-wraps `item_key` of every live current version (tombstones carry no wrap; older retained versions are not touched) under `K_iw'` (payload untouched; about 100 B per item) and builds the new manifest. The leaf set accepts a re-wrap only for the current version (5.6 step 5); older retained versions stay under their old epoch key, are not leaves, and become unreadable to a removed member only by the history window.
4. One atomic commit: roster, shares, wraps, manifest. S deletes the removed member's shares and wraps, drops their access, rejects writes tagged epoch e (policy).
5. Remaining members verify (5.8), re-seal self-wraps, continue at e+1. An offline member keeps cache but cannot sync until it processes the share.
6. UI lists what the removed member could see; offers per-item rotation. A member who leaves follows 7.18, which ends in this flow.
The epoch rule is enforced by the verifier: a roster that removes a member and does not set `epoch = e+1` is `E_EPOCH` (5.6 step 3). Test E31.
G8 holds for clients with local state or a confirmed head.

### 7.9 Item create, edit, delete; commit and conflicts (rulings 14, 15)

A commit is the only write: `{vault_id, base_seq, manifest, roster?, shares?, item ops (wires), rewraps?, att_ids}`, atomic. S checks `base_seq == head`, `ver == current+1`, role from the roster, epoch, size; a commit is idempotent by `(vault, base_seq, manifest hash)`. Edit: fresh `item_key`, `ver = base_ver + 1`, leaf, manifest `seq+1` over the full leaf set. Delete: tombstone leaf.
On `409` the client pulls, verifies (5.6), then re-bases its pending ops on the new head. Same item edited on both sides = whole-item last-writer-wins by server order: the re-based edit becomes `ver = remote_ver + 1`, the remote version stays in item history, the user sees a notice naming the replaced version; an edit over a remote tombstone resurrects the item. No per-field merge. The client flushes its pending queue as one commit.

### 7.10 Attachments

`att_id`, `file_key`, `nonce_prefix` fresh; encrypt to a staging file (5.7); upload chunks (idempotent, resumable from the staged bytes); complete with chunk count; add the descriptor to details and commit a new item version listing `att_ids`. S garbage-collects uploads unreferenced for 24 h and blobs no retained version references. Download: fetch in order, decrypt by the nonce rule, verify the last flag and `size`, write to an app-sandbox temp file, move on success.

### 7.11 Recovery code: create and use

Create (reauth): generate RC; `K_rc`, `K_rc_auth`; `rc_wrap`; signed enrolment; `account.rc_gen+1`; upload; show RC once with confirmation. The kit warns against storing RC with the kit. RC alone plus `rc_wrap` opens AK; a leaked RC means AK is exposed (replace RC and treat as compromise).
Use (all devices lost, or password or SK lost):

1. User enters login id and RC. Recovery prelogin returns `(account_id, rgen)`. C sends `K_rc_auth`; S checks `H(K_rc_auth) == h_auth` and starts the delay (default 24 h).
2. S posts notices to every session of the account (delivered by sync, shown as an alert on the member's other devices) and sends SMTP mail to `notify_email` if configured (optional). A normal sign-in or "this was not me" on any device during the delay aborts it. If all devices are lost and no notifier exists the delay is only an unnotified wait.
3. After the delay S mints a recovery-session bearer token (32 random bytes, stored as `H`, valid 1 hour, bound to the recovery session) at `recover_fetch` and releases `rc_wrap`, keyset and records with it. `h_wrap` in the recovery enrolment is SHA-256 of the canonical CBOR of `rc_wrap`. `recover_start` is idempotent while one recovery is pending for the account (it returns the same recovery session and does not restart the delay). C opens `rc_wrap`, `keys`, verifies the record, `rgen == rc_gen`.
Resume (v2.7): steps 1 to 2 and steps 3 to 4 may run in different processes; the client keeps the ticket (4.6) in between and a resumed `recover_fetch` before `release_at` answers `E_PENDING` with `retry_after`. `recover_register_start` and `recover_complete` carry `recovery_id` as field 0 of the body (the other fields shift by one); the server refuses an id other than the one the recovery-session token belongs to. Test mode (v2.7): only a server built with its `testing` feature can shorten the delay; no configuration key, environment variable or flag of a production build can.
4. C sets a new password and Secret Key, builds `ak_wrap'`, registers a new OPAQUE credential (an OPAQUE registration round trip with `recover_register_start`, then `recover_complete`, both authorised by the recovery-session token), makes a new RC (`rgen+1`); S revokes all sessions. The device is **unconfirmed** (7.3). C recommends 7.4 compromise response.

### 7.12 Family recovery via a shared item (ruling 4; opt-in, default off)

No new crypto and no protocol role. Member M creates a shared vault `Recovery` owned by M with the family organizer as viewer (7.7), and stores the current RC as an item. Recovery is then the ordinary 7.11 flow, started by whoever holds the RC (the organizer hands it to M, or M reads it from a surviving shared copy).

| Trade-off | Statement |
|---|---|
| What the organizer gains | The organizer can read RC. With RC and the server delay the organizer, or anyone who compromises the organizer's account, can take over M's account (AK opens everything, including the Private vault). Same for an operator who is also the organizer. |
| What the delay does | It gives M's other devices a window to see the notice and abort. A server that colludes can suppress notices. With no other device and no SMTP there is no warning. |
| Revocation | Remove the organizer from `Recovery` (epoch bump) and create a new RC. This protects against the future only: a server or backup that kept the old `rc_wrap` plus the organizer's copy of the old RC still yields AK until AK rotation exists (v1.5). |
| Maintenance | A new RC after any recovery must be re-stored in the item; the client does this automatically while the option is on. |
| Not protected | A compromised organizer device; a hostile operator-organizer. |

The UI shows these rows before enabling.

### 7.13 Device revocation, account deletion

Revoke: delete the session row; the device item is set to `status 2` by a commit; other devices see the list update. A device that learns it is revoked erases its local data and keys: it does so when its own device item (5.11) is `status 2` after a verified pull, and an extension (7.16) does so when its session is refused and it has no password path. The device then returns to the empty state and needs a new sign-in or pairing. UI offers 7.4 compromise response and states that data cached on a lost device is the real exposure (G7).
Delete (reauth): the server refuses (`conflict`) while the account owns an active shared vault or is an active member (not leaving, not removed) of one; the client therefore dissolves each owned shared vault (7.17) first (transfer is deferred), and a member leaves (7.18) first. A leaving or removed member may delete. For each shared vault the user is a member of, the client sends a leave request (7.18) first. Sign the final account record (`status 2`, `seq+1`); S deletes records, blobs, sessions. Deleted login ids are reusable and yield a new `account_id`; pins are keyed by `account_id`.

### 7.14 Export, backup, rehost, server-secret loss

**Export envelope `.haspx`** (user-initiated, reauth; writes only to a user-chosen path; no plaintext temp files or logs; viewers may export):

```
file    = "VLTX" || cbor(header) || stream
header  = {0 v=1, 1 created, 2 key_mode (1 passphrase, 2 backup key), 3 kdf {0 m,1 t,2 p,3 salt(16)}, 4 nonce_prefix(15), 5 chunk_size=2^20, 6 bk_nonce(16) (mode 2), 7 kcv(16)}
`H(header)` below is the hash of the canonical encoding of the header without key 7 (the kcv depends on `K_exp`).
K_exp   : mode 1 = X(Argon2id(NFKD(passphrase), salt, m,t,p), "export-key", H(header)); mode 2 = X(bk_key, "export-key", H(header), bk_nonce); in mode 2 `kdf` describes `bk_key = Argon2id(NFKD(passphrase), salt, m,t,p)` (so restore needs only the passphrase), and a reader holding `bk_key` may unlock directly
kcv     : first 16 bytes of X(K_exp, "export-kcv") (its own derived key; K_exp is never used as a MAC key)
stream  : STREAM chunks as 5.7 over the byte string  seq of (u32_be len || cbor record), AAD Ctx{1:13, 8:[H(header), chunk_size]}
records : {0 type} 1 vault{vault_id, name, kind}, 2 item{vault_id, item_id, overview, details, history[]}, 3 attachment{1 att_id, 2 item_id, 3 name, 4 size, 5 mime, 6 offset, 7 data}, 9 end{counts}
```

The key is never derived from AK (an AK change must not break old exports). Item records use the payload codec of 5.7 (overview and details, history as `[overview, details]` pairs holding the versions authenticated by `prev_h`, newest first) and carry no attachment descriptors (their `file_key` belongs to the source store): files travel as attachment records and the importing client re-encrypts them. An attachment is split into pieces of at most 1 MiB, contiguous by `offset` (a zero-byte file is one empty piece). Untrusted header `kdf` bounds are the suite ceiling of 2.1 (m <= 524288, t <= 12, p <= 4, all non-zero), checked before any Argon2 (`E_KDF_PARAMS`); `salt` is 16 bytes. Errors: the kcv is checked after the KDF and before any chunk; a mismatch is `WrongPassphrase`; every later failure (chunk AEAD, truncation, a last chunk that opens as non-last, padding, record framing) is `Corrupt`. A restore verifies the whole stream before applying anything and imports records as new data (no roster or manifest becomes authority). Passkeys are included; plain JSON export is a separate explicit action with a warning.
**Scheduled backup (opt-in)**: at opt-in the user sets a passphrase; the client derives `bk_key = Argon2id(passphrase, bk_salt)` once and stores it in the gated store (password-only platforms: not offered unattended); each file uses `key_mode 2` with a fresh `bk_nonce` and `nonce_prefix`; the file is written while the client is unlocked. Restore needs only the passphrase.
**Server-side backup**: `haspd backup` writes the DB and the attachment directory. `secrets/server.key` is not in a snapshot unless the operator asks for it and chooses a separate destination (a DB and the OPRF seed together allow offline password guessing). Restore stages and verifies the snapshot (integrity check, vault heads read from the snapshot DB, not from its manifest), swaps it in atomically, and revokes every session, enrolment channel and pending recovery so each device signs in again; it refuses a DB whose vault heads are older than a client reports unless `--acknowledge-rollback` (E20).
**Client after a server restore (v2.8)**: a client that sees the server's vault chain behind its own head (`E_ROLLBACK`) or different from it at the height of its own head (`E_FORK`) records the vault as `server_behind` and keeps working on its local copy; it never fixes the server silently. The user-confirmed action `accept_older_server_state` pulls the server chain from genesis, verifies it alone, refuses unless the server's roster hash equals the device's head roster (a restore must not re-admit a removed member or lower the epoch; otherwise the device re-enrols that vault), replaces the vault's local items with the server's and turns every local newest version the server lacks into an ordinary pending operation on top of the server's leaf. A second device whose history the restored server no longer has, after the first device accepted and wrote on, sees a different hash at its own head: this fork is recorded like a rollback and may be accepted the same way. Attachment chunks the restored server lacks are not re-uploaded (known limit).
**Rehost (move an account to a new server)**: stateful device, reauth. Rehost is a replay of the verified local copy into a new account, not a chain transplant: a server accepts a vault only from `seq` 1 and an account only at `gen` 1 and `rc_gen` 0. (1) The new server issues a signup token. (2) C registers a new OPAQUE credential at the new origin (same password, same Secret Key) and replays its verified local copy as a fresh account: new account and vault ids, new genesis, current items (history and tombstones are not carried), attachments, self-wraps. (3) Shared vaults are not moved: the owner creates new shared vaults at the new origin and re-invites the members, who accept as for any new vault. (4) Other devices re-pin the new origin and server key by entering the new kit data (the old server is untrusted: compare `sf`). (5) The old account is deleted by the user. Because ids and chains are new, other clients see new vaults and not a rollback; the old copy remains readable until deleted.
**Server-secret loss** (`server.key` lost, DB intact): all OPAQUE records are invalid and the server key changes. The operator creates per-account re-registration tokens (`haspd admin reregister`: kind 3, bound to one active account through the token row's `target`, 7-day expiry, single use). Re-registration (v2.7): the client opens its local copy with password and SK (proves possession; a wrong password never reaches the server), sends `reregister_start {token, request}`, receives the OPAQUE response for the token's target account and compares the server key in it with the fingerprint the user took from `haspd fingerprint` (a mismatch aborts before anything else is sent, `E_SERVER_KEY`), sends `reregister_finish {token, record}` and signs in again with the same password and SK. The server accepts a token only if its kind is 3, it is unused and unexpired, and its target is an active account; it then replaces the account's OPAQUE record, bumps `cred_gen`, revokes every session of the account and spends the token. Keys, keyset and account record do not change, so no data is re-wrapped. A token for one account never affects another. Without the local copy the user falls back to RC (7.11).

### 7.15 Repair (wedged vault)

See 5.6 Repair. Owner flow: pick the last good seq, review dropped commits and authors, sign the repair manifest, then `repair_publish` it. The server checks the caller is an active owner and the author, the manifest has `repair = 1` and no roster or shares, `2 <= seq <= head`, and the result under `verify_repair` (`prev` is the stored hash at `seq - 1`, owner signature, root over the last good leaf set plus the repair's ops). It drops the stored suffix from `seq` (manifests, item rows and their attachment references, commit log), stores the repair as the new head and answers with the new head; a repeat of the same repair is idempotent. A suffix that contains a roster or shares is refused (`unsupported`): repair covers item faults only in v1. Members pull the repair as an ordinary commit at the wedge `seq`; a client holding state for the vault does not apply it but shows a pending-repair notice (author, `seq`, hash) and blocks writes to that vault until the user confirms, then verifies with `verify_repair`, applies it and clears any quarantine. A quarantined vault is skipped by sync; the user can retry, which lifts the quarantine and pulls again from the last good head (a still-bad commit quarantines again, a repaired head shows the pending repair). A device that already applied the dropped suffix sees a fork and must restore the vault from the server or an export.

### 7.16 Extension unlock via desktop (extension paired by 7.2 C)

`K_ext` is 32 random bytes per extension device, made by the desktop at pairing. The desktop keeps it as `ext_key = Sealed(DUK, K_ext)` (4.6, rtype 11 field 8). The extension persists only `ext_ak = Sealed(K_ext, AK)` and `ext_session = Sealed(K_ext, token)` (field 6, 7) and never stores `K_ext`.
Unlock:

1. The extension makes 16 fresh random bytes `nonce`, shows the code in a window only the extension can open, and sends `unlock {device_id, nonce}` over the verified channel (7.2 C step 1 runs on every connection). A message without a 16-byte `nonce` is malformed.
2. The desktop requires user presence (biometric, or password where no biometrics exist) in a prompt that shows the code `NNN NNN`, the first four bytes of `SHA-256("hasp/v1/ext-unlock-code" || device_id || nonce)` read as a big-endian 32-bit number modulo 10^6, printed as two groups of three digits. The user approves only if it equals the code in the extension window. The desktop refuses before any prompt when the device is revoked or unknown, when `ext_key` was sealed for another browser or extension id, or when the 14-day password rule is due; it does not hold its engine lock while the prompt is open. After three denials on one connection it closes the link. If the desktop is itself being unlocked, that one approval covers both.
3. The desktop replies `{K_ext, valid_until}`. Nothing else is sent: never AK, the session token, the Secret Key or the password.
4. The extension opens `ext_ak` and `ext_session`, and holds `K_ext`, AK and the token only in memory or session-scoped storage. It discards all three at the first of: a `lock` message from the desktop (app lock), `valid_until` (the shared lock policy idle timeout, default 10 minutes, extended only by activity the desktop sees), browser exit.
Session expiry (6.4) with the desktop present: the desktop repeats 7.2 C steps 2 and 3 for the same `device_id` (biometric, no Argon2); the server replaces the session.
Desktop absent (app not running, no socket, or peer verification failed): the extension cannot open `ext_ak`. It falls back to password unlock: Argon2id with `local_salt` opens `local_ak_pw` and `local_session_pw` (4.6, password-only class, UI says so); the session blob of 4.6 then carries the unlock across a worker eviction, and the password is never stored. Without those blobs it asks the user to start the desktop app or sign in with the kit (7.2 A). The fallback never weakens the desktop path and the desktop never learns the password.
Unpair or revoke: revoking the extension's session (6.4) or "unpair" on the desktop deletes `ext_key`; the extension's `ext_*` blobs are then undecryptable and it must pair again.

### 7.17 Dissolve a vault (owner)

Applies to shared vaults (`kind 2`) only; the Private vault goes with the account (7.13). Reauth is required.

1. Owner `O`'s client pulls and verifies to the head (5.6), shows the members who lose access, offers an export of the vault (7.14) or a copy of its items into another vault (5.7), and asks for typed confirmation of the vault name.
2. `O` signs the dissolve record (5.13) over its verified head `(rver, epoch, seq, manifest hash)`; `epoch` is not bumped.
3. `O` calls `vault_dissolve`. S checks the session is the owner's, the vault is `kind 2` and active, the signature matches the owner key of the latest stored roster, and `seq` and hash equal the head (else `409 stale_head`: `O` pulls, reviews the new commits, signs again). In one transaction S sets the vault state to `dissolved`, stores the record, deletes manifests, rosters, items, shares, self-wraps, attachments (and files), invites and `commit_log` rows of the vault, sets member rows to `dissolved`, and posts a `vault_dissolved` notice to each member. `O` removes the vault locally after step 1.
4. A member's `pull` returns the record for a vault whose member row is `dissolved`. The client verifies: signature by the owner key in its latest roster for that vault, `vault_id` matches, `rver`, `epoch` and `seq` are not below its stored marks (else `E_ROLLBACK`). On success the vault becomes read-only "dissolved" on that client: no sync, banner offering export or removal of the local copy.
5. A vault that merely disappears from a pull, without a valid record, is ordinary `not_member` handling (a notice, never a silent delete) and is indistinguishable from a removal; a server cannot forge a dissolve (E32).
Members keep everything they cached (A4); dissolve does not revoke what they saw.

### 7.18 Leave a vault (member)

Applies to an `editor` or `viewer`; the owner dissolves (7.17).

1. Member `M` confirms. `M`'s client signs a leave request (5.13) with its current `(rver, epoch)`.
2. `M` calls `leave_request`. S checks `M` is an active non-owner member and the signature matches the key in the stored roster. In one transaction S sets `M`'s member state to `leaving` and stores the request, deletes `M`'s shares and self-wraps for the vault, refuses further reads and writes of the vault by `M` (policy, 403 `not_member`), and posts a `member_leaving` notice to the owner. `M`'s client marks the vault "left, waiting for the owner", offers an export, and stops syncing it.
3. Owner `O`'s next pull returns the request. `O` verifies the signature with `M`'s key from `O`'s own roster and that `rver` and `epoch` equal `O`'s latest roster; a stale request is dropped. The notice alone is a display hint, not authority.
4. `O` runs the removal flow (7.8): roster `rver+1` without `M`, `epoch = e+1` and a new `vk_commit` (mandatory, 5.3), shares to the remaining members, re-wrapped items, one atomic commit. On that commit S sets `M` to `removed` and discards the request.
Until step 4 the vault is still at epoch `e` with `M` in the signed roster: `M` is cut off by server policy only, so a malicious server could still serve `M`; the UI tells the owner "rotate now". The owner's clients prompt at every unlock until done. If the owner never acts, cryptographic removal does not happen (12.4 item 9).

---

## 8. Versioning (R19)

- Every record carries `v`. A client built for max version N accepts `[min_accepted, N]`, where `min_accepted` is a compile-time constant plus the account's signed `min_v`.
- Greater `v`: refuse, tell the user to update. Lower than the accepted range: refuse (downgrade); only the standalone `hasp-migrate` tool reads old versions.
- A field named alg, suite, method or iterations in any server message is ignored; in a record it is `E_FORMAT`.
- Suite 2 (the only mechanism): complete spec and vectors; clients read both; per-account migration on a stateful device (new keyset under `v=2`, every owned vault re-encrypted into a `v=2` epoch with `prev` = last `v=1` hash, shares re-sent, `min_v = 2`); a vault migrates only when all members' clients support it (advertised by client version, not a record field); `max_seen_v` per account and vault; sunset date after which the main client stops reading `v=1`.
- The server may advertise a supported range; it never selects a format.

---

## 9. Server state and operations 

### 9.1 Tables

| Table | Key | Content | Written by |
|---|---|---|---|
| `server_secret` (file, not a table) | | `server_master` (6.1) | first start |
| `accounts` | account_id | login (opaque to the server, exact-bytes unique, 2.1), `notify_email` (optional, plaintext), `is_admin`, state (active, disabled; a deleted account is purged and status 2 exists only in its final account record, 5.1), `cred_gen`, created | sign-up, admin, change credential, delete |
| `account_records` | (account_id, seq) | signed account record | sign-up, KDF change, deletion |
| `opaque_records` | account_id | OPAQUE registration record for `acct`, `cred_gen` | sign-up, change, recovery, re-registration |
| `keysets` | account_id | `gen`, `ak_wrap`, `keys` | sign-up, change, recovery |
| `signup_tokens` | token hash | creator, target account (kind re-register only), expiry, used_by, kind (signup, rehost, re-register; the server stores rehost but refuses it as unsupported in v1) | admin, operator |
| `sessions` | session_id | account_id, `H(T)`, device_id (client-given), platform, label (Sealed, K_meta), created, last_seen, idle_expires, abs_expires, reauth_until | login, enrolment approve, recovery |
| `enrol_channels` | esid | account_id, creating session, expiry, state (open, approved, aborted), four write-once slots (request, offer, reveal, payload; 1 MiB each), write count (at most 16) | enrolment |
| `recovery_enrolments` | (account_id, rgen) | signed body, `rc_wrap`, `h_auth` | create RC |
| `recovery_sessions` | id | account_id, rgen, started, release_at, state (pending, released, aborted, done), source | recovery |
| `notices` | id | account_id, kind, created, payload (plain, display-only, unauthenticated); no delivered flag: `pull` takes a `notices_after` id cursor per device | server events |
| `vaults` | vault_id | kind, owner account_id, head `seq`, head hash, `rver`, `epoch`, state (active, dissolved), dissolve record (signed, once dissolved), created | commit, dissolve |
| `rosters` | (vault_id, rver) | signed roster | commit |
| `manifests` | (vault_id, seq) | signed manifest, author | commit, repair |
| `members` | (vault_id, account_id) | role (mirror of the roster, for routing and policy), state (invited, active, leaving, removed, dissolved), `rver`, leave request (signed, while leaving) | commit, leave, dissolve |
| `shares` | (vault_id, epoch, recipient) | signed share | commit |
| `self_wraps` | (account_id, vault_id, epoch) | Sealed self-wrap | share accept, rotation |
| `items` | (vault_id, item_id, ver, epoch) | wire bytes, tomb, `att_ids`, size bucket, commit seq, current flag; the 10 newest versions kept (an epoch-bump re-wrap is a new row with the same `ver` and a new epoch; the earlier row is not overwritten, so the wire an earlier manifest hashed survives while retained; pruning follows 5.6) | commit |
| `invites` | invite_id | vault, inviter, role, expiry, state, invitee account_id, accept blob | invite flow |
| `attachments` | att_id | vault_id, size, chunk count, state (uploading, complete), created | upload |
| `commit_log` | (vault_id, base_seq) | manifest hash (idempotence) | commit |

Server-side backup = DB + `server.key` + attachment files. Pins and devices are Private-vault items, not tables.

### 9.2 Operations (names are logical)

| Operation | Auth | Tables |
|---|---|---|
| `prelogin`, `recover_prelogin` | none | accounts, opaque_records, recovery_enrolments (HMAC fake path) |
| `register` (OPAQUE 1) | signup token | all of 7.1 atomically |
| `login`, `reauth` (KE1-KE3) | none / session | opaque_records, sessions |
| `account_get`, `account_lookup(login)` | session | account_records, keysets |
| `change_credential` | reauth | opaque_records, keysets, account_records, sessions |
| `session_list`, `session_revoke` | session | sessions |
| `enrol_open`, `enrol_approve` | session | enrol_channels, sessions |
| `enrol_msg` | esid | enrol_channels |
| `enrol_abort` | esid (rate limited per esid) | enrol_channels |
| `rc_set` | reauth | recovery_enrolments, account_records |
| `recover_start`, `recover_abort` | `K_rc_auth` (`recover_abort` also by a session: `recovery_id` and `k_rc_auth` both null) | recovery_sessions, notices |
| `recover_fetch` | released recovery session (mints the recovery-session token) | keysets, recovery_enrolments, recovery_sessions |
| `recover_register_start`, `recover_complete` (body field 0 `recovery_id`) | recovery-session token | opaque_records, keysets, recovery_enrolments, sessions |
| `reregister_start`, `reregister_finish` | re-register token (kind 3, bound to its target account) | signup_tokens, opaque_records, accounts, sessions |
| `pull` (cursors: per-vault `seq`, `notices_after`) | session | manifests, rosters, items, shares, self_wraps, notices; dissolve record of a dissolved vault |
| `commit` | session | all vault tables atomically (item ops as byte strings, 3.1; the author's self-wraps ride along) |
| `repair_publish` | session (active owner, author of the repair) | manifests, items, commit_log, vaults, attachments (references) atomically |
| `self_wrap_put` | session (active member; epoch not above the vault epoch) | self_wraps |
| `invite_create`, `invite_get`, `invite_accept`, `invite_decline` | session | invites, members |
| `invite_list` (owner only; returns the invitee's account record and the accept blob, so the owner can add the member; `invite_get` returns the inviter's record) | session | invites, accounts, account_records |
| `leave_request` | session (member) | members, shares, self_wraps, notices |
| `vault_dissolve` | reauth (owner) | vaults, members, rosters, manifests, items, shares, self_wraps, invites, attachments (+ files), commit_log, notices |
| `attachment_put`, `attachment_get`, `attachment_complete` | session | attachments (+ files) |
| `account_delete` | reauth (refused while the account owns or actively belongs to a shared vault, 7.13) | all account rows |
| `admin_*` (disable, delete, tokens, list) | session + `is_admin` | accounts, signup_tokens |
| `health` | none | |
| `server_key` | none | (returns the server's long-term OPAQUE public key and its origin; public material) |

Flow to records: sign-up (accounts, account_records, opaque_records, keysets, vaults, rosters, manifests, items, self_wraps, sessions); sign-in A (prelogin, login, keysets, account_records, pull); sign-in B (enrol_channels, sessions); recovery (recovery_enrolments, recovery_sessions, notices); invite (invites, members, shares, rosters, manifests); removal (rosters, shares, items, self_wraps, manifests, members); leave (members, shares, self_wraps, notices, then removal); dissolve (vaults and every vault table); extension pairing (enrol_channels, sessions); attachments (attachments, items.att_ids).

### 9.3 Who enforces what

| Control | Cryptographic (client verifies) | Server policy |
|---|---|---|
| Roles, membership | roster signature, manifest author role | role check on commit; roster member keys equal the member's latest account record; a new member needs an accepted invite with the same role |
| Commit validity | the whole of 5.6 | `commit` runs the proto verifier (`verify_genesis`, `verify_batch`) on every commit against the leaf set rebuilt from stored rows (signatures, chain, roster rules, leaf-set root); availability, not trust |
| Epoch | `E_EPOCH`, leaf epochs, epoch +1 on any removal | reject stale epoch writes |
| Dissolve, leave | owner-signed dissolve record, member-signed leave request, owner-signed removal roster | deletes data, stops serving a leaving member |
| KDF floor | allow-list | none needed |
| Attachments | AEAD, `size`, `att_ids` in `h_item` | chunk and total limits, ordered idempotent writes, 24 h sweep (5.7) |
| Delays, rate limits, session expiry, quotas | none | server |
| Notices | none (display-only hints) | server |
| Export, reveal | none | none (client-only; viewers may export) |

---

## 10. Attack mapping

S = defeated by the mechanism; S* = defeated under the stated condition; R = residual (section 12).

### 10.1 ETH attacks

| Id | Mechanism | Result |
|---|---|---|
| BW01, LP01 Malicious auto-enrolment, password reset | No escrow, no admin keys fetched, no auto-enrolment; family recovery is a member-made shared item (7.12) | S for protocol mechanisms; R: an organizer who reads the RC item can recover the account after the delay |
| BW02 Malicious key rotation | v1 has no key rotation; wrap targets for removal or bump come from the owner's own signed roster, not pins or the server (5.10, 7.8) | S |
| BW03 Key Connector | feature absent | S (absent) |
| 1P01 Recovery group | no per-vault recovery wrap | S |
| BW04, LP06 Unprotected item metadata | types, times, names inside AEAD; ids, `ver`, `epoch`, sizes in AAD or leaf | S for content metadata; R: ids, sizes, membership, author per commit, roles, counts, write times (12.3) |
| BW05, LP02 Field swapping | per-field keys, AAD binds vault, item, field, ver | S |
| BW06, LP03 Icon URL decryption | as BW05; no network request from decrypted fields; no icon service | S |
| BW07, LP04, 1P04, DL04 Remove KDF iterations | floors in client; params in signed record, AAD, 2SKD salt; rejected before derivation | S |
| DL06 Lucky 64 | no no-derivation mode; Argon2id mandatory | S |
| LP05 Malleable vault | AEAD, signed manifest over leaf hashes | S |
| DL01 Transaction replay | per-version leaf in a signed hash-chained manifest; stale roster signer rejected (H1) | S* stateful or confirmed clients; R for an unconfirmed stateless device (up to rollback) |
| 1P02 Item dropping/duplication | `root` over the full current leaf set in the signed manifest | S* up to rollback for unconfirmed devices |
| 1P03 Vault injection | roster owner-signed; own wraps symmetric; share must match `vk_commit` | S |
| BW08 Organisation injection | membership only via owner-signed roster plus verified share | S |
| BW09, LP07, DL02, 1P05 Sharing key overwrite | invite carries `fp(owner)`; share from another key refused (H3); roster own-key check; pins | S* invitee side always; inviter side only if `fp(invitee)` was checked, else R (pin `tofu`) |
| 1P06 Vault substitution | symmetric self-wrap; shared key must match `vk_commit` | S |
| BW10, BW11, BW12, DL03, DL05 Downgrades, CBC, injection | one suite, no legacy parser, signed `min_v` | S |

Gadgets BWb1, DLb1, DLb2 (CBC oracles) are inapplicable: no CBC, one AEAD error.

### 10.2 White paper limitations

| Limitation | Mechanism | Result |
|---|---|---|
| A.1 Web client / HTTPS | no web vault; signed releases; reproducible builds for server image, CLI, extension (apps best effort) | R: store and OS update channels (12.4) |
| A.2 Recovery Group | none; RC; optional family item | R: 7.12 trade-offs |
| A.3 Public key verification | self-signed records, pins, invite fp, own-key check, KEY_CHANGED | S* as BW09 row |
| A.4 Limited re-encryption | epoch bump and re-wrap on removal | S for future data; removed member keeps what it saw |
| A.5 Password change keeps keysets | documented semantics, compromise response (7.4); full key rotation is deferred | R until v1.5: a compromised AK is not rotatable |
| A.6 Secondary accounts | absent | S (absent) |
| A.7 Policy enforcement | 9.3 table | S as documentation; client-only controls (export) stay client-only |
| A.8 Malicious client | out of scope | R |
| A.9 Server data | minimised metadata; 2SKD | S/R |
| A.10 Malicious processes; SK at rest | SK gated by hardware where present; no plaintext second factor; password-only platforms labelled | S* hardware platforms (iOS, macOS with Enclave, Android, Hello+TPM); R on Linux, extension-only, DPAPI-only; memory scraping out of scope |
| A.11 Who is registered | uniform prelogin from the real distribution, fake OPAQUE, uniform errors | S; R: registration is an oracle (token, rate limit) |
| A.12 Email | email is not a trust anchor; `notify_email` optional notice only | S |
| Transport replay | no request MAC (deferred); writes signed and `base_seq`-bound | R: rogue-CA MITM can steal a bearer token (G10) |
| Cert pinning | OPAQUE server key pin | S* after first contact; R first contact (kit `sf` or QR `sf` closes it) |
| Email invitation | invite code holds `fp(owner)`; share is signed | S* as BW09 |
| Emergency Kit loss | RC; otherwise unrecoverable | R accepted |
| Server sees usage | not hidden | R (12.3) |

---

## 11. Test plan

### 11.1 Vectors (shared by every binding)

| Group | Source |
|---|---|
| Argon2id | RFC 9106 KATs; project KATs for `S_kdf, K_pw, AUK, OPK` incl. NFKD edge inputs |
| HKDF, HMAC, SHA-256, Ed25519 (strict), ChaCha20-Poly1305, XChaCha | RFCs, libsodium, Wycheproof-style non-canonical and small-order cases |
| X-Wing, HPKE | draft -11 vectors; RFC 9180 Appendix A pipeline check; project share vector; invalid-ek vector; HPKE `DeriveKeyPair` never called |
| OPAQUE | RFC 9807 Appendix C (real and fake), Identity KSF; project vectors for the context and `credential_identifier` |
| CBOR | RFC 8949 Appendix A; non-canonical corpus (long ints, unsorted or duplicate keys, indefinite lengths, floats, tags, trailing bytes, unknown keys, ints above 2^53-1) |
| SK/RC | fixed RNG, checksum, parse failures |
| Records | one canonical vector per record and Sealed use from the Rust reference, replayed by every binding (Swift, Kotlin, TypeScript) |
| Leaf set | roots for 0, 1, 2, 3, 7, 1000 leaves, order by raw `item_id` |
| Attachments | 0, 1, 1 MiB-1, 1 MiB, 1 MiB+1 bytes, 3 chunks; truncate, reorder, extend must fail |
| Export | round trip, wrong passphrase, truncation, mode 2 |
| Labels | every Appendix A label has a vector; label uniqueness test |

A differential check of the CBOR decoder against a second implementation (Python `cbor2` canonical check) runs in CI.

### 11.2 Property tests

Encode/decode round trip; every mutation of a canonical encoding fails; AAD injectivity; bit-flip fails closed; key independence; state-machine model (honest server, random create, edit, delete, invite, remove, bump, revoke with N clients: convergence, root equals leaf set, epoch monotonic, no removed member decrypts post-removal data, whole-item LWW); rollback and equivocation invariants.

### 11.3 Malicious-server harness

An in-process adversarial server with scriptable policy (drop, duplicate, reorder, replay, substitute, fork per client, roll back, delay, edit headers, serve alternate keys per requester, old keysets, alter pre-auth hints, equivocate on server key) running the real clients. Negative control by mutation testing: `cargo-mutants` runs on the verifier modules and every removed check MUST fail a harness test (no insecure-* cargo features in production crates).

| Scenario | Classes | Action | Expected |
|---|---|---|---|
| E1 key substitution on share | LP07, DL02, 1P05, BW09 | attacker keys for invitee at invite time; for owner at accept time | invitee: `E_INVITE`/`E_PIN`; roster own-key mismatch `E_ROSTER`; inviter side without `fp` check: pin stays `tofu` |
| E2 vault key substitution | 1P06, 1P03 | swap self-wrap or share `ct` | `E_AEAD` or `E_ROSTER` |
| E3 escrow injection | BW01, BW03, LP01, 1P01 | add recovery or admin keys | none produced; unsigned enrolment rejected |
| E4 wrap target swap | BW02 | substitute KEM keys during removal or bump | targets only from own roster; pin rollback does not matter (E26) |
| E5 field/item swap | BW05, BW06, LP02, LP03 | swap Sealed values | `E_AEAD`, no network call |
| E6 metadata tamper | BW04, LP06 | change `ver`, `epoch`, flags | `E_AEAD` or `E_ROOT` |
| E7 set manipulation | 1P02, DL01 | drop, duplicate, reorder, replay commits | `E_ROOT`/`E_ROLLBACK` |
| E8 fork | 1P02 family | different heads per client | `E_FORK` on contact |
| E9 KDF downgrade | BW07 family | prelogin m=8 MiB t=1; lower params in record | `E_KDF_PARAMS`, no Argon2 |
| E10 suite downgrade | BW10-12, DL03, DL05 | `v=0`, `v=2`, `alg` fields, CBC blobs | `E_VERSION`/`E_FORMAT` |
| E11 malleability | LP05 | flip every byte of every blob | fails closed |
| E12 injection | BW08, BW09, 1P03 | foreign vault or member; old roster | `E_SIG`/`E_ROSTER`/`E_ROLLBACK` |
| E13 transport | G10 | rogue-CA MITM steals a token | reads ciphertext only; every forged write rejected by signature |
| E14 enumeration | A.11 | known vs unknown login, including non-floor parameters and `cred_gen>1` | indistinguishable shape, values, timing |
| E15 enrolment | A6 | relay substitutes B, replays `esid`, wrong code, stolen QR | MAC or commitment failure, attempt limit, abort |
| E16 revoked session | | revoked token writes | rejected |
| E17 recovery | A.2 | forge `rc_wrap`, stale `rgen`, skip delay, abort via sign-in | `E_AEAD`/`E_ROLLBACK`; delay enforced |
| E18 attachments | 5.7 | truncate, reorder, splice, other file under same `att_id` | AEAD failure, nothing written |
| E19 server identity | | other OPAQUE key after pin | `E_SERVER_KEY` |
| E20 stale restore | | backup older than device head | explicit acknowledge |
| E21 stale roster signer | H1 | removed writer signs a commit with the old `rver` and copied epoch | `E_ROSTER` when it extends the head; `E_ROLLBACK` when it lands at a seq at or below the head |
| E22 bad-root writer | M5 | editor signs a commit whose root mismatches | quarantine with author; owner repair applies only after confirmation |
| E23 stateless rollback | H2 | pre-removal state to an unconfirmed device, with and without head code | shared writes blocked; code mismatch detected |
| E24 SAS grinding | M1 | relay knowing `e` grinds keys | commitment prevents; success rate 10^-6 per attempt |
| E25 resume with changed source | M2 | modify file mid-upload | restart with fresh keys, never reuse |
| E26 pin rollback | M4 | serve empty or old pins during removal | wraps still go to roster keys |
| E27 wrong invite fp | H3 | share from another key | `E_INVITE` |
| E28 low-epoch leaf | M7 | leaf epoch below manifest epoch | `E_EPOCH` |
| E29 session authority | 6.4 | session attempts a reauth-only action | refused |
| E30 invalid ek | 2.3 | encapsulate to a bad ML-KEM key | rejected |
| E31 removal without bump | 5.3, 7.18 | owner roster removes a member at the same epoch | `E_EPOCH`, quarantine |
| E32 forged dissolve or leave | 7.17, 7.18 | server fabricates a dissolve record, a stale or foreign leave request, or serves an older dissolve | `E_SIG`/`E_ROLLBACK`; vault kept; request ignored |
| E33 extension channel | 7.2 C | same-user process execs the host; spoofed browser; unknown extension id; replay of `unlock` after revoke | peer verification fails, no prompt; no `K_ext` released |

ETH proof-of-concept scripts (doi 10.5281/zenodo.17977565) were not fetchable **[unverified reusability]**; scenarios are written from the paper's descriptions.

### 11.4 Fuzzing and gates

Fuzz targets (bolero): the strict CBOR decoder and one generic record-verify target (batch verifier with arbitrary commit sequences), plus SK/RC parser, OPAQUE message decoders, share open, attachment reader. CI: 5 minutes per target per pull request, 1 hour nightly.
Release gates: independent cryptographic review of sections 4-6 and the share, removal and enrolment flows; X-Wing and OPAQUE vectors blocking; `cargo-deny` clean; harness mutation run green.

---

## 12. Residual risks and open questions

### 12.1 Residual risks (stated to users)

1. First contact: the inviter side of an invite is verified only if the owner checks `fp(invitee)`; otherwise a fabricating server can obtain that vault's key. The pin shows `tofu`.
2. Stateless rollback: Path A and recovery devices read possibly stale state until confirmed (7.3); a single-device user without members cannot confirm.
3. Equivocation across users: a server that forks two members' views is detected only when they compare head codes. Key transparency is future work.
4. Compromised member or client: not bounded.
5. Quantum: Ed25519 and OPAQUE are classical.
6. Kit plus password theft, or RC alone, equals total loss. A compromised AK cannot be rotated until v1.5.
7. Extension channel: authentication is OS-level, not cryptographic; a process that passes it still needs the biometric approval, and a compromised browser holds AK while the extension is unlocked (1.2). Leave and removal: the owner's roster is the only cryptographic removal (7.18).
8. Family recovery trade-offs (7.12).
9. Account enumeration (6.3): a login whose account uses non-default KDF parameters or `cred_gen` above 3 is distinguishable from a non-existent login by prelogin.
10. Stateless devices and devices in the retention fallback verify the leaf-set root at the head only (5.6).
11. First sync of a device after pruning shows no older versions of an item (5.7). Session token theft by a rogue-CA MITM (G10). Revoking a session does not stop a device that holds the password and Secret Key.

### 12.2 Reserved for v1.5

Identity-key rotation (`rot`, keyset `gen`, roster key replacement with owner acceptance and a signed member-key-update record), ownership transfer, per-request MAC, server TOTP 2FA, S3.

### 12.3 Metadata visible to the server

Login id, `notify_email`, account ids, session and device ids, platforms, IPs, vault ids and membership graph, public keys, roles, item ids, versions, epochs, `att_ids` per item version, commit authors and times, bucketed sizes, number of items per vault, session activity, conflict timing (inferable). Hidden: names, URLs, types, tags, favourites, client timestamps, session labels, vault names, pins, device labels. The server cannot prove deleted data is gone from backups.

### 12.4 Open questions

1. Resolved in v2.2: X-Wing -11 and hpke-pq vectors pass on `x-wing` 0.1.1 and `hpke` 0.15.1.
2. Resolved in v2.2: `opaque-ke` 4.0.1 replays RFC 9807 Appendix C.1.1 and C.1.2; the move to 5.0 waits for a stable release.
3. Identity KSF acceptability (6.1).
4. XChaCha20-Poly1305 standards status.
5. Unicode normalisation consistency across platforms.
6. Ordering of an owner's removal against a member's concurrent actions needs a model-checked spec.
7. Gossip of head codes through shared items.
8. Formal model (Tamarin or ProVerif) of enrolment and sharing is not written.
9. Owner as single point of loss for membership until transfer exists (v1.5).
10. Supply chain: store and OS update channels can ship a malicious client; mitigation is signed releases, reproducible builds (server image, CLI, extension), published hashes; not a protocol property.
11. Deferred to M2: the browser extension's password-only fallback after pairing (7.2 C step 5, `local_ak_pw`); M1 ships the `K_ext` unlock only.
12. Deferred to M2/M3: attachment upload staging on disk (5.7); M1 stages in memory.

---

## Appendix A. Labels (exact strings; each used once)

`X(k, name, ...)` names (string `hasp/v1/<name>`): `argon-salt`, `2skd`, `auk`, `opaque-input`, `keyset-seal`, `self-wrap`, `account-meta`, `item-wrap`, `field`, `att-chunk`, `vk-commit`, `rc-prk`, `rc-wrap`, `rc-auth`, `session-token`, `enrol-mac`, `enrol-key`, `enrol-code`, `enrol-commit`, `fp`, `sk-check`, `head-code`, `leafset`, `pin-id`, `export-key`, `export-kcv`, `srv/oprf`, `srv/ake`, `srv/prelogin`.
HPKE: `hasp/v1/share`, `hasp/v1/share-aad`.
Signature (`label || 0x00 || body`): `hasp/v1/sig/account`, `hasp/v1/sig/roster`, `hasp/v1/sig/manifest`, `hasp/v1/sig/share`, `hasp/v1/sig/recovery`, `hasp/v1/sig/dissolve`, `hasp/v1/sig/leave`.
Device-local AAD that is not a derivation label: `hasp/v1/local/recovery-ticket` (4.6).
A new key purpose requires a new label; labels are never reused across record types. `hasp/v1/login-id` is not a label (normalisation has no key).

## Appendix B. Changelog (v1 to v2.7)

Rulings applied: 1 H1 binding (5.6); 2 H2 marks and head confirmation (7.2 B, 7.3); 3 H3 invite fp (5.12, 7.7); 4 organizer 2-of-2 removed, family recovery via shared item (7.12); 5 recovery delay kept, notices through sync, SMTP optional (7.11); 6 commit-reveal (7.2 B), fresh attachment keys (5.7), QR in-app only (4.4), pins in the Private manifest (5.10), repair (5.6), no gate bypass (4.6), uniform prelogin (6.3); 7 per-device OPAQUE cut, sessions as device list (5.11, 6.4); 8 flat leaf-set hash (5.5); 9 request MAC deferred (6.4); 10 HPKE kept (2.1); 11 roles owner/editor/viewer (5.3, 5.4); 12 key rotation deferred (7.4, 12.2); 13 mapping rows fixed (10).
Removed: organizer recovery, `orgrel`, `s_S`, `org_wrap`, device records, device OPAQUE credentials, `DCS`, request and response MAC and counters, `Idempotency-Key`, Merkle tree, history leaves, pin-store record and key, vault record (folded into the roster), `xfer`, `rot` cross-signature, account `label`, `suite`, `sup`, `org_rec`, manifest `count` and `ts`, Key rotation flow, organizer rtypes, three unused labels, all Reviewer notes that were resolved.
Added: export envelope, `oprf_seed` storage and backup, rehost, server-secret loss flow, wedged-vault repair, head confirmation UX, invite code, enrolment commit-reveal and approval by D1, QR snapshot, session authority matrix, server tables and operations, who-enforces-what table, whole-item LWW rule, compromise response without rotation, honest family recovery trade-offs, platform key-storage table, per-device KDF ceiling, attachment last-chunk rule, leaf epoch rule, one fingerprint definition, exact label table, tests E21-E30.

v2.1: extension pairing and desktop unlock (7.2 C, 7.16, 4.6, rtype 11 fields 6 to 8, E33); vault dissolve and member leave (5.13, 7.17, 7.18, rtypes 15 and 16, labels `sig/dissolve` and `sig/leave`, `vault_dissolve` and `leave_request`, table states, E31 and E32); removal now requires an epoch bump in the verifier (5.3, 5.6 step 3); fixes: label `rc-prk` split from `rc-wrap`, epoch-bump reference 6.4 now 7.8, "pin-store" wording in E4, residual risk renumbered.

v2.2: label prefix `vault/v1/` renamed `hasp/v1/` (Appendix A, all uses); M0 spec decisions folded in: Secret Key and Recovery Code check tag and symbol encoding (4.3), Crockford base32 for fingerprints and invite codes (4.5, 5.12), account-record seq rule (5.1), roster immutability and epoch rules (5.3), rollback versus fork choices and the epoch-bump re-wrap rule (5.6 steps 1, 5), bundled-share checks (5.6), tombstone `att_ids` (5.7), share open error mapping (5.8), dissolve and leave error mapping (5.13), text and record limit scope (3.1), OPAQUE server setup derivation (6.1), HMAC algorithms for OTP (2.1); vectors marked verified (2.2, 2.3, 12.4).

v2.3: M0 rulings C1 and C3 folded in: CBOR nesting scope and transport limit (3.1); login id opaque on the server (2.1); stateless replay and retention rule, flagged for the phase F crypto review (5.6); payload codec in `hasp-proto` with fixed key numbers (5.7); attachment limits (5.7, 9.3); OPAQUE context fields (6.1); session token derivation (6.4); enrolment slots and `enrol_abort` (7.2, 9.1, 9.2); current-version re-wrap at an epoch bump and `self_wrap_put` (7.8, 9.2); recovery-session token and `recover_register_start` (7.11, 9.2); account-deletion refusal (7.13); export header `kcv`, mode-2 `kdf`, attachment record `mime` and `offset`, KDF bounds = suite ceiling (7.14); `items` keyed with epoch, notices cursor instead of a delivered flag (9.1); `invite_list` and server-side proto verification (9.2, 9.3). Known M0 limitation: import plaintext held in serde values is not zeroised until the batch is built (7.14).

v2.4: M0 C2 items folded in: payload key numbers and limits (notes 256 KiB, concealed values and history 64 KiB, 5.7); export kcv placement (header key 7, outside `H(header)`, 7.14); enrolment request MAC over the whole body (7.2 B); pre-auth `server_key` operation and the kit or QR `sf` check before OPAQUE login (7.2 A, B, 9.2); `repair_publish` operation, member confirmation and quarantine retry (5.6, 7.15, 9.2); rehost as a replay of the verified copy into a new account, with shared vaults re-invited (7.14); E21 outcome by path; deferred items listed in 12.4 (extension password-only fallback, attachment staging on disk).

v2.5: text rules fixed (2.1): trim set is `White_Space` (U+0085 trimmed, U+200B and U+FEFF not); login id uses full `toNFKC_Casefold` instead of lowercase; unassigned code points rejected in login ids only; Unicode 18.0.0 pinned in the Rust core, platform libraries never normalise.

v2.6: phase F review fixes folded in: page handling decided by seq and hash with staging, stored-head root check, no fallback to the weak replay except provable retention pruning, per-op epoch check in chain replay (5.6); invitee role from the owner (7.7); `prev_h` in the item wire (key 11) and authenticated history (5.7, 7.14); short text values are CBOR text strings, long and secret ones byte strings (5.7); `export-kcv` label and key-check value from its own derived key (7.14, Appendix A); unverified pins loaded while a device is unconfirmed (5.10); account record and keyset re-fetch with rollback checks (5.1, 5.2); revoked device erases local data (7.13); pseudo-record from the HMAC alone with floor parameters (6.3, 12.1); `recover_abort` authenticated by `K_rc_auth` or a session (9.2); unknown manifest author is `E_AUTHZ`; padding, `kem_pk_hash`, `K_pre`, `enrol_msg` and `enrol_abort` and deleted-account text aligned with the code (3.4, 5.8, 6.3, 7.2, 9.1).

v2.7: M1 integration rulings folded in: Emergency Kit rendering and regeneration (4.4); persistable recovery ticket and resume, `recovery_id` in the bodies of `recover_register_start` and `recover_complete`, test-mode delay only in a `testing` build (4.6, 7.11, 9.2); re-registration after server-secret loss made concrete, token `target`, ops `reregister_start` and `reregister_finish` (OpIds 47 and 48), sessions revoked (7.14, 9.1, 9.2). Transport: bodies are CBOR, path ids are aliases, `POST` plus `X-HTTP-Method-Override`.

v2.8: M1 security review folded in: server snapshots exclude `server.key` by default and restore is staged, verified against the snapshot content and revokes sessions (7.14); client behaviour after a server restore, including the fork case of a second device (7.14); sign-up and sign-in compare the server fingerprint before any registration or login (7.2, CLI input by `--server-fingerprint` or prompt); plain HTTP only for loopback IP literals, never by host name (transport).

v2.9: M2 integration: ES256 in the suite table for passkeys (2.1, 2.2); session key for the standalone extension, password never stored (4.6, 7.16); passkey algorithm and counter note (5.7).
v2.9 (M2 security): `unlock` carries a 16-byte `nonce`; the unlock and pairing prompts show a six-digit code the extension shows too (7.2 C, 7.16, E33); `page_reply` carries `focused`.
v2.9 (M3 design note, no wire or record change): the AutoFill extension unlocks with the device key only (`unlock_provider`: DUK opens `ak_bio`, no Argon2, no server call, no pin refresh). Two device-local notes, sealed like every local note under a key derived from AK, are not synced and not part of any record: `provider-index` (metadata of each live item with the leaf stamp `ver.epoch.h_item[..8]` it was built from; no password, OTP seed or passkey private key) and `identity-snapshot` (hash of each identity last handed to the system store). A client that holds a newer leaf than the index entry re-opens that one item. Passkeys created through an OS credential provider receive `clientDataHash` instead of `clientDataJSON` and sign `authenticatorData || clientDataHash`; flags, counter 0 and attestation `none` are those of 5.7. CXF 1.0 import maps to the existing item payload (5.7) and needs no new field.

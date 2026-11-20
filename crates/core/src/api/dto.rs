use zeroize::Zeroize;

pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn take(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        hasp_crypto::ct_eq(&self.0, &other.0)
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

pub trait Mirror<T> {
    fn mirror(self) -> T;
}

macro_rules! scalar_mirror {
    ($($t:ty),*) => {
        $(impl Mirror<$t> for $t {
            fn mirror(self) -> $t {
                self
            }
        })*
    };
}

scalar_mirror!(String, bool, u8, i32, u32, u64, f64);

impl<T: Mirror<U>, U> Mirror<Vec<U>> for Vec<T> {
    fn mirror(self) -> Vec<U> {
        self.into_iter().map(Mirror::mirror).collect()
    }
}

impl<T: Mirror<U>, U> Mirror<Option<U>> for Option<T> {
    fn mirror(self) -> Option<U> {
        self.map(Mirror::mirror)
    }
}

#[macro_export]
macro_rules! with_api_types {
    ($callback:path, $context:tt) => {
        $callback! { $context
            enum LockState { Empty, Locked, Unlocked }
            enum UnlockMode { Hardware, PasswordOnly, Extension }
            struct AccountStatus {
                state: LockState,
                login: Option<String>,
                origin: Option<String>,
                unlock_mode: Option<UnlockMode>,
                biometric_ready: bool,
                retry_after: u64,
                device_confirmed: bool,
                fingerprint: Option<String>,
                password_required: bool,
            }
            struct KitPreview {
                origin: String,
                login: String,
                server_fingerprint: String,
            }
            struct SignInRequest {
                origin: String,
                login: String,
                secret_key: Secret,
                password: Secret,
                server_fingerprint: String,
            }
            struct SignUpRequest {
                origin: String,
                login: String,
                code: Secret,
                password: Secret,
                server_fingerprint: String,
            }
            struct SignUpKit {
                origin: String,
                login: String,
                server_fingerprint: String,
                secret_key: Secret,
                qr_blob: Secret,
                qr_text: Secret,
                document_text: Secret,
                document_pdf: Secret,
            }
            struct PasswordSession {
                session_blob: Secret,
            }
            struct VaultInfo {
                id: String,
                name: String,
                kind: String,
                role: String,
                confirmed: bool,
                quarantined: bool,
                repair_pending: bool,
                members: u32,
                writable: bool,
            }
            enum ItemStatus { Active, Archived, Trashed }
            struct ItemRow {
                vault: String,
                id: String,
                kind: String,
                title: String,
                subtitle: String,
                hosts: Vec<String>,
                tags: Vec<String>,
                favourite: bool,
                status: ItemStatus,
                has_totp: bool,
                has_passkey: bool,
                has_attachments: bool,
                modified: u64,
                created: u64,
                expires_at: Option<u64>,
                pending: bool,
                version: u64,
            }
            struct SearchQuery {
                text: String,
                vault: Option<String>,
                kind: Option<String>,
                tag: Option<String>,
                favourites_only: bool,
                status: Option<ItemStatus>,
                boost_url: Option<String>,
                limit: u32,
            }
            struct FieldView {
                id: String,
                label: String,
                kind: String,
                purpose: Option<String>,
                concealed: bool,
                value: Option<String>,
                expires_alert: bool,
            }
            struct SectionView {
                id: String,
                title: String,
                fields: Vec<FieldView>,
            }
            struct UrlView {
                id: String,
                url: String,
                mode: String,
                kind: String,
                confirmed_hosts: Vec<String>,
            }
            struct AttachmentView {
                id: String,
                name: String,
                mime: String,
                size: u64,
            }
            struct ItemDetail {
                row: ItemRow,
                sections: Vec<SectionView>,
                notes: Option<String>,
                urls: Vec<UrlView>,
                attachments: Vec<AttachmentView>,
                passkeys: u32,
                password_history: u32,
            }
            struct FieldDraft {
                id: Option<String>,
                label: String,
                kind: String,
                purpose: Option<String>,
                concealed: bool,
                expires_alert: bool,
                value: Secret,
                keep_value: bool,
            }
            struct SectionDraft {
                id: Option<String>,
                title: String,
                fields: Vec<FieldDraft>,
            }
            struct UrlDraft {
                id: Option<String>,
                url: String,
                mode: String,
                kind: String,
            }
            struct ItemDraft {
                kind: String,
                title: String,
                subtitle: String,
                tags: Vec<String>,
                favourite: bool,
                notes: Option<String>,
                expires_at: Option<u64>,
                sections: Vec<SectionDraft>,
                urls: Vec<UrlDraft>,
            }
            struct Category {
                id: String,
                name_en: String,
                name_ko: String,
                icon: String,
                autofill: String,
            }
            struct HistoryRow {
                version: u64,
                epoch: u64,
                title: String,
                modified: u64,
            }
            struct TotpCode {
                code: Secret,
                remaining: u32,
                period: u32,
                digits: u32,
            }
            struct ExtensionRelease {
                key: Secret,
                valid_until: u64,
            }
            struct AttachmentUpload {
                name: String,
                mime: String,
                data: Secret,
            }
            struct SyncSummary {
                vaults: u32,
                changed: u32,
                needs_attention: u32,
            }
            enum GeneratorKind { Random, Memorable, Pin, KoreanSafe }
            enum Strength { VeryWeak, Weak, Fair, Strong, VeryStrong }
            struct GeneratorRequest {
                kind: GeneratorKind,
                length: u32,
                lower: bool,
                upper: bool,
                digits: bool,
                symbols: Option<String>,
                exclude_ambiguous: bool,
                words: u32,
                separator: String,
                capitalize: bool,
                append_digit: bool,
                origin: Option<String>,
                site_rules: Option<String>,
                field_min_length: Option<u32>,
                field_max_length: Option<u32>,
            }
            struct GeneratedPassword {
                value: Secret,
                bits: f64,
                strength: Strength,
                length: u32,
                site_rules_applied: bool,
            }
            enum MatchTier { Exact, Domain, Related }
            enum FillPolicy { Never, ConfirmFirst, OneClick }
            struct FrameContext {
                top_frame: bool,
                cross_origin_frame: bool,
                sandboxed: bool,
                obscured: bool,
                visibility_check_supported: bool,
            }
            struct AutofillQuery {
                page_url: String,
                origin: String,
                frame: FrameContext,
            }
            struct Candidate {
                vault: String,
                item: String,
                title: String,
                subtitle: String,
                tier: MatchTier,
                fill: FillPolicy,
                host_to_confirm: Option<String>,
                has_totp: bool,
                has_passkey: bool,
                favourite: bool,
            }
            struct SiteQuirks {
                append_2fa: bool,
                no_autosubmit: bool,
                per_char_events: bool,
                skip_save: bool,
                iframe_login: bool,
            }
            struct AutofillResult {
                candidates: Vec<Candidate>,
                refusal: Option<String>,
                quirks: SiteQuirks,
                password_rules: Option<String>,
                change_password_url: Option<String>,
            }
            enum FillKind { Login, Otp, Card, Identity }
            enum StepUp {
                Allow,
                InlineConfirmHost,
                ConfirmPerHost,
                BrowserUi,
            }
            struct FillRequest {
                vault: String,
                item: String,
                origin: String,
                page_url: String,
                kind: FillKind,
                frame: FrameContext,
                approved: bool,
                remember_host: bool,
                in_iframe_click: bool,
            }
            struct FillSlot {
                purpose: String,
                label: String,
                needs_click: bool,
            }
            struct FillPlan {
                step_up: StepUp,
                host: Option<String>,
                tier: MatchTier,
                slots: Vec<FillSlot>,
                quirks: SiteQuirks,
            }
            struct FillValue {
                purpose: String,
                label: String,
                value: Secret,
            }
            struct FillPayload {
                values: Vec<FillValue>,
                otp_wait_seconds: u32,
                autosubmit_allowed: bool,
            }
            enum SaveKind { New, Update, Identical, Suppressed }
            struct SaveDraft {
                origin: String,
                page_url: String,
                username: String,
                password: Secret,
                generated: bool,
            }
            struct SaveProposal {
                kind: SaveKind,
                vault: Option<String>,
                item: Option<String>,
                suggested_title: String,
                username: String,
                reason: Option<String>,
            }
            struct SaveCommit {
                draft: SaveDraft,
                kind: SaveKind,
                vault: String,
                item: Option<String>,
                title: String,
            }
            struct ItemRef {
                vault: String,
                item: String,
            }
            struct SecretTag {
                word: String,
                glyph: u32,
            }
            struct LockPolicy {
                idle_minutes: u32,
                lock_on_sleep: bool,
                lock_on_screen_lock: bool,
                lock_on_user_switch: bool,
                lock_on_quit: bool,
                background_seconds: u32,
                password_every_days: u32,
                clipboard_clear_seconds: u32,
            }
            struct Settings {
                lock: LockPolicy,
                secret_tag: Option<SecretTag>,
                language: String,
                inline_menu: bool,
                auto_submit: bool,
                ask_before_filling: bool,
                hardened_mode: bool,
                copy_totp_after_fill: bool,
                breach_check: bool,
            }
            enum LockTrigger { Sleep, ScreenLock, UserSwitch, Idle, Quit, Background, Manual }
            enum EventKind {
                Locked,
                Unlocked,
                SyncStarted,
                SyncFinished,
                VaultChanged,
                Conflict,
                NeedsAttention,
                SessionRevoked,
                DeviceRevoked,
                SettingsChanged,
                Offline,
            }
            struct EngineEvent {
                kind: EventKind,
                vault: Option<String>,
                item: Option<String>,
                detail: Option<String>,
                count: u32,
            }
            enum WatchKind {
                Vulnerable,
                Reused,
                Weak,
                InsecureUrl,
                Expiring,
            }
            struct WatchFinding {
                kind: WatchKind,
                vault: String,
                item: String,
                title: String,
                detail: Option<String>,
                group: Option<u32>,
            }
            struct WatchtowerReport {
                findings: Vec<WatchFinding>,
                checked: u32,
                breach_check_ran: bool,
                generated_at: u64,
            }
            enum BrowserFillDecision {
                Fill,
                ConfirmInBrowser,
                NoMatchingPage,
                Locked,
                Unavailable,
            }
            struct BrowserFillCheck {
                vault: String,
                item: String,
                origin: String,
                page_url: String,
                frame: FrameContext,
            }
            enum UserVerification { Required, Preferred, Discouraged }
            struct PasskeyQuery {
                origin: String,
                frame: FrameContext,
                rp_id: Option<String>,
                allow: Vec<String>,
            }
            struct PasskeyCandidate {
                vault: String,
                item: String,
                credential_id: String,
                rp_id: String,
                user_name: String,
                display_name: String,
                title: String,
                created: u64,
                last_used: Option<u64>,
            }
            struct PasskeyCreateRequest {
                origin: String,
                frame: FrameContext,
                rp_id: Option<String>,
                rp_name: String,
                challenge: String,
                user_handle: String,
                user_name: String,
                user_display_name: String,
                algorithms: Vec<i32>,
                exclude: Vec<String>,
                user_verification: UserVerification,
                user_verified: bool,
                vault: Option<String>,
                item: Option<String>,
            }
            struct PasskeyCreated {
                vault: String,
                item: String,
                rp_id: String,
                credential_id: String,
                client_data_json: String,
                attestation_object: String,
                authenticator_data: String,
                public_key: String,
                public_key_algorithm: i32,
            }
            struct PasskeyGetRequest {
                origin: String,
                frame: FrameContext,
                rp_id: Option<String>,
                challenge: String,
                allow: Vec<String>,
                user_verification: UserVerification,
                user_verified: bool,
                vault: Option<String>,
                item: Option<String>,
                credential_id: Option<String>,
            }
            struct PasskeyAssertion {
                vault: String,
                item: String,
                rp_id: String,
                credential_id: String,
                client_data_json: String,
                authenticator_data: String,
                signature: String,
                user_handle: String,
            }
            enum IdentityKind { Password, OneTimeCode, Passkey }
            struct CredentialIdentity {
                record: String,
                kind: IdentityKind,
                vault: String,
                item: String,
                service: String,
                user: String,
                title: String,
                favourite: bool,
                credential_id: Option<String>,
                user_handle: Option<String>,
            }
            struct IdentityDiff {
                changed: bool,
                fingerprint: String,
                identities: Vec<CredentialIdentity>,
                skipped: u32,
                added: Vec<String>,
                updated: Vec<String>,
                removed: Vec<String>,
            }
            struct ProviderQuery {
                identifiers: Vec<String>,
                limit: u32,
            }
            struct ProviderFillCheck {
                fill: FillPolicy,
                host: String,
            }
            struct ProviderPassword {
                vault: String,
                item: String,
                user: String,
                password: Secret,
                host: String,
            }
            struct ProviderPasskeyQuery {
                rp_id: String,
                allow: Vec<String>,
            }
            struct OsAssertionRequest {
                rp_id: String,
                client_data_hash: String,
                allow: Vec<String>,
                user_verification: UserVerification,
                user_verified: bool,
                vault: Option<String>,
                item: Option<String>,
                credential_id: Option<String>,
            }
            struct OsAssertion {
                vault: String,
                item: String,
                rp_id: String,
                credential_id: String,
                authenticator_data: String,
                signature: String,
                user_handle: String,
                client_data_hash: String,
            }
            struct OsRegistrationRequest {
                rp_id: String,
                rp_name: String,
                client_data_hash: String,
                user_name: String,
                user_display_name: String,
                user_handle: String,
                algorithms: Vec<i32>,
                exclude: Vec<String>,
                user_verification: UserVerification,
                user_verified: bool,
                vault: Option<String>,
                item: Option<String>,
            }
            struct OsRegistration {
                vault: String,
                item: String,
                rp_id: String,
                credential_id: String,
                attestation_object: String,
                authenticator_data: String,
                public_key: String,
                public_key_algorithm: i32,
            }
            struct TextQuery {
                text: String,
                limit: u32,
            }
            struct TextCandidate {
                vault: String,
                item: String,
                field: String,
                item_title: String,
                item_kind: String,
                label: String,
                purpose: Option<String>,
                preview: String,
                concealed: bool,
            }
            struct CxfImportRequest {
                data: Secret,
                dry_run: bool,
            }
            struct CxfImportReport {
                dry_run: bool,
                imported: u32,
                merged_passkeys: u32,
                duplicates: u32,
                unchanged: u32,
                changed: Vec<String>,
                skipped: u32,
                with_loss: u32,
                passkeys: u32,
                report_id: Option<String>,
                report: String,
            }
            struct DeviceView {
                session: String,
                device: String,
                platform: String,
                label: Option<String>,
                current: bool,
                revoked: bool,
            }
        }
    };
}

macro_rules! define_plain {
    ({} $($kind:ident $name:ident { $($body:tt)* })*) => {
        $(define_plain!(@one $kind $name { $($body)* });)*
    };
    (@one struct $name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Debug, Clone, PartialEq)]
        pub struct $name {
            $(pub $field: $ty),*
        }
    };
    (@one enum $name:ident { $($variant:ident),* $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($variant),*
        }
    };
}

with_api_types!(define_plain, {});

#![expect(
    clippy::needless_pass_by_value,
    reason = "UniFFI hands every argument over by value"
)]

use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use hasp_boundary::Mirror;
use hasp_core::CoreError;
use hasp_core::api::{Engine, EngineConfig, HintEvent};
use hasp_core::platform::{Platform, SystemClock};
use hasp_core::store::FileStore;
use hasp_net::{Hint, HintClient, HintConfig, HttpTransport, NetConfig, Origin};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

use crate::HaspError;
use crate::platform::{
    BreachRange, EventListener, ForeignBiometric, ForeignChannel, ForeignRange, ForeignStore,
    PairingChannel, PlatformBiometric, PlatformStore,
};
use crate::secret::Secret;
use crate::types::{
    AccountStatus, AttachmentUpload, AttachmentView, AutofillQuery, AutofillResult,
    BrowserFillCheck, BrowserFillDecision, Candidate, Category, CxfImportReport, CxfImportRequest,
    DeviceView, ExtensionRelease, FillPayload, FillPlan, FillRequest, GeneratedPassword,
    GeneratorRequest, HistoryRow, IdentityDiff, ItemDetail, ItemDraft, ItemRef, ItemRow,
    ItemStatus, KitPreview, LockTrigger, OsAssertion, OsAssertionRequest, OsRegistration,
    OsRegistrationRequest, PasskeyAssertion, PasskeyCandidate, PasskeyCreateRequest,
    PasskeyCreated, PasskeyGetRequest, PasskeyQuery, PasswordSession, ProviderFillCheck,
    ProviderPasskeyQuery, ProviderPassword, ProviderQuery, SaveCommit, SaveDraft, SaveProposal,
    SearchQuery, Settings, SignInRequest, SignUpKit, SignUpRequest, SyncSummary, TextCandidate,
    TextQuery, TotpCode, VaultInfo, WatchtowerReport,
};

pub(crate) type Core = Engine<HttpTransport, FileStore>;

impl From<hasp_net::OriginError> for HaspError {
    fn from(_: hasp_net::OriginError) -> Self {
        Self::Refused
    }
}

impl From<hasp_net::NetError> for HaspError {
    fn from(_: hasp_net::NetError) -> Self {
        Self::Refused
    }
}

#[derive(uniffi::Object)]
pub struct Client {
    pub(crate) engine: Arc<Core>,
    pub(crate) runtime: Runtime,
    origin: Origin,
    hints: Mutex<Option<CancellationToken>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Client(..)")
    }
}

impl Client {
    fn run<R>(&self, work: impl Future<Output = Result<R, CoreError>>) -> Result<R, HaspError> {
        self.runtime.block_on(work).map_err(HaspError::from)
    }
}

#[uniffi::export]
pub fn parse_kit_qr(blob: Vec<u8>) -> Result<KitPreview, HaspError> {
    Ok(Core::parse_kit_qr(&blob)?.mirror())
}

#[uniffi::export]
pub fn registrable_domain(host: String) -> Option<String> {
    hasp_core::api::registrable_domain(&host)
}

#[uniffi::export]
impl Client {
    #[uniffi::constructor]
    pub fn open(
        directory: String,
        server_url: String,
        platform_name: String,
        store: Arc<dyn PlatformStore>,
        biometric: Arc<dyn PlatformBiometric>,
    ) -> Result<Arc<Self>, HaspError> {
        let origin = Origin::parse(&server_url)?;
        let transport = HttpTransport::new(origin.clone(), NetConfig::new("hasp"))?;
        let platform = Platform {
            secure: Arc::new(ForeignStore(store)),
            biometric: Arc::new(ForeignBiometric(biometric)),
            clock: Arc::new(SystemClock),
        };
        let engine = Engine::new(
            transport,
            FileStore::open(Path::new(&directory)).map_err(CoreError::from)?,
            platform,
            EngineConfig::new(&platform_name),
        )?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| HaspError::Internal)?;
        Ok(Arc::new(Self {
            engine: Arc::new(engine),
            runtime,
            origin,
            hints: Mutex::new(None),
        }))
    }

    pub fn cancel(&self) {
        self.engine.cancel();
    }

    pub fn start_events(&self, listener: Arc<dyn EventListener>) {
        let engine = Arc::clone(&self.engine);
        self.runtime.spawn(async move {
            loop {
                listener.on_event(engine.next_event().await.mirror());
            }
        });
    }

    pub fn start_hints(&self) -> Result<(), HaspError> {
        self.stop_hints();
        let token = self.run(async { self.engine.hint_token().await })?;
        let client = HintClient::new(self.origin.clone(), HintConfig::standard())?;
        let (sender, mut receiver) = client.channel();
        let stop = CancellationToken::new();
        *self.hints.lock().unwrap_or_else(PoisonError::into_inner) = Some(stop.clone());
        let session = hasp_proto_token(&token)?;
        let engine = Arc::clone(&self.engine);
        let stopper = stop.clone();
        self.runtime.spawn(async move {
            if client.run(&session, &sender, &stopper).await == hasp_net::HintEnd::SessionRevoked {
                engine.session_revoked().await;
            }
        });
        let engine = Arc::clone(&self.engine);
        self.runtime.spawn(async move {
            while let Some(hint) = receiver.recv().await {
                engine
                    .on_hint(match hint {
                        Hint::Vault { vault, .. } => HintEvent::Vault(vault),
                        Hint::Notice => HintEvent::Notice,
                        Hint::SessionRevoked => HintEvent::SessionRevoked,
                    })
                    .await;
            }
        });
        Ok(())
    }

    pub fn stop_hints(&self) {
        if let Some(stop) = self
            .hints
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            stop.cancel();
        }
    }

    pub fn status(&self) -> Result<AccountStatus, HaspError> {
        self.run(self.engine.status()).map(Mirror::mirror)
    }

    pub fn sign_in(&self, request: SignInRequest) -> Result<(), HaspError> {
        self.run(self.engine.sign_in(request.mirror()))
    }

    pub fn server_fingerprint(&self, origin: String) -> Result<String, HaspError> {
        self.run(self.engine.server_fingerprint(&origin))
    }

    pub fn sign_up(&self, request: SignUpRequest) -> Result<SignUpKit, HaspError> {
        self.run(self.engine.sign_up(request.mirror()))
            .map(Mirror::mirror)
    }

    pub fn sign_in_with_kit_qr(&self, blob: Vec<u8>, password: Secret) -> Result<(), HaspError> {
        self.run(self.engine.sign_in_with_kit_qr(&blob, password.mirror()))
    }

    pub fn unlock_password(&self, password: Secret) -> Result<(), HaspError> {
        self.run(self.engine.unlock_password(password.mirror()))
    }

    pub fn unlock_with_password(&self, password: Secret) -> Result<PasswordSession, HaspError> {
        self.run(self.engine.unlock_with_password(password.mirror()))
            .map(Mirror::mirror)
    }

    pub fn resume_session(&self, session_blob: Secret) -> Result<(), HaspError> {
        self.run(self.engine.resume_session(session_blob.mirror()))
    }

    pub fn enable_hardware_unlock(&self, password: Secret) -> Result<(), HaspError> {
        self.run(self.engine.enable_hardware_unlock(password.mirror()))
    }

    pub fn unlock_biometric(&self) -> Result<(), HaspError> {
        self.run(self.engine.unlock_biometric())
    }

    pub fn unlock_extension(&self, key: Secret) -> Result<(), HaspError> {
        self.run(self.engine.unlock_extension(key.mirror()))
    }

    pub fn lock(&self) {
        self.runtime.block_on(self.engine.lock());
    }

    pub fn apply_lock_trigger(
        &self,
        trigger: LockTrigger,
        elapsed_seconds: u64,
    ) -> Result<bool, HaspError> {
        self.run(
            self.engine
                .apply_lock_trigger(trigger.mirror(), elapsed_seconds),
        )
    }

    pub fn serve_extension_pairing(
        &self,
        channel: Arc<dyn PairingChannel>,
        peer: String,
    ) -> Result<String, HaspError> {
        self.run(
            self.engine
                .serve_extension_pairing(&ForeignChannel(channel), &peer),
        )
    }

    pub fn pair_with_desktop(
        &self,
        channel: Arc<dyn PairingChannel>,
        browser: String,
    ) -> Result<Secret, HaspError> {
        self.run(
            self.engine
                .pair_with_desktop(&ForeignChannel(channel), &browser),
        )
        .map(Mirror::mirror)
    }

    pub fn release_extension_key(
        &self,
        device: String,
        peer: String,
        nonce: String,
    ) -> Result<ExtensionRelease, HaspError> {
        self.run(self.engine.release_extension_key(&device, &peer, &nonce))
            .map(Mirror::mirror)
    }

    pub fn forget_extension_key(&self, device: String) -> Result<(), HaspError> {
        self.run(self.engine.forget_extension_key(&device))
    }

    pub fn sync(&self) -> Result<SyncSummary, HaspError> {
        self.run(self.engine.sync()).map(Mirror::mirror)
    }

    pub fn sync_vault(&self, vault: String) -> Result<(), HaspError> {
        self.run(self.engine.sync_vault(&vault))
    }

    pub fn devices(&self) -> Result<Vec<DeviceView>, HaspError> {
        self.run(self.engine.devices()).map(Mirror::mirror)
    }

    pub fn revoke_device(&self, session: String, device: String) -> Result<(), HaspError> {
        self.run(self.engine.revoke_device(&session, &device))
    }

    pub fn vaults(&self) -> Result<Vec<VaultInfo>, HaspError> {
        self.run(self.engine.vaults()).map(Mirror::mirror)
    }

    pub fn items(&self, vault: String) -> Result<Vec<ItemRow>, HaspError> {
        self.run(self.engine.items(&vault)).map(Mirror::mirror)
    }

    pub fn search(&self, query: SearchQuery) -> Result<Vec<ItemRow>, HaspError> {
        self.run(self.engine.search(query.mirror()))
            .map(Mirror::mirror)
    }

    pub fn item_detail(&self, vault: String, item: String) -> Result<ItemDetail, HaspError> {
        self.run(self.engine.item_detail(&vault, &item))
            .map(Mirror::mirror)
    }

    pub fn reveal_field(
        &self,
        vault: String,
        item: String,
        field: String,
    ) -> Result<Secret, HaspError> {
        self.run(self.engine.reveal_field(&vault, &item, &field))
            .map(Mirror::mirror)
    }

    pub fn edit_draft(&self, vault: String, item: String) -> Result<ItemDraft, HaspError> {
        self.run(self.engine.edit_draft(&vault, &item))
            .map(Mirror::mirror)
    }

    pub fn blank_draft(&self, kind: String) -> Result<ItemDraft, HaspError> {
        Ok(self.engine.blank_draft(&kind)?.mirror())
    }

    pub fn categories(&self) -> Vec<Category> {
        self.engine.categories().mirror()
    }

    pub fn create_item(&self, vault: String, draft: ItemDraft) -> Result<ItemRef, HaspError> {
        self.run(self.engine.create_item(&vault, draft.mirror()))
            .map(Mirror::mirror)
    }

    pub fn edit_item(
        &self,
        vault: String,
        item: String,
        draft: ItemDraft,
    ) -> Result<(), HaspError> {
        self.run(self.engine.edit_item(&vault, &item, draft.mirror()))
    }

    pub fn set_status(
        &self,
        vault: String,
        item: String,
        status: ItemStatus,
    ) -> Result<(), HaspError> {
        self.run(self.engine.set_status(&vault, &item, status.mirror()))
    }

    pub fn set_favourite(
        &self,
        vault: String,
        item: String,
        favourite: bool,
    ) -> Result<(), HaspError> {
        self.run(self.engine.set_favourite(&vault, &item, favourite))
    }

    pub fn delete_item(&self, vault: String, item: String) -> Result<(), HaspError> {
        self.run(self.engine.delete_item(&vault, &item))
    }

    pub fn history(&self, vault: String, item: String) -> Result<Vec<HistoryRow>, HaspError> {
        self.run(self.engine.history(&vault, &item))
            .map(Mirror::mirror)
    }

    pub fn restore_version(
        &self,
        vault: String,
        item: String,
        version: u64,
    ) -> Result<(), HaspError> {
        self.run(self.engine.restore_version(&vault, &item, version))
    }

    pub fn totp(
        &self,
        vault: String,
        item: String,
        field: Option<String>,
    ) -> Result<TotpCode, HaspError> {
        self.run(self.engine.totp(&vault, &item, field))
            .map(Mirror::mirror)
    }

    pub fn attach_file(
        &self,
        vault: String,
        item: String,
        upload: AttachmentUpload,
    ) -> Result<AttachmentView, HaspError> {
        self.run(self.engine.attach_file(&vault, &item, upload.mirror()))
            .map(Mirror::mirror)
    }

    pub fn download_attachment(
        &self,
        vault: String,
        item: String,
        attachment: String,
    ) -> Result<Secret, HaspError> {
        self.run(self.engine.download_attachment(&vault, &item, &attachment))
            .map(Mirror::mirror)
    }

    pub fn remove_attachment(
        &self,
        vault: String,
        item: String,
        attachment: String,
    ) -> Result<(), HaspError> {
        self.run(self.engine.remove_attachment(&vault, &item, &attachment))
    }

    pub fn generate(&self, request: GeneratorRequest) -> Result<GeneratedPassword, HaspError> {
        Ok(self.engine.generate(&request.mirror())?.mirror())
    }

    pub fn autofill_query(&self, query: AutofillQuery) -> Result<AutofillResult, HaspError> {
        self.run(self.engine.autofill_query(query.mirror()))
            .map(Mirror::mirror)
    }

    pub fn fill_plan(&self, request: FillRequest) -> Result<FillPlan, HaspError> {
        self.run(self.engine.fill_plan(request.mirror()))
            .map(Mirror::mirror)
    }

    pub fn fill_payload(&self, request: FillRequest) -> Result<FillPayload, HaspError> {
        self.run(self.engine.fill_payload(request.mirror()))
            .map(Mirror::mirror)
    }

    pub fn browser_fill_decision(
        &self,
        check: BrowserFillCheck,
    ) -> Result<BrowserFillDecision, HaspError> {
        self.run(self.engine.browser_fill_decision(check.mirror()))
            .map(Mirror::mirror)
    }

    pub fn propose_save(&self, draft: SaveDraft) -> Result<SaveProposal, HaspError> {
        self.run(self.engine.propose_save(draft.mirror()))
            .map(Mirror::mirror)
    }

    pub fn commit_save(&self, commit: SaveCommit) -> Result<ItemRef, HaspError> {
        self.run(self.engine.commit_save(commit.mirror()))
            .map(Mirror::mirror)
    }

    pub fn passkey_candidates(
        &self,
        query: PasskeyQuery,
    ) -> Result<Vec<PasskeyCandidate>, HaspError> {
        self.run(self.engine.passkey_candidates(query.mirror()))
            .map(Mirror::mirror)
    }

    pub fn passkey_create(
        &self,
        request: PasskeyCreateRequest,
    ) -> Result<PasskeyCreated, HaspError> {
        self.run(self.engine.passkey_create(request.mirror()))
            .map(Mirror::mirror)
    }

    pub fn passkey_get(&self, request: PasskeyGetRequest) -> Result<PasskeyAssertion, HaspError> {
        self.run(self.engine.passkey_get(request.mirror()))
            .map(Mirror::mirror)
    }

    pub fn provider_unlock(&self) -> Result<(), HaspError> {
        self.run(self.engine.provider_unlock())
    }

    pub fn provider_index_refresh(&self) -> Result<u32, HaspError> {
        self.run(self.engine.provider_index_refresh())
    }

    pub fn identity_diff(&self) -> Result<IdentityDiff, HaspError> {
        self.run(self.engine.identity_diff()).map(Mirror::mirror)
    }

    pub fn identity_ack(&self, fingerprint: String) -> Result<(), HaspError> {
        self.run(self.engine.identity_ack(&fingerprint))
    }

    pub fn provider_candidates(&self, query: ProviderQuery) -> Result<Vec<Candidate>, HaspError> {
        self.run(self.engine.provider_candidates(query.mirror()))
            .map(Mirror::mirror)
    }

    pub fn provider_list(&self, query: SearchQuery) -> Result<Vec<ItemRow>, HaspError> {
        self.run(self.engine.provider_list(query.mirror()))
            .map(Mirror::mirror)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the two consent flags are separate FFI arguments"
    )]
    pub fn provider_password(
        &self,
        vault: String,
        item: String,
        service: Option<String>,
        manual: bool,
        confirmed: bool,
    ) -> Result<ProviderPassword, HaspError> {
        self.run(
            self.engine
                .provider_password(&vault, &item, service, manual, confirmed),
        )
        .map(Mirror::mirror)
    }

    pub fn provider_fill_check(
        &self,
        vault: String,
        item: String,
        service: Option<String>,
        manual: bool,
    ) -> Result<ProviderFillCheck, HaspError> {
        self.run(
            self.engine
                .provider_fill_check(&vault, &item, service, manual),
        )
        .map(Mirror::mirror)
    }

    pub fn provider_passkeys(
        &self,
        query: ProviderPasskeyQuery,
    ) -> Result<Vec<PasskeyCandidate>, HaspError> {
        self.run(self.engine.provider_passkeys(query.mirror()))
            .map(Mirror::mirror)
    }

    pub fn provider_passkey_assert(
        &self,
        request: OsAssertionRequest,
    ) -> Result<OsAssertion, HaspError> {
        self.run(self.engine.provider_passkey_assert(request.mirror()))
            .map(Mirror::mirror)
    }

    pub fn provider_passkey_register(
        &self,
        request: OsRegistrationRequest,
    ) -> Result<OsRegistration, HaspError> {
        self.run(self.engine.provider_passkey_register(request.mirror()))
            .map(Mirror::mirror)
    }

    pub fn text_candidates(&self, query: TextQuery) -> Result<Vec<TextCandidate>, HaspError> {
        self.run(self.engine.text_candidates(query.mirror()))
            .map(Mirror::mirror)
    }

    pub fn text_value(
        &self,
        vault: String,
        item: String,
        field: String,
    ) -> Result<Secret, HaspError> {
        self.run(self.engine.text_value(&vault, &item, &field))
            .map(Mirror::mirror)
    }

    pub fn cxf_import(&self, request: CxfImportRequest) -> Result<CxfImportReport, HaspError> {
        self.run(self.engine.cxf_import(request.mirror()))
            .map(Mirror::mirror)
    }

    pub fn settings(&self) -> Result<Settings, HaspError> {
        self.run(self.engine.settings()).map(Mirror::mirror)
    }

    pub fn set_settings(&self, settings: Settings) -> Result<(), HaspError> {
        self.run(self.engine.set_settings(settings.mirror()))
    }

    pub fn watchtower_report(&self) -> Result<WatchtowerReport, HaspError> {
        self.run(self.engine.watchtower_report())
            .map(Mirror::mirror)
    }

    pub fn watchtower_check_breaches(
        &self,
        range: Arc<dyn BreachRange>,
    ) -> Result<WatchtowerReport, HaspError> {
        self.run(self.engine.watchtower_check_breaches(&ForeignRange(range)))
            .map(Mirror::mirror)
    }
}

fn hasp_proto_token(
    secret: &hasp_core::api::Secret,
) -> Result<hasp_proto::wire::SessionToken, HaspError> {
    let bytes: [u8; 32] = secret
        .as_bytes()
        .try_into()
        .map_err(|_| HaspError::Internal)?;
    Ok(hasp_proto::wire::SessionToken::from_bytes(bytes))
}

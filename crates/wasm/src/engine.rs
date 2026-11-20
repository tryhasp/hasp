use std::rc::Rc;
use std::sync::Arc;

use hasp_boundary::{Mirror, NoBiometric, SnapshotStore, SoftSecureStore};
use hasp_core::CoreError;
use hasp_core::api::{Engine, EngineConfig, Secret as CoreSecret};
use hasp_core::platform::Platform;
use js_sys::Function;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tsify::Ts;
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::HaspError;
use crate::error::thrown;
use crate::fetch::FetchTransport;
use crate::js::{JsChannel, JsClock, JsHandle, JsRange};
use crate::types::{
    AccountStatus, AttachmentUpload, AttachmentView, AutofillQuery, AutofillResult,
    BrowserFillCheck, BrowserFillDecision, Category, DeviceView, EngineEvent, ExtensionRelease,
    FillPayload, FillPlan, FillRequest, GeneratedPassword, GeneratorRequest, HistoryRow,
    ItemDetail, ItemDraft, ItemRef, ItemRow, ItemStatus, KitPreview, LockTrigger, PasskeyAssertion,
    PasskeyCandidate, PasskeyCreateRequest, PasskeyCreated, PasskeyGetRequest, PasskeyQuery,
    PasswordSession, SaveCommit, SaveDraft, SaveProposal, SearchQuery, Settings, SignInRequest,
    SignUpKit, SignUpRequest, SyncSummary, TotpCode, VaultInfo, WatchtowerReport,
};

type Core = Engine<FetchTransport, SnapshotStore>;
type Failure = Ts<HaspError>;

fn out<M: Serialize, T: Mirror<M>>(result: Result<T, CoreError>) -> Result<JsValue, Failure> {
    let value: M = result.map_err(thrown)?.mirror();
    tsify::serde_wasm_bindgen::to_value(&value).map_err(|_| HaspError::Internal.into())
}

fn input<M: DeserializeOwned + Mirror<T>, T>(value: JsValue) -> Result<T, Failure> {
    tsify::serde_wasm_bindgen::from_value::<M>(value)
        .map(Mirror::mirror)
        .map_err(|_| HaspError::Format.into())
}

fn done(result: Result<(), CoreError>) -> Result<(), Failure> {
    result.map_err(thrown)
}

fn bytes(result: Result<CoreSecret, CoreError>) -> Result<Vec<u8>, Failure> {
    result.map(CoreSecret::take).map_err(thrown)
}

#[wasm_bindgen(js_name = extensionUnlockCode)]
pub fn extension_unlock_code(device: &str, nonce: &str) -> Result<String, Failure> {
    hasp_core::api::extension_unlock_code(device, nonce).map_err(thrown)
}

#[wasm_bindgen(js_name = extensionPairingCode)]
pub fn extension_pairing_code(enrol_request: &[u8]) -> Result<String, Failure> {
    hasp_core::api::extension_pairing_code(enrol_request).map_err(thrown)
}

#[wasm_bindgen(js_name = registrableDomain)]
pub fn registrable_domain(host: &str) -> Option<String> {
    hasp_core::api::registrable_domain(host)
}

#[wasm_bindgen]
pub struct Client {
    engine: Rc<Core>,
    store: SnapshotStore,
    origin: String,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Client(..)")
    }
}

#[wasm_bindgen(js_name = parseKitQr, unchecked_return_type = "KitPreview")]
pub fn parse_kit_qr(blob: &[u8]) -> Result<JsValue, Failure> {
    out::<KitPreview, _>(Core::parse_kit_qr(blob))
}

#[wasm_bindgen]
impl Client {
    /// `snapshot` is the output of a previous `exportStore`, or absent for a new device.
    #[wasm_bindgen(constructor)]
    pub fn new(
        origin: &str,
        platform_name: &str,
        snapshot: Option<Vec<u8>>,
    ) -> Result<Client, Failure> {
        let store = match snapshot {
            Some(bytes) => SnapshotStore::restore(&bytes).map_err(|_| HaspError::Format)?,
            None => SnapshotStore::new(),
        };
        let transport = FetchTransport::new(origin).map_err(|_| HaspError::Refused)?;
        let platform = Platform {
            secure: Arc::new(SoftSecureStore::default()),
            biometric: Arc::new(NoBiometric),
            clock: Arc::new(JsClock),
        };
        let engine = Engine::new(
            transport,
            store.clone(),
            platform,
            EngineConfig::new(platform_name),
        )
        .map_err(thrown)?;
        Ok(Self {
            engine: Rc::new(engine),
            store,
            origin: origin.to_owned(),
        })
    }

    pub fn origin(&self) -> String {
        self.origin.clone()
    }

    /// Bumps on every write to the device store, so the host persists only when it changed.
    #[wasm_bindgen(js_name = storeRevision)]
    pub fn store_revision(&self) -> f64 {
        #[expect(
            clippy::cast_precision_loss,
            reason = "a write counter stays far below 2^53"
        )]
        let revision = self.store.revision() as f64;
        revision
    }

    #[wasm_bindgen(js_name = exportStore)]
    pub fn export_store(&self) -> Vec<u8> {
        self.store.export()
    }

    pub fn cancel(&self) {
        self.engine.cancel();
    }

    #[wasm_bindgen(js_name = nextEvent, unchecked_return_type = "EngineEvent")]
    pub async fn next_event(&self) -> Result<JsValue, Failure> {
        let engine = Rc::clone(&self.engine);
        out::<EngineEvent, _>(Ok::<_, CoreError>(engine.next_event().await))
    }

    #[wasm_bindgen(js_name = hintAuthFrame)]
    pub async fn hint_auth_frame(&self) -> Result<Vec<u8>, Failure> {
        bytes(self.engine.hint_auth_frame().await)
    }

    #[wasm_bindgen(js_name = handleHintFrame)]
    pub async fn handle_hint_frame(&self, frame: String) -> Result<(), Failure> {
        done(self.engine.handle_hint_frame(&frame).await)
    }

    #[wasm_bindgen(unchecked_return_type = "AccountStatus")]
    pub async fn status(&self) -> Result<JsValue, Failure> {
        out::<AccountStatus, _>(self.engine.status().await)
    }

    #[wasm_bindgen(js_name = signIn)]
    pub async fn sign_in(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SignInRequest")] request: JsValue,
    ) -> Result<(), Failure> {
        done(
            self.engine
                .sign_in(input::<SignInRequest, _>(request)?)
                .await,
        )
    }

    #[wasm_bindgen(js_name = serverFingerprint)]
    pub async fn server_fingerprint(&self) -> Result<String, Failure> {
        self.engine
            .server_fingerprint(&self.origin)
            .await
            .map_err(thrown)
    }

    #[wasm_bindgen(js_name = signUp, unchecked_return_type = "SignUpKit")]
    pub async fn sign_up(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SignUpRequest")] request: JsValue,
    ) -> Result<JsValue, Failure> {
        out::<SignUpKit, _>(
            self.engine
                .sign_up(input::<SignUpRequest, _>(request)?)
                .await,
        )
    }

    #[wasm_bindgen(js_name = signInWithKitQr)]
    pub async fn sign_in_with_kit_qr(
        &self,
        blob: Vec<u8>,
        password: Vec<u8>,
    ) -> Result<(), Failure> {
        done(
            self.engine
                .sign_in_with_kit_qr(&blob, CoreSecret::new(password))
                .await,
        )
    }

    #[wasm_bindgen(js_name = unlockPassword)]
    pub async fn unlock_password(&self, password: Vec<u8>) -> Result<(), Failure> {
        done(self.engine.unlock_password(CoreSecret::new(password)).await)
    }

    #[wasm_bindgen(js_name = unlockWithPassword, unchecked_return_type = "PasswordSession")]
    pub async fn unlock_with_password(&self, password: Vec<u8>) -> Result<JsValue, Failure> {
        out::<PasswordSession, _>(
            self.engine
                .unlock_with_password(CoreSecret::new(password))
                .await,
        )
    }

    #[wasm_bindgen(js_name = resumeSession)]
    pub async fn resume_session(&self, session_blob: Vec<u8>) -> Result<(), Failure> {
        done(
            self.engine
                .resume_session(CoreSecret::new(session_blob))
                .await,
        )
    }

    #[wasm_bindgen(js_name = unlockExtension)]
    pub async fn unlock_extension(&self, key: Vec<u8>) -> Result<(), Failure> {
        done(self.engine.unlock_extension(CoreSecret::new(key)).await)
    }

    pub async fn lock(&self) {
        self.engine.lock().await;
    }

    #[wasm_bindgen(js_name = applyLockTrigger)]
    pub async fn apply_lock_trigger(
        &self,
        #[wasm_bindgen(unchecked_param_type = "LockTrigger")] trigger: JsValue,
        elapsed_seconds: f64,
    ) -> Result<bool, Failure> {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "elapsed seconds are a small non-negative number"
        )]
        let elapsed = elapsed_seconds as u64;
        self.engine
            .apply_lock_trigger(input::<LockTrigger, _>(trigger)?, elapsed)
            .await
            .map_err(thrown)
    }

    #[wasm_bindgen(js_name = pairWithDesktop)]
    pub async fn pair_with_desktop(
        &self,
        send: Function,
        recv: Function,
        browser: String,
    ) -> Result<Vec<u8>, Failure> {
        let channel = JsChannel {
            send: JsHandle(send),
            recv: JsHandle(recv),
        };
        bytes(self.engine.pair_with_desktop(&channel, &browser).await)
    }

    #[wasm_bindgen(js_name = serveExtensionPairing)]
    pub async fn serve_extension_pairing(
        &self,
        send: Function,
        recv: Function,
        peer: String,
    ) -> Result<String, Failure> {
        let channel = JsChannel {
            send: JsHandle(send),
            recv: JsHandle(recv),
        };
        self.engine
            .serve_extension_pairing(&channel, &peer)
            .await
            .map_err(thrown)
    }

    #[wasm_bindgen(js_name = releaseExtensionKey, unchecked_return_type = "ExtensionRelease")]
    pub async fn release_extension_key(
        &self,
        device: String,
        peer: String,
        nonce: String,
    ) -> Result<JsValue, Failure> {
        out::<ExtensionRelease, _>(
            self.engine
                .release_extension_key(&device, &peer, &nonce)
                .await,
        )
    }

    #[wasm_bindgen(unchecked_return_type = "SyncSummary")]
    pub async fn sync(&self) -> Result<JsValue, Failure> {
        out::<SyncSummary, _>(self.engine.sync().await)
    }

    #[wasm_bindgen(js_name = syncVault)]
    pub async fn sync_vault(&self, vault: String) -> Result<(), Failure> {
        done(self.engine.sync_vault(&vault).await)
    }

    #[wasm_bindgen(unchecked_return_type = "DeviceView[]")]
    pub async fn devices(&self) -> Result<JsValue, Failure> {
        out::<Vec<DeviceView>, _>(self.engine.devices().await)
    }

    #[wasm_bindgen(js_name = revokeDevice)]
    pub async fn revoke_device(&self, session: String, device: String) -> Result<(), Failure> {
        done(self.engine.revoke_device(&session, &device).await)
    }

    #[wasm_bindgen(unchecked_return_type = "VaultInfo[]")]
    pub async fn vaults(&self) -> Result<JsValue, Failure> {
        out::<Vec<VaultInfo>, _>(self.engine.vaults().await)
    }

    #[wasm_bindgen(unchecked_return_type = "ItemRow[]")]
    pub async fn items(&self, vault: String) -> Result<JsValue, Failure> {
        out::<Vec<ItemRow>, _>(self.engine.items(&vault).await)
    }

    #[wasm_bindgen(unchecked_return_type = "ItemRow[]")]
    pub async fn search(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SearchQuery")] query: JsValue,
    ) -> Result<JsValue, Failure> {
        out::<Vec<ItemRow>, _>(self.engine.search(input::<SearchQuery, _>(query)?).await)
    }

    #[wasm_bindgen(js_name = itemDetail, unchecked_return_type = "ItemDetail")]
    pub async fn item_detail(&self, vault: String, item: String) -> Result<JsValue, Failure> {
        out::<ItemDetail, _>(self.engine.item_detail(&vault, &item).await)
    }

    #[wasm_bindgen(js_name = revealField)]
    pub async fn reveal_field(
        &self,
        vault: String,
        item: String,
        field: String,
    ) -> Result<Vec<u8>, Failure> {
        bytes(self.engine.reveal_field(&vault, &item, &field).await)
    }

    #[wasm_bindgen(js_name = editDraft, unchecked_return_type = "ItemDraft")]
    pub async fn edit_draft(&self, vault: String, item: String) -> Result<JsValue, Failure> {
        out::<ItemDraft, _>(self.engine.edit_draft(&vault, &item).await)
    }

    #[wasm_bindgen(js_name = blankDraft, unchecked_return_type = "ItemDraft")]
    pub fn blank_draft(&self, kind: &str) -> Result<JsValue, Failure> {
        out::<ItemDraft, _>(self.engine.blank_draft(kind))
    }

    #[wasm_bindgen(unchecked_return_type = "Category[]")]
    pub fn categories(&self) -> Result<JsValue, Failure> {
        out::<Vec<Category>, _>(Ok::<_, CoreError>(self.engine.categories()))
    }

    #[wasm_bindgen(js_name = createItem, unchecked_return_type = "ItemRef")]
    pub async fn create_item(
        &self,
        vault: String,
        #[wasm_bindgen(unchecked_param_type = "ItemDraft")] draft: JsValue,
    ) -> Result<JsValue, Failure> {
        out::<ItemRef, _>(
            self.engine
                .create_item(&vault, input::<ItemDraft, _>(draft)?)
                .await,
        )
    }

    #[wasm_bindgen(js_name = editItem)]
    pub async fn edit_item(
        &self,
        vault: String,
        item: String,
        #[wasm_bindgen(unchecked_param_type = "ItemDraft")] draft: JsValue,
    ) -> Result<(), Failure> {
        done(
            self.engine
                .edit_item(&vault, &item, input::<ItemDraft, _>(draft)?)
                .await,
        )
    }

    #[wasm_bindgen(js_name = setStatus)]
    pub async fn set_status(
        &self,
        vault: String,
        item: String,
        #[wasm_bindgen(unchecked_param_type = "ItemStatus")] status: JsValue,
    ) -> Result<(), Failure> {
        done(
            self.engine
                .set_status(&vault, &item, input::<ItemStatus, _>(status)?)
                .await,
        )
    }

    #[wasm_bindgen(js_name = setFavourite)]
    pub async fn set_favourite(
        &self,
        vault: String,
        item: String,
        favourite: bool,
    ) -> Result<(), Failure> {
        done(self.engine.set_favourite(&vault, &item, favourite).await)
    }

    #[wasm_bindgen(js_name = deleteItem)]
    pub async fn delete_item(&self, vault: String, item: String) -> Result<(), Failure> {
        done(self.engine.delete_item(&vault, &item).await)
    }

    #[wasm_bindgen(unchecked_return_type = "HistoryRow[]")]
    pub async fn history(&self, vault: String, item: String) -> Result<JsValue, Failure> {
        out::<Vec<HistoryRow>, _>(self.engine.history(&vault, &item).await)
    }

    #[wasm_bindgen(js_name = restoreVersion)]
    pub async fn restore_version(
        &self,
        vault: String,
        item: String,
        version: f64,
    ) -> Result<(), Failure> {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a version is a small non-negative integer"
        )]
        let version = version as u64;
        done(self.engine.restore_version(&vault, &item, version).await)
    }

    #[wasm_bindgen(unchecked_return_type = "TotpCode")]
    pub async fn totp(
        &self,
        vault: String,
        item: String,
        field: Option<String>,
    ) -> Result<JsValue, Failure> {
        out::<TotpCode, _>(self.engine.totp(&vault, &item, field).await)
    }

    #[wasm_bindgen(js_name = attachFile, unchecked_return_type = "AttachmentView")]
    pub async fn attach_file(
        &self,
        vault: String,
        item: String,
        #[wasm_bindgen(unchecked_param_type = "AttachmentUpload")] upload: JsValue,
    ) -> Result<JsValue, Failure> {
        out::<AttachmentView, _>(
            self.engine
                .attach_file(&vault, &item, input::<AttachmentUpload, _>(upload)?)
                .await,
        )
    }

    #[wasm_bindgen(js_name = downloadAttachment)]
    pub async fn download_attachment(
        &self,
        vault: String,
        item: String,
        attachment: String,
    ) -> Result<Vec<u8>, Failure> {
        bytes(
            self.engine
                .download_attachment(&vault, &item, &attachment)
                .await,
        )
    }

    #[wasm_bindgen(js_name = removeAttachment)]
    pub async fn remove_attachment(
        &self,
        vault: String,
        item: String,
        attachment: String,
    ) -> Result<(), Failure> {
        done(
            self.engine
                .remove_attachment(&vault, &item, &attachment)
                .await,
        )
    }

    #[wasm_bindgen(unchecked_return_type = "GeneratedPassword")]
    pub fn generate(
        &self,
        #[wasm_bindgen(unchecked_param_type = "GeneratorRequest")] request: JsValue,
    ) -> Result<JsValue, Failure> {
        out::<GeneratedPassword, _>(
            self.engine
                .generate(&input::<GeneratorRequest, _>(request)?),
        )
    }

    #[wasm_bindgen(js_name = autofillQuery, unchecked_return_type = "AutofillResult")]
    pub async fn autofill_query(
        &self,
        #[wasm_bindgen(unchecked_param_type = "AutofillQuery")] query: JsValue,
    ) -> Result<JsValue, Failure> {
        out::<AutofillResult, _>(
            self.engine
                .autofill_query(input::<AutofillQuery, _>(query)?)
                .await,
        )
    }

    #[wasm_bindgen(js_name = fillPlan, unchecked_return_type = "FillPlan")]
    pub async fn fill_plan(
        &self,
        #[wasm_bindgen(unchecked_param_type = "FillRequest")] request: JsValue,
    ) -> Result<JsValue, Failure> {
        out::<FillPlan, _>(
            self.engine
                .fill_plan(input::<FillRequest, _>(request)?)
                .await,
        )
    }

    #[wasm_bindgen(js_name = fillPayload, unchecked_return_type = "FillPayload")]
    pub async fn fill_payload(
        &self,
        #[wasm_bindgen(unchecked_param_type = "FillRequest")] request: JsValue,
    ) -> Result<JsValue, Failure> {
        out::<FillPayload, _>(
            self.engine
                .fill_payload(input::<FillRequest, _>(request)?)
                .await,
        )
    }

    #[wasm_bindgen(js_name = browserFillDecision, unchecked_return_type = "BrowserFillDecision")]
    pub async fn browser_fill_decision(
        &self,
        #[wasm_bindgen(unchecked_param_type = "BrowserFillCheck")] check: JsValue,
    ) -> Result<JsValue, Failure> {
        out::<BrowserFillDecision, _>(
            self.engine
                .browser_fill_decision(input::<BrowserFillCheck, _>(check)?)
                .await,
        )
    }

    #[wasm_bindgen(js_name = proposeSave, unchecked_return_type = "SaveProposal")]
    pub async fn propose_save(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SaveDraft")] draft: JsValue,
    ) -> Result<JsValue, Failure> {
        out::<SaveProposal, _>(
            self.engine
                .propose_save(input::<SaveDraft, _>(draft)?)
                .await,
        )
    }

    #[wasm_bindgen(js_name = commitSave, unchecked_return_type = "ItemRef")]
    pub async fn commit_save(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SaveCommit")] commit: JsValue,
    ) -> Result<JsValue, Failure> {
        out::<ItemRef, _>(
            self.engine
                .commit_save(input::<SaveCommit, _>(commit)?)
                .await,
        )
    }

    #[wasm_bindgen(js_name = passkeyCandidates, unchecked_return_type = "PasskeyCandidate[]")]
    pub async fn passkey_candidates(
        &self,
        #[wasm_bindgen(unchecked_param_type = "PasskeyQuery")] query: JsValue,
    ) -> Result<JsValue, Failure> {
        out::<Vec<PasskeyCandidate>, _>(
            self.engine
                .passkey_candidates(input::<PasskeyQuery, _>(query)?)
                .await,
        )
    }

    #[wasm_bindgen(js_name = passkeyCreate, unchecked_return_type = "PasskeyCreated")]
    pub async fn passkey_create(
        &self,
        #[wasm_bindgen(unchecked_param_type = "PasskeyCreateRequest")] request: JsValue,
    ) -> Result<JsValue, Failure> {
        out::<PasskeyCreated, _>(
            self.engine
                .passkey_create(input::<PasskeyCreateRequest, _>(request)?)
                .await,
        )
    }

    #[wasm_bindgen(js_name = passkeyGet, unchecked_return_type = "PasskeyAssertion")]
    pub async fn passkey_get(
        &self,
        #[wasm_bindgen(unchecked_param_type = "PasskeyGetRequest")] request: JsValue,
    ) -> Result<JsValue, Failure> {
        out::<PasskeyAssertion, _>(
            self.engine
                .passkey_get(input::<PasskeyGetRequest, _>(request)?)
                .await,
        )
    }

    #[wasm_bindgen(unchecked_return_type = "Settings")]
    pub async fn settings(&self) -> Result<JsValue, Failure> {
        out::<Settings, _>(self.engine.settings().await)
    }

    #[wasm_bindgen(js_name = setSettings)]
    pub async fn set_settings(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Settings")] settings: JsValue,
    ) -> Result<(), Failure> {
        done(
            self.engine
                .set_settings(input::<Settings, _>(settings)?)
                .await,
        )
    }

    #[wasm_bindgen(js_name = watchtowerReport, unchecked_return_type = "WatchtowerReport")]
    pub async fn watchtower_report(&self) -> Result<JsValue, Failure> {
        out::<WatchtowerReport, _>(self.engine.watchtower_report().await)
    }

    #[wasm_bindgen(
        js_name = watchtowerCheckBreaches,
        unchecked_return_type = "WatchtowerReport"
    )]
    pub async fn watchtower_check_breaches(&self, range: Function) -> Result<JsValue, Failure> {
        out::<WatchtowerReport, _>(
            self.engine
                .watchtower_check_breaches(&JsRange(JsHandle(range)))
                .await,
        )
    }
}

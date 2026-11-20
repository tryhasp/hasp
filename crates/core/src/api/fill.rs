use hasp_proto::{ItemId, VaultId};

use super::convert::{draft_of, purpose_name, secret_text};
use super::engine::Engine;
use super::{
    AutofillQuery, AutofillResult, BrowserFillCheck, BrowserFillDecision, Candidate, FillKind,
    FillPayload, FillPlan, FillPolicy, FillRequest, FillSlot, FillValue, ItemRef, MatchTier,
    SaveCommit, SaveDraft, SaveKind, SaveProposal, Secret, SiteQuirks, StepUp, ids,
};
use crate::CoreError;
use crate::client::Client;
use crate::matcher::origin::{Origin, Refusal};
use crate::matcher::policy::{Fill, Match, MatchLevel};
use crate::matcher::sites::Quirks;
use crate::model::field::{Field, FieldValue, Purpose, Section};
use crate::model::item::Item;
use crate::store::{LocalVaultStatus, Store};
use crate::transport::Transport;

const OTP_MIN_WINDOW_S: u32 = 3;
const CONFIRMED: &str = "fill-confirmed";

const LOGIN_PURPOSES: [Purpose; 2] = [Purpose::Username, Purpose::Password];
const OTP_PURPOSES: [Purpose; 1] = [Purpose::Totp];
const CARD_PURPOSES: [Purpose; 7] = [
    Purpose::CardHolder,
    Purpose::CardNumber,
    Purpose::CardExpiry,
    Purpose::CardExpiryMonth,
    Purpose::CardExpiryYear,
    Purpose::CardType,
    Purpose::CardCvc,
];
const IDENTITY_PURPOSES: [Purpose; 14] = [
    Purpose::Name,
    Purpose::GivenName,
    Purpose::FamilyName,
    Purpose::Email,
    Purpose::Phone,
    Purpose::Birthday,
    Purpose::StreetAddress,
    Purpose::AddressLine1,
    Purpose::AddressLine2,
    Purpose::City,
    Purpose::Region,
    Purpose::PostalCode,
    Purpose::Country,
    Purpose::Organization,
];

pub(super) fn tier_of(level: MatchLevel) -> Option<MatchTier> {
    match level {
        MatchLevel::None => None,
        MatchLevel::Related => Some(MatchTier::Related),
        MatchLevel::Domain => Some(MatchTier::Domain),
        MatchLevel::Exact => Some(MatchTier::Exact),
    }
}

pub(super) fn policy_of(fill: Fill) -> FillPolicy {
    match fill {
        Fill::Never => FillPolicy::Never,
        Fill::ConfirmFirst => FillPolicy::ConfirmFirst,
        Fill::OneClick => FillPolicy::OneClick,
    }
}

fn quirks_of(quirks: &Quirks) -> SiteQuirks {
    SiteQuirks {
        append_2fa: quirks.append_2fa,
        no_autosubmit: quirks.no_autosubmit,
        per_char_events: quirks.per_char_events,
        skip_save: quirks.skip_save,
        iframe_login: quirks.iframe_login,
    }
}

fn refusal_name(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::InsecureOrigin => "insecure-origin",
        Refusal::UnsupportedScheme => "unsupported-scheme",
    }
}

fn purposes_of(kind: FillKind) -> &'static [Purpose] {
    match kind {
        FillKind::Login => &LOGIN_PURPOSES,
        FillKind::Otp => &OTP_PURPOSES,
        FillKind::Card => &CARD_PURPOSES,
        FillKind::Identity => &IDENTITY_PURPOSES,
    }
}

fn username_of(item: &Item) -> String {
    item.details()
        .sections
        .iter()
        .flat_map(Section::fields)
        .find(|f| f.purpose() == Some(Purpose::Username))
        .and_then(|f| super::convert::plain_text(f.value()))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| item.overview().subtitle.clone())
}

fn host_and_path(page_url: &str) -> (String, String) {
    url::Url::parse(page_url).map_or_else(
        |_| (String::new(), String::new()),
        |u| {
            (
                u.host_str().unwrap_or_default().to_owned(),
                u.path().to_owned(),
            )
        },
    )
}

fn plain_username(field: &Field) -> Option<String> {
    match field.value() {
        FieldValue::Text(t) | FieldValue::Email(t) => Some(t.clone()),
        _ => None,
    }
}

struct Located {
    vault: VaultId,
    id: ItemId,
    item: Item,
}

struct Evaluation {
    located: Located,
    result: Match,
    best_entry: Option<usize>,
    host: String,
    step_up: StepUp,
    slots: Vec<(Purpose, bool)>,
    quirks: Quirks,
}

impl<T: Transport, S: Store> Engine<T, S> {
    pub(super) fn active_items(
        client: &Client<T, S>,
    ) -> Result<Vec<(crate::client::ItemSummary, Item)>, CoreError> {
        let mut out = Vec::new();
        for vault in client.vaults()? {
            if vault.status != LocalVaultStatus::Active || vault.quarantined {
                continue;
            }
            out.extend(
                Self::loaded_items(client, &vault.vault_id)?
                    .into_iter()
                    .filter(|(_, item)| item.overview().state.is_active()),
            );
        }
        Ok(out)
    }

    pub async fn autofill_query(&self, query: AutofillQuery) -> Result<AutofillResult, CoreError> {
        let (host, path) = host_and_path(if query.page_url.is_empty() {
            &query.origin
        } else {
            &query.page_url
        });
        let mut result = AutofillResult {
            candidates: Vec::new(),
            refusal: None,
            quirks: quirks_of(&self.matcher.sites().quirks(&host, &path)),
            password_rules: self
                .matcher
                .sites()
                .password_rules(&host)
                .map(str::to_owned),
            change_password_url: self
                .matcher
                .sites()
                .change_password_url(&host)
                .map(str::to_owned),
        };
        if query.frame.sandboxed {
            result.refusal = Some("sandboxed-frame".to_owned());
            return Ok(result);
        }
        let Ok(page) = Origin::parse(&query.origin) else {
            result.refusal = Some("unsupported-scheme".to_owned());
            return Ok(result);
        };
        if let Err(refusal) = page.check_fillable() {
            result.refusal = Some(refusal_name(refusal).to_owned());
            return Ok(result);
        }
        let client = self.client.lock().await;
        let mut keyed = Vec::new();
        let mut loaded = Vec::new();
        for (summary, item) in Self::active_items(&client)? {
            if item.details().urls.is_empty() {
                continue;
            }
            keyed.push((loaded.len(), item.details().urls.clone()));
            loaded.push((summary, item));
        }
        let mut ranked = self.matcher.rank_items(&page, &keyed);
        ranked.sort_by_key(|r| {
            let (_, item) = &loaded[r.key];
            std::cmp::Reverse((
                r.result.level,
                r.result.fill,
                item.overview().favourite.is_some(),
                item.overview().client_modified,
            ))
        });
        let page_host = page.host_string();
        for ranked in ranked {
            let (summary, item) = &loaded[ranked.key];
            let Some(tier) = tier_of(ranked.result.level) else {
                continue;
            };
            result.candidates.push(Candidate {
                vault: ids::hex(summary.vault_id.as_bytes()),
                item: ids::hex(summary.item_id.as_bytes()),
                title: item.overview().title.clone(),
                subtitle: username_of(item),
                tier,
                fill: policy_of(ranked.result.fill),
                host_to_confirm: (ranked.result.fill == Fill::ConfirmFirst)
                    .then(|| page_host.clone()),
                has_totp: item.overview().flags.has_totp,
                has_passkey: item.overview().flags.has_passkey,
                favourite: item.overview().favourite.is_some(),
            });
        }
        Ok(result)
    }

    fn confirmed_list(client: &Client<T, S>) -> Vec<String> {
        client
            .local_note_get(CONFIRMED)
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_slice(raw.expose()).ok())
            .unwrap_or_default()
    }

    fn evaluate(
        &self,
        client: &Client<T, S>,
        request: &FillRequest,
    ) -> Result<Evaluation, CoreError> {
        if request.frame.sandboxed {
            return Err(CoreError::Refused("sandboxed frame"));
        }
        let vault = ids::vault(&request.vault)?;
        let id = ids::item(&request.item)?;
        let item = client.item(&vault, &id)?;
        if !item.overview().state.is_active() {
            return Err(CoreError::Refused("item is not active"));
        }
        let page = Origin::parse(&request.origin).map_err(|_| CoreError::Refused("origin"))?;
        let host = page.host_string();
        let (_, path) = host_and_path(&request.page_url);
        let quirks = self.matcher.sites().quirks(&host, &path);
        let settings = Self::settings_sync(client);
        let urlbased = matches!(request.kind, FillKind::Login | FillKind::Otp);
        let (result, best_entry) = if urlbased {
            page.check_fillable()
                .map_err(|_| CoreError::Refused("insecure origin"))?;
            let entries = &item.details().urls;
            let overall = self.matcher.rank(&page, entries);
            let best = entries
                .iter()
                .enumerate()
                .map(|(i, entry)| (i, self.matcher.rank(&page, std::slice::from_ref(entry))))
                .filter(|(_, m)| m.level == overall.level && m.fill == overall.fill)
                .map(|(i, _)| i)
                .next();
            if overall.level == MatchLevel::None || overall.fill == Fill::Never {
                return Err(CoreError::Refused("no match for this origin"));
            }
            (overall, best)
        } else {
            page.check_fillable()
                .map_err(|_| CoreError::Refused("insecure origin"))?;
            (
                Match {
                    level: MatchLevel::Related,
                    fill: Fill::ConfirmFirst,
                    refusal: None,
                },
                None,
            )
        };
        let wanted = purposes_of(request.kind);
        let slots: Vec<(Purpose, bool)> = item
            .details()
            .sections
            .iter()
            .flat_map(Section::fields)
            .filter_map(Field::purpose)
            .filter(|p| wanted.contains(p))
            .map(|p| (p, p == Purpose::CardCvc))
            .collect();
        if slots.is_empty() {
            return Err(CoreError::NotFound("nothing to fill"));
        }
        let suspicious = request.frame.obscured
            || (!request.frame.top_frame && request.frame.cross_origin_frame);
        let visibility = request.frame.visibility_check_supported;
        let confirmed = Self::confirmed_list(client).contains(&format!("{}@{host}", request.item));
        let step_up = if suspicious {
            StepUp::BrowserUi
        } else if urlbased {
            match result.fill {
                Fill::ConfirmFirst if visibility => StepUp::InlineConfirmHost,
                Fill::ConfirmFirst => StepUp::BrowserUi,
                _ if settings.ask_before_filling => StepUp::ConfirmPerHost,
                _ => StepUp::Allow,
            }
        } else if confirmed && visibility {
            StepUp::Allow
        } else if visibility {
            StepUp::ConfirmPerHost
        } else {
            StepUp::BrowserUi
        };
        Ok(Evaluation {
            located: Located { vault, id, item },
            result,
            best_entry,
            host,
            step_up,
            slots,
            quirks,
        })
    }

    pub async fn fill_plan(&self, request: FillRequest) -> Result<FillPlan, CoreError> {
        let client = self.client.lock().await;
        let eval = self.evaluate(&client, &request)?;
        let tier = tier_of(eval.result.level).unwrap_or(MatchTier::Related);
        let fields: Vec<&Field> = eval
            .located
            .item
            .details()
            .sections
            .iter()
            .flat_map(Section::fields)
            .collect();
        Ok(FillPlan {
            step_up: eval.step_up,
            host: (eval.step_up != StepUp::Allow).then(|| eval.host.clone()),
            tier,
            slots: eval
                .slots
                .iter()
                .filter_map(|(purpose, click)| {
                    fields
                        .iter()
                        .find(|f| f.purpose() == Some(*purpose))
                        .map(|f| FillSlot {
                            purpose: purpose_name(*purpose).to_owned(),
                            label: f.label().to_owned(),
                            needs_click: *click,
                        })
                })
                .collect(),
            quirks: quirks_of(&eval.quirks),
        })
    }

    /// What an extension does with a desktop `fill_request` for the active page:
    /// the same match and step-up rules as `fill_plan`, folded into the answer the extension
    /// gives back. The desktop never sees a page or a secret.
    pub async fn browser_fill_decision(
        &self,
        check: BrowserFillCheck,
    ) -> Result<BrowserFillDecision, CoreError> {
        let request = FillRequest {
            vault: check.vault,
            item: check.item,
            origin: check.origin,
            page_url: check.page_url,
            kind: FillKind::Login,
            frame: check.frame,
            approved: false,
            remember_host: false,
            in_iframe_click: false,
        };
        Ok(match self.fill_plan(request).await {
            Ok(plan) if plan.step_up == StepUp::Allow => BrowserFillDecision::Fill,
            Ok(_) => BrowserFillDecision::ConfirmInBrowser,
            Err(CoreError::Locked) => BrowserFillDecision::Locked,
            Err(CoreError::Refused(_)) => BrowserFillDecision::NoMatchingPage,
            Err(_) => BrowserFillDecision::Unavailable,
        })
    }

    /// Releases the secrets for one approved fill. The caller proves the step-up was
    /// shown by setting `approved`; the engine refuses when a step-up applies and it is not set.
    /// The host or item is remembered only when `remember_host` is also set, which only a path
    /// that showed the user that exact host may do: a fill the desktop started never does.
    pub async fn fill_payload(&self, request: FillRequest) -> Result<FillPayload, CoreError> {
        let mut client = self.client.lock().await;
        let eval = self.evaluate(&client, &request)?;
        if eval.step_up != StepUp::Allow && !request.approved {
            return Err(CoreError::Refused("step-up required"));
        }
        if request.approved && request.remember_host {
            match (eval.step_up, request.kind) {
                (StepUp::InlineConfirmHost, FillKind::Login | FillKind::Otp) => {
                    Self::remember_host(&mut client, &eval)?;
                }
                (StepUp::ConfirmPerHost, FillKind::Card | FillKind::Identity) => {
                    let mut list = Self::confirmed_list(&client);
                    let entry = format!("{}@{}", request.item, eval.host);
                    if !list.contains(&entry) {
                        list.push(entry);
                        let raw = serde_json::to_vec(&list)
                            .map_err(|_| CoreError::Internal("confirmed list"))?;
                        client.local_note_put(CONFIRMED, &raw)?;
                    }
                }
                _ => {}
            }
        }
        let now = client.now();
        let mut wait = 0;
        let mut values = Vec::new();
        for (purpose, needs_click) in &eval.slots {
            if *needs_click && !request.in_iframe_click {
                continue;
            }
            let Some(field) = eval
                .located
                .item
                .details()
                .sections
                .iter()
                .flat_map(Section::fields)
                .find(|f| f.purpose() == Some(*purpose))
            else {
                continue;
            };
            let value =
                if let (FillKind::Otp, FieldValue::Otp(params)) = (request.kind, field.value()) {
                    let left = params.seconds_remaining(now)?;
                    if left < OTP_MIN_WINDOW_S {
                        wait = left;
                    }
                    Secret::new(
                        secrecy::ExposeSecret::expose_secret(
                            &params.code_at(now.saturating_add(u64::from(wait)))?,
                        )
                        .as_bytes()
                        .to_vec(),
                    )
                } else {
                    secret_text(field)
                };
            values.push(FillValue {
                purpose: purpose_name(*purpose).to_owned(),
                label: field.label().to_owned(),
                value,
            });
        }
        let settings = Self::settings_sync(&client);
        Ok(FillPayload {
            values,
            otp_wait_seconds: wait,
            autosubmit_allowed: settings.auto_submit && !eval.quirks.no_autosubmit,
        })
    }

    fn remember_host(client: &mut Client<T, S>, eval: &Evaluation) -> Result<(), CoreError> {
        let Some(index) = eval.best_entry else {
            return Ok(());
        };
        let mut parts = client
            .item(&eval.located.vault, &eval.located.id)?
            .into_parts();
        let Some(entry) = parts.urls.get_mut(index) else {
            return Ok(());
        };
        entry.confirm_host(&eval.host)?;
        let updated = Item::new(parts)?;
        client.edit_item(&eval.located.vault, &eval.located.id, &updated)
    }

    pub async fn propose_save(&self, draft: SaveDraft) -> Result<SaveProposal, CoreError> {
        let (host, path) = host_and_path(if draft.page_url.is_empty() {
            &draft.origin
        } else {
            &draft.page_url
        });
        let title = host.strip_prefix("www.").unwrap_or(&host).to_owned();
        let suppressed = |reason: &str| SaveProposal {
            kind: SaveKind::Suppressed,
            vault: None,
            item: None,
            suggested_title: title.clone(),
            username: draft.username.clone(),
            reason: Some(reason.to_owned()),
        };
        let quirks = self.matcher.sites().quirks(&host, &path);
        if quirks.skip_save {
            return Ok(suppressed("skip-save"));
        }
        if quirks.append_2fa {
            return Ok(suppressed("append-2fa"));
        }
        let page = match Origin::parse(&draft.origin) {
            Ok(page) if page.check_fillable().is_ok() => page,
            _ => return Ok(suppressed("insecure-origin")),
        };
        let client = self.client.lock().await;
        let wanted = crate::normalise_login(&draft.username)
            .unwrap_or_else(|_| draft.username.trim().to_lowercase());
        let mut proposal = SaveProposal {
            kind: SaveKind::New,
            vault: client.private_vault().ok().map(|v| ids::hex(v.as_bytes())),
            item: None,
            suggested_title: title.clone(),
            username: draft.username.clone(),
            reason: None,
        };
        for (summary, item) in Self::active_items(&client)? {
            if self.matcher.rank(&page, &item.details().urls).level == MatchLevel::None {
                continue;
            }
            let fields = item.details().sections.iter().flat_map(Section::fields);
            let mut username = None;
            let mut password = None;
            for field in fields {
                match field.purpose() {
                    Some(Purpose::Username) => username = plain_username(field),
                    Some(Purpose::Password) => password = Some(secret_text(field)),
                    _ => {}
                }
            }
            let same_user = username.is_some_and(|name| {
                crate::normalise_login(&name).unwrap_or_else(|_| name.trim().to_lowercase())
                    == wanted
            });
            if !same_user {
                continue;
            }
            proposal.vault = Some(ids::hex(summary.vault_id.as_bytes()));
            proposal.item = Some(ids::hex(summary.item_id.as_bytes()));
            proposal.suggested_title.clone_from(&item.overview().title);
            proposal.kind = if password.is_some_and(|p| p == draft.password) {
                SaveKind::Identical
            } else {
                SaveKind::Update
            };
            return Ok(proposal);
        }
        Ok(proposal)
    }

    pub async fn commit_save(&self, commit: SaveCommit) -> Result<ItemRef, CoreError> {
        match commit.kind {
            SaveKind::Identical | SaveKind::Suppressed => {
                Err(CoreError::Refused("nothing to save"))
            }
            SaveKind::New => {
                let mut draft = self.blank_draft("login")?;
                for field in draft.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
                    match field.purpose.as_deref() {
                        Some("username") => {
                            field.value = Secret::new(commit.draft.username.clone().into_bytes());
                        }
                        Some("password") => field.value = commit.draft.password.clone(),
                        _ => {}
                    }
                }
                draft.title = commit.title;
                draft.urls.push(super::UrlDraft {
                    id: None,
                    url: commit.draft.origin.clone(),
                    mode: "domain".to_owned(),
                    kind: "sign-in".to_owned(),
                });
                self.create_item(&commit.vault, draft).await
            }
            SaveKind::Update => {
                let item = commit
                    .item
                    .ok_or(CoreError::Refused("update needs an item"))?;
                let (vault_id, item_id) = (ids::vault(&commit.vault)?, ids::item(&item)?);
                let mut draft = {
                    let client = self.client.lock().await;
                    draft_of(&client.item(&vault_id, &item_id)?)
                };
                for field in draft.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
                    if field.purpose.as_deref() == Some("password") {
                        field.value = commit.draft.password.clone();
                        field.keep_value = false;
                    }
                }
                self.edit_item(&commit.vault, &item, draft).await?;
                Ok(ItemRef {
                    vault: commit.vault,
                    item,
                })
            }
        }
    }

    pub async fn edit_draft(&self, vault: &str, item: &str) -> Result<super::ItemDraft, CoreError> {
        let (vault_id, item_id) = (ids::vault(vault)?, ids::item(item)?);
        let client = self.client.lock().await;
        Ok(draft_of(&client.item(&vault_id, &item_id)?))
    }
}

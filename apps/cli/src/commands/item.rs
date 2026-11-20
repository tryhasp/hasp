use hasp_core::client::ItemSummary;
use hasp_core::generator::entropy::OsEntropy;
use hasp_core::generator::random::{self, RandomOptions};
use hasp_core::generator::rules::FieldConstraints;
use hasp_core::model::field::{FieldKind, FieldValue, Purpose, Section};
use hasp_core::model::item::{Item, ItemState};
use hasp_core::model::tag::Tag;
use hasp_core::model::template::Templates;
use hasp_core::transport::Transport;
use hasp_crypto::to_hex;
use hasp_proto::payload::ItemState as ListedState;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

use crate::app::{App, Cli};
use crate::cli::{
    ItemCmd, ItemCreateArgs, ItemEditArgs, ItemFlags, ItemListArgs, ItemRef, TemplateCmd,
};
use crate::error::CliError;
use crate::itemspec::{self, Changes, FieldSet};
use crate::output::Format;
use crate::resolve::{self};

fn templates() -> Result<Templates, CliError> {
    Ok(Templates::bundled()?)
}

fn state_name(state: ListedState) -> &'static str {
    match state {
        ListedState::Active => "active",
        ListedState::Archived { .. } => "archived",
        ListedState::Trashed { .. } => "trashed",
    }
}

fn tag_matches(tags: &[String], wanted: &str) -> bool {
    let wanted = wanted.to_lowercase();
    tags.iter().any(|tag| {
        let tag = tag.to_lowercase();
        tag == wanted || tag.starts_with(&format!("{wanted}/"))
    })
}

fn list_filter(args: &ItemListArgs, item: &ItemSummary) -> bool {
    let wanted = if args.trashed {
        "trashed"
    } else if args.archived {
        "archived"
    } else {
        "active"
    };
    state_name(item.overview.state) == wanted
        && args
            .category
            .as_deref()
            .is_none_or(|c| c == item.overview.kind)
        && args
            .tag
            .as_deref()
            .is_none_or(|t| tag_matches(&item.overview.tags, t))
        && (!args.favorite || item.overview.favourite.is_some())
}

pub(crate) async fn run<T: Transport>(app: &App<'_, T>, cmd: ItemCmd) -> Result<(), CliError> {
    match cmd {
        ItemCmd::Template(cmd) => template(app, &cmd),
        ItemCmd::List(args) => list(app, &args).await,
        ItemCmd::Get(args) => get(app, &args.target).await,
        ItemCmd::Create(args) => create(app, args).await,
        ItemCmd::Edit(args) => edit(app, args).await,
        ItemCmd::Delete(args) => {
            let mut client = app.open().await?;
            let (vault, id) =
                resolve::item(&client, args.target.vault.as_deref(), &args.target.item)?;
            if args.permanent {
                client.delete_item(&vault, &id)?;
            } else {
                let item = client.item(&vault, &id)?;
                let now = app.now();
                client.edit_item(
                    &vault,
                    &id,
                    &item.with_state(ItemState::Trashed { at: now }, now),
                )?;
            }
            app.push(&mut client, &[vault]).await?;
            app.out.record(vec![
                ("id", json!(to_hex(id.as_bytes()))),
                ("permanent", json!(args.permanent)),
            ])
        }
        ItemCmd::Archive(target) => set_state(app, &target, Some(true)).await,
        ItemCmd::Restore(target) => set_state(app, &target, None).await,
        ItemCmd::Move(args) => {
            let mut client = app.open().await?;
            let (from, id) =
                resolve::item(&client, args.target.vault.as_deref(), &args.target.item)?;
            let to = resolve::vault(&client, &args.to)?;
            let moved = client
                .move_item(&from, &id, &to, &App::<T>::cancel())
                .await?;
            app.push(&mut client, &[from, to]).await?;
            app.out.record(vec![
                ("id", json!(to_hex(moved.as_bytes()))),
                ("vault", json!(to_hex(to.as_bytes()))),
            ])
        }
        ItemCmd::History(args) => history(app, &args.target, args.restore).await,
        ItemCmd::Totp(target) => totp(app, target).await,
    }
}

fn template<T: Transport>(app: &App<'_, T>, cmd: &TemplateCmd) -> Result<(), CliError> {
    let templates = templates()?;
    match cmd {
        TemplateCmd::List => app.out.list(
            &["id", "name", "fields"],
            templates
                .iter()
                .map(|t| vec![json!(t.id), json!(t.name.en), json!(t.fields().count())])
                .collect(),
        ),
        TemplateCmd::Get { category } => {
            let template = templates
                .resolve(category)
                .map_err(|_| CliError::not_found(format!("no category {category}")))?;
            app.out.list(
                &["key", "label", "kind", "purpose", "required"],
                template
                    .fields()
                    .map(|f| {
                        vec![
                            json!(f.key),
                            json!(f.label.en),
                            json!(itemspec::kind_name(f.kind)),
                            json!(f.purpose.map(itemspec::purpose_name)),
                            json!(f.required),
                        ]
                    })
                    .collect(),
            )
        }
    }
}

async fn list<T: Transport>(app: &App<'_, T>, args: &ItemListArgs) -> Result<(), CliError> {
    let client = app.open().await?;
    let names: std::collections::BTreeMap<_, _> = resolve::active_vaults(&client)?
        .into_iter()
        .map(|v| (v.vault_id, v.name))
        .collect();
    let items = resolve::items_in(&client, args.vault.as_deref())?;
    let rows = items
        .iter()
        .filter(|item| list_filter(args, item))
        .map(|item| {
            vec![
                json!(to_hex(item.item_id.as_bytes())),
                json!(names.get(&item.vault_id)),
                json!(item.overview.title),
                json!(item.overview.kind),
                json!(item.overview.subtitle),
                json!(item.overview.tags),
                json!(item.overview.favourite.is_some()),
                json!(item.overview.client_modified),
                json!(item.pending),
            ]
        })
        .collect();
    app.out.list(
        &[
            "id",
            "vault",
            "title",
            "category",
            "subtitle",
            "tags",
            "favourite",
            "modified",
            "pending",
        ],
        rows,
    )
}

fn item_state_name(state: ItemState) -> &'static str {
    match state {
        ItemState::Active => "active",
        ItemState::Archived { .. } => "archived",
        ItemState::Trashed { .. } => "trashed",
    }
}

async fn get<T: Transport>(app: &App<'_, T>, target: &ItemRef) -> Result<(), CliError> {
    let client = app.open().await?;
    let (vault, id) = resolve::item(&client, target.vault.as_deref(), &target.item)?;
    let item = client.item(&vault, &id)?;
    let overview = item.overview();
    let urls: Vec<Value> = item.details().urls.iter().map(|u| json!(u.url())).collect();
    let attachments: Vec<Value> = item
        .details()
        .attachments
        .iter()
        .map(|a| json!({ "name": a.name, "mime": a.mime, "size": a.size }))
        .collect();
    let fields = itemspec::fields_json(&item, app.out.reveal());
    let tags: Vec<&str> = overview.tags.iter().map(Tag::as_str).collect();
    let mut head = vec![
        ("id", json!(to_hex(id.as_bytes()))),
        ("vault", json!(to_hex(vault.as_bytes()))),
        ("category", json!(overview.kind)),
        ("title", json!(overview.title)),
        ("subtitle", json!(overview.subtitle)),
        ("state", json!(item_state_name(overview.state))),
        ("tags", json!(tags)),
        ("urls", Value::Array(urls)),
        ("notes", json!(item.details().notes)),
        ("created", json!(overview.created)),
        ("modified", json!(overview.client_modified)),
        ("attachments", Value::Array(attachments)),
    ];
    if app.out.format() == Format::Json {
        head.push(("fields", Value::Array(fields)));
        return app.out.record(head);
    }
    app.out.record(head)?;
    app.out.list(
        &["label", "kind", "value"],
        fields
            .iter()
            .map(|f| vec![f["label"].clone(), f["kind"].clone(), f["value"].clone()])
            .collect(),
    )
}

fn changes_from<T: Transport>(
    app: &App<'_, T>,
    flags: ItemFlags,
    category: Option<String>,
) -> Result<Changes, CliError> {
    let mut changes = Changes::default();
    if let Some(source) = &flags.template {
        if source != "-" {
            return Err(CliError::usage(
                "--template reads JSON from stdin: use --template -",
            ));
        }
        if app.opts.password_stdin || !flags.fields_stdin.is_empty() {
            return Err(CliError::usage(
                "--template - takes all of stdin; it cannot combine with other stdin inputs",
            ));
        }
        let bytes = app.env.io.stdin_all()?;
        changes = Changes::from_template(&bytes)?;
    }
    let mut argv = Changes {
        category: category.or(None),
        title: flags.title,
        subtitle: flags.subtitle,
        tags_add: flags.tags,
        tags_remove: flags.untag,
        notes: flags.notes,
        urls_add: flags.urls,
        favourite: flags.favourite,
        fields: Vec::new(),
    };
    for pair in &flags.fields {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| CliError::usage("--field takes KEY=VALUE"))?;
        argv.fields.push(FieldSet {
            key: key.to_owned(),
            value: SecretString::from(value.to_owned()),
            section: None,
            concealed: None,
        });
    }
    for key in &flags.fields_stdin {
        let value = app.read_secret(true, &format!("value for {key}"))?;
        argv.fields.push(FieldSet {
            key: key.clone(),
            value,
            section: None,
            concealed: None,
        });
    }
    if flags.generate_password {
        let generated = random::random(
            &mut OsEntropy,
            &RandomOptions::standard(),
            None,
            FieldConstraints {
                min_length: None,
                max_length: None,
            },
        )
        .map_err(hasp_core::CoreError::from)?;
        argv.fields.push(FieldSet {
            key: "password".to_owned(),
            value: generated,
            section: None,
            concealed: Some(true),
        });
    }
    changes.merge(argv);
    Ok(changes)
}

fn warn_argv_secrets<T: Transport>(app: &App<'_, T>, item: &Item, flags: &[String]) {
    for pair in flags {
        let key = pair.split_once('=').map_or(pair.as_str(), |(key, _)| key);
        let secret = item
            .details()
            .sections
            .iter()
            .flat_map(Section::fields)
            .any(|f| itemspec::field_matches(f, key) && itemspec::is_secret(f));
        if secret {
            app.out.warn(&format!(
                "warning: the value of {key} was passed as an argument; other processes can read it. Use --field-stdin {key}."
            ));
        }
    }
}

async fn create<T: Transport>(app: &App<'_, T>, args: ItemCreateArgs) -> Result<(), CliError> {
    let mut client = app.open().await?;
    let vault = resolve::default_vault(&client, args.vault.as_deref())?;
    let argv_fields = args.flags.fields.clone();
    let mut changes = changes_from(app, args.flags, None)?;
    if changes.category.is_none() {
        changes.category = Some(args.category);
    }
    let item = itemspec::create(&templates()?, &changes, app.now())?;
    warn_argv_secrets(app, &item, &argv_fields);
    let id = client.create_item(&vault, &item)?;
    app.push(&mut client, &[vault]).await?;
    app.out.record(vec![
        ("id", json!(to_hex(id.as_bytes()))),
        ("vault", json!(to_hex(vault.as_bytes()))),
        ("title", json!(item.overview().title)),
    ])
}

async fn edit<T: Transport>(app: &App<'_, T>, args: ItemEditArgs) -> Result<(), CliError> {
    let mut client = app.open().await?;
    let (vault, id) = resolve::item(&client, args.target.vault.as_deref(), &args.target.item)?;
    let argv_fields = args.flags.fields.clone();
    let changes = changes_from(app, args.flags, None)?;
    let current = client.item(&vault, &id)?;
    let edited = itemspec::edit(&templates()?, current, &changes, app.now())?;
    warn_argv_secrets(app, &edited, &argv_fields);
    client.edit_item(&vault, &id, &edited)?;
    app.push(&mut client, &[vault]).await?;
    app.out.record(vec![
        ("id", json!(to_hex(id.as_bytes()))),
        ("title", json!(edited.overview().title)),
    ])
}

async fn set_state<T: Transport>(
    app: &App<'_, T>,
    target: &ItemRef,
    archive: Option<bool>,
) -> Result<(), CliError> {
    let mut client = app.open().await?;
    let (vault, id) = resolve::item(&client, target.vault.as_deref(), &target.item)?;
    let item = client.item(&vault, &id)?;
    let now = app.now();
    let state = if archive == Some(true) {
        ItemState::Archived { at: now }
    } else {
        ItemState::Active
    };
    let updated = item.with_state(state, now);
    let name = item_state_name(state);
    client.edit_item(&vault, &id, &updated)?;
    app.push(&mut client, &[vault]).await?;
    app.out.record(vec![
        ("id", json!(to_hex(id.as_bytes()))),
        ("state", json!(name)),
    ])
}

async fn history<T: Transport>(
    app: &App<'_, T>,
    target: &ItemRef,
    restore: Option<u64>,
) -> Result<(), CliError> {
    let mut client = app.open().await?;
    let (vault, id) = resolve::item(&client, target.vault.as_deref(), &target.item)?;
    if let Some(version) = restore {
        client.restore_version(&vault, &id, version)?;
        app.push(&mut client, &[vault]).await?;
        return app.out.record(vec![
            ("id", json!(to_hex(id.as_bytes()))),
            ("restored_version", json!(version)),
        ]);
    }
    let rows = client
        .history(&vault, &id)?
        .iter()
        .map(|h| vec![json!(h.version), json!(h.title), json!(h.client_modified)])
        .collect();
    app.out.list(&["version", "title", "modified"], rows)
}

pub(crate) async fn totp<T: Transport>(app: &App<'_, T>, target: ItemRef) -> Result<(), CliError> {
    let client: Cli<T> = app.open().await?;
    let (vault, id) = resolve::item(&client, target.vault.as_deref(), &target.item)?;
    let item = client.item(&vault, &id)?;
    let params = item
        .details()
        .sections
        .iter()
        .flat_map(Section::fields)
        .find_map(|f| match f.value() {
            FieldValue::Otp(params)
                if f.purpose() == Some(Purpose::Totp) || f.kind() == FieldKind::Otp =>
            {
                Some(params)
            }
            _ => None,
        })
        .ok_or_else(|| CliError::not_found("the item has no one-time password"))?;
    let now = app.now();
    let code = params.code_at(now).map_err(hasp_core::CoreError::from)?;
    let remaining = params
        .seconds_remaining(now)
        .map_err(hasp_core::CoreError::from)?;
    app.out.record(vec![
        ("code", json!(code.expose_secret())),
        ("seconds_remaining", json!(remaining)),
    ])
}

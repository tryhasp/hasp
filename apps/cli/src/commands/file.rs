use hasp_core::client::NewAttachment;
use hasp_core::model::item::Item;
use hasp_core::transport::Transport;
use hasp_crypto::to_hex;
use hasp_proto::AttId;
use serde_json::json;

use crate::app::{App, Cli};
use crate::cli::{FileCmd, FileGetArgs, FilePutArgs, FileRmArgs, ItemRef};
use crate::error::CliError;
use crate::fsx;
use crate::resolve;

fn find<'a>(
    item: &'a Item,
    name: &str,
) -> Result<&'a hasp_core::model::item::AttachmentDesc, CliError> {
    item.details()
        .attachments
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| CliError::not_found(format!("no file {name}")))
}

fn mime_of(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_lowercase)
        .as_deref()
    {
        Some("txt") => "text/plain",
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}

pub(crate) async fn run<T: Transport>(app: &App<'_, T>, cmd: FileCmd) -> Result<(), CliError> {
    let mut client = app.open().await?;
    match cmd {
        FileCmd::List(target) => list(app, &client, &target),
        FileCmd::Put(args) => put(app, &mut client, &args).await,
        FileCmd::Get(args) => get(app, &mut client, &args).await,
        FileCmd::Rm(args) => remove(app, &mut client, &args).await,
    }
}

fn list<T: Transport>(app: &App<'_, T>, client: &Cli<T>, target: &ItemRef) -> Result<(), CliError> {
    let (vault, id) = resolve::item(client, target.vault.as_deref(), &target.item)?;
    let rows = client
        .item(&vault, &id)?
        .details()
        .attachments
        .iter()
        .map(|a| vec![json!(a.name), json!(a.mime), json!(a.size)])
        .collect();
    app.out.list(&["name", "mime", "size"], rows)
}

async fn put<T: Transport>(
    app: &App<'_, T>,
    client: &mut Cli<T>,
    args: &FilePutArgs,
) -> Result<(), CliError> {
    let (vault, id) = resolve::item(client, args.target.vault.as_deref(), &args.target.item)?;
    let data = zeroize::Zeroizing::new(std::fs::read(&args.path)?);
    let name = args
        .name
        .clone()
        .or_else(|| {
            args.path
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_owned)
        })
        .ok_or_else(|| CliError::usage("the file needs a --name"))?;
    let mime = args
        .mime
        .clone()
        .unwrap_or_else(|| mime_of(&args.path).to_owned());
    let attachment = NewAttachment {
        name: &name,
        mime: &mime,
        data: &data,
    };
    let info = client
        .attach_file(&vault, &id, &attachment, &App::<T>::cancel())
        .await?;
    app.push(client, &[vault]).await?;
    app.out.record(vec![
        ("name", json!(info.name)),
        ("size", json!(info.size)),
        ("id", json!(to_hex(info.att_id.as_bytes()))),
    ])
}

async fn get<T: Transport>(
    app: &App<'_, T>,
    client: &mut Cli<T>,
    args: &FileGetArgs,
) -> Result<(), CliError> {
    let (vault, id) = resolve::item(client, args.target.vault.as_deref(), &args.target.item)?;
    let item = client.item(&vault, &id)?;
    let att = AttId::from_bytes(*find(&item, &args.name)?.att_id.as_bytes());
    let data = client
        .download_attachment(&vault, &id, &att, &App::<T>::cancel())
        .await?;
    match &args.out {
        Some(path) => {
            fsx::write_private(path, &data)?;
            app.out.record(vec![
                ("written", json!(path.display().to_string())),
                ("size", json!(data.len())),
            ])
        }
        None => app.out.raw(&data),
    }
}

async fn remove<T: Transport>(
    app: &App<'_, T>,
    client: &mut Cli<T>,
    args: &FileRmArgs,
) -> Result<(), CliError> {
    let (vault, id) = resolve::item(client, args.target.vault.as_deref(), &args.target.item)?;
    let item = client.item(&vault, &id)?;
    find(&item, &args.name)?;
    let mut parts = item.into_parts();
    parts.attachments.retain(|a| a.name != args.name);
    parts.client_modified = app.now();
    client.edit_item(&vault, &id, &Item::new(parts)?)?;
    app.push(client, &[vault]).await?;
    app.out.record(vec![("removed", json!(args.name))])
}

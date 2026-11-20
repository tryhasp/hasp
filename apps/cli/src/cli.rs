use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent command line switches"
)]
#[command(
    name = "hasp",
    version,
    about = "hasp password manager",
    disable_help_subcommand = true
)]
pub(crate) struct Cli {
    #[arg(long, global = true, value_name = "DIR")]
    pub(crate) data_dir: Option<PathBuf>,
    #[arg(long, global = true, value_enum)]
    pub(crate) format: Option<FormatArg>,
    #[arg(long, global = true, conflicts_with = "format")]
    pub(crate) json: bool,
    #[arg(long, short, global = true)]
    pub(crate) quiet: bool,
    #[arg(long, global = true)]
    pub(crate) reveal: bool,
    #[arg(long, global = true)]
    pub(crate) no_input: bool,
    #[arg(long, global = true)]
    pub(crate) offline: bool,
    #[arg(
        long,
        global = true,
        help = "read the account password from the first stdin line"
    )]
    pub(crate) password_stdin: bool,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum FormatArg {
    Table,
    Json,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    #[command(about = "create an account with a signup code")]
    Signup(SignupArgs),
    #[command(about = "sign in with the Secret Key, or enrol through another device")]
    Signin(SigninArgs),
    #[command(about = "remove this device's account and local data")]
    Signout,
    #[command(about = "show the signed-in login, server and fingerprint")]
    Whoami,
    #[command(about = "lock this device")]
    Lock,
    #[command(about = "check the password or device key and reset the lock timers")]
    Unlock,
    #[command(about = "show sign-in, unlock method and lock policy state")]
    Status,
    #[command(about = "account recovery, password and device enrolment")]
    #[command(subcommand)]
    Account(AccountCmd),
    #[command(about = "list and revoke signed-in devices")]
    #[command(subcommand, alias = "session")]
    Devices(DevicesCmd),
    #[command(about = "vaults, sharing and members")]
    #[command(subcommand)]
    Vault(VaultCmd),
    #[command(about = "items")]
    #[command(subcommand)]
    Item(ItemCmd),
    #[command(about = "item attachments")]
    #[command(subcommand)]
    File(FileCmd),
    #[command(about = "print one value from a hasp:// secret reference")]
    Read(ReadArgs),
    #[command(about = "print the current one-time password of an item")]
    Otp(ItemRef),
    #[command(about = "generate a password, passphrase or PIN")]
    Generate(GenerateArgs),
    #[command(about = "import from 1Password, Bitwarden or CSV")]
    #[command(subcommand)]
    Import(ImportCmd),
    #[command(about = "write an encrypted .haspx export")]
    Export(ExportArgs),
    #[command(about = "unattended backups")]
    #[command(subcommand)]
    Backup(BackupCmd),
    #[command(about = "restore a .haspx export or backup into this account")]
    Restore(RestoreArgs),
    #[command(about = "pull and push changes now")]
    Sync,
    #[command(about = "server administration")]
    #[command(subcommand)]
    Admin(AdminCmd),
}

#[derive(Debug, Args)]
pub(crate) struct SignupArgs {
    #[arg(long)]
    pub(crate) origin: String,
    #[arg(long)]
    pub(crate) login: String,
    #[arg(
        long,
        value_name = "SGN1-CODE",
        conflicts_with = "code_stdin",
        help = "visible in the process list; prefer --code-stdin or the prompt"
    )]
    pub(crate) code: Option<String>,
    #[arg(long, help = "read the signup code from stdin (before the password)")]
    pub(crate) code_stdin: bool,
    #[arg(
        long,
        value_name = "FINGERPRINT",
        help = "the server fingerprint printed by `haspd init`; asked for when omitted"
    )]
    pub(crate) server_fingerprint: Option<String>,
    #[arg(long, value_name = "FILE")]
    pub(crate) kit_out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct SigninArgs {
    #[arg(long)]
    pub(crate) origin: Option<String>,
    #[arg(long)]
    pub(crate) login: Option<String>,
    #[arg(long, help = "read the Secret Key from stdin (before the password)")]
    pub(crate) secret_key_stdin: bool,
    #[arg(
        long,
        value_name = "ENR1-CODE",
        conflicts_with = "enrol_stdin",
        help = "enrol through another signed-in device; visible in the process list, prefer --enrol-stdin"
    )]
    pub(crate) enrol: Option<String>,
    #[arg(
        long,
        help = "read the enrolment code from stdin (before the password)"
    )]
    pub(crate) enrol_stdin: bool,
    #[arg(
        long,
        value_name = "FINGERPRINT",
        help = "the server fingerprint printed on the kit; asked for when omitted"
    )]
    pub(crate) server_fingerprint: Option<String>,
    #[arg(long, value_name = "FILE", help = "write the new kit to FILE")]
    pub(crate) kit_out: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AccountCmd {
    RecoveryCode(RecoveryArgs),
    Password(PasswordArgs),
    Enrol(EnrolArgs),
    #[command(about = "write the Emergency Kit of this account as text and a printable PDF")]
    EmergencyKit(KitArgs),
    #[command(about = "after the server lost its key: register again with the operator's code")]
    Reregister(ReregisterArgs),
    Delete(DeleteArgs),
}

#[derive(Debug, Args)]
pub(crate) struct KitArgs {
    #[arg(long, value_name = "FILE", help = "write the printable PDF to FILE")]
    pub(crate) pdf_out: Option<PathBuf>,
    #[arg(long, value_name = "FILE", help = "write the kit text to FILE")]
    pub(crate) text_out: Option<PathBuf>,
    #[arg(
        long,
        help = "read the last Secret Key group from stdin after the password"
    )]
    pub(crate) last_group_stdin: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ReregisterArgs {
    #[arg(
        long,
        value_name = "CODE",
        conflicts_with = "code_stdin",
        help = "the code from `haspd admin reregister`; visible in the process list, prefer --code-stdin"
    )]
    pub(crate) code: Option<String>,
    #[arg(long, help = "read the code from stdin (before the password)")]
    pub(crate) code_stdin: bool,
    #[arg(
        long,
        value_name = "FINGERPRINT",
        help = "the new server fingerprint from `haspd fingerprint`"
    )]
    pub(crate) server_fingerprint: String,
}

#[derive(Debug, Args)]
pub(crate) struct RecoveryArgs {
    #[command(subcommand)]
    pub(crate) action: RecoveryAction,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RecoveryAction {
    Create,
    Use(RecoveryUse),
}

#[derive(Debug, Args)]
pub(crate) struct RecoveryUse {
    #[arg(long)]
    pub(crate) origin: String,
    #[arg(long)]
    pub(crate) login: String,
    #[arg(
        long,
        help = "read the recovery code from stdin before the new password"
    )]
    pub(crate) code_stdin: bool,
    #[arg(long, help = "keep waiting for the delay instead of exiting")]
    pub(crate) wait: bool,
    #[arg(long, help = "drop a saved recovery and start again")]
    pub(crate) restart: bool,
}

#[derive(Debug, Args)]
pub(crate) struct PasswordArgs {
    #[arg(long, help = "read the new password from stdin after the current one")]
    pub(crate) new_password_stdin: bool,
    #[arg(long)]
    pub(crate) new_secret_key: bool,
}

#[derive(Debug, Args)]
pub(crate) struct EnrolArgs {
    #[arg(long, help = "read the code shown on the new device from stdin")]
    pub(crate) code_stdin: bool,
}

#[derive(Debug, Args)]
pub(crate) struct DeleteArgs {
    #[arg(long)]
    pub(crate) yes: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum DevicesCmd {
    List,
    Revoke { device: String },
}

#[derive(Debug, Subcommand)]
pub(crate) enum VaultCmd {
    List,
    Get {
        vault: String,
    },
    Create {
        name: String,
    },
    Share(ShareArgs),
    Join {
        code: String,
    },
    #[command(subcommand)]
    Members(MembersCmd),
    Leave {
        vault: String,
    },
    Dissolve(DissolveArgs),
    Bump {
        vault: String,
    },
    AcceptRollback(AcceptRollbackArgs),
    HeadCode {
        vault: Option<String>,
    },
    Confirm(ConfirmArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ShareArgs {
    pub(crate) vault: String,
    #[arg(long, value_enum, default_value = "editor")]
    pub(crate) role: RoleArg,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum RoleArg {
    Viewer,
    Editor,
    Owner,
}

#[derive(Debug, Subcommand)]
pub(crate) enum MembersCmd {
    List { vault: String },
    Pending { vault: String },
    Add(AddMemberArgs),
    SetRole(SetRoleArgs),
    Remove(RemoveMemberArgs),
}

#[derive(Debug, Args)]
pub(crate) struct AddMemberArgs {
    pub(crate) vault: String,
    pub(crate) invite: String,
    #[arg(
        long,
        value_name = "FINGERPRINT",
        help = "the fingerprint the invitee read out"
    )]
    pub(crate) fingerprint: Option<String>,
    #[arg(long, help = "admit without comparing fingerprints")]
    pub(crate) not_compared: bool,
}

#[derive(Debug, Args)]
pub(crate) struct SetRoleArgs {
    pub(crate) vault: String,
    pub(crate) member: String,
    #[arg(value_enum)]
    pub(crate) role: RoleArg,
}

#[derive(Debug, Args)]
pub(crate) struct RemoveMemberArgs {
    pub(crate) vault: String,
    pub(crate) member: String,
}

#[derive(Debug, Args)]
pub(crate) struct DissolveArgs {
    pub(crate) vault: String,
    #[arg(
        long,
        value_name = "NAME",
        help = "the vault name, typed again to confirm"
    )]
    pub(crate) confirm: String,
}

#[derive(Debug, Args)]
pub(crate) struct AcceptRollbackArgs {
    pub(crate) vault: String,
    #[arg(
        long,
        help = "confirm the server was restored to older data on purpose"
    )]
    pub(crate) yes: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ConfirmArgs {
    pub(crate) vault: String,
    #[arg(long)]
    pub(crate) seq: u64,
    #[arg(long)]
    pub(crate) code: String,
}

#[derive(Debug, Args)]
pub(crate) struct ItemRef {
    pub(crate) item: String,
    #[arg(long)]
    pub(crate) vault: Option<String>,
}

#[derive(Debug, Args, Default)]
pub(crate) struct ItemFlags {
    #[arg(long)]
    pub(crate) title: Option<String>,
    #[arg(long)]
    pub(crate) subtitle: Option<String>,
    #[arg(long = "tag")]
    pub(crate) tags: Vec<String>,
    #[arg(long = "untag")]
    pub(crate) untag: Vec<String>,
    #[arg(long)]
    pub(crate) notes: Option<String>,
    #[arg(long = "url")]
    pub(crate) urls: Vec<String>,
    #[arg(long)]
    pub(crate) favourite: Option<bool>,
    #[arg(
        long = "field",
        value_name = "KEY=VALUE",
        help = "a field value; a secret on argv is warned about"
    )]
    pub(crate) fields: Vec<String>,
    #[arg(
        long = "field-stdin",
        value_name = "KEY",
        help = "read this field's value from stdin"
    )]
    pub(crate) fields_stdin: Vec<String>,
    #[arg(long, help = "read the item as JSON from stdin")]
    pub(crate) template: Option<String>,
    #[arg(long)]
    pub(crate) generate_password: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ItemCmd {
    List(ItemListArgs),
    Get(ItemGetArgs),
    Create(ItemCreateArgs),
    Edit(ItemEditArgs),
    Delete(ItemDeleteArgs),
    Archive(ItemRef),
    Restore(ItemRef),
    Move(ItemMoveArgs),
    History(ItemHistoryArgs),
    Totp(ItemRef),
    #[command(subcommand)]
    Template(TemplateCmd),
}

#[derive(Debug, Args)]
pub(crate) struct ItemListArgs {
    #[arg(long)]
    pub(crate) vault: Option<String>,
    #[arg(long)]
    pub(crate) tag: Option<String>,
    #[arg(long)]
    pub(crate) category: Option<String>,
    #[arg(long)]
    pub(crate) favorite: bool,
    #[arg(long)]
    pub(crate) archived: bool,
    #[arg(long)]
    pub(crate) trashed: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ItemGetArgs {
    #[command(flatten)]
    pub(crate) target: ItemRef,
}

#[derive(Debug, Args)]
pub(crate) struct ItemCreateArgs {
    #[arg(long, default_value = "login")]
    pub(crate) category: String,
    #[arg(long)]
    pub(crate) vault: Option<String>,
    #[command(flatten)]
    pub(crate) flags: ItemFlags,
}

#[derive(Debug, Args)]
pub(crate) struct ItemEditArgs {
    #[command(flatten)]
    pub(crate) target: ItemRef,
    #[command(flatten)]
    pub(crate) flags: ItemFlags,
}

#[derive(Debug, Args)]
pub(crate) struct ItemDeleteArgs {
    #[command(flatten)]
    pub(crate) target: ItemRef,
    #[arg(long)]
    pub(crate) permanent: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ItemMoveArgs {
    #[command(flatten)]
    pub(crate) target: ItemRef,
    #[arg(long)]
    pub(crate) to: String,
}

#[derive(Debug, Args)]
pub(crate) struct ItemHistoryArgs {
    #[command(flatten)]
    pub(crate) target: ItemRef,
    #[arg(long, value_name = "VERSION")]
    pub(crate) restore: Option<u64>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum TemplateCmd {
    List,
    Get { category: String },
}

#[derive(Debug, Subcommand)]
pub(crate) enum FileCmd {
    Put(FilePutArgs),
    Get(FileGetArgs),
    Rm(FileRmArgs),
    List(ItemRef),
}

#[derive(Debug, Args)]
pub(crate) struct FilePutArgs {
    #[command(flatten)]
    pub(crate) target: ItemRef,
    pub(crate) path: PathBuf,
    #[arg(long)]
    pub(crate) name: Option<String>,
    #[arg(long)]
    pub(crate) mime: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct FileGetArgs {
    #[command(flatten)]
    pub(crate) target: ItemRef,
    pub(crate) name: String,
    #[arg(long, value_name = "FILE")]
    pub(crate) out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct FileRmArgs {
    #[command(flatten)]
    pub(crate) target: ItemRef,
    pub(crate) name: String,
}

#[derive(Debug, Args)]
pub(crate) struct ReadArgs {
    pub(crate) reference: String,
    #[arg(long)]
    pub(crate) newline: bool,
    #[arg(long, value_name = "FILE")]
    pub(crate) out_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent command line switches"
)]
pub(crate) struct GenerateArgs {
    #[arg(long)]
    pub(crate) length: Option<u32>,
    #[arg(long, conflicts_with_all = ["pin", "rules"])]
    pub(crate) memorable: bool,
    #[arg(long, conflicts_with_all = ["memorable", "rules"])]
    pub(crate) pin: bool,
    #[arg(long, value_name = "RULES", conflicts_with_all = ["memorable", "pin"])]
    pub(crate) rules: Option<String>,
    #[arg(long)]
    pub(crate) no_symbols: bool,
    #[arg(long)]
    pub(crate) exclude_ambiguous: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ImportCmd {
    #[command(name = "1pux")]
    Onepux(ImportArgs),
    Bitwarden(ImportArgs),
    Csv(ImportArgs),
    #[command(subcommand)]
    Report(ReportCmd),
}

#[derive(Debug, Args)]
pub(crate) struct ImportArgs {
    pub(crate) file: PathBuf,
    #[arg(long, help = "preview only")]
    pub(crate) dry_run: bool,
    #[arg(long, help = "commit after the preview without asking")]
    pub(crate) yes: bool,
    #[arg(long, value_name = "FILE")]
    pub(crate) report_out: Option<PathBuf>,
    #[arg(long, help = "delete the source file after a successful import")]
    pub(crate) delete_source: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ReportCmd {
    List,
    Show {
        id: String,
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub(crate) struct ExportArgs {
    #[arg(long, value_name = "FILE")]
    pub(crate) out: PathBuf,
    #[arg(
        long,
        help = "read the passphrase from stdin after the account password"
    )]
    pub(crate) passphrase_stdin: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum BackupCmd {
    Enable(PassphraseArgs),
    Now {
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
}

#[derive(Debug, Args)]
pub(crate) struct PassphraseArgs {
    #[arg(long, help = "read the passphrase from stdin")]
    pub(crate) passphrase_stdin: bool,
}

#[derive(Debug, Args)]
pub(crate) struct RestoreArgs {
    pub(crate) file: PathBuf,
    #[arg(long, help = "read the passphrase from stdin")]
    pub(crate) passphrase_stdin: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AdminCmd {
    #[command(subcommand)]
    Token(TokenCmd),
}

#[derive(Debug, Subcommand)]
pub(crate) enum TokenCmd {
    Create,
}

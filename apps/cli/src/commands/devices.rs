use hasp_core::transport::Transport;
use hasp_crypto::to_hex;
use serde_json::json;

use crate::app::App;
use crate::cli::DevicesCmd;
use crate::error::CliError;

pub(crate) async fn run<T: Transport>(app: &App<'_, T>, cmd: DevicesCmd) -> Result<(), CliError> {
    let mut client = app.open().await?;
    let cancel = App::<T>::cancel();
    let devices = client.devices(&cancel).await?;
    match cmd {
        DevicesCmd::List => app.out.list(
            &[
                "session",
                "device",
                "platform",
                "label",
                "current",
                "recognised",
                "revoked",
            ],
            devices
                .iter()
                .map(|d| {
                    vec![
                        json!(to_hex(d.session_id.as_bytes())),
                        json!(to_hex(d.device_id.as_bytes())),
                        json!(d.platform),
                        json!(d.label),
                        json!(d.current),
                        json!(d.recognised),
                        json!(d.revoked),
                    ]
                })
                .collect(),
        ),
        DevicesCmd::Revoke { device } => {
            let wanted = device.to_lowercase();
            let matched: Vec<_> = devices
                .iter()
                .filter(|d| {
                    to_hex(d.session_id.as_bytes()).starts_with(&wanted)
                        || to_hex(d.device_id.as_bytes()).starts_with(&wanted)
                })
                .collect();
            let target = match matched.as_slice() {
                [one] => *one,
                [] => return Err(CliError::not_found(format!("no device {device}"))),
                many => {
                    return Err(CliError::ambiguous(
                        &format!("device {device}"),
                        many.iter()
                            .map(|d| format!("{} ({})", to_hex(d.device_id.as_bytes()), d.platform))
                            .collect(),
                    ));
                }
            };
            if target.current {
                return Err(CliError::usage(
                    "this is the current device; use `hasp signout`",
                ));
            }
            client
                .revoke_device(&target.session_id, &target.device_id, &cancel)
                .await?;
            app.out.record(vec![(
                "revoked",
                json!(to_hex(target.device_id.as_bytes())),
            )])
        }
    }
}

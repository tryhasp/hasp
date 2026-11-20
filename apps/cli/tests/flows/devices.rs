use super::*;

#[test]
fn devices_list_and_revoke() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", false);
    let listed = unlocked(&device, &["devices", "list"]).ok().data();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["current"], true);
    let own = listed[0]["device"].as_str().unwrap().to_owned();
    let refused = unlocked(&device, &["devices", "revoke", &own]);
    assert_eq!(refused.code, 2);
    assert_eq!(
        unlocked(&device, &["devices", "revoke", "ffffffff"]).code,
        4
    );
}

#[test]
fn qr_enrolment_joins_a_second_device() {
    let mut world = World::new();
    let first = signed_up(&mut world, "ada", false);
    create_login(&first, "GitHub", "enrol-me-12345");
    let second = Device::new(&world, false);
    let (code_sender, code_receiver) = std::sync::mpsc::channel::<String>();
    let (password_sender, password_receiver) = std::sync::mpsc::channel::<String>();
    let (first_input, first_receiver) = std::sync::mpsc::channel::<String>();
    first_input.send(PASSWORD.to_owned()).unwrap();
    drop(first_input);

    let first_outcome = std::thread::scope(|scope| {
        let first = &first;
        let initiator = scope.spawn(move || {
            first.run_with(
                &["--password-stdin", "account", "enrol", "--code-stdin"],
                join_streams(first_receiver, code_receiver),
            )
        });
        let enrol_code = harness::wait_for_line(first, |line| {
            line.starts_with("ENR1-").then(|| line.to_owned())
        });
        let second = &second;
        password_sender.send(enrol_code).unwrap();
        password_sender.send(PASSWORD.to_owned()).unwrap();
        drop(password_sender);
        let joiner = scope.spawn(move || {
            second.run_with(
                &[
                    "--password-stdin",
                    "signin",
                    "--origin",
                    ORIGIN,
                    "--enrol-stdin",
                ],
                password_receiver,
            )
        });
        let typed = harness::wait_for_line(second, |line| {
            line.split("signed-in device: ").nth(1).map(str::to_owned)
        });
        code_sender.send(typed).unwrap();
        let finished = joiner.join().unwrap();
        assert_eq!(finished.code, 0, "{}", finished.err);
        initiator.join().unwrap()
    });
    assert_eq!(first_outcome.code, 0, "{}", first_outcome.err);
    let listed = second.run(&["--password-stdin", "item", "list"], &[PASSWORD]);
    assert_eq!(listed.code, 0, "{}", listed.err);
    assert_eq!(listed.data().as_array().unwrap().len(), 1);
}

#[test]
fn a_refused_enrolment_stops_the_joiner_at_once() {
    let mut world = World::new();
    let first = signed_up(&mut world, "ada", false);
    let second = Device::new(&world, false);
    let (code_sender, code_receiver) = std::sync::mpsc::channel::<String>();
    let (password_sender, password_receiver) = std::sync::mpsc::channel::<String>();
    let (first_input, first_receiver) = std::sync::mpsc::channel::<String>();
    first_input.send(PASSWORD.to_owned()).unwrap();
    drop(first_input);

    let (initiator_outcome, joiner_outcome) = std::thread::scope(|scope| {
        let first = &first;
        let initiator = scope.spawn(move || {
            first.run_with(
                &["--password-stdin", "account", "enrol", "--code-stdin"],
                join_streams(first_receiver, code_receiver),
            )
        });
        let enrol_code = harness::wait_for_line(first, |line| {
            line.starts_with("ENR1-").then(|| line.to_owned())
        });
        let second = &second;
        password_sender.send(enrol_code).unwrap();
        password_sender.send(PASSWORD.to_owned()).unwrap();
        drop(password_sender);
        let joiner = scope.spawn(move || {
            second.run_with(
                &[
                    "--password-stdin",
                    "signin",
                    "--origin",
                    ORIGIN,
                    "--enrol-stdin",
                ],
                password_receiver,
            )
        });
        harness::wait_for_line(second, |line| {
            line.split("signed-in device: ").nth(1).map(str::to_owned)
        });
        code_sender.send("000000".to_owned()).unwrap();
        (initiator.join().unwrap(), joiner.join().unwrap())
    });
    assert_ne!(initiator_outcome.code, 0);
    assert_eq!(joiner_outcome.code, 8, "{}", joiner_outcome.err);
    assert!(joiner_outcome.err.contains("refused or cancelled"));
    assert_eq!(second.run(&["status"], &[]).data()["signed_in"], false);
}

fn join_streams(
    first: std::sync::mpsc::Receiver<String>,
    second: std::sync::mpsc::Receiver<String>,
) -> std::sync::mpsc::Receiver<String> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in first {
            if sender.send(line).is_err() {
                return;
            }
        }
        for line in second {
            if sender.send(line).is_err() {
                return;
            }
        }
    });
    receiver
}

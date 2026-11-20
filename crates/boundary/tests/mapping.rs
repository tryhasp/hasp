use hasp_boundary::hasp_error;
use hasp_crypto::CryptoError;
use hasp_proto::ProtoError;
use hasp_replay::ReplayError;

hasp_error! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
}

#[test]
fn every_variant_is_listed_once() {
    let mut names: Vec<String> = HaspError::ALL.iter().map(|e| format!("{e:?}")).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), HaspError::ALL.len());
}

#[test]
fn proto_errors_keep_their_protocol_code() {
    let cases = [
        (ProtoError::Format, HaspError::Format),
        (ProtoError::Version, HaspError::Version),
        (ProtoError::Sig, HaspError::Sig),
        (ProtoError::Aead, HaspError::Aead),
        (ProtoError::Pin, HaspError::Pin),
        (ProtoError::Rollback, HaspError::Rollback),
        (ProtoError::Fork, HaspError::Fork),
        (ProtoError::Roster, HaspError::Roster),
        (ProtoError::KdfParams, HaspError::KdfParams),
        (ProtoError::Epoch, HaspError::Epoch),
        (ProtoError::Root, HaspError::Root),
        (ProtoError::Authz, HaspError::Authz),
        (ProtoError::Invite, HaspError::Invite),
    ];
    for (source, expected) in cases {
        assert_eq!(HaspError::from(source), expected);
    }
}

#[test]
fn crypto_errors_do_not_reveal_their_cause() {
    assert_eq!(HaspError::from(CryptoError::Signature), HaspError::Sig);
    assert_eq!(HaspError::from(CryptoError::Aead), HaspError::Aead);
    assert_eq!(HaspError::from(CryptoError::Length), HaspError::Format);
    assert_eq!(HaspError::from(CryptoError::Random), HaspError::Internal);
}

#[test]
fn replay_errors_collapse_to_internal_unless_they_carry_a_code() {
    assert_eq!(HaspError::from(ReplayError::Group), HaspError::Internal);
    assert_eq!(
        HaspError::from(ReplayError::Proto(ProtoError::Pin)),
        HaspError::Pin
    );
}

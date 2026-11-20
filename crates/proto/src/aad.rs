use crate::ProtoError;
use crate::cbor::Writer;
use crate::id::{AccountId, AttId, DeviceId, Hash32, ItemId, VaultId};
use crate::record::account::KdfWire;
use crate::uint::{Epoch, Uint53, Version};

const AAD_VERSION: u64 = 1;
const FIELD_OVERVIEW: u8 = 1;
const FIELD_DETAILS: u8 = 2;
const FIELD_ITEM_KEY_WRAP: u8 = 3;
const FIELD_ATTACHMENT: u8 = 4;
const FIELD_AK_WRAP: u8 = 1;
const FIELD_KEYS: u8 = 2;
const FIELD_RC_WRAP: u8 = 1;
const FIELD_SESSION_LABEL: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rtype {
    Account,
    Keyset,
    Roster,
    Manifest,
    ItemPayload,
    ItemKeyWrap,
    AttachmentChunk,
    Share,
    Recovery,
    SelfWrap,
    DeviceLocal,
    EnrolmentChannel,
    ExportStream,
    AccountMeta,
    VaultDissolve,
    LeaveRequest,
}

impl Rtype {
    pub fn code(self) -> u8 {
        match self {
            Self::Account => 1,
            Self::Keyset => 2,
            Self::Roster => 3,
            Self::Manifest => 4,
            Self::ItemPayload => 5,
            Self::ItemKeyWrap => 6,
            Self::AttachmentChunk => 7,
            Self::Share => 8,
            Self::Recovery => 9,
            Self::SelfWrap => 10,
            Self::DeviceLocal => 11,
            Self::EnrolmentChannel => 12,
            Self::ExportStream => 13,
            Self::AccountMeta => 14,
            Self::VaultDissolve => 15,
            Self::LeaveRequest => 16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalField {
    AkBio,
    Sk,
    Session,
    AkPw,
    SessionPw,
    ExtAk,
    ExtSession,
    ExtKey,
}

impl LocalField {
    fn code(self) -> u8 {
        match self {
            Self::AkBio => 1,
            Self::Sk => 2,
            Self::Session => 3,
            Self::AkPw => 4,
            Self::SessionPw => 5,
            Self::ExtAk => 6,
            Self::ExtSession => 7,
            Self::ExtKey => 8,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtraValue {
    Uint(Uint53),
    Id([u8; 16]),
    Hash(Hash32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Extra {
    List(Vec<ExtraValue>),
    Hash(Hash32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct Aad {
    rtype: Rtype,
    account: Option<AccountId>,
    vault: Option<VaultId>,
    item: Option<ItemId>,
    field: Option<u8>,
    epoch: Option<Uint53>,
    ver: Option<Uint53>,
    extra: Option<Extra>,
}

impl Aad {
    pub fn new(rtype: Rtype) -> Self {
        Self {
            rtype,
            account: None,
            vault: None,
            item: None,
            field: None,
            epoch: None,
            ver: None,
            extra: None,
        }
    }

    pub fn account(mut self, id: AccountId) -> Self {
        self.account = Some(id);
        self
    }

    pub fn vault(mut self, id: VaultId) -> Self {
        self.vault = Some(id);
        self
    }

    pub fn item(mut self, id: ItemId) -> Self {
        self.item = Some(id);
        self
    }

    pub fn field(mut self, field: u8) -> Self {
        self.field = Some(field);
        self
    }

    pub fn epoch(mut self, epoch: Epoch) -> Self {
        self.epoch = Some(epoch.uint());
        self
    }

    pub fn version(mut self, ver: Version) -> Self {
        self.ver = Some(ver.uint());
        self
    }

    pub fn extra(mut self, extra: Extra) -> Self {
        self.extra = Some(extra);
        self
    }

    pub fn ak_wrap(account: AccountId, kdf: &KdfWire, generation: Uint53) -> Self {
        Self::new(Rtype::Keyset)
            .account(account)
            .field(FIELD_AK_WRAP)
            .extra(Extra::List(vec![
                ExtraValue::Uint(generation),
                ExtraValue::Uint(Uint53::from(kdf.m)),
                ExtraValue::Uint(Uint53::from(kdf.t)),
                ExtraValue::Uint(Uint53::from(kdf.p)),
            ]))
    }

    pub fn keyset_keys(account: AccountId, generation: Uint53) -> Self {
        Self::new(Rtype::Keyset)
            .account(account)
            .field(FIELD_KEYS)
            .extra(Extra::List(vec![ExtraValue::Uint(generation)]))
    }

    pub fn item_overview(vault: VaultId, item: ItemId, ver: Version) -> Self {
        Self::item_payload(vault, item, ver, FIELD_OVERVIEW)
    }

    pub fn item_details(vault: VaultId, item: ItemId, ver: Version) -> Self {
        Self::item_payload(vault, item, ver, FIELD_DETAILS)
    }

    pub fn item_key_wrap(vault: VaultId, item: ItemId, epoch: Epoch, ver: Version) -> Self {
        Self::new(Rtype::ItemKeyWrap)
            .vault(vault)
            .item(item)
            .field(FIELD_ITEM_KEY_WRAP)
            .epoch(epoch)
            .version(ver)
    }

    pub fn attachment_chunk(vault: VaultId, item: ItemId, att: AttId, chunk_size: Uint53) -> Self {
        Self::new(Rtype::AttachmentChunk)
            .vault(vault)
            .item(item)
            .field(FIELD_ATTACHMENT)
            .extra(Extra::List(vec![
                ExtraValue::Id(*att.as_bytes()),
                ExtraValue::Uint(chunk_size),
            ]))
    }

    pub fn self_wrap(account: AccountId, vault: VaultId, epoch: Epoch) -> Self {
        Self::new(Rtype::SelfWrap)
            .account(account)
            .vault(vault)
            .epoch(epoch)
    }

    pub fn recovery_wrap(account: AccountId, rgen: Uint53) -> Self {
        let mut aad = Self::new(Rtype::Recovery)
            .account(account)
            .field(FIELD_RC_WRAP);
        aad.epoch = Some(rgen);
        aad
    }

    pub fn device_local(
        account: AccountId,
        field: LocalField,
        device: DeviceId,
        local_gen: Uint53,
    ) -> Self {
        Self::new(Rtype::DeviceLocal)
            .account(account)
            .field(field.code())
            .extra(Extra::List(vec![
                ExtraValue::Id(*device.as_bytes()),
                ExtraValue::Uint(local_gen),
            ]))
    }

    pub fn account_meta(account: AccountId, device: DeviceId) -> Self {
        Self::new(Rtype::AccountMeta)
            .account(account)
            .field(FIELD_SESSION_LABEL)
            .extra(Extra::List(vec![ExtraValue::Id(*device.as_bytes())]))
    }

    pub fn enrolment(transcript: Hash32) -> Self {
        Self::new(Rtype::EnrolmentChannel).extra(Extra::Hash(transcript))
    }

    pub fn export_stream(header_hash: Hash32, chunk_size: Uint53) -> Self {
        Self::new(Rtype::ExportStream).extra(Extra::List(vec![
            ExtraValue::Hash(header_hash),
            ExtraValue::Uint(chunk_size),
        ]))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ProtoError> {
        let entries = [
            true,
            true,
            self.account.is_some(),
            self.vault.is_some(),
            self.item.is_some(),
            self.field.is_some(),
            self.epoch.is_some(),
            self.ver.is_some(),
            self.extra.is_some(),
        ]
        .iter()
        .filter(|present| **present)
        .count();
        let mut w = Writer::new();
        w.map(entries)?;
        w.key(0)?;
        w.uint(AAD_VERSION)?;
        w.key(1)?;
        w.uint(u64::from(self.rtype.code()))?;
        if let Some(account) = &self.account {
            w.key(2)?;
            w.bytes(account.as_bytes())?;
        }
        if let Some(vault) = &self.vault {
            w.key(3)?;
            w.bytes(vault.as_bytes())?;
        }
        if let Some(item) = &self.item {
            w.key(4)?;
            w.bytes(item.as_bytes())?;
        }
        if let Some(field) = self.field {
            w.key(5)?;
            w.uint(u64::from(field))?;
        }
        if let Some(epoch) = self.epoch {
            w.key(6)?;
            w.uint(epoch.get())?;
        }
        if let Some(ver) = self.ver {
            w.key(7)?;
            w.uint(ver.get())?;
        }
        if let Some(extra) = &self.extra {
            w.key(8)?;
            encode_extra(&mut w, extra)?;
        }
        Ok(w.into_bytes())
    }

    fn item_payload(vault: VaultId, item: ItemId, ver: Version, field: u8) -> Self {
        Self::new(Rtype::ItemPayload)
            .vault(vault)
            .item(item)
            .field(field)
            .version(ver)
    }
}

fn encode_extra(w: &mut Writer, extra: &Extra) -> Result<(), ProtoError> {
    match extra {
        Extra::Hash(hash) => w.bytes(hash.as_bytes()),
        Extra::List(values) => {
            w.array(values.len())?;
            for value in values {
                match value {
                    ExtraValue::Uint(v) => w.uint(v.get())?,
                    ExtraValue::Id(id) => w.bytes(id)?,
                    ExtraValue::Hash(h) => w.bytes(h.as_bytes())?,
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (AccountId, VaultId, ItemId) {
        (
            AccountId::from_bytes([0xa1; 16]),
            VaultId::from_bytes([0xb2; 16]),
            ItemId::from_bytes([0xc3; 16]),
        )
    }

    #[test]
    fn self_wrap_encodes_keys_in_order_and_omits_absent_ones() {
        let (account, vault, _) = ids();
        let bytes = Aad::self_wrap(account, vault, Epoch::new(3).unwrap())
            .to_bytes()
            .unwrap();
        let mut expected = vec![0xa5, 0x00, 0x01, 0x01, 0x0a, 0x02, 0x50];
        expected.extend([0xa1; 16]);
        expected.extend([0x03, 0x50]);
        expected.extend([0xb2; 16]);
        expected.extend([0x06, 0x03]);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn item_overview_and_details_differ_only_in_field() {
        let (_, vault, item) = ids();
        let ver = Version::new(2).unwrap();
        let ov = Aad::item_overview(vault, item, ver).to_bytes().unwrap();
        let det = Aad::item_details(vault, item, ver).to_bytes().unwrap();
        let diffs: Vec<_> = ov.iter().zip(&det).filter(|(a, b)| a != b).collect();
        assert_eq!(diffs.len(), 1);
        assert_eq!(ov.len(), det.len());
    }

    #[test]
    fn item_payload_aad_excludes_epoch_and_key_wrap_includes_it() {
        let (_, vault, item) = ids();
        let ver = Version::new(1).unwrap();
        let payload = Aad::item_overview(vault, item, ver).to_bytes().unwrap();
        let wrap = Aad::item_key_wrap(vault, item, Epoch::new(5).unwrap(), ver)
            .to_bytes()
            .unwrap();
        assert_eq!(payload[0], 0xa6);
        assert_eq!(wrap[0], 0xa7);
    }

    #[test]
    fn every_context_value_changes_the_encoding() {
        let (account, vault, item) = ids();
        let ver = Version::new(1).unwrap();
        let base = Aad::item_key_wrap(vault, item, Epoch::new(1).unwrap(), ver);
        let variants = [
            Aad::item_key_wrap(
                VaultId::from_bytes([0; 16]),
                item,
                Epoch::new(1).unwrap(),
                ver,
            ),
            Aad::item_key_wrap(
                vault,
                ItemId::from_bytes([0; 16]),
                Epoch::new(1).unwrap(),
                ver,
            ),
            Aad::item_key_wrap(vault, item, Epoch::new(2).unwrap(), ver),
            Aad::item_key_wrap(
                vault,
                item,
                Epoch::new(1).unwrap(),
                Version::new(2).unwrap(),
            ),
            Aad::self_wrap(account, vault, Epoch::new(1).unwrap()),
        ];
        for variant in variants {
            assert_ne!(base.to_bytes().unwrap(), variant.to_bytes().unwrap());
        }
    }

    #[test]
    fn ak_wrap_binds_generation_and_kdf_parameters() {
        let (account, ..) = ids();
        let kdf = KdfWire {
            m: 65_536,
            t: 3,
            p: 4,
        };
        let generation = Uint53::new(1).unwrap();
        let a = Aad::ak_wrap(account, &kdf, generation).to_bytes().unwrap();
        let lower = KdfWire {
            m: 8_192,
            t: 3,
            p: 4,
        };
        let b = Aad::ak_wrap(account, &lower, generation)
            .to_bytes()
            .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rtype_codes_are_one_through_sixteen() {
        let all = [
            Rtype::Account,
            Rtype::Keyset,
            Rtype::Roster,
            Rtype::Manifest,
            Rtype::ItemPayload,
            Rtype::ItemKeyWrap,
            Rtype::AttachmentChunk,
            Rtype::Share,
            Rtype::Recovery,
            Rtype::SelfWrap,
            Rtype::DeviceLocal,
            Rtype::EnrolmentChannel,
            Rtype::ExportStream,
            Rtype::AccountMeta,
            Rtype::VaultDissolve,
            Rtype::LeaveRequest,
        ];
        for (i, rtype) in all.iter().enumerate() {
            assert_eq!(usize::from(rtype.code()), i + 1);
        }
    }

    #[test]
    fn enrolment_extra_is_the_bare_transcript_hash() {
        let bytes = Aad::enrolment(Hash32::from_bytes([5; 32]))
            .to_bytes()
            .unwrap();
        assert_eq!(&bytes[..6], [0xa3, 0x00, 0x01, 0x01, 0x0c, 0x08]);
        assert_eq!(&bytes[6..9], [0x58, 0x20, 5]);
    }
}

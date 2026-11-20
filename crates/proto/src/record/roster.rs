use hasp_crypto::{KemPublicKey, VerifyingKey};

use crate::ProtoError;
use crate::aad::Rtype;
use crate::cbor::{Reader, Wire, Writer};
use crate::id::{AccountId, Hash32, VaultId};
use crate::record::{begin, read_exact};
use crate::uint::{Epoch, Rver};

const ROSTER_ENTRIES: usize = 9;
const MEMBER_ENTRIES: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Viewer,
    Editor,
    Owner,
}

impl Role {
    pub fn can_write(self) -> bool {
        match self {
            Self::Viewer => false,
            Self::Editor | Self::Owner => true,
        }
    }
}

impl Wire for Role {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.uint(match self {
            Self::Viewer => 1,
            Self::Editor => 2,
            Self::Owner => 3,
        })
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        match r.uint()?.get() {
            1 => Ok(Self::Viewer),
            2 => Ok(Self::Editor),
            3 => Ok(Self::Owner),
            _ => Err(ProtoError::Format),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultKind {
    Private,
    Shared,
}

impl Wire for VaultKind {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.uint(match self {
            Self::Private => 1,
            Self::Shared => 2,
        })
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        match r.uint()?.get() {
            1 => Ok(Self::Private),
            2 => Ok(Self::Shared),
            _ => Err(ProtoError::Format),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub account_id: AccountId,
    pub ik_pk: VerifyingKey,
    pub kem_pk: KemPublicKey,
    pub role: Role,
    pub added_rver: Rver,
}

impl Wire for Member {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.map(MEMBER_ENTRIES)?;
        w.field(0, &self.account_id)?;
        w.field(1, &self.ik_pk)?;
        w.field(2, &self.kem_pk)?;
        w.field(3, &self.role)?;
        w.field(4, &self.added_rver)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.map(|r, n| {
            if n != MEMBER_ENTRIES {
                return Err(ProtoError::Format);
            }
            Ok(Self {
                account_id: r.field(0)?,
                ik_pk: r.field(1)?,
                kem_pk: r.field(2)?,
                role: r.field(3)?,
                added_rver: r.field(4)?,
            })
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roster {
    pub vault_id: VaultId,
    pub rver: Rver,
    pub epoch: Epoch,
    pub prev: Option<Hash32>,
    pub kind: VaultKind,
    pub members: Vec<Member>,
    pub vk_commit: Hash32,
}

impl Roster {
    pub fn member(&self, account: &AccountId) -> Option<&Member> {
        self.members
            .iter()
            .find(|member| member.account_id == *account)
    }

    pub fn owner(&self) -> Option<&Member> {
        let mut owners = self
            .members
            .iter()
            .filter(|member| member.role == Role::Owner);
        match (owners.next(), owners.next()) {
            (Some(owner), None) => Some(owner),
            (Some(_) | None, Some(_) | None) => None,
        }
    }
}

impl Wire for Roster {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        begin(w, Rtype::Roster, ROSTER_ENTRIES)?;
        w.field(2, &self.vault_id)?;
        w.field(3, &self.rver)?;
        w.field(4, &self.epoch)?;
        w.field(5, &self.prev)?;
        w.field(6, &self.kind)?;
        w.field(7, &self.members)?;
        w.field(8, &self.vk_commit)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        read_exact(r, Rtype::Roster, ROSTER_ENTRIES, |r| {
            let roster = Self {
                vault_id: r.field(2)?,
                rver: r.field(3)?,
                epoch: r.field(4)?,
                prev: r.field(5)?,
                kind: r.field(6)?,
                members: r.field(7)?,
                vk_commit: r.field(8)?,
            };
            let sorted = roster.members.windows(2).all(|pair| match pair {
                [a, b] => a.account_id < b.account_id,
                _ => true,
            });
            if !sorted {
                return Err(ProtoError::Format);
            }
            Ok(roster)
        })
    }
}

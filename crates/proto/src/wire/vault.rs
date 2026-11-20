use super::account::Membership;
use super::common::{Ack, Blob, Notice, OpId, Operation};
use crate::{
    AttId, Dissolve, Epoch, Hash32, InviteId, ItemWire, LeaveRequest, Manifest, ProtoError, Reader,
    Role, Roster, SealedRaw, Seq, Share, Signed, Uint53, VaultId, Wire, Writer,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitBundle {
    pub manifest: Signed<Manifest>,
    pub roster: Option<Signed<Roster>>,
    pub shares: Vec<Signed<Share>>,
    pub ops: Vec<ItemWire>,
}

impl Wire for CommitBundle {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.map(4)?;
        w.field(0, &self.manifest)?;
        w.field(1, &self.roster)?;
        w.field(2, &self.shares)?;
        w.key(3)?;
        w.array(self.ops.len())?;
        for op in &self.ops {
            w.bytes(&op.to_cbor()?)?;
        }
        Ok(())
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.map(|r, n| {
            if n != 4 {
                return Err(ProtoError::Format);
            }
            let manifest = r.field(0)?;
            let roster = r.field(1)?;
            let shares = r.field(2)?;
            r.key(3)?;
            let ops = r.array(|r, n| {
                let mut ops = Vec::with_capacity(n);
                for _ in 0..n {
                    ops.push(ItemWire::from_cbor(r.bytes()?)?);
                }
                Ok(ops)
            })?;
            Ok(Self {
                manifest,
                roster,
                shares,
                ops,
            })
        })
    }
}

message!(SelfWrapEntry {
    0 epoch: Epoch,
    1 wrap: SealedRaw,
});

code_enum!(
    VaultStatus {
        Ok = 1,
        NotMember = 2,
        Dissolved = 3,
    }
);

message!(VaultCursor {
    0 vault_id: VaultId,
    1 seq: Seq,
});

message!(Pull {
    0 vaults: Vec<VaultCursor>,
    1 notices_after: Uint53,
    2 limit: Uint53,
});

message!(VaultPull {
    0 vault_id: VaultId,
    1 status: VaultStatus,
    2 head_seq: Seq,
    3 head_hash: Option<Hash32>,
    4 has_more: bool,
    5 commits: Vec<CommitBundle>,
    6 shares: Vec<Signed<Share>>,
    7 self_wraps: Vec<SelfWrapEntry>,
    8 leave_requests: Vec<Signed<LeaveRequest>>,
    9 dissolve: Option<Signed<Dissolve>>,
});

message!(PullResponse {
    0 vaults: Vec<VaultPull>,
    1 memberships: Vec<Membership>,
    2 notices: Vec<Notice>,
});
operation!(Pull => PullResponse, Pull);

message!(Commit {
    0 vault_id: VaultId,
    1 base_seq: Seq,
    2 bundle: CommitBundle,
    3 self_wraps: Vec<SelfWrapEntry>,
});
message!(CommitResponse {
    0 head_seq: Seq,
    1 head_hash: Hash32,
});
operation!(Commit => CommitResponse, Commit);

message!(RepairPublish {
    0 vault_id: VaultId,
    1 bundle: CommitBundle,
});
operation!(RepairPublish => CommitResponse, RepairPublish);

message!(SelfWrapPut {
    0 vault_id: VaultId,
    1 entry: SelfWrapEntry,
});
operation!(SelfWrapPut => Ack, SelfWrapPut);

code_enum!(
    InviteState {
        Open = 1,
        Accepted = 2,
        Declined = 3,
        Used = 4,
        Expired = 5,
    }
);

message!(InviteCreate {
    0 vault_id: VaultId,
    1 role: Role,
});
message!(InviteCreateResponse {
    0 invite_id: InviteId,
    1 expires: Uint53,
});
operation!(InviteCreate => InviteCreateResponse, InviteCreate);

message!(InviteGet { 0 invite_id: InviteId });
message!(InviteView {
    0 invite_id: InviteId,
    1 vault_id: VaultId,
    2 role: Role,
    3 state: InviteState,
    4 expires: Uint53,
    5 inviter: Signed<crate::AccountRecord>,
});
operation!(InviteGet => InviteView, InviteGet);

message!(InviteList { 0 vault_id: VaultId });
message!(InviteEntry {
    0 invite_id: InviteId,
    1 role: Role,
    2 state: InviteState,
    3 expires: Uint53,
    4 invitee: Option<Signed<crate::AccountRecord>>,
    5 accept: Option<Blob>,
});
message!(InviteListResponse { 0 invites: Vec<InviteEntry> });
operation!(InviteList => InviteListResponse, InviteList);

message!(InviteAccept {
    0 invite_id: InviteId,
    1 accept: Blob,
});
operation!(InviteAccept => Ack, InviteAccept);

message!(InviteDecline { 0 invite_id: InviteId });
operation!(InviteDecline => Ack, InviteDecline);

message!(Leave { 0 request: Signed<LeaveRequest> });
operation!(Leave => Ack, Leave);

message!(VaultDissolve { 0 record: Signed<Dissolve> });
operation!(VaultDissolve => Ack, VaultDissolve);

message!(AttachmentPut {
    0 vault_id: VaultId,
    1 att_id: AttId,
    2 index: Uint53,
    3 data: Blob,
});
operation!(AttachmentPut => Ack, AttachmentPut);

message!(AttachmentGet {
    0 vault_id: VaultId,
    1 att_id: AttId,
    2 index: Uint53,
});
message!(AttachmentGetResponse {
    0 data: Blob,
    1 last: bool,
});
operation!(AttachmentGet => AttachmentGetResponse, AttachmentGet);

message!(AttachmentComplete {
    0 vault_id: VaultId,
    1 att_id: AttId,
    2 chunks: Uint53,
});
operation!(AttachmentComplete => Ack, AttachmentComplete);

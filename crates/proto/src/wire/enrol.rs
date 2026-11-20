use super::common::{Ack, Blob, DeviceInfo, OpId, Operation, SessionGrant};
use crate::{Esid, Uint53};

code_enum!(
    EnrolSlot {
        Request = 1,
        Offer = 2,
        Reveal = 3,
        Payload = 4,
    }
);

message!(EnrolOpen { 0 esid: Esid });
message!(EnrolOpenResponse { 0 expires: Uint53 });
operation!(EnrolOpen => EnrolOpenResponse, EnrolOpen);

message!(EnrolApprove {
    0 esid: Esid,
    1 device: DeviceInfo,
});
operation!(EnrolApprove => SessionGrant, EnrolApprove);

message!(EnrolAbort { 0 esid: Esid });
operation!(EnrolAbort => Ack, EnrolAbort);

message!(EnrolMsgPut {
    0 esid: Esid,
    1 slot: EnrolSlot,
    2 data: Blob,
});
operation!(EnrolMsgPut => Ack, EnrolMsgPut);

message!(EnrolMsgGet {
    0 esid: Esid,
    1 slot: EnrolSlot,
});
message!(EnrolMsgGetResponse { 0 data: Option<Blob> });
operation!(EnrolMsgGet => EnrolMsgGetResponse, EnrolMsgGet);

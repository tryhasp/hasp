use hasp_boundary::mirror_types;

use crate::secret::Secret;

mirror_types! {
    struct: [#[derive(Debug, Clone, uniffi::Record)]]
    enum: [#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]]
}

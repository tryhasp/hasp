use hasp_boundary::mirror_types;
use serde::{Deserialize, Serialize};
use tsify::Tsify;

use crate::secret::Secret;

mirror_types! {
    struct: [
        #[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
        #[serde(rename_all = "camelCase")]
    ]
    enum: [
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Tsify)]
        #[serde(rename_all = "kebab-case")]
    ]
}

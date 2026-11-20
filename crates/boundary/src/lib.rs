mod memory;

pub use memory::{NoBiometric, SnapshotError, SnapshotStore, SoftSecureStore};

#[doc(hidden)]
pub use {hasp_core, hasp_crypto, hasp_proto, hasp_replay};

pub use hasp_core::api::Mirror;

#[macro_export]
macro_rules! hasp_error {
    ($(#[$meta:meta])*) => {
        $(#[$meta])*
        pub enum HaspError {
            #[error("format")]
            Format,
            #[error("version")]
            Version,
            #[error("sig")]
            Sig,
            #[error("aead")]
            Aead,
            #[error("pin")]
            Pin,
            #[error("rollback")]
            Rollback,
            #[error("fork")]
            Fork,
            #[error("roster")]
            Roster,
            #[error("kdf parameters")]
            KdfParams,
            #[error("epoch")]
            Epoch,
            #[error("root")]
            Root,
            #[error("auth")]
            Auth,
            #[error("server key")]
            ServerKey,
            #[error("authz")]
            Authz,
            #[error("invite")]
            Invite,
            #[error("locked")]
            Locked,
            #[error("cancelled")]
            Cancelled,
            #[error("offline")]
            Offline,
            #[error("not found")]
            NotFound,
            #[error("refused")]
            Refused,
            #[error("pending")]
            Pending,
            #[error("read only")]
            ReadOnly,
            #[error("rate limited")]
            RateLimited,
            #[error("conflict")]
            Conflict,
            #[error("quarantined")]
            Quarantined,
            #[error("unconfirmed")]
            Unconfirmed,
            #[error("device revoked")]
            DeviceRevoked,
            #[error("internal")]
            Internal,
        }

        impl HaspError {
            pub const ALL: [Self; 28] = [
                Self::Format,
                Self::Version,
                Self::Sig,
                Self::Aead,
                Self::Pin,
                Self::Rollback,
                Self::Fork,
                Self::Roster,
                Self::KdfParams,
                Self::Epoch,
                Self::Root,
                Self::Auth,
                Self::ServerKey,
                Self::Authz,
                Self::Invite,
                Self::Locked,
                Self::Cancelled,
                Self::Offline,
                Self::NotFound,
                Self::Refused,
                Self::Pending,
                Self::ReadOnly,
                Self::RateLimited,
                Self::Conflict,
                Self::Quarantined,
                Self::Unconfirmed,
                Self::DeviceRevoked,
                Self::Internal,
            ];
        }

        impl From<$crate::hasp_proto::ProtoError> for HaspError {
            fn from(error: $crate::hasp_proto::ProtoError) -> Self {
                use $crate::hasp_proto::ProtoError;
                match error {
                    ProtoError::Format => Self::Format,
                    ProtoError::Version => Self::Version,
                    ProtoError::Sig => Self::Sig,
                    ProtoError::Aead => Self::Aead,
                    ProtoError::Pin => Self::Pin,
                    ProtoError::Rollback => Self::Rollback,
                    ProtoError::Fork => Self::Fork,
                    ProtoError::Roster => Self::Roster,
                    ProtoError::KdfParams => Self::KdfParams,
                    ProtoError::Epoch => Self::Epoch,
                    ProtoError::Root => Self::Root,
                    ProtoError::Authz => Self::Authz,
                    ProtoError::Invite => Self::Invite,
                    ProtoError::Internal(_) => Self::Internal,
                }
            }
        }

        impl From<$crate::hasp_crypto::CryptoError> for HaspError {
            fn from(error: $crate::hasp_crypto::CryptoError) -> Self {
                use $crate::hasp_crypto::CryptoError;
                match error {
                    CryptoError::Aead => Self::Aead,
                    CryptoError::Signature => Self::Sig,
                    CryptoError::KdfParams => Self::KdfParams,
                    CryptoError::Length | CryptoError::Kem => Self::Format,
                    CryptoError::Opaque | CryptoError::Random | CryptoError::Internal(_) => {
                        Self::Internal
                    }
                }
            }
        }

        impl From<$crate::hasp_replay::ReplayError> for HaspError {
            fn from(error: $crate::hasp_replay::ReplayError) -> Self {
                use $crate::hasp_replay::ReplayError;
                match error {
                    ReplayError::Proto(error) => error.into(),
                    ReplayError::Crypto(error) => error.into(),
                    ReplayError::Vector(_) | ReplayError::Group => Self::Internal,
                }
            }
        }

        impl From<$crate::hasp_core::transport::TransportError> for HaspError {
            fn from(error: $crate::hasp_core::transport::TransportError) -> Self {
                use $crate::hasp_core::transport::TransportError;
                use $crate::hasp_proto::wire::ErrorCode;
                match error {
                    TransportError::Unreachable => Self::Offline,
                    TransportError::Codec(error) => error.into(),
                    TransportError::Server(wire) => match wire.code {
                        ErrorCode::Format | ErrorCode::TooLarge => Self::Format,
                        ErrorCode::Version | ErrorCode::Unsupported => Self::Version,
                        ErrorCode::Sig => Self::Sig,
                        ErrorCode::Aead => Self::Aead,
                        ErrorCode::Pin => Self::Pin,
                        ErrorCode::Rollback => Self::Rollback,
                        ErrorCode::Fork => Self::Fork,
                        ErrorCode::Roster => Self::Roster,
                        ErrorCode::KdfParams => Self::KdfParams,
                        ErrorCode::Epoch | ErrorCode::EpochStale => Self::Epoch,
                        ErrorCode::Root => Self::Root,
                        ErrorCode::Auth | ErrorCode::ReauthRequired | ErrorCode::Expired => {
                            Self::Auth
                        }
                        ErrorCode::ServerKey => Self::ServerKey,
                        ErrorCode::Authz | ErrorCode::NotMember => Self::Authz,
                        ErrorCode::Invite => Self::Invite,
                        ErrorCode::StaleHead | ErrorCode::Conflict => Self::Conflict,
                        ErrorCode::ReadOnly => Self::ReadOnly,
                        ErrorCode::RateLimited => Self::RateLimited,
                        ErrorCode::NotFound => Self::NotFound,
                        ErrorCode::Pending => Self::Pending,
                        ErrorCode::Internal => Self::Internal,
                    },
                }
            }
        }

        impl From<$crate::hasp_core::CoreError> for HaspError {
            fn from(error: $crate::hasp_core::CoreError) -> Self {
                use $crate::hasp_core::CoreError;
                use $crate::hasp_core::platform::PlatformError;
                match error {
                    CoreError::Proto(error) => error.into(),
                    CoreError::Crypto(error) => error.into(),
                    CoreError::Transport(error) => error.into(),
                    CoreError::Model(_)
                    | CoreError::Generator(_)
                    | CoreError::Otp(_)
                    | CoreError::Matcher(_)
                    | CoreError::Import(_)
                    | CoreError::Export(_) => Self::Format,
                    CoreError::Store($crate::hasp_core::store::StoreError::Locked) => Self::Pending,
                    CoreError::Store(_) => Self::Internal,
                    CoreError::Platform(PlatformError::Denied) | CoreError::Cancelled => {
                        Self::Cancelled
                    }
                    CoreError::Platform(PlatformError::Missing) | CoreError::NotFound(_) => {
                        Self::NotFound
                    }
                    CoreError::Platform(_) | CoreError::Internal(_) => Self::Internal,
                    CoreError::Locked => Self::Locked,
                    CoreError::Credentials | CoreError::SessionExpired => Self::Auth,
                    CoreError::DeviceRevoked => Self::DeviceRevoked,
                    CoreError::ServerKey => Self::ServerKey,
                    CoreError::Unconfirmed => Self::Unconfirmed,
                    CoreError::Quarantined { .. } | CoreError::RepairPending { .. } => {
                        Self::Quarantined
                    }
                    CoreError::VaultInactive(_) => Self::NotFound,
                    CoreError::Refused(_) => Self::Refused,
                    CoreError::Pending { .. } => Self::Pending,
                    CoreError::Diverged(_) => Self::Fork,
                    CoreError::Conflict(_) => Self::Conflict,
                    CoreError::Watchtower(_) => Self::Offline,
                }
            }
        }
    };
}

#[macro_export]
macro_rules! mirror_one {
    ([$(#[$sattr:meta])*] [$(#[$eattr:meta])*] struct $name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        $(#[$sattr])*
        pub struct $name {
            $(pub $field: $ty),*
        }

        impl $crate::Mirror<$crate::hasp_core::api::$name> for $name {
            fn mirror(self) -> $crate::hasp_core::api::$name {
                $crate::hasp_core::api::$name {
                    $($field: $crate::Mirror::mirror(self.$field)),*
                }
            }
        }

        impl $crate::Mirror<$name> for $crate::hasp_core::api::$name {
            fn mirror(self) -> $name {
                $name {
                    $($field: $crate::Mirror::mirror(self.$field)),*
                }
            }
        }
    };
    ([$(#[$sattr:meta])*] [$(#[$eattr:meta])*] enum $name:ident { $($variant:ident),* $(,)? }) => {
        $(#[$eattr])*
        pub enum $name {
            $($variant),*
        }

        impl $crate::Mirror<$crate::hasp_core::api::$name> for $name {
            fn mirror(self) -> $crate::hasp_core::api::$name {
                match self {
                    $(Self::$variant => $crate::hasp_core::api::$name::$variant),*
                }
            }
        }

        impl $crate::Mirror<$name> for $crate::hasp_core::api::$name {
            fn mirror(self) -> $name {
                match self {
                    $(Self::$variant => $name::$variant),*
                }
            }
        }
    };
}

#[macro_export]
macro_rules! mirror_each {
    ({ struct: $sattr:tt enum: $eattr:tt } $($kind:ident $name:ident { $($body:tt)* })*) => {
        $($crate::mirror_one! { $sattr $eattr $kind $name { $($body)* } })*
    };
}

#[macro_export]
macro_rules! mirror_types {
    ($($context:tt)*) => {
        $crate::hasp_core::with_api_types!($crate::mirror_each, { $($context)* });
    };
}

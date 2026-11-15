use std::fmt;

/// Vault errors. Each variant maps to a stable code shared by every binding (docs/CONTRACTS.md §1.2).
/// No variant carries user data, secrets or raw parser messages (they could echo plaintext).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// Malformed JSON, field, length, encoding or unknown field. The reason is a static, non-sensitive string.
    InvalidFormat(&'static str),
    /// Unknown `formatVersion` / `schemaVersion`.
    UnsupportedVersion,
    /// KDF parameters or salt outside the accepted bounds.
    ParamsOutOfBounds,
    /// Wrong master password / recovery key (the key slot could not be opened).
    InvalidCredentials,
    /// Recovery key failed its checksum (typo).
    InvalidRecoveryKey,
    /// Header or payload was tampered with or is corrupt.
    IntegrityError,
    /// Attempt to merge a container belonging to another vault.
    VaultMismatch,
    /// The remote container has newer keys (master password changed or data key rotated on another device). It is
    /// never adopted silently: the user must re-authenticate against it (`adopt_remote_keys`).
    KeyringChanged,
    /// Unknown entry id.
    NotFound,
    /// Invalid input; the payload names the field, never its value.
    Validation(&'static str),
    /// Operation on a locked handle (bindings only).
    Locked,
    /// Internal cryptographic or randomness failure.
    Crypto,
}

impl VaultError {
    /// Stable machine-readable code.
    pub fn code(&self) -> &'static str {
        match self {
            VaultError::InvalidFormat(_) => "INVALID_FORMAT",
            VaultError::UnsupportedVersion => "UNSUPPORTED_VERSION",
            VaultError::ParamsOutOfBounds => "PARAMS_OUT_OF_BOUNDS",
            VaultError::InvalidCredentials => "INVALID_CREDENTIALS",
            VaultError::InvalidRecoveryKey => "INVALID_RECOVERY_KEY",
            VaultError::IntegrityError => "INTEGRITY_ERROR",
            VaultError::VaultMismatch => "VAULT_MISMATCH",
            VaultError::KeyringChanged => "KEYRING_CHANGED",
            VaultError::NotFound => "NOT_FOUND",
            VaultError::Validation(_) => "VALIDATION",
            VaultError::Locked => "LOCKED",
            VaultError::Crypto => "CRYPTO",
        }
    }

    /// Optional non-sensitive detail (field name or format reason).
    pub fn detail(&self) -> Option<&'static str> {
        match self {
            VaultError::InvalidFormat(r) | VaultError::Validation(r) => Some(r),
            _ => None,
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.detail() {
            Some(d) => write!(f, "{}: {}", self.code(), d),
            None => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<keyvora_crypto::CryptoError> for VaultError {
    fn from(e: keyvora_crypto::CryptoError) -> Self {
        match e {
            keyvora_crypto::CryptoError::InvalidParameters(_) => VaultError::ParamsOutOfBounds,
            keyvora_crypto::CryptoError::AuthenticationFailed => VaultError::IntegrityError,
            _ => VaultError::Crypto,
        }
    }
}

/// Result alias.
pub type Result<T> = std::result::Result<T, VaultError>;

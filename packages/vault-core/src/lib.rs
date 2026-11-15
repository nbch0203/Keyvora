//! Keyvora vault core: versioned encrypted container (`keyvora.vault` v1), key slots (master password + recovery
//! key), unlocked-session CRUD, and origin matching for autofill. See docs/VAULT_FORMAT.md and docs/CONTRACTS.md.
#![forbid(unsafe_code)]

pub mod container;
mod error;
pub mod model;
pub mod origin;
pub mod recovery;
pub mod timefmt;
mod vault;

pub use error::{Result, VaultError};
pub use keyvora_crypto::Argon2Params;
pub use model::{
    ConflictKind, ConflictSnapshot, Dot, Entry, EntryInput, EntrySummary, HistoryItem, Payload, Record, Version,
};
pub use origin::MatchLevel;
pub use recovery::RecoveryKey;
pub use vault::{ConflictChoice, CredentialMatch, ForeignVault, UnlockedVault, MAX_MASTER_LEN, MIN_MASTER_LEN};

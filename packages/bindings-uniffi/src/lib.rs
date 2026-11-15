//! UniFFI bindings for Android (docs/CONTRACTS.md §3). Kotlin package: `uniffi.keyvora_ffi`.
#![forbid(unsafe_code)]

use keyvora_passgen::GeneratorOptions;
use keyvora_vault::{self as kv, Argon2Params, ConflictChoice, UnlockedVault, VaultError};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

/// Error codes shared with every client (stable).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum KeyvoraError {
    #[error("INVALID_FORMAT")]
    InvalidFormat { detail: String },
    #[error("UNSUPPORTED_VERSION")]
    UnsupportedVersion,
    #[error("PARAMS_OUT_OF_BOUNDS")]
    ParamsOutOfBounds,
    #[error("INVALID_CREDENTIALS")]
    InvalidCredentials,
    #[error("INVALID_RECOVERY_KEY")]
    InvalidRecoveryKey,
    #[error("INTEGRITY_ERROR")]
    IntegrityError,
    #[error("VAULT_MISMATCH")]
    VaultMismatch,
    #[error("KEYRING_CHANGED")]
    KeyringChanged,
    #[error("NOT_FOUND")]
    NotFound,
    #[error("VALIDATION")]
    Validation { field: String },
    #[error("LOCKED")]
    Locked,
    #[error("CRYPTO")]
    Crypto,
}

impl From<VaultError> for KeyvoraError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::InvalidFormat(d) => KeyvoraError::InvalidFormat { detail: d.to_owned() },
            VaultError::UnsupportedVersion => KeyvoraError::UnsupportedVersion,
            VaultError::ParamsOutOfBounds => KeyvoraError::ParamsOutOfBounds,
            VaultError::InvalidCredentials => KeyvoraError::InvalidCredentials,
            VaultError::InvalidRecoveryKey => KeyvoraError::InvalidRecoveryKey,
            VaultError::IntegrityError => KeyvoraError::IntegrityError,
            VaultError::VaultMismatch => KeyvoraError::VaultMismatch,
            VaultError::KeyringChanged => KeyvoraError::KeyringChanged,
            VaultError::NotFound => KeyvoraError::NotFound,
            VaultError::Validation(f) => KeyvoraError::Validation { field: f.to_owned() },
            VaultError::Locked => KeyvoraError::Locked,
            VaultError::Crypto => KeyvoraError::Crypto,
        }
    }
}

type R<T> = Result<T, KeyvoraError>;

#[derive(uniffi::Record, Clone, Copy)]
pub struct FfiKdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl From<FfiKdfParams> for Argon2Params {
    fn from(p: FfiKdfParams) -> Self {
        Argon2Params { memory_kib: p.memory_kib, iterations: p.iterations, parallelism: p.parallelism }
    }
}

#[derive(uniffi::Record)]
pub struct FfiEntryInput {
    pub title: String,
    pub username: String,
    pub password: String,
    pub urls: Vec<String>,
    pub notes: String,
}

impl From<FfiEntryInput> for kv::EntryInput {
    fn from(i: FfiEntryInput) -> Self {
        kv::EntryInput { title: i.title, username: i.username, password: i.password, urls: i.urls, notes: i.notes }
    }
}

#[derive(uniffi::Record)]
pub struct FfiEntrySummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub urls: Vec<String>,
    pub updated_at: String,
    pub has_conflicts: bool,
}

impl From<&kv::EntrySummary> for FfiEntrySummary {
    fn from(s: &kv::EntrySummary) -> Self {
        Self {
            id: s.id.clone(),
            title: s.title.clone(),
            username: s.username.clone(),
            urls: s.urls.clone(),
            updated_at: s.updated_at.clone(),
            has_conflicts: s.has_conflicts,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiHistoryItem {
    pub password: String,
    pub retired_at: String,
}

#[derive(uniffi::Record)]
pub struct FfiConflict {
    /// "edit" | "deletion"
    pub kind: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub urls: Vec<String>,
    pub notes: String,
    pub updated_at: String,
    pub updated_by: String,
}

#[derive(uniffi::Record)]
pub struct FfiEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub urls: Vec<String>,
    pub notes: String,
    pub created_at: String,
    pub updated_at: String,
    pub updated_by: String,
    pub password_history: Vec<FfiHistoryItem>,
    pub conflicts: Vec<FfiConflict>,
}

impl From<&kv::Entry> for FfiEntry {
    fn from(e: &kv::Entry) -> Self {
        Self {
            id: e.id.clone(),
            title: e.title.clone(),
            username: e.username.clone(),
            password: e.password.clone(),
            urls: e.urls.clone(),
            notes: e.notes.clone(),
            created_at: e.created_at.clone(),
            updated_at: e.updated_at.clone(),
            updated_by: e.updated_by.clone(),
            password_history: e
                .password_history
                .iter()
                .map(|h| FfiHistoryItem { password: h.password.clone(), retired_at: h.retired_at.clone() })
                .collect(),
            conflicts: e
                .conflicts
                .iter()
                .map(|c| FfiConflict {
                    kind: match c.kind {
                        kv::ConflictKind::Edit => "edit".into(),
                        kv::ConflictKind::Deletion => "deletion".into(),
                    },
                    title: c.title.clone(),
                    username: c.username.clone(),
                    password: c.password.clone(),
                    urls: c.urls.clone(),
                    notes: c.notes.clone(),
                    updated_at: c.updated_at.clone(),
                    updated_by: c.updated_by.clone(),
                })
                .collect(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiCredentialMatch {
    pub entry: FfiEntrySummary,
    /// "exact" | "sameSite"
    pub level: String,
    pub matched_url: String,
    pub page_host: String,
    pub page_is_idn: bool,
}

impl From<&kv::CredentialMatch> for FfiCredentialMatch {
    fn from(m: &kv::CredentialMatch) -> Self {
        Self {
            entry: (&m.entry).into(),
            level: m.level.as_str().into(),
            matched_url: m.matched_url.clone(),
            page_host: m.page_host.clone(),
            page_is_idn: m.page_is_idn,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiMergeReport {
    pub remote_revision: u64,
    pub adopted_remote: bool,
    pub needs_upload: bool,
    pub added: u32,
    pub updated: u32,
    pub removed: u32,
    pub new_conflicts: Vec<String>,
    pub keyring_adopted: bool,
    pub keyring_conflict: bool,
    pub kdf_weakened: bool,
    pub recovery_key_changed: bool,
}

impl From<keyvora_sync::MergeReport> for FfiMergeReport {
    fn from(r: keyvora_sync::MergeReport) -> Self {
        Self {
            remote_revision: r.remote_revision,
            adopted_remote: r.adopted_remote,
            needs_upload: r.needs_upload,
            added: r.added,
            updated: r.updated,
            removed: r.removed,
            new_conflicts: r.new_conflicts,
            keyring_adopted: r.keyring_adopted,
            keyring_conflict: r.keyring_conflict,
            kdf_weakened: r.kdf_weakened,
            recovery_key_changed: r.recovery_key_changed,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiGeneratorOptions {
    pub length: u32,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
    pub require_each_class: bool,
}

impl From<FfiGeneratorOptions> for GeneratorOptions {
    fn from(o: FfiGeneratorOptions) -> Self {
        GeneratorOptions {
            length: o.length,
            lowercase: o.lowercase,
            uppercase: o.uppercase,
            digits: o.digits,
            symbols: o.symbols,
            exclude_ambiguous: o.exclude_ambiguous,
            require_each_class: o.require_each_class,
        }
    }
}

/// Unlocked vault handle. `lock()` wipes the DEK; later calls throw `KeyvoraException.Locked`.
#[derive(uniffi::Object)]
pub struct VaultHandle {
    inner: Mutex<Option<UnlockedVault>>,
    recovery_key: Mutex<Option<Zeroizing<String>>>,
}

impl VaultHandle {
    fn new(v: UnlockedVault, rk: Option<Zeroizing<String>>) -> Arc<Self> {
        Arc::new(Self { inner: Mutex::new(Some(v)), recovery_key: Mutex::new(rk) })
    }
    fn with<T>(&self, f: impl FnOnce(&mut UnlockedVault) -> Result<T, VaultError>) -> R<T> {
        let mut g = self.inner.lock().map_err(|_| KeyvoraError::Crypto)?;
        let v = g.as_mut().ok_or(KeyvoraError::Locked)?;
        f(v).map_err(Into::into)
    }
}

#[uniffi::export]
impl VaultHandle {
    #[uniffi::constructor]
    pub fn create(master: String, params: FfiKdfParams, device_id: String, now_ms: i64) -> R<Arc<Self>> {
        let (v, rk) = UnlockedVault::create(&master, params.into(), &device_id, now_ms)?;
        Ok(Self::new(v, Some(rk.to_display())))
    }

    #[uniffi::constructor]
    pub fn unlock_with_password(container: String, master: String, device_id: String) -> R<Arc<Self>> {
        Ok(Self::new(UnlockedVault::unlock_with_password(&container, &master, &device_id)?, None))
    }

    #[uniffi::constructor]
    pub fn unlock_with_recovery_key(container: String, recovery_key: String, device_id: String) -> R<Arc<Self>> {
        Ok(Self::new(UnlockedVault::unlock_with_recovery_key(&container, &recovery_key, &device_id)?, None))
    }

    #[uniffi::constructor]
    pub fn open_with_data_key(container: String, dek: Vec<u8>, device_id: String) -> R<Arc<Self>> {
        Ok(Self::new(UnlockedVault::open_with_data_key(&container, &dek, &device_id)?, None))
    }

    /// Recovery key from `create`/`rotateRecoveryKey`, returned only once.
    pub fn take_recovery_key(&self) -> Option<String> {
        self.recovery_key.lock().ok().and_then(|mut g| g.take()).map(|z| z.to_string())
    }

    pub fn export_container(&self) -> R<String> {
        self.with(|v| v.export_container())
    }
    pub fn vault_id(&self) -> R<String> {
        self.with(|v| Ok(v.vault_id()))
    }
    pub fn revision(&self) -> R<u64> {
        self.with(|v| Ok(v.revision()))
    }
    pub fn is_dirty(&self) -> R<bool> {
        self.with(|v| Ok(v.is_dirty()))
    }
    pub fn is_locked(&self) -> bool {
        self.inner.lock().map(|g| g.is_none()).unwrap_or(true)
    }
    pub fn list_entries(&self) -> R<Vec<FfiEntrySummary>> {
        self.with(|v| Ok(v.list_entries().iter().map(Into::into).collect()))
    }
    pub fn search(&self, query: String) -> R<Vec<FfiEntrySummary>> {
        self.with(|v| Ok(v.search(&query).iter().map(Into::into).collect()))
    }
    pub fn get_entry(&self, id: String) -> R<FfiEntry> {
        self.with(|v| v.get_entry(&id).map(|e| (&e).into()))
    }
    pub fn create_entry(&self, input: FfiEntryInput, now_ms: i64) -> R<FfiEntry> {
        self.with(|v| v.create_entry(input.into(), now_ms).map(|e| (&e).into()))
    }
    pub fn update_entry(&self, id: String, input: FfiEntryInput, now_ms: i64) -> R<FfiEntry> {
        self.with(|v| v.update_entry(&id, input.into(), now_ms).map(|e| (&e).into()))
    }
    pub fn delete_entry(&self, id: String, now_ms: i64) -> R<()> {
        self.with(|v| v.delete_entry(&id, now_ms))
    }
    /// `choice < 0` keeps the current version; `choice ≥ 0` takes that conflict.
    pub fn resolve_conflict(&self, id: String, choice: i32, now_ms: i64) -> R<()> {
        let c = if choice < 0 { ConflictChoice::KeepCurrent } else { ConflictChoice::TakeConflict(choice as usize) };
        self.with(|v| v.resolve_conflict(&id, c, now_ms))
    }
    pub fn find_matches(&self, page_url: String) -> R<Vec<FfiCredentialMatch>> {
        self.with(|v| Ok(v.find_matches(&page_url).iter().map(Into::into).collect()))
    }
    pub fn find_app_matches(&self, package_name: String) -> R<Vec<FfiCredentialMatch>> {
        self.with(|v| Ok(v.find_app_matches(&package_name).iter().map(Into::into).collect()))
    }
    pub fn change_master_password(&self, current: String, next: String, params: FfiKdfParams) -> R<()> {
        self.with(|v| v.change_master_password(&current, &next, params.into()))
    }
    pub fn reset_master_password_with_recovery(
        &self,
        recovery_key: String,
        next: String,
        params: FfiKdfParams,
    ) -> R<()> {
        self.with(|v| v.reset_master_password_with_recovery(&recovery_key, &next, params.into()))
    }
    /// Rotates the recovery key; read it with `takeRecoveryKey()`.
    pub fn rotate_recovery_key(&self, current: String) -> R<()> {
        let rk = self.with(|v| v.rotate_recovery_key(&current))?;
        if let Ok(mut g) = self.recovery_key.lock() {
            *g = Some(rk.to_display());
        }
        Ok(())
    }
    /// Rotates the data-encryption key (also issues a new recovery key: read it with `takeRecoveryKey()`).
    pub fn rotate_data_key(&self, current: String) -> R<()> {
        let rk = self.with(|v| v.rotate_data_key(&current))?;
        if let Ok(mut g) = self.recovery_key.lock() {
            *g = Some(rk.to_display());
        }
        Ok(())
    }
    /// KDF parameters of the master-password slot.
    pub fn password_kdf_params(&self) -> R<FfiKdfParams> {
        self.with(|v| {
            let p = v.password_kdf_params();
            Ok(FfiKdfParams { memory_kib: p.memory_kib, iterations: p.iterations, parallelism: p.parallelism })
        })
    }
    /// Fails with `KeyringChanged` when the remote keys are newer: then call `adoptRemoteKeys`.
    pub fn merge_remote(&self, remote_container: String) -> R<FfiMergeReport> {
        self.with(|v| keyvora_sync::merge_remote(v, &remote_container).map(Into::into))
    }
    /// Re-authenticates with the master password valid for `remote_container` and adopts its keys (merging local data).
    pub fn adopt_remote_keys(&self, remote_container: String, master: String) -> R<FfiMergeReport> {
        self.with(|v| keyvora_sync::adopt_remote_keys(v, &remote_container, &master).map(Into::into))
    }
    /// Lists the entries of another container of this vault (restore UIs).
    pub fn preview_container(&self, container: String) -> R<Vec<FfiEntrySummary>> {
        self.with(|v| {
            let f = v.decrypt_foreign(&container)?;
            Ok(f.payload.records.iter().filter_map(kv::Record::to_summary).map(|s| (&s).into()).collect())
        })
    }
    pub fn restore_entries_from(&self, container: String, ids: Vec<String>, now_ms: i64) -> R<Vec<FfiEntry>> {
        self.with(|v| v.restore_entries_from(&container, &ids, now_ms).map(|l| l.iter().map(Into::into).collect()))
    }
    /// DEK for wrapping with an Android Keystore key (biometric unlock). Never persist it in plaintext.
    pub fn export_data_key(&self) -> R<Vec<u8>> {
        self.with(|v| Ok(v.export_data_key().to_vec()))
    }
    pub fn lock(&self) {
        if let Ok(mut g) = self.inner.lock() {
            *g = None;
        }
        if let Ok(mut g) = self.recovery_key.lock() {
            *g = None;
        }
    }
}

#[uniffi::export]
pub fn generate_password(options: FfiGeneratorOptions) -> R<String> {
    keyvora_passgen::generate_password(&options.into())
        .map_err(|_| KeyvoraError::Validation { field: "generatorOptions".into() })
}

#[uniffi::export]
pub fn password_entropy_bits(options: FfiGeneratorOptions) -> R<f64> {
    keyvora_passgen::entropy_bits(&options.into())
        .map_err(|_| KeyvoraError::Validation { field: "generatorOptions".into() })
}

#[uniffi::export]
pub fn default_generator_options() -> FfiGeneratorOptions {
    let d = GeneratorOptions::default();
    FfiGeneratorOptions {
        length: d.length,
        lowercase: d.lowercase,
        uppercase: d.uppercase,
        digits: d.digits,
        symbols: d.symbols,
        exclude_ambiguous: d.exclude_ambiguous,
        require_each_class: d.require_each_class,
    }
}

#[uniffi::export]
pub fn default_kdf_params() -> FfiKdfParams {
    let d = Argon2Params::DEFAULT;
    FfiKdfParams { memory_kib: d.memory_kib, iterations: d.iterations, parallelism: d.parallelism }
}

/// "exact" | "sameSite" | "none"
#[uniffi::export]
pub fn match_level(entry_url: String, page_url: String) -> String {
    kv::origin::match_level(&entry_url, &page_url).as_str().into()
}

/// Normalized origin of a fillable web domain (`https://host`), used for Android webDomain values.
#[uniffi::export]
pub fn page_origin(page_url: String) -> Option<String> {
    kv::origin::parse_page_url(&page_url).map(|o| o.serialize())
}

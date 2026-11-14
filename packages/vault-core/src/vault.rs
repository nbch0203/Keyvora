//! Unlocked vault session (typestate: protected operations only exist on an unlocked vault).

use crate::container::{payload_aad, slot_aad, Container, KdfSpec, KeySlot, SlotKind, RECOVERY_INFO};
use crate::error::{Result, VaultError};
use crate::model::*;
use crate::origin::{self, MatchLevel};
use crate::recovery::RecoveryKey;
use crate::timefmt;
use keyvora_crypto::{self as kc, Argon2Params, SecretKey};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Minimum master password length (Unicode scalar values). UIs should recommend ≥ 12 and show strength.
pub const MIN_MASTER_LEN: usize = 8;
/// Maximum master password length.
pub const MAX_MASTER_LEN: usize = 1024;
const SALT_LEN: usize = 32;

/// User choice when resolving a conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictChoice {
    /// Keep the current version and discard pending conflicts.
    KeepCurrent,
    /// Replace the current version with the conflict at this index.
    TakeConflict(usize),
}

/// A credential that matches a page or app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialMatch {
    /// The entry (no password).
    pub entry: EntrySummary,
    /// Best level among the entry's URLs.
    pub level: MatchLevel,
    /// Entry URL that produced the match.
    pub matched_url: String,
    /// Normalized page host (punycode for IDN) to display in confirmations.
    pub page_host: String,
    /// Whether the page host is an IDN (show a warning).
    pub page_is_idn: bool,
}

/// A decrypted container from elsewhere (remote / older revision) of the **same** vault.
#[derive(Debug, Clone)]
pub struct ForeignVault {
    /// Its revision.
    pub revision: u64,
    /// Its keyring revision.
    pub keyring_revision: u64,
    /// Its key slots.
    pub slots: Vec<KeySlot>,
    /// Its decrypted payload.
    pub payload: Payload,
}

/// An unlocked vault. Dropping it wipes the DEK and plaintext entries.
pub struct UnlockedVault {
    vault_id: Uuid,
    revision: u64,
    keyring_revision: u64,
    slots: Vec<KeySlot>,
    dek: SecretKey,
    payload: Payload,
    device_id: String,
    dirty: bool,
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault").field("vault_id", &self.vault_id).field("revision", &self.revision).field("entries", &self.payload.entries.len()).finish_non_exhaustive()
    }
}

fn normalize_master(master: &str) -> Result<Zeroizing<String>> {
    let n = Zeroizing::new(master.nfc().collect::<String>());
    let len = n.chars().count();
    if !(MIN_MASTER_LEN..=MAX_MASTER_LEN).contains(&len) {
        return Err(VaultError::Validation("masterPassword"));
    }
    Ok(n)
}

fn new_uuid() -> Result<Uuid> {
    let mut b = [0u8; 16];
    kc::fill_random(&mut b)?;
    Ok(uuid::Builder::from_random_bytes(b).into_uuid())
}

fn password_slot(vault_id: &Uuid, dek: &SecretKey, master: &str, params: Argon2Params) -> Result<KeySlot> {
    params.validate().map_err(|_| VaultError::ParamsOutOfBounds)?;
    let master = normalize_master(master)?;
    let salt = kc::random_bytes(SALT_LEN)?;
    let kek = kc::derive_wrapping_key(master.as_bytes(), &salt, &params)?;
    let kdf = KdfSpec::Argon2id { salt, params };
    let wrap = kc::wrap_data_key(dek, &kek, &slot_aad(vault_id, SlotKind::Password, &kdf))?;
    Ok(KeySlot { kind: SlotKind::Password, kdf, wrap })
}

fn recovery_slot(vault_id: &Uuid, dek: &SecretKey, rk: &RecoveryKey) -> Result<KeySlot> {
    let salt = kc::random_bytes(SALT_LEN)?;
    let kek = kc::derive_recovery_key(rk.secret().expose(), &salt, RECOVERY_INFO)?;
    let kdf = KdfSpec::HkdfSha256 { salt };
    let wrap = kc::wrap_data_key(dek, &kek, &slot_aad(vault_id, SlotKind::Recovery, &kdf))?;
    Ok(KeySlot { kind: SlotKind::Recovery, kdf, wrap })
}

/// Opens a slot with the master password. Wrong password or tampered slot → `InvalidCredentials`.
fn open_password_slot(vault_id: &Uuid, slot: &KeySlot, master: &str) -> Result<SecretKey> {
    let KdfSpec::Argon2id { salt, params } = &slot.kdf else { return Err(VaultError::InvalidFormat("password slot kdf")) };
    let master = Zeroizing::new(master.nfc().collect::<String>());
    let kek = kc::derive_wrapping_key(master.as_bytes(), salt, params).map_err(VaultError::from)?;
    kc::unwrap_data_key(&slot.wrap, &kek, &slot_aad(vault_id, SlotKind::Password, &slot.kdf)).map_err(|_| VaultError::InvalidCredentials)
}

fn open_recovery_slot(vault_id: &Uuid, slot: &KeySlot, rk: &RecoveryKey) -> Result<SecretKey> {
    let KdfSpec::HkdfSha256 { salt } = &slot.kdf else { return Err(VaultError::InvalidFormat("recovery slot kdf")) };
    let kek = kc::derive_recovery_key(rk.secret().expose(), salt, RECOVERY_INFO)?;
    kc::unwrap_data_key(&slot.wrap, &kek, &slot_aad(vault_id, SlotKind::Recovery, &slot.kdf)).map_err(|_| VaultError::InvalidCredentials)
}

fn decrypt_payload(c: &Container, dek: &SecretKey) -> Result<Payload> {
    let aad = payload_aad(&c.vault_id, c.revision, c.keyring_revision, &c.slots);
    let plain = kc::decrypt(dek, &aad, &c.payload).map_err(|_| VaultError::IntegrityError)?;
    // Never surface serde messages: they may quote plaintext.
    let payload: Payload = serde_json::from_slice(&plain).map_err(|_| VaultError::InvalidFormat("payload"))?;
    payload.validate()?;
    Ok(payload)
}

impl UnlockedVault {
    fn from_parts(c: Container, dek: SecretKey, device_id: &str) -> Result<Self> {
        validate_device_id(device_id)?;
        let payload = decrypt_payload(&c, &dek)?;
        Ok(Self { vault_id: c.vault_id, revision: c.revision, keyring_revision: c.keyring_revision, slots: c.slots, dek, payload, device_id: device_id.to_owned(), dirty: false })
    }

    /// Creates a new empty vault. Returns it with its recovery key, which must be shown to the user once.
    pub fn create(master: &str, params: Argon2Params, device_id: &str, _now_ms: i64) -> Result<(Self, RecoveryKey)> {
        validate_device_id(device_id)?;
        let vault_id = new_uuid()?;
        let dek = kc::generate_data_key()?;
        let rk = RecoveryKey::generate()?;
        let slots = vec![password_slot(&vault_id, &dek, master, params)?, recovery_slot(&vault_id, &dek, &rk)?];
        let v = Self { vault_id, revision: 0, keyring_revision: 1, slots, dek, payload: Payload::default(), device_id: device_id.to_owned(), dirty: true };
        Ok((v, rk))
    }

    /// Unlocks with the master password.
    pub fn unlock_with_password(container: &str, master: &str, device_id: &str) -> Result<Self> {
        let c = Container::parse(container)?;
        let dek = open_password_slot(&c.vault_id, c.password_slot(), master)?;
        Self::from_parts(c, dek, device_id)
    }

    /// Unlocks with the recovery key.
    pub fn unlock_with_recovery_key(container: &str, recovery: &str, device_id: &str) -> Result<Self> {
        let c = Container::parse(container)?;
        let rk = RecoveryKey::parse(recovery)?;
        let slot = c.recovery_slot().ok_or(VaultError::InvalidCredentials)?;
        let dek = open_recovery_slot(&c.vault_id, slot, &rk)?;
        Self::from_parts(c, dek, device_id)
    }

    /// Re-opens a vault with a DEK kept by the platform (browser session storage, biometric keystore).
    pub fn open_with_data_key(container: &str, dek: &[u8], device_id: &str) -> Result<Self> {
        let c = Container::parse(container)?;
        let dek = SecretKey::from_slice(dek).map_err(|_| VaultError::InvalidCredentials)?;
        Self::from_parts(c, dek, device_id).map_err(|e| if e == VaultError::IntegrityError { VaultError::InvalidCredentials } else { e })
    }

    /// Encrypts the current state into a container. Bumps the revision if there were changes.
    pub fn export_container(&mut self) -> Result<String> {
        if self.dirty {
            self.revision += 1;
        }
        self.payload.normalize();
        let plain = Zeroizing::new(serde_json::to_vec(&self.payload).map_err(|_| VaultError::Crypto)?);
        let aad = payload_aad(&self.vault_id, self.revision, self.keyring_revision, &self.slots);
        let sealed = kc::encrypt(&self.dek, &aad, &plain)?;
        let c = Container { vault_id: self.vault_id, revision: self.revision, keyring_revision: self.keyring_revision, slots: self.slots.clone(), payload: sealed };
        self.dirty = false;
        Ok(c.to_json())
    }

    /// Vault id.
    pub fn vault_id(&self) -> String {
        self.vault_id.hyphenated().to_string()
    }
    /// Revision of the last export (or of the opened container).
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Keyring revision.
    pub fn keyring_revision(&self) -> u64 {
        self.keyring_revision
    }
    /// Whether there are changes not yet exported.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
    /// This device's id.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
    /// Read-only access to the decrypted payload (sync layer).
    pub fn payload(&self) -> &Payload {
        &self.payload
    }
    /// Current key slots.
    pub fn slots(&self) -> &[KeySlot] {
        &self.slots
    }

    /// DEK copy for platform session storage / biometric wrapping. Never log or sync it.
    pub fn export_data_key(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.dek.expose().to_vec())
    }

    // ---------- reading ----------

    /// Summaries sorted by title (case-insensitive).
    pub fn list_entries(&self) -> Vec<EntrySummary> {
        let mut v: Vec<EntrySummary> = self.payload.entries.iter().map(EntrySummary::from).collect();
        v.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()).then_with(|| a.id.cmp(&b.id)));
        v
    }

    /// Case-insensitive search over title, username and URLs (UI search, **not** used for autofill).
    pub fn search(&self, query: &str) -> Vec<EntrySummary> {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return self.list_entries();
        }
        self.list_entries()
            .into_iter()
            .filter(|e| e.title.to_lowercase().contains(&q) || e.username.to_lowercase().contains(&q) || e.urls.iter().any(|u| u.to_lowercase().contains(&q)))
            .collect()
    }

    /// Full entry including password.
    pub fn get_entry(&self, id: &str) -> Result<Entry> {
        self.payload.entry_index(id).map(|i| self.payload.entries[i].clone()).ok_or(VaultError::NotFound)
    }

    /// Entries whose URLs match `page_url`, best matches first. Only `Exact` and `SameSite` are returned.
    pub fn find_matches(&self, page_url: &str) -> Vec<CredentialMatch> {
        let Some(page) = origin::parse_page_url(page_url) else { return Vec::new() };
        let mut out = Vec::new();
        for e in &self.payload.entries {
            let mut best: Option<(MatchLevel, &String)> = None;
            for u in &e.urls {
                if let Some(eo) = origin::parse_entry_url(u) {
                    let lvl = origin::match_origins(&eo, &page);
                    if lvl != MatchLevel::None && best.is_none_or(|(b, _)| lvl > b) {
                        best = Some((lvl, u));
                    }
                }
            }
            if let Some((level, url)) = best {
                out.push(CredentialMatch { entry: EntrySummary::from(e), level, matched_url: url.clone(), page_host: page.host.clone(), page_is_idn: page.is_idn() });
            }
        }
        out.sort_by(|a, b| b.level.cmp(&a.level).then_with(|| a.entry.title.to_lowercase().cmp(&b.entry.title.to_lowercase())));
        out
    }

    /// Entries explicitly associated with an Android package (`androidapp://package`).
    pub fn find_app_matches(&self, package: &str) -> Vec<CredentialMatch> {
        let mut out: Vec<CredentialMatch> = self
            .payload
            .entries
            .iter()
            .filter_map(|e| {
                e.urls.iter().find(|u| origin::parse_android_app(u).as_deref() == Some(package)).map(|u| CredentialMatch {
                    entry: EntrySummary::from(e),
                    level: MatchLevel::Exact,
                    matched_url: u.clone(),
                    page_host: package.to_owned(),
                    page_is_idn: false,
                })
            })
            .collect();
        out.sort_by(|a, b| a.entry.title.to_lowercase().cmp(&b.entry.title.to_lowercase()));
        out
    }

    // ---------- writing ----------

    fn bump(&self, clock: &Clock) -> Clock {
        let mut c = clock.clone();
        *c.entry(self.device_id.clone()).or_insert(0) += 1;
        c
    }

    /// Creates a new entry with a fresh random id.
    pub fn create_entry(&mut self, input: EntryInput, now_ms: i64) -> Result<Entry> {
        validate_input(&input)?;
        if self.payload.entries.len() + self.payload.tombstones.len() >= MAX_RECORDS {
            return Err(VaultError::Validation("too many entries"));
        }
        let now = timefmt::format_ms(now_ms)?;
        let id = new_uuid()?.hyphenated().to_string();
        let e = Entry {
            id,
            title: input.title.clone(),
            username: input.username.clone(),
            password: input.password.clone(),
            urls: input.urls.iter().map(|u| u.trim().to_owned()).collect(),
            notes: input.notes.clone(),
            created_at: now.clone(),
            updated_at: now,
            updated_by: self.device_id.clone(),
            clock: [(self.device_id.clone(), 1u64)].into_iter().collect(),
            password_history: Vec::new(),
            conflicts: Vec::new(),
        };
        self.payload.upsert_entry(e.clone());
        self.dirty = true;
        Ok(e)
    }

    /// Updates one entry; the others are untouched. A changed password is kept in the history.
    pub fn update_entry(&mut self, id: &str, input: EntryInput, now_ms: i64) -> Result<Entry> {
        validate_input(&input)?;
        let now = timefmt::format_ms(now_ms)?;
        let i = self.payload.entry_index(id).ok_or(VaultError::NotFound)?;
        let clock = self.bump(&self.payload.entries[i].clock);
        let device = self.device_id.clone();
        let e = &mut self.payload.entries[i];
        if e.password != input.password && !e.password.is_empty() {
            e.password_history.insert(0, HistoryItem { password: e.password.clone(), retired_at: now.clone() });
            e.password_history.truncate(MAX_HISTORY);
        }
        e.title = input.title.clone();
        e.username = input.username.clone();
        e.password = input.password.clone();
        e.urls = input.urls.iter().map(|u| u.trim().to_owned()).collect();
        e.notes = input.notes.clone();
        e.updated_at = now;
        e.updated_by = device;
        e.clock = clock;
        let out = e.clone();
        self.dirty = true;
        Ok(out)
    }

    /// Deletes an entry (leaves a tombstone so the deletion propagates).
    pub fn delete_entry(&mut self, id: &str, now_ms: i64) -> Result<()> {
        let now = timefmt::format_ms(now_ms)?;
        let i = self.payload.entry_index(id).ok_or(VaultError::NotFound)?;
        let removed = self.payload.entries.remove(i);
        let t = Tombstone { id: removed.id.clone(), deleted_at: now, deleted_by: self.device_id.clone(), clock: self.bump(&removed.clock) };
        self.payload.upsert_tombstone(t);
        self.dirty = true;
        Ok(())
    }

    /// Resolves the pending conflicts of an entry.
    pub fn resolve_conflict(&mut self, id: &str, choice: ConflictChoice, now_ms: i64) -> Result<()> {
        let i = self.payload.entry_index(id).ok_or(VaultError::NotFound)?;
        let current = self.payload.entries[i].clone();
        match choice {
            ConflictChoice::KeepCurrent => {
                let now = timefmt::format_ms(now_ms)?;
                let clock = self.bump(&current.clock);
                let e = &mut self.payload.entries[i];
                e.conflicts.clear();
                e.clock = clock;
                e.updated_at = now;
                e.updated_by = self.device_id.clone();
            }
            ConflictChoice::TakeConflict(idx) => {
                let snap = current.conflicts.get(idx).ok_or(VaultError::Validation("conflictIndex"))?.clone();
                match snap.kind {
                    ConflictKind::Deletion => return self.delete_entry(id, now_ms),
                    ConflictKind::Edit => {
                        let input = EntryInput { title: snap.title.clone(), username: snap.username.clone(), password: snap.password.clone(), urls: snap.urls.clone(), notes: snap.notes.clone() };
                        self.update_entry(id, input, now_ms)?;
                        self.payload.entries[i].conflicts.clear();
                    }
                }
            }
        }
        self.dirty = true;
        Ok(())
    }

    // ---------- keys ----------

    /// Changes the master password after verifying the current one. Re-wraps the DEK (entries are not re-encrypted
    /// individually; the payload is re-encrypted on the next export because the slot set is bound into its AAD).
    pub fn change_master_password(&mut self, current: &str, new: &str, params: Argon2Params) -> Result<()> {
        let dek = open_password_slot(&self.vault_id, &self.slots[0], current)?;
        if dek != self.dek {
            return Err(VaultError::InvalidCredentials);
        }
        self.slots[0] = password_slot(&self.vault_id, &self.dek, new, params)?;
        self.keyring_revision += 1;
        self.dirty = true;
        Ok(())
    }

    /// Sets a new master password after proving possession of the recovery key.
    pub fn reset_master_password_with_recovery(&mut self, recovery: &str, new: &str, params: Argon2Params) -> Result<()> {
        let rk = RecoveryKey::parse(recovery)?;
        let slot = self.slots.get(1).ok_or(VaultError::InvalidCredentials)?;
        let dek = open_recovery_slot(&self.vault_id, slot, &rk)?;
        if dek != self.dek {
            return Err(VaultError::InvalidCredentials);
        }
        self.slots[0] = password_slot(&self.vault_id, &self.dek, new, params)?;
        self.keyring_revision += 1;
        self.dirty = true;
        Ok(())
    }

    /// Replaces the recovery key (the old one stops working once the new container is written).
    pub fn rotate_recovery_key(&mut self, current: &str) -> Result<RecoveryKey> {
        let dek = open_password_slot(&self.vault_id, &self.slots[0], current)?;
        if dek != self.dek {
            return Err(VaultError::InvalidCredentials);
        }
        let rk = RecoveryKey::generate()?;
        let slot = recovery_slot(&self.vault_id, &self.dek, &rk)?;
        if self.slots.len() > 1 {
            self.slots[1] = slot;
        } else {
            self.slots.push(slot);
        }
        self.keyring_revision += 1;
        self.dirty = true;
        Ok(rk)
    }

    // ---------- sync hooks ----------

    /// Decrypts another container of the same vault with this session's DEK (remote copy, older revision, backup).
    pub fn decrypt_foreign(&self, container: &str) -> Result<ForeignVault> {
        let c = Container::parse(container)?;
        if c.vault_id != self.vault_id {
            return Err(VaultError::VaultMismatch);
        }
        let payload = decrypt_payload(&c, &self.dek)?;
        Ok(ForeignVault { revision: c.revision, keyring_revision: c.keyring_revision, slots: c.slots, payload })
    }

    /// Installs the result of a merge (called by `keyvora-sync`).
    ///
    /// `adopt_remote_state = true` means the merged state equals `remote` exactly: the local vault becomes the
    /// remote revision and is clean. Otherwise the vault is marked dirty and its next export gets
    /// `max(local, remote) + 1`.
    pub fn apply_merge(&mut self, merged: Payload, slots: Option<(Vec<KeySlot>, u64)>, remote_revision: u64, adopt_remote_state: bool) -> Result<()> {
        merged.validate()?;
        self.payload = merged;
        if let Some((s, kr)) = slots {
            self.slots = s;
            self.keyring_revision = kr;
        }
        if adopt_remote_state {
            self.revision = remote_revision;
            self.dirty = false;
        } else {
            self.revision = self.revision.max(remote_revision);
            self.dirty = true;
        }
        Ok(())
    }

    /// Copies chosen entries from an older container of this vault as **new** entries (restore after deletion).
    pub fn restore_entries_from(&mut self, container: &str, ids: &[String], now_ms: i64) -> Result<Vec<Entry>> {
        let old = self.decrypt_foreign(container)?;
        let mut out = Vec::new();
        for id in ids {
            let i = old.payload.entry_index(id).ok_or(VaultError::NotFound)?;
            let e = &old.payload.entries[i];
            let input = EntryInput { title: e.title.clone(), username: e.username.clone(), password: e.password.clone(), urls: e.urls.clone(), notes: e.notes.clone() };
            out.push(self.create_entry(input, now_ms)?);
        }
        Ok(out)
    }
}

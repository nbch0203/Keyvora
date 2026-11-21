//! Unlocked vault session (typestate: protected operations only exist on an unlocked vault).

use crate::container::{
    payload_aad, slot_aad, Container, KdfSpec, KeySlot, SlotKind, MAX_CONTAINER_BYTES, RECOVERY_INFO,
};
use crate::error::{Result, VaultError};
use crate::model::*;
use crate::origin::{self, MatchLevel};
use crate::recovery::RecoveryKey;
use crate::strength;
use crate::timefmt;
use crate::totp;
use keyvora_crypto::{self as kc, Argon2Params, SecretKey};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Minimum master password length (Unicode scalar values) for new or changed master passwords.
pub const MIN_MASTER_LEN: usize = 12;
/// Maximum master password length.
pub const MAX_MASTER_LEN: usize = 1024;
const SALT_LEN: usize = 32;
/// Argon2id parameters for the master-password history hashes (only used to refuse reusing an old password).
const HISTORY_PARAMS: Argon2Params = Argon2Params { memory_kib: 19 * 1024, iterations: 2, parallelism: 1 };
/// The encrypted payload is padded to these granularities so its size does not reveal how many entries there are.
const PAD_SMALL: usize = 4 * 1024;
const PAD_SMALL_LIMIT: usize = 64 * 1024;
const PAD_LARGE: usize = 64 * 1024;

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
        f.debug_struct("UnlockedVault")
            .field("vault_id", &self.vault_id)
            .field("revision", &self.revision)
            .field("records", &self.payload.records.len())
            .finish_non_exhaustive()
    }
}

/// NFC-normalized copy in a pre-sized, zeroized buffer (avoids leaving reallocation copies behind).
fn nfc(master: &str) -> Zeroizing<String> {
    let mut n = Zeroizing::new(String::with_capacity(master.len() * 3 + 4));
    n.extend(master.nfc());
    n
}

/// NFC-normalizes a new master password and enforces the policy: length, then strength (no trivial passwords such
/// as repeats, sequences or well-known ones — see [`strength`]).
fn normalize_master(master: &str) -> Result<Zeroizing<String>> {
    let n = nfc(master);
    let len = n.chars().count();
    if !(MIN_MASTER_LEN..=MAX_MASTER_LEN).contains(&len) {
        return Err(VaultError::Validation("masterPassword"));
    }
    let st = strength::master_password_strength(&n);
    if st.problems.iter().any(|p| p == "tooShort") {
        return Err(VaultError::Validation("masterPassword"));
    }
    if !st.acceptable() {
        return Err(VaultError::Validation("masterWeak"));
    }
    Ok(n)
}

/// Argon2id hash of a (normalized) master password for the reuse history.
fn master_hash(master_nfc: &str, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let k = kc::derive_wrapping_key(master_nfc.as_bytes(), salt, &HISTORY_PARAMS)?;
    Ok(Zeroizing::new(k.expose().to_vec()))
}

/// Pads serialized JSON with trailing spaces (valid JSON whitespace, ignored by the parser) to the next size bucket,
/// never beyond what still fits in a container.
fn pad_plaintext(buf: &mut Zeroizing<Vec<u8>>) {
    let len = buf.len();
    let gran = if len < PAD_SMALL_LIMIT { PAD_SMALL } else { PAD_LARGE };
    let target = len.div_ceil(gran).max(1) * gran;
    // Base64 grows 4/3; keep generous room for the JSON header and slots.
    let max_plain = (MAX_CONTAINER_BYTES - 16 * 1024) / 4 * 3;
    let target = target.min(max_plain.max(len));
    buf.resize(target, b' ');
}

fn new_uuid() -> Result<Uuid> {
    let mut b = [0u8; 16];
    kc::fill_random(&mut b)?;
    Ok(uuid::Builder::from_random_bytes(b).into_uuid())
}

/// Builds a password slot. `master` must already be NFC-normalized (see [`normalize_master`] / [`nfc`]).
fn password_slot(vault_id: &Uuid, dek: &SecretKey, master: &str, params: Argon2Params) -> Result<KeySlot> {
    params.validate().map_err(|_| VaultError::ParamsOutOfBounds)?;
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
    let KdfSpec::Argon2id { salt, params } = &slot.kdf else {
        return Err(VaultError::InvalidFormat("password slot kdf"));
    };
    let master = nfc(master);
    let kek = kc::derive_wrapping_key(master.as_bytes(), salt, params).map_err(VaultError::from)?;
    kc::unwrap_data_key(&slot.wrap, &kek, &slot_aad(vault_id, SlotKind::Password, &slot.kdf))
        .map_err(|_| VaultError::InvalidCredentials)
}

fn open_recovery_slot(vault_id: &Uuid, slot: &KeySlot, rk: &RecoveryKey) -> Result<SecretKey> {
    let KdfSpec::HkdfSha256 { salt } = &slot.kdf else { return Err(VaultError::InvalidFormat("recovery slot kdf")) };
    let kek = kc::derive_recovery_key(rk.secret().expose(), salt, RECOVERY_INFO)?;
    kc::unwrap_data_key(&slot.wrap, &kek, &slot_aad(vault_id, SlotKind::Recovery, &slot.kdf))
        .map_err(|_| VaultError::InvalidCredentials)
}

/// QA-DEF-002: a retired key can never be newer than the keyring it is stored under.
fn check_retired_keys(p: &Payload, keyring_revision: u64) -> Result<()> {
    if p.retired_keys.iter().any(|k| k.keyring_revision > keyring_revision) {
        return Err(VaultError::InvalidFormat("retiredKeys newer than keyring"));
    }
    Ok(())
}

/// `v + 1`, refusing to exceed [`MAX_COUNTER`] (keeps every counter exact in JavaScript and never wraps).
fn checked_inc(v: u64) -> Result<u64> {
    if v >= MAX_COUNTER {
        return Err(VaultError::Validation("counter limit reached"));
    }
    Ok(v + 1)
}

/// Serializes the payload into a pre-sized zeroized buffer (best effort against reallocation copies).
fn serialize_payload(p: &Payload) -> Result<Zeroizing<Vec<u8>>> {
    let estimate: usize = 256
        + p.records
            .iter()
            .map(|r| {
                512 + r.password_history.iter().map(|h| h.password.len() * 2 + 64).sum::<usize>()
                    + r.versions
                        .iter()
                        .map(|v| {
                            256 + 2 * (v.title.len() + v.username.len() + v.password.len() + v.notes.len())
                                + v.urls.iter().map(|u| 2 * u.len() + 8).sum::<usize>()
                        })
                        .sum::<usize>()
            })
            .sum::<usize>();
    let mut buf = Zeroizing::new(Vec::with_capacity(estimate));
    serde_json::to_writer(&mut *buf, p).map_err(|_| VaultError::Crypto)?;
    Ok(buf)
}

fn decrypt_payload(c: &Container, dek: &SecretKey) -> Result<Payload> {
    let aad = payload_aad(&c.vault_id, c.revision, c.keyring_revision, &c.slots);
    let plain = kc::decrypt(dek, &aad, &c.payload).map_err(|_| VaultError::IntegrityError)?;
    // Never surface serde messages: they may quote plaintext.
    let payload: Payload = serde_json::from_slice(&plain).map_err(|_| VaultError::InvalidFormat("payload"))?;
    payload.validate()?;
    check_retired_keys(&payload, c.keyring_revision)?;
    Ok(payload)
}

impl UnlockedVault {
    fn from_parts(c: Container, dek: SecretKey, device_id: &str) -> Result<Self> {
        validate_device_id(device_id)?;
        let payload = decrypt_payload(&c, &dek)?;
        Ok(Self {
            vault_id: c.vault_id,
            revision: c.revision,
            keyring_revision: c.keyring_revision,
            slots: c.slots,
            dek,
            payload,
            device_id: device_id.to_owned(),
            dirty: false,
        })
    }

    /// Creates a new empty vault. Returns it with its recovery key, which must be shown to the user once.
    pub fn create(master: &str, params: Argon2Params, device_id: &str, now_ms: i64) -> Result<(Self, RecoveryKey)> {
        validate_device_id(device_id)?;
        let now = timefmt::format_ms(now_ms)?;
        let vault_id = new_uuid()?;
        let dek = kc::generate_data_key()?;
        let rk = RecoveryKey::generate()?;
        let master = normalize_master(master)?;
        let slots = vec![password_slot(&vault_id, &dek, &master, params)?, recovery_slot(&vault_id, &dek, &rk)?];
        let v = Self {
            vault_id,
            revision: 0,
            keyring_revision: 1,
            slots,
            dek,
            payload: Payload { master_changed_at: Some(now), ..Payload::default() },
            device_id: device_id.to_owned(),
            dirty: true,
        };
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
        Self::from_parts(c, dek, device_id).map_err(|e| {
            if e == VaultError::IntegrityError {
                VaultError::InvalidCredentials
            } else {
                e
            }
        })
    }

    /// Encrypts the current state into a container. Bumps the revision if there were changes.
    ///
    /// The writer enforces exactly the reader's invariants (structure, limits, counters, size): it returns an error
    /// instead of ever emitting a container that no client could open again.
    pub fn export_container(&mut self) -> Result<String> {
        let revision = if self.dirty { checked_inc(self.revision)? } else { self.revision };
        self.payload.normalize();
        self.payload.validate()?;
        check_retired_keys(&self.payload, self.keyring_revision)?;
        let mut plain = serialize_payload(&self.payload)?;
        pad_plaintext(&mut plain);
        let aad = payload_aad(&self.vault_id, revision, self.keyring_revision, &self.slots);
        let sealed = kc::encrypt(&self.dek, &aad, &plain)?;
        let c = Container {
            vault_id: self.vault_id,
            revision,
            keyring_revision: self.keyring_revision,
            slots: self.slots.clone(),
            payload: sealed,
        };
        let json = c.to_json();
        if json.len() > MAX_CONTAINER_BYTES {
            return Err(VaultError::Validation("vault too large"));
        }
        self.revision = revision;
        self.dirty = false;
        Ok(json)
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

    /// Last time the master password was set (ISO), for the monthly change reminder.
    pub fn master_changed_at(&self) -> Option<&str> {
        self.payload.master_changed_at.as_deref()
    }

    /// DEK copy for platform session storage / biometric wrapping. Never log or sync it.
    pub fn export_data_key(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.dek.expose().to_vec())
    }

    // ---------- reading ----------

    /// Summaries sorted by title (case-insensitive).
    pub fn list_entries(&self) -> Vec<EntrySummary> {
        let mut v: Vec<EntrySummary> = self.payload.records.iter().filter_map(Record::to_summary).collect();
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
            .filter(|e| {
                e.title.to_lowercase().contains(&q)
                    || e.username.to_lowercase().contains(&q)
                    || e.urls.iter().any(|u| u.to_lowercase().contains(&q))
            })
            .collect()
    }

    /// Full entry including password.
    pub fn get_entry(&self, id: &str) -> Result<Entry> {
        self.payload.record_index(id).and_then(|i| self.payload.records[i].to_entry()).ok_or(VaultError::NotFound)
    }

    /// Entries whose URLs match `page_url`, best matches first. Only `Exact` and `SameSite` are returned.
    pub fn find_matches(&self, page_url: &str) -> Vec<CredentialMatch> {
        let Some(page) = origin::parse_page_url(page_url) else { return Vec::new() };
        let mut out = Vec::new();
        for (r, m) in self.payload.live_entries() {
            let mut best: Option<(MatchLevel, &String)> = None;
            for u in &m.urls {
                if let Some(eo) = origin::parse_entry_url(u) {
                    let lvl = origin::match_origins(&eo, &page);
                    if lvl != MatchLevel::None && best.is_none_or(|(b, _)| lvl > b) {
                        best = Some((lvl, u));
                    }
                }
            }
            if let (Some((level, url)), Some(summary)) = (best, r.to_summary()) {
                out.push(CredentialMatch {
                    entry: summary,
                    level,
                    matched_url: url.clone(),
                    page_host: page.display_host(),
                    page_is_idn: page.is_idn(),
                });
            }
        }
        out.sort_by(|a, b| {
            b.level.cmp(&a.level).then_with(|| a.entry.title.to_lowercase().cmp(&b.entry.title.to_lowercase()))
        });
        out
    }

    /// Entries explicitly associated with an Android package (`androidapp://package`).
    pub fn find_app_matches(&self, package: &str) -> Vec<CredentialMatch> {
        let mut out: Vec<CredentialMatch> = self
            .payload
            .live_entries()
            .filter_map(|(r, m)| {
                let u = m.urls.iter().find(|u| origin::parse_android_app(u).as_deref() == Some(package))?;
                Some(CredentialMatch {
                    entry: r.to_summary()?,
                    level: MatchLevel::Exact,
                    matched_url: u.clone(),
                    page_host: package.to_owned(),
                    page_is_idn: false,
                })
            })
            .collect();
        out.sort_by_key(|m| m.entry.title.to_lowercase());
        out
    }

    // ---------- writing ----------

    fn new_version(&self, record: &mut Record, input: Option<&EntryInput>, now: &str) -> Result<Version> {
        let dot = record.next_dot(&self.device_id)?;
        Ok(match input {
            Some(i) => Version {
                dot,
                deleted: false,
                title: i.title.clone(),
                username: i.username.clone(),
                password: i.password.clone(),
                urls: i.urls.iter().map(|u| u.trim().to_owned()).collect(),
                notes: i.notes.clone(),
                updated_at: now.to_owned(),
            },
            None => Version {
                dot,
                deleted: true,
                title: String::new(),
                username: String::new(),
                password: String::new(),
                urls: Vec::new(),
                notes: String::new(),
                updated_at: now.to_owned(),
            },
        })
    }

    /// Creates a new entry with a fresh random id.
    pub fn create_entry(&mut self, input: EntryInput, now_ms: i64) -> Result<Entry> {
        validate_input(&input)?;
        if self.payload.live_count() >= MAX_ENTRIES || self.payload.records.len() >= MAX_RECORDS {
            return Err(VaultError::Validation("too many entries"));
        }
        let now = timefmt::format_ms(now_ms)?;
        let mut r = Record {
            id: new_uuid()?.hyphenated().to_string(),
            created_at: now.clone(),
            context: Clock::new(),
            versions: Vec::new(),
            password_history: Vec::new(),
            history_floor: Clock::new(),
        };
        let v = self.new_version(&mut r, Some(&input), &now)?;
        r.versions.push(v);
        let view = r.to_entry().ok_or(VaultError::Crypto)?;
        self.payload.upsert(r);
        self.dirty = true;
        Ok(view)
    }

    /// Updates the shown version of one entry; other entries and pending conflicts are untouched.
    /// A changed password is kept in the history.
    pub fn update_entry(&mut self, id: &str, input: EntryInput, now_ms: i64) -> Result<Entry> {
        validate_input(&input)?;
        let now = timefmt::format_ms(now_ms)?;
        let i = self.payload.live_index(id).ok_or(VaultError::NotFound)?;
        let mut r = self.payload.records[i].clone();
        let main = r.main_index().ok_or(VaultError::NotFound)?;
        let old_password = r.versions[main].password.clone();
        r.versions.remove(main);
        let v = self.new_version(&mut r, Some(&input), &now)?;
        r.retire_password(&old_password, &input.password, &now, &v.dot);
        r.versions.push(v);
        r.versions.sort_by(|a, b| a.dot.cmp(&b.dot));
        let view = r.to_entry().ok_or(VaultError::Crypto)?;
        self.payload.records[i] = r;
        self.dirty = true;
        Ok(view)
    }

    /// Deletes an entry with all the versions shown to the user (writes a deletion so it propagates).
    pub fn delete_entry(&mut self, id: &str, now_ms: i64) -> Result<()> {
        let now = timefmt::format_ms(now_ms)?;
        let i = self.payload.live_index(id).ok_or(VaultError::NotFound)?;
        let mut r = self.payload.records[i].clone();
        let v = self.new_version(&mut r, None, &now)?;
        r.versions = vec![v];
        r.clear_history();
        self.payload.records[i] = r;
        self.dirty = true;
        Ok(())
    }

    /// Resolves the pending conflicts of an entry by writing the chosen version as a new version that supersedes all
    /// the ones currently shown (concurrent resolutions on other devices are kept as new conflicts, never lost).
    pub fn resolve_conflict(&mut self, id: &str, choice: ConflictChoice, now_ms: i64) -> Result<()> {
        let now = timefmt::format_ms(now_ms)?;
        let i = self.payload.live_index(id).ok_or(VaultError::NotFound)?;
        let mut r = self.payload.records[i].clone();
        let main = r.main().ok_or(VaultError::NotFound)?.clone();
        let chosen = match choice {
            ConflictChoice::KeepCurrent => main.clone(),
            ConflictChoice::TakeConflict(idx) => {
                (*r.conflict_versions().get(idx).ok_or(VaultError::Validation("conflictIndex"))?).clone()
            }
        };
        let v = if chosen.deleted {
            let v = self.new_version(&mut r, None, &now)?;
            r.clear_history();
            v
        } else {
            let input = EntryInput {
                title: chosen.title.clone(),
                username: chosen.username.clone(),
                password: chosen.password.clone(),
                urls: chosen.urls.clone(),
                notes: chosen.notes.clone(),
            };
            let v = self.new_version(&mut r, Some(&input), &now)?;
            r.retire_password(&main.password, &chosen.password, &now, &v.dot);
            v
        };
        r.versions = vec![v];
        self.payload.records[i] = r;
        self.dirty = true;
        Ok(())
    }

    // ---------- keys ----------

    /// Replaces the data key, the password slot and the recovery key (CORE-010, audit ALTA-1). Anyone holding a
    /// previous master password, recovery key or data key — even together with old copies of the file — cannot read
    /// containers written after this point. The old DEK is kept, encrypted under the new one, only so the user can
    /// still restore entries from old copies. `master_nfc` must already be NFC-normalized.
    fn rekey(&mut self, master_nfc: &str, params: Argon2Params) -> Result<RecoveryKey> {
        let kr = checked_inc(self.keyring_revision)?;
        let new_dek = kc::generate_data_key()?;
        let rk = RecoveryKey::generate()?;
        let slots = vec![
            password_slot(&self.vault_id, &new_dek, master_nfc, params)?,
            recovery_slot(&self.vault_id, &new_dek, &rk)?,
        ];
        use base64::Engine;
        let retired = RetiredKey {
            keyring_revision: self.keyring_revision,
            key: base64::engine::general_purpose::STANDARD.encode(self.dek.expose()),
        };
        let mut keys = std::mem::take(&mut self.payload.retired_keys);
        keys.push(retired);
        self.payload.retired_keys = normalize_retired_keys(keys);
        self.slots = slots;
        self.dek = new_dek;
        self.keyring_revision = kr;
        self.dirty = true;
        Ok(rk)
    }

    fn current_params(&self) -> Argon2Params {
        match &self.slots[0].kdf {
            KdfSpec::Argon2id { params, .. } => *params,
            KdfSpec::HkdfSha256 { .. } => Argon2Params::DEFAULT,
        }
    }

    /// Refuses a new master password equal to the current one or to one of the last [`MAX_MASTER_HISTORY`].
    fn check_not_reused(&self, new_nfc: &str, current_nfc: Option<&str>) -> Result<()> {
        if current_nfc.is_some_and(|c| kc::ct_eq(c.as_bytes(), new_nfc.as_bytes())) {
            return Err(VaultError::Validation("masterReused"));
        }
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        for h in &self.payload.master_history {
            let salt = b64.decode(&h.salt).map_err(|_| VaultError::InvalidFormat("masterHistory"))?;
            let stored = Zeroizing::new(b64.decode(&h.hash).map_err(|_| VaultError::InvalidFormat("masterHistory"))?);
            if kc::ct_eq(&master_hash(new_nfc, &salt)?, &stored) {
                return Err(VaultError::Validation("masterReused"));
            }
        }
        Ok(())
    }

    fn remember_master(&mut self, old_nfc: &str, now: &str) -> Result<()> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let salt = kc::random_bytes(16)?;
        let hash = master_hash(old_nfc, &salt)?;
        let mut items = std::mem::take(&mut self.payload.master_history);
        items.push(MasterHistoryItem { changed_at: now.to_owned(), salt: b64.encode(&salt), hash: b64.encode(&*hash) });
        self.payload.master_history = normalize_master_history(items);
        Ok(())
    }

    /// Changes the master password after verifying the current one. Also rotates the data key and issues a **new
    /// recovery key** (returned; show it once): whoever knew the old password and kept an old copy of the file can
    /// no longer read anything written from now on. The new password must be strong and differ from the current
    /// one and the last [`MAX_MASTER_HISTORY`].
    pub fn change_master_password(
        &mut self,
        current: &str,
        new: &str,
        params: Argon2Params,
        now_ms: i64,
    ) -> Result<RecoveryKey> {
        let dek = open_password_slot(&self.vault_id, &self.slots[0], current)?;
        if dek != self.dek {
            return Err(VaultError::InvalidCredentials);
        }
        let now = timefmt::format_ms(now_ms)?;
        let new = normalize_master(new)?;
        let current = nfc(current);
        self.check_not_reused(&new, Some(&current))?;
        self.remember_master(&current, &now)?;
        self.payload.master_changed_at = Some(now);
        self.rekey(&new, params)
    }

    /// Sets a new master password after proving possession of the recovery key. Rotates the data key and issues a
    /// new recovery key (the one just used may be compromised).
    pub fn reset_master_password_with_recovery(
        &mut self,
        recovery: &str,
        new: &str,
        params: Argon2Params,
        now_ms: i64,
    ) -> Result<RecoveryKey> {
        let rk = RecoveryKey::parse(recovery)?;
        let slot = self.slots.get(1).ok_or(VaultError::InvalidCredentials)?;
        let dek = open_recovery_slot(&self.vault_id, slot, &rk)?;
        if dek != self.dek {
            return Err(VaultError::InvalidCredentials);
        }
        let now = timefmt::format_ms(now_ms)?;
        let new = normalize_master(new)?;
        self.check_not_reused(&new, None)?;
        self.payload.master_changed_at = Some(now);
        self.rekey(&new, params)
    }

    /// Issues a new recovery key. The data key is rotated too: otherwise whoever holds the old recovery key and an
    /// old copy of the file could still unwrap the (unchanged) data key and read new data.
    pub fn rotate_recovery_key(&mut self, current: &str) -> Result<RecoveryKey> {
        self.rotate_data_key(current)
    }

    /// Rotates the data-encryption key (CORE-010): new random DEK, password slot re-created (same password, new
    /// salt) and a **new recovery key**. Old copies (Drive revisions, exports) stay readable with the old secrets:
    /// rotation protects data written from now on. Containers encrypted with the old key are no longer merged by sync.
    pub fn rotate_data_key(&mut self, current: &str) -> Result<RecoveryKey> {
        let dek = open_password_slot(&self.vault_id, &self.slots[0], current)?;
        if dek != self.dek {
            return Err(VaultError::InvalidCredentials);
        }
        let params = self.current_params();
        let master = nfc(current);
        self.rekey(&master, params)
    }

    // ---------- two-step verification (TOTP) ----------

    /// Whether two-step verification is enabled.
    pub fn two_factor_enabled(&self) -> bool {
        self.payload.two_factor.as_ref().is_some_and(TwoFactor::enabled)
    }

    /// Starts enabling: a fresh secret and its `otpauth://` URI (for the QR code). Nothing is stored until
    /// [`Self::enable_two_factor`] confirms a code generated by the authenticator.
    pub fn new_two_factor_secret(&self) -> Result<(String, String)> {
        let secret = totp::generate_secret()?;
        let uri = totp::otpauth_uri(&secret);
        Ok((secret, uri))
    }

    /// Enables two-step verification once the user proves the authenticator works. Returns the accepted step.
    pub fn enable_two_factor(&mut self, secret: &str, code: &str, now_ms: i64) -> Result<u64> {
        totp::validate_secret(secret)?;
        let step = totp::verify(secret, code, unix_secs(now_ms)?, None)?;
        self.payload.two_factor = Some(TwoFactor { secret: secret.to_owned(), updated_at: timefmt::format_ms(now_ms)? });
        self.dirty = true;
        Ok(step)
    }

    /// Checks a code (clients keep `last_step` per device so a code is never accepted twice). Returns the step.
    pub fn verify_two_factor(&self, code: &str, now_ms: i64, last_step: Option<u64>) -> Result<u64> {
        let t = self.payload.two_factor.as_ref().filter(|t| t.enabled()).ok_or(VaultError::NotFound)?;
        totp::verify(&t.secret, code, unix_secs(now_ms)?, last_step)
    }

    /// Disables two-step verification (needs a valid code; recovery-key users re-enable it with a new secret).
    pub fn disable_two_factor(&mut self, code: &str, now_ms: i64, last_step: Option<u64>) -> Result<u64> {
        let step = self.verify_two_factor(code, now_ms, last_step)?;
        self.payload.two_factor = Some(TwoFactor { secret: String::new(), updated_at: timefmt::format_ms(now_ms)? });
        self.dirty = true;
        Ok(step)
    }

    /// Disables two-step verification without a code. Only after unlocking with the **recovery key** (the user lost
    /// the authenticator): the recovery key is a stronger proof than a TOTP code.
    pub fn reset_two_factor_with_recovery(&mut self, recovery: &str, now_ms: i64) -> Result<()> {
        let rk = RecoveryKey::parse(recovery)?;
        let slot = self.slots.get(1).ok_or(VaultError::InvalidCredentials)?;
        if open_recovery_slot(&self.vault_id, slot, &rk)? != self.dek {
            return Err(VaultError::InvalidCredentials);
        }
        if self.two_factor_enabled() {
            self.payload.two_factor = Some(TwoFactor { secret: String::new(), updated_at: timefmt::format_ms(now_ms)? });
            self.dirty = true;
        }
        Ok(())
    }

    /// KDF parameters of the master-password slot (clients warn when they are below the defaults).
    pub fn password_kdf_params(&self) -> Argon2Params {
        match &self.slots[0].kdf {
            KdfSpec::Argon2id { params, .. } => *params,
            KdfSpec::HkdfSha256 { .. } => Argon2Params::DEFAULT,
        }
    }

    /// Replaces this session by another one of the **same vault** (used after re-authenticating against a remote
    /// container whose keys changed). The previous DEK and plaintext are wiped.
    pub fn replace_with(&mut self, other: UnlockedVault) -> Result<()> {
        if other.vault_id != self.vault_id {
            return Err(VaultError::VaultMismatch);
        }
        *self = other;
        Ok(())
    }

    // ---------- sync hooks ----------

    /// Decrypts a container of the same vault with the **current** data key only. Used by sync: a container
    /// encrypted with a retired key is never merged automatically (audit ALTA-2: after a rotation, whoever kept the
    /// old key must not be able to inject changes through the cloud).
    pub fn decrypt_current(&self, container: &str) -> Result<ForeignVault> {
        let c = Container::parse(container)?;
        if c.vault_id != self.vault_id {
            return Err(VaultError::VaultMismatch);
        }
        let payload = decrypt_payload(&c, &self.dek)?;
        Ok(ForeignVault { revision: c.revision, keyring_revision: c.keyring_revision, slots: c.slots, payload })
    }

    /// Decrypts another container of the same vault with the current DEK or a retired one (older revision,
    /// backup). Only for explicit user actions (preview, restore of chosen entries), never for automatic merges.
    pub fn decrypt_foreign(&self, container: &str) -> Result<ForeignVault> {
        let c = Container::parse(container)?;
        if c.vault_id != self.vault_id {
            return Err(VaultError::VaultMismatch);
        }
        // Current key first; containers written before a rotation open with a retired key.
        let payload = match decrypt_payload(&c, &self.dek) {
            Err(VaultError::IntegrityError) if !self.payload.retired_keys.is_empty() => {
                let mut found = None;
                for k in &self.payload.retired_keys {
                    use base64::Engine;
                    let raw = Zeroizing::new(
                        base64::engine::general_purpose::STANDARD.decode(&k.key).map_err(|_| VaultError::Crypto)?,
                    );
                    let key = SecretKey::from_slice(&raw)?;
                    if let Ok(p) = decrypt_payload(&c, &key) {
                        found = Some(p);
                        break;
                    }
                }
                found.ok_or(VaultError::IntegrityError)?
            }
            other => other?,
        };
        Ok(ForeignVault { revision: c.revision, keyring_revision: c.keyring_revision, slots: c.slots, payload })
    }

    /// Installs the result of a merge (called by `keyvora-sync`).
    ///
    /// `adopt_remote_state = true` means the merged state equals `remote` exactly: the local vault becomes the
    /// remote revision and is clean. Otherwise the vault is marked dirty and its next export gets
    /// `max(local, remote) + 1`.
    pub fn apply_merge(
        &mut self,
        merged: Payload,
        slots: Option<(Vec<KeySlot>, u64)>,
        remote_revision: u64,
        adopt_remote_state: bool,
    ) -> Result<()> {
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
    /// All or nothing: every id is checked (and validated) before anything is created.
    pub fn restore_entries_from(&mut self, container: &str, ids: &[String], now_ms: i64) -> Result<Vec<Entry>> {
        let old = self.decrypt_foreign(container)?;
        let mut inputs = Vec::with_capacity(ids.len());
        for id in ids {
            let i = old.payload.record_index(id).ok_or(VaultError::NotFound)?;
            let e = old.payload.records[i].main().ok_or(VaultError::NotFound)?;
            let input = EntryInput {
                title: e.title.clone(),
                username: e.username.clone(),
                password: e.password.clone(),
                urls: e.urls.clone(),
                notes: e.notes.clone(),
            };
            validate_input(&input)?;
            inputs.push(input);
        }
        if self.payload.live_count() + inputs.len() > MAX_ENTRIES {
            return Err(VaultError::Validation("too many entries"));
        }
        let snapshot = (self.payload.clone(), self.dirty);
        let mut out = Vec::with_capacity(inputs.len());
        for input in inputs {
            match self.create_entry(input, now_ms) {
                Ok(e) => out.push(e),
                Err(e) => {
                    (self.payload, self.dirty) = snapshot;
                    return Err(e);
                }
            }
        }
        Ok(out)
    }
}

fn unix_secs(now_ms: i64) -> Result<u64> {
    u64::try_from(now_ms / 1000).map_err(|_| VaultError::Validation("time"))
}

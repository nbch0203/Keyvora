//! Plaintext payload model (lives only inside the encrypted payload). See docs/VAULT_FORMAT.md §5.

use crate::error::{Result, VaultError};
use crate::{origin, timefmt};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Current payload schema version.
pub const SCHEMA_VERSION: u32 = 1;
/// Maximum entries + tombstones.
pub const MAX_RECORDS: usize = 20_000;
/// Field limits (in Unicode scalar values).
pub const MAX_TITLE: usize = 256;
/// Max username length.
pub const MAX_USERNAME: usize = 512;
/// Max password length.
pub const MAX_PASSWORD: usize = 4096;
/// Max notes length.
pub const MAX_NOTES: usize = 16_384;
/// Max URLs per entry.
pub const MAX_URLS: usize = 16;
/// Max URL length.
pub const MAX_URL_LEN: usize = 2048;
/// Max retained password history items.
pub const MAX_HISTORY: usize = 10;
/// Max pending conflict snapshots per entry.
pub const MAX_CONFLICTS: usize = 64;
/// Max devices in a version vector.
pub const MAX_CLOCK_DEVICES: usize = 64;

/// Version vector: device id → counter.
pub type Clock = BTreeMap<String, u64>;

/// Causal relation between two version vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockOrder {
    /// Identical.
    Equal,
    /// Left strictly dominates right.
    Greater,
    /// Right strictly dominates left.
    Less,
    /// Neither dominates.
    Concurrent,
}

/// Compares two version vectors (missing entries count as 0).
pub fn compare_clocks(a: &Clock, b: &Clock) -> ClockOrder {
    let mut a_gt = false;
    let mut b_gt = false;
    for k in a.keys().chain(b.keys()) {
        let x = a.get(k).copied().unwrap_or(0);
        let y = b.get(k).copied().unwrap_or(0);
        if x > y {
            a_gt = true;
        } else if y > x {
            b_gt = true;
        }
    }
    match (a_gt, b_gt) {
        (false, false) => ClockOrder::Equal,
        (true, false) => ClockOrder::Greater,
        (false, true) => ClockOrder::Less,
        (true, true) => ClockOrder::Concurrent,
    }
}

/// Point-wise maximum of two version vectors.
pub fn max_clock(a: &Clock, b: &Clock) -> Clock {
    let mut out = a.clone();
    for (k, v) in b {
        let e = out.entry(k.clone()).or_insert(0);
        *e = (*e).max(*v);
    }
    out
}

/// A previous password of an entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryItem {
    /// The retired password.
    pub password: String,
    /// When it was replaced.
    pub retired_at: String,
}

/// Kind of a pending conflict snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConflictKind {
    /// A concurrent edit that lost the deterministic tie-break.
    Edit,
    /// A concurrent deletion of an entry that was edited elsewhere.
    Deletion,
}

/// A version of an entry that lost a concurrent merge and awaits the user's decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConflictSnapshot {
    /// Edit or deletion.
    #[zeroize(skip)]
    pub kind: ConflictKind,
    /// Title of that version.
    pub title: String,
    /// Username of that version.
    pub username: String,
    /// Password of that version.
    pub password: String,
    /// URLs of that version.
    pub urls: Vec<String>,
    /// Notes of that version.
    pub notes: String,
    /// When that version was written / deleted.
    pub updated_at: String,
    /// Device that wrote it.
    pub updated_by: String,
}

impl ConflictSnapshot {
    /// Deterministic ordering/dedup key.
    pub fn sort_key(&self) -> (String, String, ConflictKind, String) {
        (self.updated_at.clone(), self.updated_by.clone(), self.kind, canonical_content(&self.title, &self.username, &self.password, &self.urls, &self.notes))
    }
}

/// A credential (plaintext; exists only inside the encrypted payload and in unlocked memory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    /// Random UUID v4.
    pub id: String,
    /// Display name.
    pub title: String,
    /// Account identifier.
    pub username: String,
    /// Secret.
    pub password: String,
    /// Associated URLs (`https://…`, `http://localhost…`, `androidapp://package`).
    pub urls: Vec<String>,
    /// Free text.
    pub notes: String,
    /// Creation time.
    pub created_at: String,
    /// Last modification time.
    pub updated_at: String,
    /// Device of the last modification.
    pub updated_by: String,
    /// Version vector.
    #[zeroize(skip)]
    pub clock: Clock,
    /// Previous passwords, newest first.
    #[serde(default)]
    pub password_history: Vec<HistoryItem>,
    /// Pending concurrent versions.
    #[serde(default)]
    pub conflicts: Vec<ConflictSnapshot>,
}

impl Entry {
    /// Canonical serialization of the user-visible content (used for deterministic tie-breaks).
    pub fn content_key(&self) -> String {
        canonical_content(&self.title, &self.username, &self.password, &self.urls, &self.notes)
    }

    /// Snapshot of the current content as an `edit` conflict.
    pub fn snapshot(&self) -> ConflictSnapshot {
        ConflictSnapshot {
            kind: ConflictKind::Edit,
            title: self.title.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            urls: self.urls.clone(),
            notes: self.notes.clone(),
            updated_at: self.updated_at.clone(),
            updated_by: self.updated_by.clone(),
        }
    }
}

/// Deletion marker so that deletions propagate through merges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Tombstone {
    /// Id of the deleted entry.
    pub id: String,
    /// Deletion time.
    pub deleted_at: String,
    /// Device that deleted it.
    pub deleted_by: String,
    /// Version vector at deletion.
    pub clock: Clock,
}

impl Tombstone {
    /// Snapshot of this deletion as a `deletion` conflict.
    pub fn snapshot(&self) -> ConflictSnapshot {
        ConflictSnapshot {
            kind: ConflictKind::Deletion,
            title: String::new(),
            username: String::new(),
            password: String::new(),
            urls: Vec::new(),
            notes: String::new(),
            updated_at: self.deleted_at.clone(),
            updated_by: self.deleted_by.clone(),
        }
    }
}

/// Decrypted payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Payload {
    /// Must equal [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Live entries sorted by id.
    pub entries: Vec<Entry>,
    /// Tombstones sorted by id.
    pub tombstones: Vec<Tombstone>,
}

impl Default for Payload {
    fn default() -> Self {
        Self { schema_version: SCHEMA_VERSION, entries: Vec::new(), tombstones: Vec::new() }
    }
}

/// User input for creating/updating an entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", default)]
pub struct EntryInput {
    /// Display name (required).
    pub title: String,
    /// Account identifier.
    pub username: String,
    /// Secret.
    pub password: String,
    /// Associated URLs.
    pub urls: Vec<String>,
    /// Free text.
    pub notes: String,
}

/// Entry without secrets, for lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntrySummary {
    /// Entry id.
    pub id: String,
    /// Title.
    pub title: String,
    /// Username.
    pub username: String,
    /// URLs.
    pub urls: Vec<String>,
    /// Last modification.
    pub updated_at: String,
    /// Whether conflicts are pending.
    pub has_conflicts: bool,
}

impl From<&Entry> for EntrySummary {
    fn from(e: &Entry) -> Self {
        Self { id: e.id.clone(), title: e.title.clone(), username: e.username.clone(), urls: e.urls.clone(), updated_at: e.updated_at.clone(), has_conflicts: !e.conflicts.is_empty() }
    }
}

fn canonical_content(title: &str, username: &str, password: &str, urls: &[String], notes: &str) -> String {
    // serde_json of a tuple is deterministic.
    serde_json::to_string(&(title, username, password, urls, notes)).unwrap_or_default()
}

fn chars(s: &str) -> usize {
    s.chars().count()
}

/// Validates a device id: 1–64 chars of `[A-Za-z0-9_-]`.
pub fn validate_device_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(VaultError::Validation("deviceId"));
    }
    Ok(())
}

fn validate_uuid(id: &str) -> Result<()> {
    match uuid::Uuid::parse_str(id) {
        Ok(u) if u.hyphenated().to_string() == id => Ok(()),
        _ => Err(VaultError::InvalidFormat("id")),
    }
}

fn validate_clock(c: &Clock) -> Result<()> {
    if c.is_empty() || c.len() > MAX_CLOCK_DEVICES {
        return Err(VaultError::InvalidFormat("clock"));
    }
    for k in c.keys() {
        validate_device_id(k).map_err(|_| VaultError::InvalidFormat("clock"))?;
    }
    Ok(())
}

/// Validates user input; errors name the field only.
pub fn validate_input(input: &EntryInput) -> Result<()> {
    let t = chars(input.title.trim());
    if t == 0 || chars(&input.title) > MAX_TITLE {
        return Err(VaultError::Validation("title"));
    }
    if chars(&input.username) > MAX_USERNAME {
        return Err(VaultError::Validation("username"));
    }
    if chars(&input.password) > MAX_PASSWORD {
        return Err(VaultError::Validation("password"));
    }
    if chars(&input.notes) > MAX_NOTES {
        return Err(VaultError::Validation("notes"));
    }
    if input.urls.len() > MAX_URLS {
        return Err(VaultError::Validation("urls"));
    }
    for u in &input.urls {
        if u.len() > MAX_URL_LEN || !origin::is_valid_entry_url(u) {
            return Err(VaultError::Validation("urls"));
        }
    }
    Ok(())
}

fn validate_content(title: &str, username: &str, password: &str, urls: &[String], notes: &str, allow_empty_title: bool) -> Result<()> {
    if (!allow_empty_title && title.trim().is_empty()) || chars(title) > MAX_TITLE {
        return Err(VaultError::InvalidFormat("title"));
    }
    if chars(username) > MAX_USERNAME || chars(password) > MAX_PASSWORD || chars(notes) > MAX_NOTES {
        return Err(VaultError::InvalidFormat("field length"));
    }
    if urls.len() > MAX_URLS || urls.iter().any(|u| u.len() > MAX_URL_LEN || !origin::is_valid_entry_url(u)) {
        return Err(VaultError::InvalidFormat("urls"));
    }
    Ok(())
}

impl Payload {
    /// Strict structural validation applied to every decrypted payload.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(VaultError::UnsupportedVersion);
        }
        if self.entries.len() + self.tombstones.len() > MAX_RECORDS {
            return Err(VaultError::InvalidFormat("too many records"));
        }
        let mut ids = HashSet::new();
        for w in self.entries.windows(2) {
            if w[0].id >= w[1].id {
                return Err(VaultError::InvalidFormat("entries not sorted/unique"));
            }
        }
        for w in self.tombstones.windows(2) {
            if w[0].id >= w[1].id {
                return Err(VaultError::InvalidFormat("tombstones not sorted/unique"));
            }
        }
        for e in &self.entries {
            validate_uuid(&e.id)?;
            ids.insert(e.id.as_str());
            validate_content(&e.title, &e.username, &e.password, &e.urls, &e.notes, false)?;
            timefmt::validate(&e.created_at)?;
            timefmt::validate(&e.updated_at)?;
            validate_device_id(&e.updated_by).map_err(|_| VaultError::InvalidFormat("updatedBy"))?;
            validate_clock(&e.clock)?;
            if e.password_history.len() > MAX_HISTORY {
                return Err(VaultError::InvalidFormat("passwordHistory"));
            }
            for h in &e.password_history {
                timefmt::validate(&h.retired_at)?;
                if chars(&h.password) > MAX_PASSWORD {
                    return Err(VaultError::InvalidFormat("passwordHistory"));
                }
            }
            if e.conflicts.len() > MAX_CONFLICTS {
                return Err(VaultError::InvalidFormat("conflicts"));
            }
            for c in &e.conflicts {
                validate_content(&c.title, &c.username, &c.password, &c.urls, &c.notes, c.kind == ConflictKind::Deletion)?;
                timefmt::validate(&c.updated_at)?;
                validate_device_id(&c.updated_by).map_err(|_| VaultError::InvalidFormat("conflict.updatedBy"))?;
            }
        }
        for t in &self.tombstones {
            validate_uuid(&t.id)?;
            if ids.contains(t.id.as_str()) {
                return Err(VaultError::InvalidFormat("id both live and deleted"));
            }
            timefmt::validate(&t.deleted_at)?;
            validate_device_id(&t.deleted_by).map_err(|_| VaultError::InvalidFormat("deletedBy"))?;
            validate_clock(&t.clock)?;
        }
        Ok(())
    }

    /// Re-establishes the sorted-by-id invariant.
    pub fn normalize(&mut self) {
        self.entries.sort_by(|a, b| a.id.cmp(&b.id));
        self.tombstones.sort_by(|a, b| a.id.cmp(&b.id));
    }

    /// Index of a live entry.
    pub fn entry_index(&self, id: &str) -> Option<usize> {
        self.entries.binary_search_by(|e| e.id.as_str().cmp(id)).ok()
    }

    /// Inserts a live entry keeping order (replaces an existing one with the same id).
    pub fn upsert_entry(&mut self, e: Entry) {
        match self.entries.binary_search_by(|x| x.id.cmp(&e.id)) {
            Ok(i) => self.entries[i] = e,
            Err(i) => self.entries.insert(i, e),
        }
    }

    /// Inserts a tombstone keeping order (replaces an existing one with the same id).
    pub fn upsert_tombstone(&mut self, t: Tombstone) {
        match self.tombstones.binary_search_by(|x| x.id.cmp(&t.id)) {
            Ok(i) => self.tombstones[i] = t,
            Err(i) => self.tombstones.insert(i, t),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn c(pairs: &[(&str, u64)]) -> Clock {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }
    #[test]
    fn clock_order() {
        assert_eq!(compare_clocks(&c(&[("a", 1)]), &c(&[("a", 1)])), ClockOrder::Equal);
        assert_eq!(compare_clocks(&c(&[("a", 2)]), &c(&[("a", 1)])), ClockOrder::Greater);
        assert_eq!(compare_clocks(&c(&[("a", 1)]), &c(&[("a", 1), ("b", 1)])), ClockOrder::Less);
        assert_eq!(compare_clocks(&c(&[("a", 2)]), &c(&[("a", 1), ("b", 1)])), ClockOrder::Concurrent);
        assert_eq!(max_clock(&c(&[("a", 2)]), &c(&[("a", 1), ("b", 1)])), c(&[("a", 2), ("b", 1)]));
    }
}

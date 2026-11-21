//! Plaintext payload model (lives only inside the encrypted payload). See docs/VAULT_FORMAT.md §5.
//!
//! Each credential is a [`Record`]: a causal context (version vector) plus a set of concurrent [`Version`]s, each
//! identified by a unique [`Dot`] `(device, counter)` — a *dotted version vector set*. Normally a record holds one
//! version; concurrent edits on different devices produce several (the newest is shown, the others are pending
//! conflicts). A record whose versions are all deletions is a tombstone, so deletions propagate.
//! Merge rule (keyvora-sync): keep a version if the other side also has it or has not seen its dot.

use crate::error::{Result, VaultError};
use crate::{origin, timefmt};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Current payload schema version.
pub const SCHEMA_VERSION: u32 = 1;
/// Maximum live entries (what the user can create).
pub const MAX_ENTRIES: usize = 20_000;
/// Maximum records including deletion tombstones (tombstones are never purged; the 32 MiB container cap also
/// bounds this).
pub const MAX_RECORDS: usize = 100_000;
/// Previous master passwords remembered (not reusable).
pub const MAX_MASTER_HISTORY: usize = 5;
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
/// Password history items kept by a local write (older ones are dropped through the history floor).
pub const MAX_HISTORY: usize = 10;
/// Max history items a record may hold after merging concurrent histories (fails visibly beyond it).
pub const MAX_HISTORY_STORED: usize = 64;
/// Max pending conflict versions per record (in addition to the current one).
pub const MAX_CONFLICTS: usize = 64;
/// Max devices in a causal context (writes beyond it fail visibly; contexts are never pruned).
pub const MAX_CLOCK_DEVICES: usize = 256;
/// Max value of every counter (dots, contexts, revisions): 2^53 − 1, exact in JavaScript numbers.
pub const MAX_COUNTER: u64 = (1 << 53) - 1;

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

/// Unique identifier of one write: the writing device and its per-record counter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Dot {
    /// Writing device.
    pub device: String,
    /// Per-record counter of that device.
    pub counter: u64,
}

impl Dot {
    /// Whether a causal context has already seen this write.
    pub fn covered_by(&self, ctx: &Clock) -> bool {
        ctx.get(&self.device).copied().unwrap_or(0) >= self.counter
    }
}

/// One concurrent version of a record (an edit or a deletion).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Version {
    /// Identity of the write.
    #[zeroize(skip)]
    pub dot: Dot,
    /// `true` for a deletion (content fields are then empty).
    pub deleted: bool,
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
    /// When it was written.
    pub updated_at: String,
}

impl Version {
    fn order_key(&self) -> (&str, &str, u64) {
        (&self.updated_at, &self.dot.device, self.dot.counter)
    }

    fn snapshot(&self) -> ConflictSnapshot {
        ConflictSnapshot {
            kind: if self.deleted { ConflictKind::Deletion } else { ConflictKind::Edit },
            title: self.title.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            urls: self.urls.clone(),
            notes: self.notes.clone(),
            updated_at: self.updated_at.clone(),
            updated_by: self.dot.device.clone(),
        }
    }
}

/// A previous password of an entry.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryItem {
    /// The retired password.
    pub password: String,
    /// When it was replaced.
    pub retired_at: String,
    /// Dot of the write that retired it (identity of the item for merging).
    #[zeroize(skip)]
    pub retired_by: Dot,
}

/// A credential with its causal history (storage form).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record {
    /// Random UUID v4.
    pub id: String,
    /// Creation time.
    pub created_at: String,
    /// Causal context: every write this record state has seen.
    #[zeroize(skip)]
    pub context: Clock,
    /// Concurrent versions, sorted by dot, never empty.
    pub versions: Vec<Version>,
    /// Previous passwords, newest first.
    #[serde(default)]
    pub password_history: Vec<HistoryItem>,
    /// History items whose `retiredBy` dot is covered by this context were dropped (deleted entry or trimmed);
    /// merges drop them too, which keeps history removal causal and the merge associative.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[zeroize(skip)]
    pub history_floor: Clock,
}

impl Record {
    /// Records a retired password (written by the write `by`) and trims the history to [`MAX_HISTORY`].
    pub fn retire_password(&mut self, old: &str, new: &str, now: &str, by: &Dot) {
        if old != new && !old.is_empty() && !by.covered_by(&self.history_floor) {
            self.password_history.push(HistoryItem {
                password: old.to_owned(),
                retired_at: now.to_owned(),
                retired_by: by.clone(),
            });
        }
        self.trim_history();
    }

    /// Keeps the newest [`MAX_HISTORY`] items; dropping an item raises the floor for its writer.
    pub fn trim_history(&mut self) {
        sort_history(&mut self.password_history);
        while self.password_history.len() > MAX_HISTORY {
            if let Some(h) = self.password_history.pop() {
                let f = self.history_floor.entry(h.retired_by.device.clone()).or_insert(0);
                *f = (*f).max(h.retired_by.counter);
            }
            let floor = self.history_floor.clone();
            self.password_history.retain(|h| !h.retired_by.covered_by(&floor));
        }
    }

    /// Drops every known history item (on deletion): the floor covers everything this state has seen.
    pub fn clear_history(&mut self) {
        self.history_floor = max_clock(&self.history_floor, &self.context);
        self.password_history.clear();
    }

    /// Index of the version shown to the user: the newest live version (deterministic tie-break by dot).
    pub fn main_index(&self) -> Option<usize> {
        self.versions
            .iter()
            .enumerate()
            .filter(|(_, v)| !v.deleted)
            .max_by(|a, b| a.1.order_key().cmp(&b.1.order_key()))
            .map(|(i, _)| i)
    }

    /// Whether the record is visible (has at least one live version).
    pub fn is_live(&self) -> bool {
        self.versions.iter().any(|v| !v.deleted)
    }

    /// The version shown to the user.
    pub fn main(&self) -> Option<&Version> {
        self.main_index().map(|i| &self.versions[i])
    }

    /// All versions except the main one, oldest first (pending conflicts).
    pub fn conflict_versions(&self) -> Vec<&Version> {
        let main = self.main_index();
        let mut v: Vec<&Version> =
            self.versions.iter().enumerate().filter(|(i, _)| Some(*i) != main).map(|(_, v)| v).collect();
        v.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
        v
    }

    /// Allocates the dot of a new write by `device` and records it in the context. Fails (instead of wrapping or
    /// producing a context no reader accepts) at [`MAX_COUNTER`] or [`MAX_CLOCK_DEVICES`].
    pub fn next_dot(&mut self, device: &str) -> Result<Dot> {
        if !self.context.contains_key(device) && self.context.len() >= MAX_CLOCK_DEVICES {
            return Err(VaultError::Validation("too many devices for this entry"));
        }
        let current = self.context.get(device).copied().unwrap_or(0);
        if current >= MAX_COUNTER {
            return Err(VaultError::Validation("counter limit reached"));
        }
        self.context.insert(device.to_owned(), current + 1);
        Ok(Dot { device: device.to_owned(), counter: current + 1 })
    }

    /// User-facing view (`None` if deleted).
    pub fn to_entry(&self) -> Option<Entry> {
        let m = self.main()?;
        Some(Entry {
            id: self.id.clone(),
            title: m.title.clone(),
            username: m.username.clone(),
            password: m.password.clone(),
            urls: m.urls.clone(),
            notes: m.notes.clone(),
            created_at: self.created_at.clone(),
            updated_at: m.updated_at.clone(),
            updated_by: m.dot.device.clone(),
            password_history: self.password_history.iter().take(MAX_HISTORY).cloned().collect(),
            conflicts: self.conflict_versions().into_iter().map(Version::snapshot).collect(),
        })
    }

    /// Summary view without secrets (`None` if deleted).
    pub fn to_summary(&self) -> Option<EntrySummary> {
        let m = self.main()?;
        Some(EntrySummary {
            id: self.id.clone(),
            title: m.title.clone(),
            username: m.username.clone(),
            urls: m.urls.clone(),
            updated_at: m.updated_at.clone(),
            has_conflicts: self.versions.len() > 1,
        })
    }
}

/// Kind of a pending conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConflictKind {
    /// A concurrent edit.
    Edit,
    /// A concurrent deletion of an entry that was edited elsewhere.
    Deletion,
}

/// View of a pending concurrent version.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
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
    /// When that version was written.
    pub updated_at: String,
    /// Device that wrote it.
    pub updated_by: String,
}

/// User-facing view of a credential (plaintext; only in unlocked memory).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    /// Random UUID v4.
    pub id: String,
    /// Display name.
    pub title: String,
    /// Account identifier.
    pub username: String,
    /// Secret.
    pub password: String,
    /// Associated URLs.
    pub urls: Vec<String>,
    /// Free text.
    pub notes: String,
    /// Creation time.
    pub created_at: String,
    /// Last modification time.
    pub updated_at: String,
    /// Device of the last modification.
    pub updated_by: String,
    /// Previous passwords, newest first.
    pub password_history: Vec<HistoryItem>,
    /// Pending concurrent versions, oldest first.
    pub conflicts: Vec<ConflictSnapshot>,
}

/// Max retired data keys kept after rotations.
pub const MAX_RETIRED_KEYS: usize = 4;

/// Order of retired keys: newest keyring revision first, then by key (deterministic).
pub fn retired_order(a: &RetiredKey, b: &RetiredKey) -> std::cmp::Ordering {
    b.keyring_revision.cmp(&a.keyring_revision).then_with(|| a.key.cmp(&b.key))
}

/// Normalizes a list of retired keys: one entry per key (highest revision), ordered, at most [`MAX_RETIRED_KEYS`].
/// Union followed by this function is associative and commutative.
pub fn normalize_retired_keys(keys: Vec<RetiredKey>) -> Vec<RetiredKey> {
    let mut by_key: BTreeMap<String, u64> = BTreeMap::new();
    for k in &keys {
        let e = by_key.entry(k.key.clone()).or_insert(0);
        *e = (*e).max(k.keyring_revision);
    }
    let mut v: Vec<RetiredKey> =
        by_key.into_iter().map(|(key, keyring_revision)| RetiredKey { keyring_revision, key }).collect();
    v.sort_by(retired_order);
    v.truncate(MAX_RETIRED_KEYS);
    v
}

/// A data key replaced by a rotation, kept **inside the payload encrypted with the new key** so that holders of the
/// new key can still merge containers written with the old one (concurrent writes, Drive revisions, backups).
/// Holders of only the old key gain nothing: they cannot decrypt the new payload.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetiredKey {
    /// Last keyring revision written with this key.
    pub keyring_revision: u64,
    /// The 32-byte key, Base64.
    pub key: String,
}

/// A previous master password as an Argon2id hash (never the password itself), so it cannot be reused. Lives only
/// inside the encrypted payload.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MasterHistoryItem {
    /// When it stopped being the master password.
    pub changed_at: String,
    /// 16-byte salt, Base64.
    pub salt: String,
    /// 32-byte Argon2id output, Base64.
    pub hash: String,
}

/// Optional two-step verification (TOTP, e.g. Authy). The newest change wins when merging.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwoFactor {
    /// Base32 TOTP secret; empty = disabled.
    pub secret: String,
    /// Time of the last enable/disable.
    pub updated_at: String,
}

impl TwoFactor {
    /// Whether two-step verification is on.
    pub fn enabled(&self) -> bool {
        !self.secret.is_empty()
    }
}

/// Decrypted payload.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Payload {
    /// Must equal [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Records sorted by id.
    pub records: Vec<Record>,
    /// Data keys replaced by rotations, newest first (≤ [`MAX_RETIRED_KEYS`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired_keys: Vec<RetiredKey>,
    /// Last time the master password was set (creation, change or reset); drives the monthly reminder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_changed_at: Option<String>,
    /// Previous master passwords (hashes), newest first (≤ [`MAX_MASTER_HISTORY`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub master_history: Vec<MasterHistoryItem>,
    /// Two-step verification settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub two_factor: Option<TwoFactor>,
}

impl Default for Payload {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            records: Vec::new(),
            retired_keys: Vec::new(),
            master_changed_at: None,
            master_history: Vec::new(),
            two_factor: None,
        }
    }
}

/// Order of the master history: newest first, then by hash (deterministic, so union + truncate is associative).
pub fn master_history_order(a: &MasterHistoryItem, b: &MasterHistoryItem) -> std::cmp::Ordering {
    b.changed_at.cmp(&a.changed_at).then_with(|| a.hash.cmp(&b.hash))
}

/// Dedupes (by hash), orders and truncates a master history.
pub fn normalize_master_history(mut items: Vec<MasterHistoryItem>) -> Vec<MasterHistoryItem> {
    items.sort_by(master_history_order);
    let mut seen = HashSet::new();
    items.retain(|i| seen.insert(i.hash.clone()));
    items.truncate(MAX_MASTER_HISTORY);
    items
}

/// User input for creating/updating an entry (wiped on drop).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct EntryInput {
    /// Display name (required).
    #[serde(default)]
    pub title: String,
    /// Account identifier.
    #[serde(default)]
    pub username: String,
    /// Secret.
    #[serde(default)]
    pub password: String,
    /// Associated URLs.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Free text.
    #[serde(default)]
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
        Self {
            id: e.id.clone(),
            title: e.title.clone(),
            username: e.username.clone(),
            urls: e.urls.clone(),
            updated_at: e.updated_at.clone(),
            has_conflicts: !e.conflicts.is_empty(),
        }
    }
}

/// Newest first; ties broken by dot (deterministic).
pub fn sort_history(h: &mut [HistoryItem]) {
    h.sort_by(|x, y| y.retired_at.cmp(&x.retired_at).then_with(|| x.retired_by.cmp(&y.retired_by)));
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
        return Err(VaultError::InvalidFormat("context"));
    }
    for (k, v) in c {
        validate_device_id(k).map_err(|_| VaultError::InvalidFormat("context"))?;
        if *v > MAX_COUNTER {
            return Err(VaultError::InvalidFormat("context counter"));
        }
    }
    Ok(())
}

/// Characters that are invisible or reorder text (spoofing in titles: U+202E + "moc.knab" is shown as "bank.com").
fn is_spoofing_char(c: char) -> bool {
    matches!(c as u32, 0x202A..=0x202E | 0x2066..=0x2069)
}

/// Single-line fields: no control characters at all, no bidi overrides.
fn clean_line(s: &str) -> bool {
    !s.chars().any(|c| c.is_control() || is_spoofing_char(c))
}

/// Validates user input; errors name the field only.
pub fn validate_input(input: &EntryInput) -> Result<()> {
    if chars(input.title.trim()) == 0 || chars(&input.title) > MAX_TITLE || !clean_line(&input.title) {
        return Err(VaultError::Validation("title"));
    }
    if chars(&input.username) > MAX_USERNAME || !clean_line(&input.username) {
        return Err(VaultError::Validation("username"));
    }
    if input.notes.chars().any(|c| (c.is_control() && !matches!(c, '\n' | '\r' | '\t')) || is_spoofing_char(c)) {
        return Err(VaultError::Validation("notes"));
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
        if u.len() > MAX_URL_LEN || !clean_line(u) || !origin::is_valid_entry_url(u) {
            return Err(VaultError::Validation("urls"));
        }
    }
    Ok(())
}

fn validate_version(v: &Version, ctx: &Clock) -> Result<()> {
    validate_device_id(&v.dot.device).map_err(|_| VaultError::InvalidFormat("dot"))?;
    if v.dot.counter == 0 || !v.dot.covered_by(ctx) {
        return Err(VaultError::InvalidFormat("dot"));
    }
    timefmt::validate(&v.updated_at)?;
    if v.deleted {
        if !(v.title.is_empty()
            && v.username.is_empty()
            && v.password.is_empty()
            && v.urls.is_empty()
            && v.notes.is_empty())
        {
            return Err(VaultError::InvalidFormat("deletion with content"));
        }
        return Ok(());
    }
    if v.title.trim().is_empty() || chars(&v.title) > MAX_TITLE {
        return Err(VaultError::InvalidFormat("title"));
    }
    if chars(&v.username) > MAX_USERNAME || chars(&v.password) > MAX_PASSWORD || chars(&v.notes) > MAX_NOTES {
        return Err(VaultError::InvalidFormat("field length"));
    }
    if v.urls.len() > MAX_URLS || v.urls.iter().any(|u| u.len() > MAX_URL_LEN || !origin::is_valid_entry_url(u)) {
        return Err(VaultError::InvalidFormat("urls"));
    }
    Ok(())
}

impl Record {
    /// Structural validation of one record.
    pub fn validate(&self) -> Result<()> {
        validate_uuid(&self.id)?;
        timefmt::validate(&self.created_at)?;
        validate_clock(&self.context)?;
        if self.versions.is_empty() || self.versions.len() > MAX_CONFLICTS + 1 {
            return Err(VaultError::InvalidFormat("versions"));
        }
        for w in self.versions.windows(2) {
            if w[0].dot >= w[1].dot {
                return Err(VaultError::InvalidFormat("versions not sorted/unique"));
            }
        }
        for v in &self.versions {
            validate_version(v, &self.context)?;
        }
        if self.password_history.len() > MAX_HISTORY_STORED {
            return Err(VaultError::InvalidFormat("passwordHistory"));
        }
        for (k, v) in &self.history_floor {
            validate_device_id(k).map_err(|_| VaultError::InvalidFormat("historyFloor"))?;
            // QA-DEF-001: a floor above the context would swallow future writes' history items.
            if *v > self.context.get(k).copied().unwrap_or(0) {
                return Err(VaultError::InvalidFormat("historyFloor"));
            }
        }
        let mut seen_dots = HashSet::new();
        for h in &self.password_history {
            if !h.retired_by.covered_by(&self.context)
                || h.retired_by.covered_by(&self.history_floor)
                || !seen_dots.insert(&h.retired_by)
            {
                return Err(VaultError::InvalidFormat("passwordHistory"));
            }
            timefmt::validate(&h.retired_at)?;
            if chars(&h.password) > MAX_PASSWORD {
                return Err(VaultError::InvalidFormat("passwordHistory"));
            }
        }
        Ok(())
    }
}

impl Payload {
    /// Strict structural validation applied to every decrypted payload.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(VaultError::UnsupportedVersion);
        }
        if self.records.len() > MAX_RECORDS {
            return Err(VaultError::InvalidFormat("too many records"));
        }
        let mut seen = HashSet::new();
        for w in self.records.windows(2) {
            if w[0].id >= w[1].id {
                return Err(VaultError::InvalidFormat("records not sorted/unique"));
            }
        }
        for r in &self.records {
            r.validate()?;
            seen.insert(r.id.as_str());
        }
        if self.retired_keys.len() > MAX_RETIRED_KEYS {
            return Err(VaultError::InvalidFormat("retiredKeys"));
        }
        for w in self.retired_keys.windows(2) {
            if retired_order(&w[0], &w[1]) != std::cmp::Ordering::Less {
                return Err(VaultError::InvalidFormat("retiredKeys not sorted/unique"));
            }
        }
        let mut keys = HashSet::new();
        if !self.retired_keys.iter().all(|k| keys.insert(k.key.as_str())) {
            return Err(VaultError::InvalidFormat("retiredKeys duplicated"));
        }
        for k in &self.retired_keys {
            use base64::Engine;
            let raw = zeroize::Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(&k.key)
                    .map_err(|_| VaultError::InvalidFormat("retiredKeys"))?,
            );
            if raw.len() != 32 || k.keyring_revision > MAX_COUNTER {
                return Err(VaultError::InvalidFormat("retiredKeys"));
            }
        }
        if let Some(t) = &self.master_changed_at {
            timefmt::validate(t)?;
        }
        if self.master_history.len() > MAX_MASTER_HISTORY {
            return Err(VaultError::InvalidFormat("masterHistory"));
        }
        for w in self.master_history.windows(2) {
            if master_history_order(&w[0], &w[1]) != std::cmp::Ordering::Less {
                return Err(VaultError::InvalidFormat("masterHistory not sorted/unique"));
            }
        }
        for h in &self.master_history {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD;
            timefmt::validate(&h.changed_at)?;
            let salt = b64.decode(&h.salt).map_err(|_| VaultError::InvalidFormat("masterHistory"))?;
            let hash = zeroize::Zeroizing::new(b64.decode(&h.hash).map_err(|_| VaultError::InvalidFormat("masterHistory"))?);
            if salt.len() != 16 || hash.len() != 32 {
                return Err(VaultError::InvalidFormat("masterHistory"));
            }
        }
        if let Some(t) = &self.two_factor {
            timefmt::validate(&t.updated_at)?;
            if t.enabled() {
                crate::totp::validate_secret(&t.secret).map_err(|_| VaultError::InvalidFormat("twoFactor"))?;
            }
        }
        Ok(())
    }

    /// Number of live (non-deleted) entries.
    pub fn live_count(&self) -> usize {
        self.records.iter().filter(|r| r.is_live()).count()
    }

    /// Re-establishes the sorted invariants.
    pub fn normalize(&mut self) {
        self.records.sort_by(|a, b| a.id.cmp(&b.id));
        for r in &mut self.records {
            r.versions.sort_by(|a, b| a.dot.cmp(&b.dot));
        }
    }

    /// Index of a record (live or deleted).
    pub fn record_index(&self, id: &str) -> Option<usize> {
        self.records.binary_search_by(|r| r.id.as_str().cmp(id)).ok()
    }

    /// Index of a live record.
    pub fn live_index(&self, id: &str) -> Option<usize> {
        self.record_index(id).filter(|&i| self.records[i].is_live())
    }

    /// Inserts a record keeping order (replaces an existing one with the same id).
    pub fn upsert(&mut self, r: Record) {
        match self.records.binary_search_by(|x| x.id.cmp(&r.id)) {
            Ok(i) => self.records[i] = r,
            Err(i) => self.records.insert(i, r),
        }
    }

    /// Live entries (views).
    pub fn live_entries(&self) -> impl Iterator<Item = (&Record, &Version)> {
        self.records.iter().filter_map(|r| r.main().map(|m| (r, m)))
    }
}

// ---------- redacted Debug (never print secrets: T13) ----------

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Version")
            .field("dot", &self.dot)
            .field("deleted", &self.deleted)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for HistoryItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoryItem").field("retired_at", &self.retired_at).finish_non_exhaustive()
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("id", &self.id)
            .field("context", &self.context)
            .field("versions", &self.versions)
            .field("password_history", &self.password_history.len())
            .finish()
    }
}

impl fmt::Debug for ConflictSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConflictSnapshot")
            .field("kind", &self.kind)
            .field("updated_at", &self.updated_at)
            .field("updated_by", &self.updated_by)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("updated_at", &self.updated_at)
            .field("conflicts", &self.conflicts.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for EntryInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EntryInput(**redacted**)")
    }
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Payload")
            .field("schema_version", &self.schema_version)
            .field("records", &self.records)
            .field("retired_keys", &self.retired_keys.len())
            .field("master_history", &self.master_history.len())
            .field("two_factor", &self.two_factor.as_ref().map(TwoFactor::enabled))
            .finish()
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
    #[test]
    fn dot_coverage() {
        let d = Dot { device: "a".into(), counter: 2 };
        assert!(d.covered_by(&c(&[("a", 2)])));
        assert!(!d.covered_by(&c(&[("a", 1), ("b", 9)])));
    }
}

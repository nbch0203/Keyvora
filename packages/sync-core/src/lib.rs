//! Keyvora sync core: deterministic, lossless merge of vault payloads (docs/SYNC_PROTOCOL.md §2).
//!
//! Every record is a *dotted version vector set*: a causal context plus concurrent versions, each identified by a
//! unique dot `(device, counter)`. Merge rule per record: keep a version if the other side also holds it or has not
//! seen its dot; the context is the point-wise maximum. This is a join-semilattice (commutative, associative,
//! idempotent) and never drops a version that the other side has not explicitly superseded. Concurrent edits stay as
//! pending conflicts until the user resolves them.
//!
//! Key policy (security review M-2): remote key slots are **never adopted silently**. A remote container with a
//! newer keyring (master password changed, data key rotated) yields `KEYRING_CHANGED`; the client must ask for the
//! master password valid for that container and call [`adopt_remote_keys`], which proves knowledge of it.
#![forbid(unsafe_code)]

use keyvora_vault::container::{Container, KdfSpec, KeySlot};
use keyvora_vault::model::{
    max_clock, normalize_master_history, normalize_retired_keys, sort_history, Clock, HistoryItem, Payload, Record,
    RetiredKey, Version, MAX_CLOCK_DEVICES, MAX_CONFLICTS, MAX_HISTORY_STORED,
};
use keyvora_vault::{Argon2Params, Result, UnlockedVault, VaultError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Counters describing how a merge changed the **local** payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MergeStats {
    /// Entries that appeared locally.
    pub added: u32,
    /// Entries whose shown content or conflicts changed locally.
    pub updated: u32,
    /// Entries removed locally (remote deletion superseded them).
    pub removed: u32,
    /// Ids that gained new pending conflicts.
    pub new_conflicts: Vec<String>,
}

/// Result of merging a remote container into the unlocked vault.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MergeReport {
    /// Revision of the remote container that was merged.
    pub remote_revision: u64,
    /// The local vault is now identical to the remote one (nothing to upload).
    pub adopted_remote: bool,
    /// The merged state contains something the remote lacks: upload it.
    pub needs_upload: bool,
    /// See [`MergeStats`].
    pub added: u32,
    /// See [`MergeStats`].
    pub updated: u32,
    /// See [`MergeStats`].
    pub removed: u32,
    /// See [`MergeStats`].
    pub new_conflicts: Vec<String>,
    /// Remote key slots were adopted (only through [`adopt_remote_keys`], after re-authentication).
    pub keyring_adopted: bool,
    /// Both sides changed the key slots concurrently (same keyring revision). The remote keys were adopted after
    /// re-authentication and this device's data key was kept as a retired key. Warn the user.
    pub keyring_conflict: bool,
    /// The adopted master-password KDF parameters are weaker than the previous ones or than the defaults. Warn.
    pub kdf_weakened: bool,
    /// The adopted keys carry a different recovery key: the one shown earlier on this device no longer opens the
    /// vault. The UI must say so and offer to rotate (issue and show) a new recovery key. (QA-DEF-004)
    pub recovery_key_changed: bool,
    /// The remote container uses an older keyring than this device (keys were rotated here since). It was **not**
    /// merged — content encrypted with old keys is never accepted automatically (audit ALTA-2) — and this device
    /// should upload its own container. For an import, restore entries from that copy explicitly instead.
    pub remote_keyring_outdated: bool,
}

/// Union of both histories minus the items under the merged floor. No truncation here (it would not be
/// associative): local writes trim through the floor, which then propagates.
fn merge_history(a: &[HistoryItem], b: &[HistoryItem], floor: &Clock) -> Result<Vec<HistoryItem>> {
    let mut by_dot: BTreeMap<_, HistoryItem> = BTreeMap::new();
    for h in a.iter().chain(b.iter()) {
        if h.retired_by.covered_by(floor) {
            continue;
        }
        match by_dot.get(&h.retired_by) {
            Some(existing) if existing != h => return Err(VaultError::IntegrityError),
            Some(_) => {}
            None => {
                by_dot.insert(h.retired_by.clone(), h.clone());
            }
        }
    }
    if by_dot.len() > MAX_HISTORY_STORED {
        return Err(VaultError::Validation("password history too long"));
    }
    let mut v: Vec<HistoryItem> = by_dot.into_values().collect();
    sort_history(&mut v);
    Ok(v)
}

/// Merges two states of the same record.
pub fn merge_record(a: &Record, b: &Record) -> Result<Record> {
    let mut versions: BTreeMap<_, Version> = BTreeMap::new();
    for (mine, other) in [(a, b), (b, a)] {
        for v in &mine.versions {
            match other.versions.iter().find(|w| w.dot == v.dot) {
                // A dot identifies exactly one write: two different versions under one dot mean corruption or a
                // malicious writer. Fail closed instead of picking one (keeps the merge commutative).
                Some(w) if w != v => return Err(VaultError::IntegrityError),
                None if v.dot.covered_by(&other.context) => continue, // seen and superseded by the other side
                _ => {
                    versions.entry(v.dot.clone()).or_insert_with(|| v.clone());
                }
            }
        }
    }
    if versions.is_empty() {
        // Impossible for well-formed states (every removal comes with a new write); fail closed.
        return Err(VaultError::InvalidFormat("merge produced an empty record"));
    }
    if versions.len() > MAX_CONFLICTS + 1 {
        // Never drop data silently: surface it and let the user resolve conflicts first.
        return Err(VaultError::Validation("too many pending conflicts"));
    }
    let context = max_clock(&a.context, &b.context);
    if context.len() > MAX_CLOCK_DEVICES {
        return Err(VaultError::Validation("too many devices for this entry"));
    }
    let history_floor = max_clock(&a.history_floor, &b.history_floor);
    Ok(Record {
        id: a.id.clone(),
        created_at: a.created_at.clone().min(b.created_at.clone()),
        context,
        versions: versions.into_values().collect(),
        password_history: merge_history(&a.password_history, &b.password_history, &history_floor)?,
        history_floor,
    })
}

/// Merges two payloads of the same vault. The resulting payload does not depend on argument order; the stats are
/// computed relative to `local`.
pub fn merge_payloads(local: &Payload, remote: &Payload) -> Result<(Payload, MergeStats)> {
    let li: BTreeMap<&str, &Record> = local.records.iter().map(|r| (r.id.as_str(), r)).collect();
    let ri: BTreeMap<&str, &Record> = remote.records.iter().map(|r| (r.id.as_str(), r)).collect();
    let ids: BTreeSet<&str> = li.keys().chain(ri.keys()).copied().collect();
    let mut out = Payload::default();
    let mut stats = MergeStats::default();
    for id in ids {
        let merged = match (li.get(id), ri.get(id)) {
            (Some(l), Some(r)) => merge_record(l, r)?,
            (Some(x), None) | (None, Some(x)) => (*x).clone(),
            (None, None) => unreachable!("id comes from one of the indexes"),
        };
        let before = li.get(id).and_then(|l| l.to_entry());
        let after = merged.to_entry();
        match (&before, &after) {
            (None, Some(_)) => stats.added += 1,
            (Some(_), None) => stats.removed += 1,
            (Some(b), Some(a)) if a != b => stats.updated += 1,
            _ => {}
        }
        if let Some(a) = &after {
            let old: &[_] = before.as_ref().map(|b| b.conflicts.as_slice()).unwrap_or(&[]);
            if a.conflicts.iter().any(|c| !old.contains(c)) {
                stats.new_conflicts.push(id.to_owned());
            }
        }
        out.records.push(merged);
    }
    out.retired_keys = merge_retired_keys(&local.retired_keys, &remote.retired_keys)?;
    // Account-level fields: newest wins, deterministic ties (associative and commutative like the records).
    out.master_changed_at = local.master_changed_at.clone().max(remote.master_changed_at.clone());
    out.master_history =
        normalize_master_history(local.master_history.iter().chain(remote.master_history.iter()).cloned().collect());
    out.two_factor = match (&local.two_factor, &remote.two_factor) {
        (Some(a), Some(b)) => {
            Some(if (&b.updated_at, &b.secret) > (&a.updated_at, &a.secret) { b.clone() } else { a.clone() })
        }
        (Some(x), None) | (None, Some(x)) => Some(x.clone()),
        (None, None) => None,
    };
    out.normalize();
    Ok((out, stats))
}

/// Union of retired keys (identity = the key itself, highest revision wins; top [`MAX_RETIRED_KEYS`]).
fn merge_retired_keys(a: &[RetiredKey], b: &[RetiredKey]) -> Result<Vec<RetiredKey>> {
    Ok(normalize_retired_keys(a.iter().chain(b.iter()).cloned().collect()))
}

fn password_params(slots: &[KeySlot]) -> Option<Argon2Params> {
    match &slots.first()?.kdf {
        KdfSpec::Argon2id { params, .. } => Some(*params),
        KdfSpec::HkdfSha256 { .. } => None,
    }
}

fn weaker(a: Argon2Params, than: Argon2Params) -> bool {
    a.memory_kib < than.memory_kib || a.iterations < than.iterations
}

fn report(stats: MergeStats, remote_revision: u64, adopted_remote: bool) -> MergeReport {
    MergeReport {
        remote_revision,
        adopted_remote,
        needs_upload: !adopted_remote,
        added: stats.added,
        updated: stats.updated,
        removed: stats.removed,
        new_conflicts: stats.new_conflicts,
        ..MergeReport::default()
    }
}

/// Merges a remote container (same vault) into the unlocked vault. Fails closed, without modifying local state, on
/// tampering (`INTEGRITY_ERROR`), a different vault (`VAULT_MISMATCH`) or different keys (`KEYRING_CHANGED`): a newer
/// remote keyring, or the same keyring revision with different slots (concurrent key changes on two devices, possibly
/// with different data keys — QA-DEF-003). Keys are never chosen automatically: the user re-authenticates.
pub fn merge_remote(vault: &mut UnlockedVault, remote_container: &str) -> Result<MergeReport> {
    let header = Container::parse(remote_container)?;
    if header.vault_id.hyphenated().to_string() != vault.vault_id() {
        return Err(VaultError::VaultMismatch);
    }
    let local_kr = vault.keyring_revision();
    if header.keyring_revision > local_kr || (header.keyring_revision == local_kr && header.slots != vault.slots()) {
        return Err(VaultError::KeyringChanged);
    }
    if header.keyring_revision < local_kr {
        // Written with keys this device already replaced: never merged automatically. A legitimate lagging device
        // re-authenticates (KEYRING_CHANGED on its side), merges its local data into the new keys and uploads again.
        return Ok(MergeReport {
            remote_revision: header.revision,
            needs_upload: true,
            remote_keyring_outdated: true,
            ..MergeReport::default()
        });
    }
    let remote = vault.decrypt_current(remote_container)?;
    let (merged, stats) = merge_payloads(vault.payload(), &remote.payload)?;
    let adopted_remote =
        merged == remote.payload && remote.keyring_revision == local_kr && remote.revision >= vault.revision();
    vault.apply_merge(merged, None, remote.revision, adopted_remote)?;
    Ok(report(stats, remote.revision, adopted_remote))
}

/// Re-authenticates against a remote container whose keys differ (`KEYRING_CHANGED`): opens it with the master
/// password valid for it — proving knowledge of the new secret — then merges this session's data into it and makes
/// it the current session (new keys, possibly a new data key). If this device's data key was different (concurrent
/// rotation), it is kept as a retired key so everything already written with it stays readable. The local data is
/// never lost: if the password is wrong nothing changes.
pub fn adopt_remote_keys(vault: &mut UnlockedVault, remote_container: &str, master: &str) -> Result<MergeReport> {
    let header = Container::parse(remote_container)?;
    if header.keyring_revision < vault.keyring_revision() {
        // Never go back to keys that were replaced (they may be the compromised ones). Audit BAJA-1.
        return Err(VaultError::Validation("olderKeyring"));
    }
    let mut remote = UnlockedVault::unlock_with_password(remote_container, master, vault.device_id())?;
    if remote.vault_id() != vault.vault_id() {
        return Err(VaultError::VaultMismatch);
    }
    let previous_params = password_params(vault.slots());
    let recovery_key_changed = vault.slots().get(1) != remote.slots().get(1);
    let concurrent = remote.keyring_revision() == vault.keyring_revision();
    let (mut merged, stats) = merge_payloads(vault.payload(), remote.payload())?;
    let own_dek = vault.export_data_key();
    if *own_dek != *remote.export_data_key() {
        use base64::Engine;
        let mut keys = std::mem::take(&mut merged.retired_keys);
        keys.push(RetiredKey {
            keyring_revision: vault.keyring_revision().min(remote.keyring_revision()),
            key: base64::engine::general_purpose::STANDARD.encode(own_dek.as_slice()),
        });
        merged.retired_keys = normalize_retired_keys(keys);
    }
    let remote_revision = remote.revision();
    let adopted_remote = merged == *remote.payload() && remote_revision >= vault.revision();
    // Revision: unchanged if the remote already had everything, otherwise max(local, remote) + 1 on next export.
    remote.apply_merge(
        merged,
        None,
        if adopted_remote { remote_revision } else { vault.revision() },
        adopted_remote,
    )?;
    let new_params = remote.password_kdf_params();
    let kdf_weakened =
        weaker(new_params, Argon2Params::DEFAULT) || previous_params.is_some_and(|p| weaker(new_params, p));
    vault.replace_with(remote)?;
    let mut r = report(stats, remote_revision, adopted_remote);
    r.keyring_adopted = true;
    r.keyring_conflict = concurrent;
    r.kdf_weakened = kdf_weakened;
    r.recovery_key_changed = recovery_key_changed;
    Ok(r)
}

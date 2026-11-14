//! Keyvora sync core: deterministic, lossless merge of vault payloads (docs/SYNC_PROTOCOL.md §2).
//!
//! Each entry carries a version vector. Merging is commutative, associative and idempotent provided that every device
//! keeps a linear local history (a device id is never reused after its local state is lost — clients generate a new
//! random device id on every fresh install). Concurrent edits are never dropped: the deterministic loser is kept in
//! `conflicts[]` until the user resolves it.
#![forbid(unsafe_code)]

use keyvora_vault::container::KeySlot;
use keyvora_vault::model::{compare_clocks, max_clock, ClockOrder, ConflictSnapshot, Entry, HistoryItem, Payload, Tombstone, MAX_CONFLICTS, MAX_HISTORY};
use keyvora_vault::{Result, UnlockedVault, VaultError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Counters describing how a merge changed the **local** payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MergeStats {
    /// Entries that appeared locally.
    pub added: u32,
    /// Entries whose content or conflicts changed locally.
    pub updated: u32,
    /// Entries removed locally (remote deletion dominated).
    pub removed: u32,
    /// Ids that gained new conflict snapshots.
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
    /// Remote key slots (newer master password / recovery key) were adopted.
    pub keyring_adopted: bool,
    /// Both sides changed the key slots concurrently; one was chosen deterministically. Warn the user.
    pub keyring_conflict: bool,
}

#[derive(Clone, Copy)]
enum Rec<'a> {
    Live(&'a Entry),
    Dead(&'a Tombstone),
}

enum Merged {
    Live(Entry),
    Dead(Tombstone),
}

fn index(p: &Payload) -> BTreeMap<&str, Rec<'_>> {
    let mut m = BTreeMap::new();
    for e in &p.entries {
        m.insert(e.id.as_str(), Rec::Live(e));
    }
    for t in &p.tombstones {
        m.insert(t.id.as_str(), Rec::Dead(t));
    }
    m
}

fn winner_key(e: &Entry) -> (String, String, String) {
    (e.updated_at.clone(), e.updated_by.clone(), e.content_key())
}

fn finalize_conflicts(winner: &Entry, mut set: Vec<ConflictSnapshot>) -> Result<Vec<ConflictSnapshot>> {
    let own = winner.snapshot();
    set.retain(|s| *s != own);
    set.sort_by_key(|a| a.sort_key());
    set.dedup();
    if set.len() > MAX_CONFLICTS {
        // Never drop data silently: surface the problem and let the user resolve conflicts first.
        return Err(VaultError::Validation("too many pending conflicts"));
    }
    Ok(set)
}

fn merge_history(a: &[HistoryItem], b: &[HistoryItem]) -> Vec<HistoryItem> {
    let mut v: Vec<HistoryItem> = a.iter().chain(b.iter()).cloned().collect();
    v.sort_by(|x, y| y.retired_at.cmp(&x.retired_at).then_with(|| x.password.cmp(&y.password)));
    v.dedup();
    v.truncate(MAX_HISTORY);
    v
}

fn merge_live(a: &Entry, b: &Entry) -> Result<Entry> {
    match compare_clocks(&a.clock, &b.clock) {
        ClockOrder::Greater => return Ok(a.clone()),
        ClockOrder::Less => return Ok(b.clone()),
        ClockOrder::Equal if a == b => return Ok(a.clone()),
        _ => {}
    }
    let (w, l) = if winner_key(a) >= winner_key(b) { (a, b) } else { (b, a) };
    let mut merged = w.clone();
    merged.clock = max_clock(&a.clock, &b.clock);
    merged.created_at = a.created_at.clone().min(b.created_at.clone());
    merged.password_history = merge_history(&a.password_history, &b.password_history);
    let mut set: Vec<ConflictSnapshot> = a.conflicts.iter().chain(b.conflicts.iter()).cloned().collect();
    set.push(l.snapshot());
    merged.conflicts = finalize_conflicts(&merged, set)?;
    Ok(merged)
}

fn merge_live_dead(e: &Entry, t: &Tombstone) -> Result<Merged> {
    match compare_clocks(&e.clock, &t.clock) {
        ClockOrder::Greater => Ok(Merged::Live(e.clone())),
        ClockOrder::Less => Ok(Merged::Dead(t.clone())),
        // Concurrent (or equal, which correct clients never produce): keep the data, record the deletion.
        _ => {
            let mut merged = e.clone();
            merged.clock = max_clock(&e.clock, &t.clock);
            let mut set = merged.conflicts.clone();
            set.push(t.snapshot());
            merged.conflicts = finalize_conflicts(&merged, set)?;
            Ok(Merged::Live(merged))
        }
    }
}

fn merge_dead(a: &Tombstone, b: &Tombstone) -> Tombstone {
    match compare_clocks(&a.clock, &b.clock) {
        ClockOrder::Greater => a.clone(),
        ClockOrder::Less => b.clone(),
        _ => {
            let w = if (&a.deleted_at, &a.deleted_by) >= (&b.deleted_at, &b.deleted_by) { a } else { b };
            Tombstone { id: a.id.clone(), deleted_at: w.deleted_at.clone(), deleted_by: w.deleted_by.clone(), clock: max_clock(&a.clock, &b.clock) }
        }
    }
}

/// Merges two payloads of the same vault. Pure, deterministic and symmetric in its result payload; the stats are
/// computed relative to `local`.
pub fn merge_payloads(local: &Payload, remote: &Payload) -> Result<(Payload, MergeStats)> {
    let li = index(local);
    let ri = index(remote);
    let ids: BTreeSet<&str> = li.keys().chain(ri.keys()).copied().collect();
    let mut out = Payload::default();
    let mut stats = MergeStats::default();
    for id in ids {
        let merged = match (li.get(id).copied(), ri.get(id).copied()) {
            (Some(Rec::Live(e)), None) | (None, Some(Rec::Live(e))) => Merged::Live(e.clone()),
            (Some(Rec::Dead(t)), None) | (None, Some(Rec::Dead(t))) => Merged::Dead(t.clone()),
            (Some(Rec::Live(a)), Some(Rec::Live(b))) => Merged::Live(merge_live(a, b)?),
            (Some(Rec::Live(e)), Some(Rec::Dead(t))) | (Some(Rec::Dead(t)), Some(Rec::Live(e))) => merge_live_dead(e, t)?,
            (Some(Rec::Dead(a)), Some(Rec::Dead(b))) => Merged::Dead(merge_dead(a, b)),
            (None, None) => unreachable!("id comes from one of the indexes"),
        };
        match (&merged, li.get(id)) {
            (Merged::Live(_), None | Some(Rec::Dead(_))) => stats.added += 1,
            (Merged::Dead(_), Some(Rec::Live(_))) => stats.removed += 1,
            (Merged::Live(m), Some(Rec::Live(l))) => {
                if m.content_key() != l.content_key() || m.conflicts != l.conflicts {
                    stats.updated += 1;
                }
                if m.conflicts.iter().any(|c| !l.conflicts.contains(c)) {
                    stats.new_conflicts.push(id.to_owned());
                }
            }
            _ => {}
        }
        if let (Merged::Live(m), None | Some(Rec::Dead(_))) = (&merged, li.get(id)) {
            if !m.conflicts.is_empty() {
                stats.new_conflicts.push(id.to_owned());
            }
        }
        match merged {
            Merged::Live(e) => out.entries.push(e),
            Merged::Dead(t) => out.tombstones.push(t),
        }
    }
    out.normalize();
    Ok((out, stats))
}

fn slots_key(slots: &[KeySlot]) -> String {
    slots
        .iter()
        .map(|s| {
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            format!("{}|{}|{}", s.kdf.canonical(), hex(&s.wrap.nonce), hex(&s.wrap.ciphertext))
        })
        .collect::<Vec<_>>()
        .join("#")
}

/// Merges a remote container (same vault) into the unlocked vault. Fails closed on tampering
/// (`INTEGRITY_ERROR`) or on a different vault (`VAULT_MISMATCH`) without modifying the local state.
pub fn merge_remote(vault: &mut UnlockedVault, remote_container: &str) -> Result<MergeReport> {
    let remote = vault.decrypt_foreign(remote_container)?;
    let (merged, stats) = merge_payloads(vault.payload(), &remote.payload)?;

    let local_kr = vault.keyring_revision();
    let (slots_choice, keyring_adopted, keyring_conflict) = if remote.keyring_revision > local_kr {
        (Some((remote.slots.clone(), remote.keyring_revision)), true, false)
    } else if remote.keyring_revision == local_kr && remote.slots != vault.slots() {
        let remote_wins = slots_key(&remote.slots) > slots_key(vault.slots());
        (remote_wins.then(|| (remote.slots.clone(), remote.keyring_revision)), remote_wins, true)
    } else {
        (None, false, false)
    };
    let final_slots_equal_remote = match &slots_choice {
        Some((s, _)) => *s == remote.slots,
        None => vault.slots() == remote.slots.as_slice(),
    };
    let final_kr = slots_choice.as_ref().map(|(_, k)| *k).unwrap_or(local_kr);
    let adopted_remote = merged == remote.payload && final_slots_equal_remote && final_kr == remote.keyring_revision && remote.revision >= vault.revision();

    vault.apply_merge(merged, slots_choice, remote.revision, adopted_remote)?;
    Ok(MergeReport {
        remote_revision: remote.revision,
        adopted_remote,
        needs_upload: !adopted_remote,
        added: stats.added,
        updated: stats.updated,
        removed: stats.removed,
        new_conflicts: stats.new_conflicts,
        keyring_adopted,
        keyring_conflict,
    })
}

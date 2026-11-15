//! Concrete sync scenarios from docs/SYNC_PROTOCOL.md.

use keyvora_sync::{adopt_remote_keys, merge_payloads, merge_remote};
use keyvora_vault::model::ConflictKind;
use keyvora_vault::{Argon2Params, ConflictChoice, EntryInput, UnlockedVault, VaultError};

const FAST: Argon2Params = Argon2Params { memory_kib: 19 * 1024, iterations: 2, parallelism: 1 };
const MASTER: &str = "correct horse battery";

fn pair() -> (UnlockedVault, UnlockedVault) {
    let (mut a, _) = UnlockedVault::create(MASTER, FAST, "phone", 0).unwrap();
    let c = a.export_container().unwrap();
    let b = UnlockedVault::unlock_with_password(&c, MASTER, "browser").unwrap();
    (a, b)
}

fn input(title: &str, pw: &str) -> EntryInput {
    EntryInput {
        title: title.into(),
        username: "me@example.com".into(),
        password: pw.into(),
        urls: vec!["https://github.com".into()],
        notes: String::new(),
    }
}

#[test]
fn offline_edits_on_both_sides_are_merged() {
    let (mut a, mut b) = pair();
    a.create_entry(input("GitHub", "a1"), 1_000).unwrap();
    b.create_entry(input("GitLab", "b1"), 2_000).unwrap();
    let r = merge_remote(&mut b, &a.export_container().unwrap()).unwrap();
    assert_eq!((r.added, r.needs_upload, r.adopted_remote), (1, true, false));
    let r = merge_remote(&mut a, &b.export_container().unwrap()).unwrap();
    assert!(r.adopted_remote && !r.needs_upload);
    assert_eq!(a.payload(), b.payload());
    assert_eq!(a.list_entries().len(), 2);
}

#[test]
fn concurrent_edit_of_same_entry_keeps_both_versions() {
    let (mut a, mut b) = pair();
    let e = a.create_entry(input("GitHub", "original"), 1_000).unwrap();
    merge_remote(&mut b, &a.export_container().unwrap()).unwrap();
    a.update_entry(&e.id, input("GitHub", "from-phone"), 2_000).unwrap();
    b.update_entry(&e.id, input("GitHub", "from-browser"), 3_000).unwrap();
    let r = merge_remote(&mut a, &b.export_container().unwrap()).unwrap();
    assert_eq!(r.new_conflicts, vec![e.id.clone()]);
    let merged = a.get_entry(&e.id).unwrap();
    // later updatedAt wins deterministically, the other version is preserved as a conflict
    assert_eq!(merged.password, "from-browser");
    assert_eq!(merged.conflicts.len(), 1);
    assert_eq!(merged.conflicts[0].password, "from-phone");
    // the browser converges to the same state
    merge_remote(&mut b, &a.export_container().unwrap()).unwrap();
    assert_eq!(a.payload(), b.payload());
    // resolution propagates and clears the conflict everywhere
    a.resolve_conflict(&e.id, ConflictChoice::TakeConflict(0), 4_000).unwrap();
    assert_eq!(a.get_entry(&e.id).unwrap().password, "from-phone");
    merge_remote(&mut b, &a.export_container().unwrap()).unwrap();
    let on_b = b.get_entry(&e.id).unwrap();
    assert_eq!(on_b.password, "from-phone");
    assert!(on_b.conflicts.is_empty());
    assert!(on_b.password_history.iter().any(|h| h.password == "from-browser"));
}

#[test]
fn delete_concurrent_with_edit_keeps_the_edit() {
    let (mut a, mut b) = pair();
    let e = a.create_entry(input("Bank", "x"), 1_000).unwrap();
    merge_remote(&mut b, &a.export_container().unwrap()).unwrap();
    a.delete_entry(&e.id, 2_000).unwrap();
    b.update_entry(&e.id, input("Bank", "y"), 3_000).unwrap();
    merge_remote(&mut a, &b.export_container().unwrap()).unwrap();
    let kept = a.get_entry(&e.id).unwrap();
    assert_eq!(kept.password, "y");
    assert_eq!(kept.conflicts.len(), 1);
    assert_eq!(kept.conflicts[0].kind, ConflictKind::Deletion);
    // choosing the deletion removes it everywhere
    a.resolve_conflict(&e.id, ConflictChoice::TakeConflict(0), 4_000).unwrap();
    merge_remote(&mut b, &a.export_container().unwrap()).unwrap();
    assert_eq!(b.get_entry(&e.id).unwrap_err(), VaultError::NotFound);
}

#[test]
fn deletion_after_seeing_edit_wins() {
    let (mut a, mut b) = pair();
    let e = a.create_entry(input("Old", "x"), 1_000).unwrap();
    merge_remote(&mut b, &a.export_container().unwrap()).unwrap();
    b.delete_entry(&e.id, 2_000).unwrap();
    let r = merge_remote(&mut a, &b.export_container().unwrap()).unwrap();
    assert_eq!(r.removed, 1);
    assert!(a.get_entry(&e.id).is_err());
}

#[test]
fn stale_remote_does_not_lose_local_data() {
    let (mut a, mut b) = pair();
    let stale = a.export_container().unwrap();
    let e = a.create_entry(input("New", "x"), 1_000).unwrap();
    let r = merge_remote(&mut a, &stale).unwrap(); // rollback/old revision
    assert!(r.needs_upload);
    assert!(a.get_entry(&e.id).is_ok());
    let _ = &mut b;
}

#[test]
fn newer_remote_keys_are_never_adopted_silently() {
    let (mut a, mut b) = pair();
    b.create_entry(input("Only on B", "b"), 500).unwrap();
    a.change_master_password(MASTER, "a brand new passphrase", FAST).unwrap();
    let remote = a.export_container().unwrap();
    let before = b.payload().clone();
    assert_eq!(merge_remote(&mut b, &remote).unwrap_err(), VaultError::KeyringChanged);
    assert_eq!(b.payload(), &before, "local state untouched");
    // Re-authentication needs the password that opens the remote container.
    assert_eq!(adopt_remote_keys(&mut b, &remote, MASTER).unwrap_err(), VaultError::InvalidCredentials);
    let r = adopt_remote_keys(&mut b, &remote, "a brand new passphrase").unwrap();
    assert!(r.keyring_adopted && r.needs_upload);
    assert_eq!(b.list_entries().len(), 1, "local data merged into the adopted keys");
    let c = b.export_container().unwrap();
    assert_eq!(UnlockedVault::unlock_with_password(&c, MASTER, "x").unwrap_err(), VaultError::InvalidCredentials);
    UnlockedVault::unlock_with_password(&c, "a brand new passphrase", "x").unwrap();
}

#[test]
fn concurrent_master_password_changes_converge_after_one_reauthentication() {
    let (mut a, mut b) = pair();
    a.change_master_password(MASTER, "passphrase number one", FAST).unwrap();
    b.change_master_password(MASTER, "passphrase number two", FAST).unwrap();
    // Same keyring revision, different slots: neither side chooses automatically.
    let from_b = b.export_container().unwrap();
    assert_eq!(merge_remote(&mut a, &from_b).unwrap_err(), VaultError::KeyringChanged);
    let r = adopt_remote_keys(&mut a, &from_b, "passphrase number two").unwrap();
    assert!(r.keyring_conflict && r.keyring_adopted);
    merge_remote(&mut b, &a.export_container().unwrap()).unwrap();
    assert_eq!(a.slots(), b.slots());
    assert_eq!(a.payload(), b.payload());
}

#[test]
fn data_key_rotation_reaches_other_devices_through_reauthentication() {
    let (mut a, mut b) = pair();
    let e = a.create_entry(input("GitHub", "x"), 1_000).unwrap();
    merge_remote(&mut b, &a.export_container().unwrap()).unwrap();
    let old_dek = b.export_data_key();
    b.update_entry(&e.id, input("GitHub", "edited-on-b"), 2_000).unwrap();
    a.rotate_data_key(MASTER).unwrap();
    let rotated = a.export_container().unwrap();
    assert_eq!(merge_remote(&mut b, &rotated).unwrap_err(), VaultError::KeyringChanged);
    adopt_remote_keys(&mut b, &rotated, MASTER).unwrap();
    assert_ne!(*b.export_data_key(), *old_dek, "B now uses the new data key");
    assert_eq!(b.get_entry(&e.id).unwrap().password, "edited-on-b", "B's offline edit survived");
    merge_remote(&mut a, &b.export_container().unwrap()).unwrap();
    assert_eq!(a.payload(), b.payload());
}

#[test]
fn weaker_remote_kdf_is_flagged() {
    let (mut a, mut b) = pair();
    let weak = Argon2Params { memory_kib: 19 * 1024, iterations: 2, parallelism: 1 };
    a.change_master_password(MASTER, "another passphrase", weak).unwrap();
    let r = adopt_remote_keys(&mut b, &a.export_container().unwrap(), "another passphrase").unwrap();
    assert!(r.kdf_weakened, "below the defaults");
}

#[test]
fn same_dot_with_different_content_is_an_integrity_error() {
    let (mut a, _) = pair();
    let e = a.create_entry(input("GitHub", "x"), 1_000).unwrap();
    let mut forged = a.payload().clone();
    forged.records[0].versions[0].password = "forged".into();
    assert_eq!(merge_payloads(a.payload(), &forged).unwrap_err(), VaultError::IntegrityError);
    assert_eq!(merge_payloads(&forged, a.payload()).unwrap_err(), VaultError::IntegrityError);
    let _ = e;
}

#[test]
fn tampered_remote_fails_closed_and_leaves_local_untouched() {
    let (mut a, mut b) = pair();
    b.create_entry(input("Local", "x"), 1_000).unwrap();
    let before = b.payload().clone();
    let mut remote: serde_json::Value = serde_json::from_str(&a.export_container().unwrap()).unwrap();
    remote["revision"] = serde_json::json!(999);
    assert_eq!(merge_remote(&mut b, &remote.to_string()).unwrap_err(), VaultError::IntegrityError);
    assert_eq!(b.payload(), &before);
}

#[test]
fn other_vault_is_rejected() {
    let (mut a, _) = pair();
    let (mut other, _) = UnlockedVault::create(MASTER, FAST, "phone", 0).unwrap();
    assert_eq!(merge_remote(&mut a, &other.export_container().unwrap()).unwrap_err(), VaultError::VaultMismatch);
}

#[test]
fn deletion_removes_password_history_everywhere() {
    let (mut a, mut b) = pair();
    let e = a.create_entry(input("Bank", "old-1"), 1_000).unwrap();
    a.update_entry(&e.id, input("Bank", "old-2"), 2_000).unwrap();
    merge_remote(&mut b, &a.export_container().unwrap()).unwrap();
    assert_eq!(b.payload().records[0].password_history.len(), 1);
    a.delete_entry(&e.id, 3_000).unwrap();
    merge_remote(&mut b, &a.export_container().unwrap()).unwrap();
    let rec = &b.payload().records[0];
    assert!(!rec.is_live() && rec.password_history.is_empty(), "no old passwords survive a deletion");
}

#[test]
fn rotating_device_still_merges_writes_made_with_the_previous_key() {
    // A rotates offline while B writes with the old key; A must merge B's container (no blocked sync).
    let (mut a, mut b) = pair();
    let e = a.create_entry(input("GitHub", "x"), 1_000).unwrap();
    merge_remote(&mut b, &a.export_container().unwrap()).unwrap();
    b.create_entry(input("Written by B with the old key", "b"), 2_000).unwrap();
    b.update_entry(&e.id, input("GitHub", "edited-on-b"), 2_500).unwrap();
    let from_b_old_key = b.export_container().unwrap();
    a.rotate_data_key(MASTER).unwrap();
    let r = merge_remote(&mut a, &from_b_old_key).unwrap();
    assert!(r.needs_upload);
    assert_eq!(a.list_entries().len(), 2);
    assert_eq!(a.get_entry(&e.id).unwrap().password, "edited-on-b");
    // the retired key travels encrypted under the new key; B adopts and converges
    let rotated = a.export_container().unwrap();
    assert_eq!(merge_remote(&mut b, &rotated).unwrap_err(), VaultError::KeyringChanged);
    adopt_remote_keys(&mut b, &rotated, MASTER).unwrap();
    assert_eq!(a.payload(), b.payload());
    // an old-key backup can still be restored from on both devices
    assert_eq!(b.restore_entries_from(&from_b_old_key, std::slice::from_ref(&e.id), 3_000).unwrap().len(), 1);
}

#[test]
fn old_key_holder_cannot_read_after_rotation_even_with_retired_keys_inside() {
    let (mut a, b) = pair();
    let old_dek = b.export_data_key();
    a.create_entry(input("Secret after rotation", "s3cr3t-after"), 1_000).unwrap();
    a.rotate_data_key(MASTER).unwrap();
    let c = a.export_container().unwrap();
    assert_eq!(
        UnlockedVault::open_with_data_key(&c, &old_dek, "attacker").unwrap_err(),
        VaultError::InvalidCredentials
    );
    assert!(!c.contains("s3cr3t-after"));
}

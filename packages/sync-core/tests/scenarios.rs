//! Concrete sync scenarios from docs/SYNC_PROTOCOL.md.

use keyvora_sync::merge_remote;
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
    EntryInput { title: title.into(), username: "me@example.com".into(), password: pw.into(), urls: vec!["https://github.com".into()], notes: String::new() }
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
fn master_password_change_propagates_through_keyring() {
    let (mut a, mut b) = pair();
    a.change_master_password(MASTER, "a brand new passphrase", FAST).unwrap();
    let r = merge_remote(&mut b, &a.export_container().unwrap()).unwrap();
    assert!(r.keyring_adopted && !r.keyring_conflict);
    let c = b.export_container().unwrap();
    assert_eq!(UnlockedVault::unlock_with_password(&c, MASTER, "x").unwrap_err(), VaultError::InvalidCredentials);
    UnlockedVault::unlock_with_password(&c, "a brand new passphrase", "x").unwrap();
}

#[test]
fn concurrent_master_password_changes_are_flagged() {
    let (mut a, mut b) = pair();
    a.change_master_password(MASTER, "passphrase one", FAST).unwrap();
    b.change_master_password(MASTER, "passphrase two", FAST).unwrap();
    let r1 = merge_remote(&mut a, &b.export_container().unwrap()).unwrap();
    let r2 = merge_remote(&mut b, &a.export_container().unwrap()).unwrap();
    assert!(r1.keyring_conflict || r2.keyring_conflict);
    assert_eq!(a.slots(), b.slots(), "both sides converge to the same deterministic keyring");
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

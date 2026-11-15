//! Functional tests: lifecycle, CRUD isolation, search, matching, history, export/import.

use keyvora_vault::{Argon2Params, EntryInput, MatchLevel, UnlockedVault, VaultError};

const FAST: Argon2Params = Argon2Params { memory_kib: 19 * 1024, iterations: 2, parallelism: 1 };
const MASTER: &str = "correct horse battery staple";

fn entry(title: &str, user: &str, pw: &str, urls: &[&str]) -> EntryInput {
    EntryInput {
        title: title.into(),
        username: user.into(),
        password: pw.into(),
        urls: urls.iter().map(|s| s.to_string()).collect(),
        notes: String::new(),
    }
}

#[test]
fn create_unlock_lock_cycle() {
    let (mut v, _rk) = UnlockedVault::create(MASTER, FAST, "dev", 0).unwrap();
    assert!(v.is_dirty());
    let c = v.export_container().unwrap();
    assert_eq!(v.revision(), 1);
    assert!(!v.is_dirty());
    drop(v); // lock = drop: DEK and plaintext are zeroized
    let v = UnlockedVault::unlock_with_password(&c, MASTER, "dev").unwrap();
    assert_eq!(v.revision(), 1);
    assert!(v.list_entries().is_empty());
}

#[test]
fn modifying_one_entry_leaves_others_untouched() {
    let (mut v, _) = UnlockedVault::create(MASTER, FAST, "dev", 0).unwrap();
    let a = v.create_entry(entry("A", "a@x.com", "pw-a", &["https://a.com"]), 1_000).unwrap();
    let b = v.create_entry(entry("B", "b@x.com", "pw-b", &["https://b.com"]), 1_000).unwrap();
    let b_before = v.get_entry(&b.id).unwrap();
    v.update_entry(&a.id, entry("A2", "a@x.com", "pw-a2", &["https://a.com"]), 2_000).unwrap();
    assert_eq!(v.get_entry(&b.id).unwrap(), b_before);
    let a2 = v.get_entry(&a.id).unwrap();
    assert_eq!((a2.title.as_str(), a2.password.as_str()), ("A2", "pw-a2"));
    assert_eq!(a2.password_history.len(), 1);
    assert_eq!(a2.password_history[0].password, "pw-a");
    assert_eq!(a2.created_at, a.created_at);
    assert_ne!(a2.updated_at, a.updated_at);
    // persisted and reloaded
    let c = v.export_container().unwrap();
    let r = UnlockedVault::unlock_with_password(&c, MASTER, "dev").unwrap();
    assert_eq!(r.get_entry(&a.id).unwrap(), a2);
    assert_eq!(r.get_entry(&b.id).unwrap(), b_before);
}

#[test]
fn unique_ids_and_delete() {
    let (mut v, _) = UnlockedVault::create(MASTER, FAST, "dev", 0).unwrap();
    let ids: std::collections::HashSet<String> =
        (0..200).map(|i| v.create_entry(entry(&format!("e{i}"), "", "", &[]), 1).unwrap().id.clone()).collect();
    assert_eq!(ids.len(), 200);
    let some = ids.iter().next().unwrap().clone();
    v.delete_entry(&some, 2).unwrap();
    assert_eq!(v.get_entry(&some).unwrap_err(), VaultError::NotFound);
    assert_eq!(v.delete_entry(&some, 3).unwrap_err(), VaultError::NotFound);
    assert_eq!(v.list_entries().len(), 199);
}

#[test]
fn history_is_bounded() {
    let (mut v, _) = UnlockedVault::create(MASTER, FAST, "dev", 0).unwrap();
    let e = v.create_entry(entry("A", "", "p0", &[]), 1).unwrap();
    for i in 1..=15 {
        v.update_entry(&e.id, entry("A", "", &format!("p{i}"), &[]), 1 + i).unwrap();
    }
    let e = v.get_entry(&e.id).unwrap();
    assert_eq!(e.password_history.len(), 10);
    assert_eq!(e.password_history[0].password, "p14");
}

#[test]
fn input_validation() {
    let (mut v, _) = UnlockedVault::create(MASTER, FAST, "dev", 0).unwrap();
    assert_eq!(v.create_entry(entry("  ", "", "", &[]), 1).unwrap_err(), VaultError::Validation("title"));
    assert_eq!(v.create_entry(entry(&"t".repeat(257), "", "", &[]), 1).unwrap_err(), VaultError::Validation("title"));
    assert_eq!(
        v.create_entry(entry("t", "", &"p".repeat(4097), &[]), 1).unwrap_err(),
        VaultError::Validation("password")
    );
    assert_eq!(
        v.create_entry(entry("t", "", "", &["javascript:alert(1)"]), 1).unwrap_err(),
        VaultError::Validation("urls")
    );
    let many: Vec<String> = (0..17).map(|i| format!("https://s{i}.com")).collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(v.create_entry(entry("t", "", "", &refs), 1).unwrap_err(), VaultError::Validation("urls"));
    v.create_entry(entry("App", "", "", &["androidapp://com.example.app", "example.com"]), 1).unwrap();
}

#[test]
fn search_and_matches() {
    let (mut v, _) = UnlockedVault::create(MASTER, FAST, "dev", 0).unwrap();
    v.create_entry(entry("GitHub", "alice", "x", &["https://github.com"]), 1).unwrap();
    v.create_entry(entry("Google", "alice@gmail.com", "y", &["https://accounts.google.com"]), 1).unwrap();
    v.create_entry(entry("Evil", "eve", "z", &["https://github.com.evil.com"]), 1).unwrap();
    v.create_entry(entry("Bank app", "bob", "w", &["androidapp://com.bank.app"]), 1).unwrap();
    assert_eq!(v.search("git").len(), 2, "UI search is substring-based by design");
    assert_eq!(v.search("ALICE").len(), 2);

    let gh = v.find_matches("https://github.com/login");
    assert_eq!(gh.len(), 1);
    assert_eq!((gh[0].entry.title.as_str(), gh[0].level), ("GitHub", MatchLevel::Exact));
    let mail = v.find_matches("https://mail.google.com/");
    assert_eq!(mail.len(), 1);
    assert_eq!(mail[0].level, MatchLevel::SameSite);
    assert!(v.find_matches("http://github.com").is_empty());
    assert!(v.find_matches("not a url").is_empty());
    let app = v.find_app_matches("com.bank.app");
    assert_eq!(app.len(), 1);
    assert!(v.find_app_matches("com.bank.app.evil").is_empty());
    // summaries never contain passwords
    let json = serde_json::to_string(&v.list_entries()).unwrap();
    assert!(!json.contains("\"password\""));
}

#[test]
fn restore_deleted_entries_from_older_container() {
    let (mut v, _) = UnlockedVault::create(MASTER, FAST, "dev", 0).unwrap();
    let e = v.create_entry(entry("Old", "u", "secret", &["https://old.com"]), 1).unwrap();
    let backup = v.export_container().unwrap();
    v.delete_entry(&e.id, 2).unwrap();
    let restored = v.restore_entries_from(&backup, std::slice::from_ref(&e.id), 3).unwrap();
    assert_eq!(restored.len(), 1);
    assert_ne!(restored[0].id, e.id);
    assert_eq!(restored[0].password, "secret");
    // a container from another vault cannot be used
    let (mut other, _) = UnlockedVault::create(MASTER, FAST, "dev", 0).unwrap();
    assert_eq!(
        v.restore_entries_from(&other.export_container().unwrap(), &[], 4).unwrap_err(),
        VaultError::VaultMismatch
    );
}

#[test]
fn revision_monotonic() {
    let (mut v, _) = UnlockedVault::create(MASTER, FAST, "dev", 0).unwrap();
    let mut last = 0;
    for i in 0..5 {
        v.create_entry(entry(&format!("x{i}"), "", "", &[]), i).unwrap();
        v.export_container().unwrap();
        assert!(v.revision() > last);
        last = v.revision();
    }
    v.export_container().unwrap();
    assert_eq!(v.revision(), last, "export without changes does not bump the revision");
}

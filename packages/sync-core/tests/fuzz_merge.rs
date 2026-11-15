//! QA-003 — adversarial merge fuzzing (docs/THREAT_MODEL.md T3, T6, T21; docs/SECURITY_REVIEW.md I-5).
//!
//! A realistic payload (3 devices, conflicts, password history, tombstone, retired keys) is merged with an
//! adversarially modified copy of itself: reordered, duplicated or forged versions/dots, history items, contexts,
//! floors, retired keys and records. Two levels are checked:
//! - Container level (what a client actually runs): the hostile payload is sealed with the right DEK and AAD (a
//!   device holding the DEK, T21) and passed to `merge_remote`. It never panics; on error the local vault is
//!   untouched; on success the local payload validates, nothing local is dropped unless the remote claims to have
//!   seen it (its context covers the dot), and the export round-trips.
//! - Model level: for hostile payloads that pass `validate()`, `merge_payloads` never panics, is commutative
//!   (same outcome both ways), its result passes `validate()`, is idempotent and absorbs both inputs.
//!
//! Default 256 cases. Longer: `PROPTEST_CASES=20000 cargo test -p keyvora-sync --test fuzz_merge --release`.
//! The deterministic `qa_def_*` tests at the end reproduce defects found by QA (ignored; see docs/QA_REPORT.md).

use keyvora_sync::{adopt_remote_keys, merge_payloads, merge_remote};
use keyvora_vault::container::{payload_aad, Container};
use keyvora_vault::model::{Dot, HistoryItem, RetiredKey, Version, MAX_COUNTER};
use keyvora_vault::{Argon2Params, EntryInput, Payload, UnlockedVault, VaultError};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use std::sync::LazyLock;

const FAST: Argon2Params = Argon2Params { memory_kib: 19 * 1024, iterations: 2, parallelism: 1 };
const MASTER: &str = "correct horse battery";

fn input(title: &str, pw: &str) -> EntryInput {
    EntryInput {
        title: title.into(),
        username: "me@example.com".into(),
        password: pw.into(),
        urls: vec!["https://github.com".into()],
        notes: String::new(),
    }
}

struct Base {
    container: String,
    dek: Vec<u8>,
    payload: Payload,
}

static BASE: LazyLock<Base> = LazyLock::new(|| {
    let (mut a, _) = UnlockedVault::create(MASTER, FAST, "dev-a", 0).unwrap();
    let t = 1_700_000_000_000;
    let gh = a.create_entry(input("GitHub", "gh-1"), t).unwrap();
    a.update_entry(&gh.id, input("GitHub", "gh-2"), t + 1).unwrap();
    let bank = a.create_entry(input("Bank", "bank-1"), t + 2).unwrap();
    let old = a.create_entry(input("Old", "old-1"), t + 3).unwrap();
    let c = a.export_container().unwrap();
    let dek = a.export_data_key();
    let mut b = UnlockedVault::open_with_data_key(&c, &dek, "dev-b").unwrap();
    let mut cc = UnlockedVault::open_with_data_key(&c, &dek, "dev-c").unwrap();
    a.update_entry(&gh.id, input("GitHub", "gh-from-a"), t + 10).unwrap();
    b.update_entry(&gh.id, input("GitHub", "gh-from-b"), t + 11).unwrap();
    b.update_entry(&bank.id, input("Bank", "bank-from-b"), t + 12).unwrap();
    cc.delete_entry(&bank.id, t + 13).unwrap();
    a.delete_entry(&old.id, t + 14).unwrap();
    merge_remote(&mut a, &b.export_container().unwrap()).unwrap();
    merge_remote(&mut a, &cc.export_container().unwrap()).unwrap();
    a.rotate_data_key(MASTER).unwrap();
    a.rotate_data_key(MASTER).unwrap();
    let container = a.export_container().unwrap();
    let p = a.payload().clone();
    assert!(p.records.iter().any(|r| r.versions.len() > 1), "fixture has conflicts");
    assert!(p.records.iter().any(|r| !r.password_history.is_empty()), "fixture has history");
    assert!(p.records.iter().any(|r| !r.is_live()), "fixture has a tombstone");
    assert_eq!(p.retired_keys.len(), 2, "fixture has retired keys");
    Base { container, dek: a.export_data_key().to_vec(), payload: p }
});

/// Seals a payload with the fixture's DEK and header (what a holder of the DEK could upload).
fn seal(p: &Payload) -> String {
    let mut c = Container::parse(&BASE.container).unwrap();
    let dek = keyvora_crypto::SecretKey::from_slice(&BASE.dek).unwrap();
    let aad = payload_aad(&c.vault_id, c.revision, c.keyring_revision, &c.slots);
    c.payload = keyvora_crypto::encrypt(&dek, &aad, &serde_json::to_vec(p).unwrap()).unwrap();
    c.to_json()
}

// ---------------------------------------------------------------------------------------------------------------
// Model-level mutations
// ---------------------------------------------------------------------------------------------------------------

const DEVICES: &[&str] = &[
    "dev-a",
    "dev-b",
    "dev-c",
    "dev-z",
    "",
    "bad dev!",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
];

#[derive(Debug, Clone)]
enum PMut {
    ReverseVersions(usize),
    DuplicateVersion(usize, usize),
    ForgeContent(usize, usize, u8),
    SetDotCounter(usize, usize, u8, bool),
    SetDotDevice(usize, usize, u8, bool),
    RemoveVersion(usize, usize),
    AddVersion(usize, u8, bool, bool),
    SetContext(usize, u8, u8),
    BloatContext(usize, u16),
    DuplicateHistory(usize, usize),
    ForgeHistory(usize, usize, u8),
    AddHistory(usize, u8),
    SetFloor(usize, u8, u8),
    RetiredDuplicate(usize),
    RetiredSameRevOtherKey(usize),
    RetiredReverse,
    RetiredAdd(u8, u8),
    RetiredBadKey(usize, u8),
    DuplicateRecord(usize),
    SwapIds(usize, usize),
    BadId(usize, u8),
    ReverseRecords,
    RemoveRecord(usize),
    CopyVersions(usize, usize),
    Deleted(usize, usize, bool),
    BadTimestamp(usize, usize, u8),
    SchemaVersion(u32),
    Normalize,
}

fn pmut() -> impl Strategy<Value = PMut> {
    let u = any::<usize>;
    prop_oneof![
        u().prop_map(PMut::ReverseVersions),
        (u(), u()).prop_map(|(r, v)| PMut::DuplicateVersion(r, v)),
        (u(), u(), any::<u8>()).prop_map(|(r, v, k)| PMut::ForgeContent(r, v, k)),
        (u(), u(), any::<u8>(), any::<bool>()).prop_map(|(r, v, k, b)| PMut::SetDotCounter(r, v, k, b)),
        (u(), u(), any::<u8>(), any::<bool>()).prop_map(|(r, v, k, b)| PMut::SetDotDevice(r, v, k, b)),
        (u(), u()).prop_map(|(r, v)| PMut::RemoveVersion(r, v)),
        (u(), any::<u8>(), any::<bool>(), any::<bool>()).prop_map(|(r, d, del, b)| PMut::AddVersion(r, d, del, b)),
        (u(), any::<u8>(), any::<u8>()).prop_map(|(r, d, k)| PMut::SetContext(r, d, k)),
        (u(), prop_oneof![1u16..8, 250u16..260]).prop_map(|(r, n)| PMut::BloatContext(r, n)),
        (u(), u()).prop_map(|(r, h)| PMut::DuplicateHistory(r, h)),
        (u(), u(), any::<u8>()).prop_map(|(r, h, k)| PMut::ForgeHistory(r, h, k)),
        (u(), prop_oneof![1u8..12, 60u8..70]).prop_map(|(r, n)| PMut::AddHistory(r, n)),
        (u(), any::<u8>(), any::<u8>()).prop_map(|(r, d, k)| PMut::SetFloor(r, d, k)),
        u().prop_map(PMut::RetiredDuplicate),
        u().prop_map(PMut::RetiredSameRevOtherKey),
        Just(PMut::RetiredReverse),
        (1u8..6, any::<u8>()).prop_map(|(n, k)| PMut::RetiredAdd(n, k)),
        (u(), any::<u8>()).prop_map(|(i, k)| PMut::RetiredBadKey(i, k)),
        u().prop_map(PMut::DuplicateRecord),
        (u(), u()).prop_map(|(a, b)| PMut::SwapIds(a, b)),
        (u(), any::<u8>()).prop_map(|(r, k)| PMut::BadId(r, k)),
        Just(PMut::ReverseRecords),
        u().prop_map(PMut::RemoveRecord),
        (u(), u()).prop_map(|(a, b)| PMut::CopyVersions(a, b)),
        (u(), u(), any::<bool>()).prop_map(|(r, v, c)| PMut::Deleted(r, v, c)),
        (u(), u(), any::<u8>()).prop_map(|(r, v, k)| PMut::BadTimestamp(r, v, k)),
        prop_oneof![Just(0u32), Just(2), Just(u32::MAX)].prop_map(PMut::SchemaVersion),
        Just(PMut::Normalize),
    ]
}

fn counter(k: u8, ctx: u64) -> u64 {
    [0, 1, 2, ctx, ctx + 1, MAX_COUNTER, MAX_COUNTER + 1, u64::MAX][k as usize % 8]
}

fn apply(p: &mut Payload, m: &PMut) {
    let nr = p.records.len();
    if nr == 0 {
        return;
    }
    let rec = |i: usize| i % nr;
    // Mutations that index into a record's versions are no-ops once a previous mutation emptied them.
    let target = match *m {
        PMut::DuplicateVersion(r, _)
        | PMut::ForgeContent(r, ..)
        | PMut::SetDotCounter(r, ..)
        | PMut::SetDotDevice(r, ..)
        | PMut::RemoveVersion(r, _)
        | PMut::AddVersion(r, ..)
        | PMut::Deleted(r, ..)
        | PMut::BadTimestamp(r, ..) => Some(rec(r)),
        _ => None,
    };
    if target.is_some_and(|r| p.records[r].versions.is_empty()) {
        return;
    }
    match *m {
        PMut::ReverseVersions(r) => p.records[rec(r)].versions.reverse(),
        PMut::DuplicateVersion(r, v) => {
            let vs = &mut p.records[rec(r)].versions;
            let x = vs[v % vs.len()].clone();
            vs.insert(v % (vs.len() + 1), x);
        }
        PMut::ForgeContent(r, v, k) => {
            let vs = &mut p.records[rec(r)].versions;
            let n = vs.len();
            let x = &mut vs[v % n];
            match k % 4 {
                0 => x.password = "forged-password".into(),
                1 => x.title = "Forged".into(),
                2 => x.updated_at = "2099-01-01T00:00:00.000Z".into(),
                _ => x.urls = vec!["https://evil.example".into()],
            }
        }
        PMut::SetDotCounter(r, v, k, bump) => {
            let rr = &mut p.records[rec(r)];
            let n = rr.versions.len();
            let dev = rr.versions[v % n].dot.device.clone();
            let ctx = rr.context.get(&dev).copied().unwrap_or(0);
            let c = counter(k, ctx);
            rr.versions[v % n].dot.counter = c;
            if bump {
                let e = rr.context.entry(dev).or_insert(0);
                *e = (*e).max(c);
            }
        }
        PMut::SetDotDevice(r, v, k, bump) => {
            let rr = &mut p.records[rec(r)];
            let n = rr.versions.len();
            let dev = DEVICES[k as usize % DEVICES.len()].to_string();
            rr.versions[v % n].dot.device = dev.clone();
            if bump {
                let c = rr.versions[v % n].dot.counter;
                let e = rr.context.entry(dev).or_insert(0);
                *e = (*e).max(c);
            }
        }
        PMut::RemoveVersion(r, v) => {
            let vs = &mut p.records[rec(r)].versions;
            let n = vs.len();
            vs.remove(v % n);
        }
        PMut::AddVersion(r, d, deleted, bump) => {
            let rr = &mut p.records[rec(r)];
            let dev = DEVICES[d as usize % 4].to_string();
            let c = rr.context.get(&dev).copied().unwrap_or(0) + 1;
            let mut x = rr.versions[0].clone();
            x.dot = Dot { device: dev.clone(), counter: c };
            x.updated_at = "2030-01-01T00:00:00.000Z".into();
            if deleted {
                x.deleted = true;
                x.title.clear();
                x.username.clear();
                x.password.clear();
                x.urls.clear();
                x.notes.clear();
            } else {
                x.deleted = false;
                x.title = "Injected".into();
                x.password = "injected-pw".into();
            }
            rr.versions.push(x);
            if bump {
                rr.context.insert(dev, c);
            }
        }
        PMut::SetContext(r, d, k) => {
            let rr = &mut p.records[rec(r)];
            let dev = DEVICES[d as usize % DEVICES.len()].to_string();
            if k % 9 == 8 {
                rr.context.remove(&dev);
            } else {
                let ctx = rr.context.get(&dev).copied().unwrap_or(0);
                rr.context.insert(dev, counter(k, ctx));
            }
        }
        PMut::BloatContext(r, n) => {
            let rr = &mut p.records[rec(r)];
            for i in 0..n {
                rr.context.insert(format!("bloat-{i}"), 1);
            }
        }
        PMut::DuplicateHistory(r, h) => {
            let hs = &mut p.records[rec(r)].password_history;
            if !hs.is_empty() {
                let x = hs[h % hs.len()].clone();
                hs.push(x);
            }
        }
        PMut::ForgeHistory(r, h, k) => {
            let rr = &mut p.records[rec(r)];
            let n = rr.password_history.len();
            if n == 0 {
                return;
            }
            let x = &mut rr.password_history[h % n];
            match k % 4 {
                0 => x.password = "forged-history".into(),
                1 => x.retired_by.counter = MAX_COUNTER,
                2 => x.retired_at = "not a date".into(),
                _ => x.retired_by.device = "dev-z".into(),
            }
        }
        PMut::AddHistory(r, n) => {
            let rr = &mut p.records[rec(r)];
            let base = rr.context.get("dev-z").copied().unwrap_or(0);
            for i in 1..=n as u64 {
                rr.password_history.push(HistoryItem {
                    password: format!("h-{i}"),
                    retired_at: format!("2025-01-01T00:00:{:02}.000Z", i % 60),
                    retired_by: Dot { device: "dev-z".into(), counter: base + i },
                });
            }
            rr.context.insert("dev-z".into(), base + n as u64);
        }
        PMut::SetFloor(r, d, k) => {
            let rr = &mut p.records[rec(r)];
            let dev = DEVICES[d as usize % 4].to_string();
            let ctx = rr.context.get(&dev).copied().unwrap_or(0);
            rr.history_floor.insert(dev, counter(k, ctx));
        }
        PMut::RetiredDuplicate(i) => {
            if !p.retired_keys.is_empty() {
                let x = p.retired_keys[i % p.retired_keys.len()].clone();
                p.retired_keys.push(x);
            }
        }
        PMut::RetiredSameRevOtherKey(i) => {
            if !p.retired_keys.is_empty() {
                let n = p.retired_keys.len();
                p.retired_keys[i % n].key = keyvora_vault_b64([9u8; 32]);
            }
        }
        PMut::RetiredReverse => p.retired_keys.reverse(),
        PMut::RetiredAdd(n, k) => {
            let start = [0u64, 1, 100, MAX_COUNTER - 10][k as usize % 4];
            for i in 0..n as u64 {
                p.retired_keys
                    .insert(0, RetiredKey { keyring_revision: start + i, key: keyvora_vault_b64([i as u8; 32]) });
            }
            p.retired_keys.sort_by_key(|k| std::cmp::Reverse(k.keyring_revision));
            p.retired_keys.dedup_by_key(|k| k.keyring_revision);
        }
        PMut::RetiredBadKey(i, k) => {
            if !p.retired_keys.is_empty() {
                let n = p.retired_keys.len();
                p.retired_keys[i % n].key = ["", "!!", "AAAA", &keyvora_vault_b64([1u8; 31])][k as usize % 4].into();
            }
        }
        PMut::DuplicateRecord(r) => {
            let x = p.records[rec(r)].clone();
            p.records.push(x);
        }
        PMut::SwapIds(a, b) => {
            let (a, b) = (rec(a), rec(b));
            let ia = p.records[a].id.clone();
            p.records[a].id = p.records[b].id.clone();
            p.records[b].id = ia;
        }
        PMut::BadId(r, k) => {
            p.records[rec(r)].id =
                ["", "NOT-A-UUID", "00000000-0000-4000-8000-00000000000A", "{00000000-0000-4000-8000-000000000000}"]
                    [k as usize % 4]
                    .into()
        }
        PMut::ReverseRecords => p.records.reverse(),
        PMut::RemoveRecord(r) => {
            p.records.remove(rec(r));
        }
        PMut::CopyVersions(a, b) => {
            let (a, b) = (rec(a), rec(b));
            let (vs, ctx) = (p.records[a].versions.clone(), p.records[a].context.clone());
            p.records[b].versions = vs;
            p.records[b].context = ctx;
        }
        PMut::Deleted(r, v, clear) => {
            let vs = &mut p.records[rec(r)].versions;
            let n = vs.len();
            let x: &mut Version = &mut vs[v % n];
            x.deleted = true;
            if clear {
                x.title.clear();
                x.username.clear();
                x.password.clear();
                x.urls.clear();
                x.notes.clear();
            }
        }
        PMut::BadTimestamp(r, v, k) => {
            let bad = [
                "",
                "2026-13-01T00:00:00.000Z",
                "2026-01-01 00:00:00.000Z",
                "2026-01-01T00:00:00Z",
                "ñññññññññññññññññññññññ",
            ][k as usize % 5];
            let rr = &mut p.records[rec(r)];
            if k % 2 == 0 {
                rr.created_at = bad.into();
            } else {
                let n = rr.versions.len();
                rr.versions[v % n].updated_at = bad.into();
            }
        }
        PMut::SchemaVersion(s) => p.schema_version = s,
        PMut::Normalize => p.normalize(),
    }
}

fn keyvora_vault_b64(b: impl AsRef<[u8]>) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// `merge_remote` with a hostile but authentic remote.
fn check_container_level(m: &Payload, valid: bool) -> Result<(), TestCaseError> {
    let remote = seal(m);
    let mut local = UnlockedVault::open_with_data_key(&BASE.container, &BASE.dek, "dev-local").unwrap();
    let before = local.payload().clone();
    let rev_before = local.revision();
    match merge_remote(&mut local, &remote) {
        Err(e) => {
            prop_assert!(local.payload() == &before, "local payload modified by a failed merge ({e:?})");
            prop_assert_eq!(local.revision(), rev_before);
        }
        Ok(_) => {
            prop_assert!(valid, "merge_remote accepted a remote payload that fails validate()");
            let after = local.payload();
            prop_assert!(after.validate().is_ok());
            // Nothing local disappears unless the remote claims to have seen (and superseded) it.
            for r in &before.records {
                let merged = &after.records[after.record_index(&r.id).expect("local record dropped")];
                let remote_ctx = m.record_index(&r.id).map(|i| &m.records[i].context);
                for v in &r.versions {
                    let kept = merged.versions.iter().any(|w| w.dot == v.dot);
                    let superseded = remote_ctx.is_some_and(|c| v.dot.covered_by(c));
                    prop_assert!(kept || superseded, "local version {:?} of {} lost silently", v.dot, r.id);
                }
            }
            let c = local.export_container();
            prop_assert!(c.is_ok(), "merged vault cannot be saved: {:?}", c.err());
            let back = UnlockedVault::open_with_data_key(&c.unwrap(), &BASE.dek, "reader");
            prop_assert!(back.is_ok_and(|b| b.payload() == local.payload()), "export does not round-trip");
        }
    }
    Ok(())
}

/// Semilattice laws on validated inputs.
fn check_model_level(m: &Payload) -> Result<(), TestCaseError> {
    let p = &BASE.payload;
    let ab = merge_payloads(p, m);
    let ba = merge_payloads(m, p);
    prop_assert_eq!(
        ab.is_ok(),
        ba.is_ok(),
        "commutativity of the outcome: {:?} vs {:?}",
        ab.as_ref().err(),
        ba.as_ref().err()
    );
    if let (Ok((ab, _)), Ok((ba, _))) = (ab, ba) {
        prop_assert!(ab == ba, "commutativity");
        prop_assert!(ab.validate().is_ok(), "merge of two valid payloads is invalid: {:?}", ab.validate().err());
        prop_assert!(merge_payloads(&ab, &ab).unwrap().0 == ab, "idempotence");
        prop_assert!(merge_payloads(&ab, p).unwrap().0 == ab, "absorption of the local input");
        prop_assert!(merge_payloads(&ab, m).unwrap().0 == ab, "absorption of the remote input");
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, .. ProptestConfig::default() })]

    #[test]
    fn hostile_copy_merge(muts in prop::collection::vec(pmut(), 1..5), normalize in any::<bool>()) {
        let mut m = BASE.payload.clone();
        for x in &muts {
            apply(&mut m, x);
        }
        if normalize {
            m.normalize();
        }
        let valid = m.validate().is_ok();
        if std::env::var("KEYVORA_FUZZ_STATS").is_ok() {
            eprintln!("QA-STAT hostile_copy_merge valid={valid}");
        }
        check_container_level(&m, valid)?;
        if valid {
            check_model_level(&m)?;
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Concurrent key changes (SYNC_PROTOCOL §2 "Ranuras de clave"). Not covered by tests/scenarios.rs.
// ---------------------------------------------------------------------------------------------------------------

fn pair() -> (UnlockedVault, UnlockedVault) {
    let (mut a, _) = UnlockedVault::create(MASTER, FAST, "phone", 0).unwrap();
    a.create_entry(input("GitHub", "x"), 1_000).unwrap();
    let c = a.export_container().unwrap();
    let b = UnlockedVault::unlock_with_password(&c, MASTER, "browser").unwrap();
    (a, b)
}

/// What a client does with a remote container (SYNC_PROTOCOL §3), with the user re-authenticating on
/// `KEYRING_CHANGED` using `password`. Returns the error that stops sync, if any.
fn client_sync(v: &mut UnlockedVault, remote: &str, password: &str) -> Result<(), VaultError> {
    match merge_remote(v, remote) {
        Err(VaultError::KeyringChanged) => adopt_remote_keys(v, remote, password).map(|_| ()),
        other => other.map(|_| ()),
    }
}

/// Recovery-key rotations on two devices at the same time converge (existing behaviour, kept as regression).
#[test]
fn concurrent_recovery_key_rotations_converge() {
    let (mut a, mut b) = pair();
    a.rotate_recovery_key(MASTER).unwrap();
    b.rotate_recovery_key(MASTER).unwrap();
    client_sync(&mut a, &b.export_container().unwrap(), MASTER).unwrap();
    client_sync(&mut b, &a.export_container().unwrap(), MASTER).unwrap();
    client_sync(&mut a, &b.export_container().unwrap(), MASTER).unwrap();
    assert_eq!(a.slots(), b.slots());
    assert!(a.payload() == b.payload());
}

/// QA-DEF-003: two devices rotate the data key (or one rotates it and the other changes the master password)
/// while offline. Both end with the same `keyringRevision` and different DEKs: `merge_remote` cannot decrypt the
/// other container (the retired-key fallback only applies to *older* keyrings) and returns `INTEGRITY_ERROR` on both
/// sides, which the client treats as tampering. Sync stays blocked forever (no `KEYRING_CHANGED`, no way to adopt).
#[test]
fn qa_def_003_concurrent_data_key_rotations_converge() {
    let mut blocked = Vec::new();
    for second_op in ["rotate", "change-password"] {
        let (mut a, mut b) = pair();
        a.rotate_data_key(MASTER).unwrap();
        match second_op {
            "rotate" => drop(b.rotate_data_key(MASTER).unwrap()),
            _ => b.change_master_password(MASTER, MASTER, FAST).unwrap(),
        }
        let (ca, cb) = (a.export_container().unwrap(), b.export_container().unwrap());
        let ra = client_sync(&mut a, &cb, MASTER);
        let rb = client_sync(&mut b, &ca, MASTER);
        if ra.is_err() || rb.is_err() {
            blocked.push(format!("{second_op}: A={ra:?} B={rb:?}"));
        }
        // Realistic follow-up: each device syncs with the other's latest upload until both agree.
        for _ in 0..3 {
            let (ca, cb) = (a.export_container().unwrap(), b.export_container().unwrap());
            client_sync(&mut b, &ca, MASTER).unwrap();
            client_sync(&mut a, &b.export_container().unwrap(), MASTER).unwrap();
            let _ = cb;
            if a.slots() == b.slots() && a.payload() == b.payload() {
                break;
            }
        }
        assert_eq!(a.slots(), b.slots(), "{second_op}: keys converge");
        assert!(a.payload() == b.payload(), "{second_op}: data converges");
    }
    assert!(blocked.is_empty(), "sync blocked: {blocked:?}");
}

/// QA-DEF-004: concurrent recovery-key rotations converge, but the device that loses the keyring conflict adopts
/// the other device's recovery slot silently: the recovery key it showed to its user stops working and neither
/// `MergeReport` (only `keyringAdopted`) nor the UI tells that user. If they later forget the master password,
/// recovery fails (acceptance criterion 11).
#[test]
fn qa_def_004_recovery_key_shown_to_the_user_keeps_working_after_a_keyring_conflict() {
    let (mut a, mut b) = pair();
    let rk_a = a.rotate_recovery_key(MASTER).unwrap().to_display().to_string();
    let rk_b = b.rotate_recovery_key(MASTER).unwrap().to_display().to_string();
    // Resolution (accepted by the orchestrator): one recovery slot exists, so only one key can survive; the
    // device whose key is replaced is told explicitly (`recovery_key_changed`) and the UI offers a new one.
    assert_eq!(merge_remote(&mut b, &a.export_container().unwrap()).unwrap_err(), VaultError::KeyringChanged);
    let report = adopt_remote_keys(&mut b, &a.export_container().unwrap(), MASTER).unwrap();
    assert!(report.recovery_key_changed, "B must be told that the recovery key it showed is no longer valid");
    let final_container = b.export_container().unwrap();
    assert!(UnlockedVault::unlock_with_recovery_key(&final_container, &rk_a, "x").is_ok());
    assert!(UnlockedVault::unlock_with_recovery_key(&final_container, &rk_b, "x").is_err());
    // A then merges normally (same keys) and nothing is silently replaced on A.
    let r = merge_remote(&mut a, &final_container).unwrap();
    assert!(!r.recovery_key_changed);
}

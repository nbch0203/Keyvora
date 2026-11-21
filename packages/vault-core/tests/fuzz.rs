//! QA-003 — robustness / mutation fuzzing of every parser that sees untrusted input (docs/THREAT_MODEL.md T3, T5,
//! T7, T21; docs/SECURITY_REVIEW.md I-5).
//!
//! Properties:
//! - `Container::parse`, `UnlockedVault::unlock_with_password` / `unlock_with_recovery_key` / `open_with_data_key`
//!   never panic on mutated containers (byte flips, truncations, insertions, JSON field mutations/removals/type
//!   changes, duplicated keys, huge numbers, deep nesting) and **any success decrypts to exactly the original
//!   payload** (no silent acceptance of tampered content).
//! - Authentic but hostile payloads (a holder of the DEK writes arbitrary JSON, T21) never panic the reader, the
//!   read API or the local write API, and the writer never emits a container that cannot be opened again.
//! - `RecoveryKey::parse` never panics; a mistyped character never yields the original key.
//! - `origin::*` never panic on arbitrary strings, and `match_level` is never `exact`/`sameSite` when the page
//!   host's registrable domain differs from the entry's (structured oracle built from known public suffixes).
//!
//! Case counts are modest by default (≤ 256 per property). Longer runs (WSL):
//! `PROPTEST_CASES=20000 cargo test -p keyvora-vault --test fuzz --release`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use keyvora_vault::container::{payload_aad, Container};
use keyvora_vault::origin::{
    is_valid_entry_url, match_level, match_origins, parse_android_app, parse_entry_url, parse_page_url,
};
use keyvora_vault::{Argon2Params, Entry, EntryInput, MatchLevel, Payload, RecoveryKey, UnlockedVault, VaultError};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use serde_json::{json, Value};
use std::sync::LazyLock;

const FAST: Argon2Params = Argon2Params { memory_kib: 19 * 1024, iterations: 2, parallelism: 1 };
const MASTER: &str = "correct horse battery staple";
const SECRET: &str = "Fuzz-S3cr3t-P@ssw0rd-github";

// ---------------------------------------------------------------------------------------------------------------
// Fixture: one realistic vault (history, conflict, tombstone, IDN/Android URLs, unicode), built once.
// ---------------------------------------------------------------------------------------------------------------

struct Fixture {
    container: String,
    dek: Vec<u8>,
    recovery: String,
    payload: Payload,
    entries: Vec<Entry>,
    revision: u64,
    keyring_revision: u64,
}

fn input(title: &str, user: &str, pw: &str, urls: &[&str], notes: &str) -> EntryInput {
    EntryInput {
        title: title.into(),
        username: user.into(),
        password: pw.into(),
        urls: urls.iter().map(|s| s.to_string()).collect(),
        notes: notes.into(),
    }
}

static FIX: LazyLock<Fixture> = LazyLock::new(|| {
    let (mut v, rk) = UnlockedVault::create(MASTER, FAST, "dev-a", 0).unwrap();
    let t = 1_700_000_000_000;
    let gh = v
        .create_entry(input("GitHub", "alice@example.com", "old-1", &["https://github.com"], "ñandú 🦀 \"quoted\""), t)
        .unwrap();
    v.update_entry(&gh.id, input("GitHub", "alice@example.com", "old-2", &["https://github.com"], "n"), t + 1).unwrap();
    v.update_entry(&gh.id, input("GitHub", "alice@example.com", SECRET, &["https://github.com"], "n"), t + 2).unwrap();
    v.create_entry(input("Banco", "bob", "pin-1234", &["androidapp://com.bank.app", "https://bücher.de"], ""), t + 3)
        .unwrap();
    let gone = v.create_entry(input("Borrada", "eve", "deleted-pw", &[], ""), t + 4).unwrap();
    v.delete_entry(&gone.id, t + 5).unwrap();
    // A pending conflict written by another device (dot dev-b:1), installed through the public merge hook.
    let mut p = v.payload().clone();
    let i = p.record_index(&gh.id).unwrap();
    let mut other = p.records[i].versions[0].clone();
    other.dot = keyvora_vault::Dot { device: "dev-b".into(), counter: 1 };
    other.password = "concurrent-from-b".into();
    other.updated_at = "2023-11-14T22:13:20.001Z".into();
    p.records[i].versions.push(other);
    p.records[i].context.insert("dev-b".into(), 1);
    p.normalize();
    let rev = v.revision();
    v.apply_merge(p, None, rev, false).unwrap();
    let container = v.export_container().unwrap();
    // Sanity: the fixture opens and has one conflict.
    let back = UnlockedVault::unlock_with_password(&container, MASTER, "probe").unwrap();
    assert_eq!(back.get_entry(&gh.id).unwrap().conflicts.len(), 1);
    let mut entries: Vec<Entry> = v.list_entries().iter().map(|e| v.get_entry(&e.id).unwrap()).collect();
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    Fixture {
        dek: v.export_data_key().to_vec(),
        recovery: rk.to_display().to_string(),
        payload: v.payload().clone(),
        entries,
        revision: v.revision(),
        keyring_revision: v.keyring_revision(),
        container,
    }
});

/// Every successful open of a (possibly mutated) container must yield exactly the original vault.
fn assert_original(v: &UnlockedVault, how: &str) -> Result<(), TestCaseError> {
    prop_assert!(v.payload() == &FIX.payload, "{how}: tampered container accepted with a different payload");
    prop_assert_eq!(v.revision(), FIX.revision, "{}: revision differs", how);
    prop_assert_eq!(v.keyring_revision(), FIX.keyring_revision, "{}: keyringRevision differs", how);
    let mut got: Vec<Entry> = v.list_entries().iter().map(|e| v.get_entry(&e.id).unwrap()).collect();
    got.sort_by(|a, b| a.id.cmp(&b.id));
    prop_assert!(got == FIX.entries, "{how}: entries differ");
    Ok(())
}

fn assert_no_leak(e: &VaultError) -> Result<(), TestCaseError> {
    let s = format!("{e} {e:?}");
    prop_assert!(!s.contains(SECRET) && !s.contains(MASTER) && !s.contains("alice"), "error leaks data: {s}");
    Ok(())
}

/// Runs every container entry point on `s`. Argon2 only runs when the header parses (keeps the suite fast).
fn check_container(s: &str) -> Result<(), TestCaseError> {
    let parsed = Container::parse(s);
    match UnlockedVault::open_with_data_key(s, &FIX.dek, "fuzz") {
        Ok(v) => {
            prop_assert!(parsed.is_ok(), "opened although the header does not parse");
            assert_original(&v, "open_with_data_key")?;
        }
        Err(e) => assert_no_leak(&e)?,
    }
    match UnlockedVault::unlock_with_recovery_key(s, &FIX.recovery, "fuzz") {
        Ok(v) => assert_original(&v, "unlock_with_recovery_key")?,
        Err(e) => assert_no_leak(&e)?,
    }
    if parsed.is_ok() {
        match UnlockedVault::unlock_with_password(s, MASTER, "fuzz") {
            Ok(v) => assert_original(&v, "unlock_with_password")?,
            Err(e) => assert_no_leak(&e)?,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Byte-level mutations
// ---------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum ByteMut {
    Flip { pos: usize, mask: u8 },
    Set { pos: usize, byte: u8 },
    Insert { pos: usize, byte: u8 },
    Delete { pos: usize, len: usize },
    Truncate { len: usize },
    Duplicate { pos: usize, len: usize },
    Move { from: usize, to: usize, len: usize },
}

fn interesting_byte() -> impl Strategy<Value = u8> {
    prop_oneof![any::<u8>(), prop::sample::select(b"{}[]\",:\\0123456789-+eE. =/A\x00\xff\n".to_vec()),]
}

fn byte_mut() -> impl Strategy<Value = ByteMut> {
    prop_oneof![
        (any::<usize>(), 1u8..=255).prop_map(|(pos, mask)| ByteMut::Flip { pos, mask }),
        (any::<usize>(), interesting_byte()).prop_map(|(pos, byte)| ByteMut::Set { pos, byte }),
        (any::<usize>(), interesting_byte()).prop_map(|(pos, byte)| ByteMut::Insert { pos, byte }),
        (any::<usize>(), 1usize..64).prop_map(|(pos, len)| ByteMut::Delete { pos, len }),
        any::<usize>().prop_map(|len| ByteMut::Truncate { len }),
        (any::<usize>(), 1usize..64).prop_map(|(pos, len)| ByteMut::Duplicate { pos, len }),
        (any::<usize>(), any::<usize>(), 1usize..64).prop_map(|(from, to, len)| ByteMut::Move { from, to, len }),
    ]
}

fn apply_byte_mut(b: &mut Vec<u8>, m: &ByteMut) {
    if b.is_empty() {
        return;
    }
    let n = b.len();
    match *m {
        ByteMut::Flip { pos, mask } => b[pos % n] ^= mask,
        ByteMut::Set { pos, byte } => b[pos % n] = byte,
        ByteMut::Insert { pos, byte } => b.insert(pos % (n + 1), byte),
        ByteMut::Delete { pos, len } => {
            let s = pos % n;
            b.drain(s..(s + len).min(n));
        }
        ByteMut::Truncate { len } => b.truncate(len % n),
        ByteMut::Duplicate { pos, len } => {
            let s = pos % n;
            let chunk: Vec<u8> = b[s..(s + len).min(n)].to_vec();
            b.splice(s..s, chunk);
        }
        ByteMut::Move { from, to, len } => {
            let s = from % n;
            let chunk: Vec<u8> = b.drain(s..(s + len).min(n)).collect();
            let t = to % (b.len() + 1);
            b.splice(t..t, chunk);
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// JSON-level mutations (applied to the container header or to an authentic payload)
// ---------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Hostile {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Str(String),
    LongStr(usize),
    EmptyArr,
    EmptyObj,
    /// Number literal that `serde_json::Value` cannot hold (inserted textually).
    BigLiteral(usize),
}

const BIG_LITERALS: &[&str] = &[
    "1e400",
    "-1e400",
    "18446744073709551616",
    "-9223372036854775809",
    "123456789012345678901234567890",
    "9007199254740992",
    "9007199254740991",
    "-0",
    "1E+2",
    "0.5",
    "1.0",
];

fn hostile() -> impl Strategy<Value = Hostile> {
    prop_oneof![
        Just(Hostile::Null),
        any::<bool>().prop_map(Hostile::Bool),
        prop_oneof![Just(-1i64), Just(0), Just(1), Just(2), Just(i64::MIN), Just(i64::MAX), any::<i64>()]
            .prop_map(Hostile::Int),
        prop_oneof![
            Just(u64::MAX),
            Just((1u64 << 53) - 1),
            Just(1u64 << 53),
            Just(u32::MAX as u64),
            Just(u32::MAX as u64 + 1),
            Just(19455u64),
            Just(19456u64),
            Just(262144u64),
            Just(262145u64),
            Just(10u64),
            Just(11u64),
            Just(8u64),
            Just(9u64),
            any::<u64>(),
        ]
        .prop_map(Hostile::Uint),
        prop_oneof![Just(1.5f64), Just(-0.0), Just(1e300), Just(f64::MIN_POSITIVE)].prop_map(Hostile::Float),
        prop_oneof![
            Just(String::new()),
            Just("A".to_string()),
            Just("AAAA".to_string()),
            Just("====".to_string()),
            Just("keyvora.vault".to_string()),
            Just("password".to_string()),
            Just("recovery".to_string()),
            Just("argon2id".to_string()),
            Just("hkdf-sha256".to_string()),
            Just("A256GCM".to_string()),
            Just("00000000-0000-4000-8000-000000000000".to_string()),
            Just("2026-01-01T00:00:00.000Z".to_string()),
            Just("javascript:alert(1)".to_string()),
            Just("dev-a".to_string()),
            Just("\u{0000}\u{FEFF}\u{202E}".to_string()),
            "\\PC{0,24}",
        ]
        .prop_map(Hostile::Str),
        (1usize..70_000).prop_map(Hostile::LongStr),
        Just(Hostile::EmptyArr),
        Just(Hostile::EmptyObj),
        (0..BIG_LITERALS.len()).prop_map(Hostile::BigLiteral),
    ]
}

#[derive(Debug, Clone)]
enum JsonMut {
    Remove(usize),
    Replace(usize, Hostile),
    AddField(usize, u8, Hostile),
    DuplicateKey(usize, Hostile),
    Nest(usize, u32),
    ReverseArray(usize),
    DuplicateElement(usize, usize),
    MutateString(usize, u8, usize),
    MutateNumber(usize, u8),
    SwapValues(usize, usize),
}

fn json_mut() -> impl Strategy<Value = JsonMut> {
    prop_oneof![
        any::<usize>().prop_map(JsonMut::Remove),
        (any::<usize>(), hostile()).prop_map(|(p, h)| JsonMut::Replace(p, h)),
        (any::<usize>(), any::<u8>(), hostile()).prop_map(|(p, k, h)| JsonMut::AddField(p, k, h)),
        (any::<usize>(), hostile()).prop_map(|(p, h)| JsonMut::DuplicateKey(p, h)),
        (any::<usize>(), prop_oneof![1u32..8, 120u32..140, Just(5_000u32), Just(100_000u32)])
            .prop_map(|(p, d)| JsonMut::Nest(p, d)),
        any::<usize>().prop_map(JsonMut::ReverseArray),
        (any::<usize>(), any::<usize>()).prop_map(|(p, i)| JsonMut::DuplicateElement(p, i)),
        (any::<usize>(), any::<u8>(), any::<usize>()).prop_map(|(p, k, i)| JsonMut::MutateString(p, k, i)),
        (any::<usize>(), any::<u8>()).prop_map(|(p, k)| JsonMut::MutateNumber(p, k)),
        (any::<usize>(), any::<usize>()).prop_map(|(a, b)| JsonMut::SwapValues(a, b)),
    ]
}

#[derive(Debug, Clone)]
enum Seg {
    Key(String),
    Idx(usize),
}

fn collect_paths(v: &Value, cur: &mut Vec<Seg>, out: &mut Vec<Vec<Seg>>) {
    out.push(cur.clone());
    match v {
        Value::Object(m) => {
            for (k, c) in m {
                cur.push(Seg::Key(k.clone()));
                collect_paths(c, cur, out);
                cur.pop();
            }
        }
        Value::Array(a) => {
            for (i, c) in a.iter().enumerate() {
                cur.push(Seg::Idx(i));
                collect_paths(c, cur, out);
                cur.pop();
            }
        }
        _ => {}
    }
}

fn at<'a>(v: &'a mut Value, p: &[Seg]) -> Option<&'a mut Value> {
    let mut cur = v;
    for s in p {
        cur = match (s, cur) {
            (Seg::Key(k), Value::Object(m)) => m.get_mut(k)?,
            (Seg::Idx(i), Value::Array(a)) => a.get_mut(*i)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Applies `m` to `v`; returns textual substitutions (sentinel string literal → raw JSON) to apply after
/// serialization, for things `Value` cannot represent (huge numbers, duplicated keys, very deep nesting).
fn apply_json_mut(v: &mut Value, m: &JsonMut, subst: &mut Vec<(String, String)>) {
    let mut paths = Vec::new();
    collect_paths(v, &mut Vec::new(), &mut paths);
    let pick = |sel: usize| paths[sel % paths.len()].clone();
    let n = subst.len();
    let hostile_value = |h: &Hostile, subst: &mut Vec<(String, String)>| -> Value {
        match h {
            Hostile::Null => Value::Null,
            Hostile::Bool(b) => json!(b),
            Hostile::Int(i) => json!(i),
            Hostile::Uint(u) => json!(u),
            Hostile::Float(f) => json!(f),
            Hostile::Str(s) => json!(s),
            Hostile::LongStr(len) => json!("A".repeat(*len)),
            Hostile::EmptyArr => json!([]),
            Hostile::EmptyObj => json!({}),
            Hostile::BigLiteral(i) => {
                let key = format!("__QA_BIG_{}_{}__", n, subst.len());
                subst.push((format!("\"{key}\""), BIG_LITERALS[*i].to_string()));
                json!(key)
            }
        }
    };
    match m {
        JsonMut::Remove(sel) => {
            let p = pick(*sel);
            if let Some((last, parent)) = p.split_last() {
                match (last, at(v, parent)) {
                    (Seg::Key(k), Some(Value::Object(o))) => {
                        o.remove(k);
                    }
                    (Seg::Idx(i), Some(Value::Array(a))) if *i < a.len() => {
                        a.remove(*i);
                    }
                    _ => {}
                }
            }
        }
        JsonMut::Replace(sel, h) => {
            let p = pick(*sel);
            let nv = hostile_value(h, subst);
            if let Some(t) = at(v, &p) {
                *t = nv;
            }
        }
        JsonMut::AddField(sel, k, h) => {
            const KEYS: &[&str] =
                &["x", "revision", "format", "formatVersion", "__proto__", "", "keySlots", "Revision", "dot", "id"];
            let p = pick(*sel);
            let nv = hostile_value(h, subst);
            if let Some(Value::Object(o)) = at(v, &p) {
                o.insert(KEYS[*k as usize % KEYS.len()].to_string(), nv);
            }
        }
        JsonMut::DuplicateKey(sel, h) => {
            let p = pick(*sel);
            let nv = hostile_value(h, subst);
            if let Some(Value::Object(o)) = at(v, &p) {
                if let Some(existing) = o.keys().next().cloned() {
                    let key = format!("__QA_DUP_{}__", subst.len());
                    subst.push((format!("\"{key}\""), serde_json::to_string(&existing).unwrap()));
                    o.insert(key, nv);
                }
            }
        }
        JsonMut::Nest(sel, depth) => {
            let p = pick(*sel);
            if let Some(t) = at(v, &p) {
                let key = format!("__QA_NEST_{}__", subst.len());
                let d = *depth as usize;
                subst.push((format!("\"{key}\""), format!("{}{}{}", "[".repeat(d), t, "]".repeat(d))));
                *t = json!(key);
            }
        }
        JsonMut::ReverseArray(sel) => {
            if let Some(Value::Array(a)) = at(v, &pick(*sel)) {
                a.reverse();
            }
        }
        JsonMut::DuplicateElement(sel, i) => {
            if let Some(Value::Array(a)) = at(v, &pick(*sel)) {
                if !a.is_empty() {
                    let e = a[i % a.len()].clone();
                    a.insert(i % (a.len() + 1), e);
                }
            }
        }
        JsonMut::MutateString(sel, kind, i) => {
            if let Some(Value::String(s)) = at(v, &pick(*sel)) {
                let mut chars: Vec<char> = s.chars().collect();
                match kind % 8 {
                    0 => chars.push('A'),
                    1 => {
                        chars.pop();
                    }
                    2 => chars = s.to_uppercase().chars().collect(),
                    3 if !chars.is_empty() => {
                        let j = i % chars.len();
                        chars[j] = if chars[j] == 'A' { 'B' } else { 'A' };
                    }
                    4 => chars.push('='),
                    5 => chars.insert(i % (chars.len() + 1), ' '),
                    6 => chars.insert(i % (chars.len() + 1), '\u{00e9}'),
                    _ => chars.clear(),
                }
                *s = chars.into_iter().collect();
            }
        }
        JsonMut::MutateNumber(sel, kind) => {
            let p = pick(*sel);
            if let Some(t) = at(v, &p) {
                if let Some(x) = t.as_u64() {
                    *t = match kind % 7 {
                        0 => json!(x.wrapping_add(1)),
                        1 => json!(x.wrapping_sub(1)),
                        2 => json!(x.wrapping_mul(2)),
                        3 => json!(0),
                        4 => json!(-(x as i128).min(i64::MAX as i128) as i64),
                        5 => json!(x as f64 + 0.5),
                        _ => json!(x.to_string()),
                    };
                }
            }
        }
        JsonMut::SwapValues(a, b) => {
            let (pa, pb) = (pick(*a), pick(*b));
            let va = at(v, &pa).cloned();
            let vb = at(v, &pb).cloned();
            if let (Some(va), Some(vb)) = (va, vb) {
                // Swapping a node with one of its descendants is skipped (would need a cycle).
                let prefix = |x: &[Seg], y: &[Seg]| {
                    x.len() <= y.len()
                        && x.iter().zip(y).all(|(s, t)| match (s, t) {
                            (Seg::Key(p), Seg::Key(q)) => p == q,
                            (Seg::Idx(p), Seg::Idx(q)) => p == q,
                            _ => false,
                        })
                };
                if !prefix(&pa, &pb) && !prefix(&pb, &pa) {
                    if let Some(t) = at(v, &pa) {
                        *t = vb;
                    }
                    if let Some(t) = at(v, &pb) {
                        *t = va;
                    }
                }
            }
        }
    }
}

fn render(v: &Value, subst: &[(String, String)]) -> String {
    let mut s = v.to_string();
    for (from, to) in subst {
        s = s.replacen(from, to, 1);
    }
    s
}

fn mutate_json(base: &Value, muts: &[JsonMut]) -> String {
    let mut v = base.clone();
    let mut subst = Vec::new();
    for m in muts {
        apply_json_mut(&mut v, m, &mut subst);
    }
    render(&v, &subst)
}

/// Re-encrypts `payload_json` under the fixture's DEK with the correct AAD: what a holder of the DEK (T21) or a
/// buggy client could upload. The header is the fixture's.
fn seal_payload(payload_json: &[u8]) -> String {
    let mut c = Container::parse(&FIX.container).unwrap();
    let dek = keyvora_crypto::SecretKey::from_slice(&FIX.dek).unwrap();
    let aad = payload_aad(&c.vault_id, c.revision, c.keyring_revision, &c.slots);
    c.payload = keyvora_crypto::encrypt(&dek, &aad, payload_json).unwrap();
    c.to_json()
}

/// Read API, local writes and the writer on a vault opened from hostile-but-authentic content.
fn exercise_session(mut v: UnlockedVault, strict_writer: bool) -> Result<(), TestCaseError> {
    let list = v.list_entries();
    let _ = v.search("a");
    let _ = v.search("ñ");
    for e in &list {
        let full = v.get_entry(&e.id);
        prop_assert!(full.is_ok(), "listed entry cannot be read");
        for u in &e.urls {
            let _ = v.find_matches(u);
            let _ = v.find_app_matches(u.trim_start_matches("androidapp://"));
        }
    }
    let _ = v.find_matches("https://github.com/login");
    let _ = v.find_matches("https://xn--bcher-kva.de/");
    let now = 1_800_000_000_000;
    let mut wrote = false;
    if let Some(first) = list.first() {
        wrote |= v.update_entry(&first.id, input("Edited", "u", "new-password-qa", &[], ""), now).is_ok();
        if let Ok(e) = v.get_entry(&first.id) {
            if !e.conflicts.is_empty() {
                wrote |= v.resolve_conflict(&first.id, keyvora_vault::ConflictChoice::TakeConflict(0), now + 1).is_ok();
            }
        }
    }
    if let Some(last) = list.last() {
        wrote |= v.delete_entry(&last.id, now + 2).is_ok();
    }
    wrote |= v.create_entry(input("New", "n", "p", &["https://example.org"], ""), now + 3).is_ok();
    match v.export_container() {
        Ok(c) => {
            // The writer never emits something unreadable, and what it emits round-trips.
            let back = UnlockedVault::open_with_data_key(&c, &FIX.dek, "reader");
            prop_assert!(back.is_ok(), "writer emitted an unreadable container: {:?}", back.err());
            prop_assert!(back.unwrap().payload() == v.payload(), "export does not round-trip");
        }
        Err(e) => {
            assert_no_leak(&e)?;
            prop_assert!(!(strict_writer && wrote), "local writes succeeded but the vault cannot be saved: {e}");
        }
    }
    Ok(())
}

fn strict_writer() -> bool {
    std::env::var("KEYVORA_FUZZ_STRICT_WRITER").is_ok_and(|v| v == "1")
}

static PAYLOAD_JSON: LazyLock<Value> = LazyLock::new(|| serde_json::to_value(&FIX.payload).unwrap());
static CONTAINER_JSON: LazyLock<Value> = LazyLock::new(|| serde_json::from_str(&FIX.container).unwrap());

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, .. ProptestConfig::default() })]

    /// Raw byte flips, truncations, insertions, deletions, duplications and moves over the whole container text.
    #[test]
    fn container_byte_mutations(muts in prop::collection::vec(byte_mut(), 1..5)) {
        let mut b = FIX.container.as_bytes().to_vec();
        for m in &muts {
            apply_byte_mut(&mut b, m);
        }
        check_container(&String::from_utf8_lossy(&b))?;
    }

    /// Structural JSON mutations of the header: removals, type changes, unknown/duplicated keys, huge numbers,
    /// deep nesting, reordering and value swaps between fields.
    #[test]
    fn container_json_mutations(muts in prop::collection::vec(json_mut(), 1..4)) {
        check_container(&mutate_json(&CONTAINER_JSON, &muts))?;
    }

    /// The payload is authentic (sealed with the right DEK and AAD) but its JSON is hostile (T21: a device holding
    /// the DEK). Reader and session API must never panic; the writer must never emit an unreadable container.
    /// `KEYVORA_FUZZ_STRICT_WRITER=1` additionally requires every accepted state to remain savable after local
    /// writes (see QA-DEF-001 / QA-DEF-002 in docs/QA_REPORT.md).
    #[test]
    fn authentic_hostile_payloads(muts in prop::collection::vec(json_mut(), 1..4)) {
        let text = mutate_json(&PAYLOAD_JSON, &muts);
        let c = seal_payload(text.as_bytes());
        let opened = UnlockedVault::open_with_data_key(&c, &FIX.dek, "dev-a");
        if std::env::var("KEYVORA_FUZZ_STATS").is_ok() {
            eprintln!("QA-STAT authentic_hostile_payloads accepted={}", opened.is_ok());
        }
        match opened {
            Ok(v) => {
                prop_assert!(v.payload().validate().is_ok());
                exercise_session(v, strict_writer())?;
            }
            Err(e) => {
                assert_no_leak(&e)?;
                prop_assert!(
                    matches!(e, VaultError::InvalidFormat(_) | VaultError::UnsupportedVersion),
                    "unexpected error class for an authentic payload: {e:?}"
                );
            }
        }
    }

    #[test]
    fn container_parse_arbitrary_text(s in prop_oneof!["\\PC{0,200}", any::<String>()]) {
        let _ = Container::parse(&s);
        let _ = UnlockedVault::open_with_data_key(&s, &FIX.dek, "fuzz");
        let _ = UnlockedVault::unlock_with_recovery_key(&s, &FIX.recovery, "fuzz");
    }

    // ---------------- recovery key ----------------

    #[test]
    fn recovery_parse_never_panics(s in prop_oneof![any::<String>(), "[A-Za-z0-9 \\-\t]{0,90}", "\\PC{0,80}"]) {
        let _ = RecoveryKey::parse(&s);
    }

    /// One substituted character never yields the original key (and almost always fails the checksum).
    #[test]
    fn recovery_single_substitution(pos in 0usize..56, c in prop::sample::select(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".to_vec())) {
        let original = RecoveryKey::parse(&FIX.recovery).unwrap();
        let mut chars: Vec<char> = FIX.recovery.chars().filter(|c| *c != '-').collect();
        prop_assume!(chars[pos] != c as char);
        chars[pos] = c as char;
        let typo: String = chars.into_iter().collect();
        match RecoveryKey::parse(&typo) {
            Err(e) => prop_assert_eq!(e, VaultError::InvalidRecoveryKey),
            Ok(k) => prop_assert!(k.secret() != original.secret(), "typo parsed to the original key"),
        }
    }

    /// Accepted spellings (case, spaces, dashes, 0/1/8 look-alikes) always give the original key.
    #[test]
    fn recovery_relaxed_spellings(lower in any::<bool>(), sep in prop::sample::select(vec!["", " ", "-", "  ", "\t", "\n"])) {
        let original = RecoveryKey::parse(&FIX.recovery).unwrap();
        let mut s = FIX.recovery.replace('-', sep);
        s = s.replace('O', "0").replace('I', "1").replace('B', "8");
        if lower {
            s = s.to_lowercase();
        }
        let k = RecoveryKey::parse(&s);
        prop_assert!(k.is_ok(), "relaxed spelling rejected");
        prop_assert!(k.unwrap().secret() == original.secret());
    }

    // ---------------- origins ----------------

    #[test]
    fn origin_functions_never_panic(
        entry in prop_oneof![any::<String>(), url_like()],
        page in prop_oneof![any::<String>(), url_like()],
    ) {
        let _ = parse_android_app(&entry);
        let _ = is_valid_entry_url(&entry);
        let e = parse_entry_url(&entry);
        let p = parse_page_url(&page);
        let lvl = match_level(&entry, &page);
        if lvl != MatchLevel::None {
            let (e, p) = (e.unwrap(), p.unwrap());
            prop_assert_eq!(&e.scheme, &p.scheme);
            prop_assert!(p.scheme == "https" || p.host == "localhost" || p.host.ends_with(".localhost") || p.is_ip);
            match lvl {
                MatchLevel::Exact => prop_assert!(e.host == p.host && e.port == p.port),
                _ => {
                    prop_assert!(!e.is_ip && !p.is_ip);
                    prop_assert!(e.registrable_domain.is_some() && e.registrable_domain == p.registrable_domain);
                }
            }
            prop_assert_eq!(match_origins(&e, &p), lvl);
        }
    }

    /// Oracle by construction: hosts are built from random labels under known public suffixes, so the expected
    /// registrable domain is known without asking the implementation.
    #[test]
    fn match_level_never_crosses_registrable_domains(case in site_pair()) {
        let got = match_level(&case.entry_url, &case.page_url);
        let expected = case.expected();
        prop_assert_eq!(got, expected, "entry {} page {} ({:?})", case.entry_url, case.page_url, case);
        if case.entry_reg != case.page_reg {
            prop_assert_eq!(got, MatchLevel::None);
        }
    }

    #[test]
    fn ip_hosts_match_exactly_only(a in any::<[u8; 4]>(), b in any::<[u8; 4]>(), same in any::<bool>(), form in 0u8..3) {
        let b = if same { a } else { b };
        let page_host = match form {
            0 => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
            1 => u32::from_be_bytes(b).to_string(),
            _ => format!("0x{:x}", u32::from_be_bytes(b)),
        };
        let entry = format!("https://{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
        let got = match_level(&entry, &format!("https://{page_host}/login"));
        prop_assert_eq!(got, if a == b { MatchLevel::Exact } else { MatchLevel::None });
    }
}

fn url_like() -> impl Strategy<Value = String> {
    (
        prop::sample::select(vec![
            "https://",
            "http://",
            "HTTPS://",
            "androidapp://",
            "javascript:",
            "data:",
            "file://",
            "ftp://",
            "blob:https://",
            "",
            "//",
        ]),
        "[a-zA-Z0-9.:@\\[\\]%_/?#~\\-\u{0430}\u{00fc}\u{3002}\u{ff0e}]{0,40}",
    )
        .prop_map(|(s, rest)| format!("{s}{rest}"))
}

// ----------------------------- structured origin oracle -----------------------------

const SUFFIXES: &[&str] = &["com", "org", "net", "de", "co.uk", "com.au", "github.io", "herokuapp.com"];

#[derive(Debug, Clone)]
struct SitePair {
    entry_url: String,
    page_url: String,
    entry_host: String,
    page_host: String,
    entry_reg: String,
    page_reg: String,
    entry_port: u16,
    page_port: u16,
    page_https: bool,
}

impl SitePair {
    fn expected(&self) -> MatchLevel {
        if !self.page_https || self.entry_reg != self.page_reg {
            MatchLevel::None
        } else if self.entry_host == self.page_host && self.entry_port == self.page_port {
            MatchLevel::Exact
        } else if self.entry_host == self.page_host {
            // Same host on another port: a different service, never offered (origin.rs, audit).
            MatchLevel::None
        } else {
            MatchLevel::SameSite
        }
    }
}

fn label() -> impl Strategy<Value = String> {
    "kq[a-z0-9]{1,6}"
}

fn site_pair() -> impl Strategy<Value = SitePair> {
    (
        prop::collection::vec(label(), 0..3),
        label(),
        0..SUFFIXES.len(),
        prop::collection::vec(label(), 0..3),
        label(),
        0..SUFFIXES.len(),
        0u8..6,
        (0u8..3, 0u8..3),
        (any::<bool>(), any::<bool>(), any::<bool>(), 0u8..4, 0u8..10),
    )
        .prop_map(|(esubs, elabel, esuf, psubs, plabel, psuf, relation, (eport, pport), deco)| {
            let (upper, trailing_dot, schemeless, userinfo, http) = deco;
            let join = |subs: &[String], reg: &str| {
                let mut h = subs.join(".");
                if !h.is_empty() {
                    h.push('.');
                }
                h.push_str(reg);
                h
            };
            let entry_reg = format!("{elabel}.{}", SUFFIXES[esuf]);
            let entry_host = join(&esubs, &entry_reg);
            // Page relation to the entry: 0 same site, 1 unrelated, 2 entry host as subdomain of attacker site,
            // 3 same label other suffix, 4 label with a suffix appended, 5 identical host.
            let (page_reg, page_host) = match relation {
                0 => (entry_reg.clone(), join(&psubs, &entry_reg)),
                1 => {
                    let r = format!("{plabel}.{}", SUFFIXES[psuf]);
                    (r.clone(), join(&psubs, &r))
                }
                2 => {
                    let r = format!("{plabel}.{}", SUFFIXES[psuf]);
                    (r.clone(), format!("{entry_host}.{r}"))
                }
                3 => {
                    let r = format!("{elabel}.{}", SUFFIXES[(esuf + 1 + psuf % (SUFFIXES.len() - 1)) % SUFFIXES.len()]);
                    (r.clone(), join(&psubs, &r))
                }
                4 => {
                    let r = format!("{elabel}x.{}", SUFFIXES[esuf]);
                    (r.clone(), join(&psubs, &r))
                }
                _ => (entry_reg.clone(), entry_host.clone()),
            };
            let port = |k: u8| match k {
                0 => (443u16, String::new()),
                1 => (443, ":443".to_string()),
                _ => (8443, ":8443".to_string()),
            };
            let ((ep, eps), (pp, pps)) = (port(eport), port(pport));
            let mut shown_page_host = page_host.clone();
            if upper {
                shown_page_host = shown_page_host.to_uppercase();
            }
            if trailing_dot {
                shown_page_host.push('.');
            }
            let info = match userinfo {
                0 => String::new(),
                1 => "user:pw@".to_string(),
                2 => format!("{entry_host}@"),
                _ => format!("{entry_host}:443@"),
            };
            let page_https = http != 0;
            let scheme = if page_https { "https" } else { "http" };
            let page_url =
                format!("{scheme}://{info}{shown_page_host}{pps}/{entry_host}/login?next=https://{entry_host}/");
            let entry_url =
                if schemeless { format!("{entry_host}{eps}/x") } else { format!("https://{entry_host}{eps}") };
            SitePair {
                entry_url,
                page_url,
                entry_host,
                page_host,
                entry_reg,
                page_reg,
                entry_port: ep,
                page_port: pp,
                page_https,
            }
        })
}

// ---------------------------------------------------------------------------------------------------------------
// Deterministic hostile inputs (not random): deep nesting and numbers at the limits.
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn deep_nesting_is_rejected_without_stack_overflow() {
    let deep = |d: usize| format!("{}{}", "[".repeat(d), "]".repeat(d));
    let cases = [
        deep(200_000),
        format!("{{\"format\":\"keyvora.vault\",\"formatVersion\":1,\"x\":{}}}", deep(200_000)),
        FIX.container.replacen("\"payload\":", &format!("\"payload\":{},\"_\":", deep(100_000)), 1),
        format!("{}{}", "{\"a\":".repeat(100_000), "}".repeat(100_000)),
    ];
    for c in &cases {
        assert!(matches!(Container::parse(c).unwrap_err(), VaultError::InvalidFormat(_)));
        assert!(UnlockedVault::open_with_data_key(c, &FIX.dek, "d").is_err());
    }
    // Inside an authentic payload too.
    let text = format!("{{\"schemaVersion\":1,\"records\":{}}}", deep(100_000));
    assert_eq!(
        UnlockedVault::open_with_data_key(&seal_payload(text.as_bytes()), &FIX.dek, "d").unwrap_err(),
        VaultError::InvalidFormat("payload")
    );
}

#[test]
fn numbers_at_and_beyond_the_limits() {
    for lit in BIG_LITERALS.iter().chain(&["-1", "\"1\"", "null", "true", "[]", "{}", "1e2", "4294967296"]) {
        for field in ["revision", "keyringRevision", "formatVersion"] {
            let v: Value = serde_json::from_str(&FIX.container).unwrap();
            let original = v[field].to_string();
            let text = FIX.container.replacen(&format!("\"{field}\":{original}"), &format!("\"{field}\":{lit}"), 1);
            if text == FIX.container {
                continue; // same value
            }
            match UnlockedVault::open_with_data_key(&text, &FIX.dek, "d") {
                Ok(v) => panic!("{field}={lit} accepted (revision {})", v.revision()),
                Err(e) => assert_ne!(e, VaultError::Crypto, "{field}={lit}"),
            }
        }
    }
    // KDF numbers: never derived when out of bounds (cheap), wrong type → format error.
    for (field, lit) in
        [("memoryKiB", "4294967296"), ("iterations", "1e1"), ("parallelism", "-1"), ("memoryKiB", "1.5")]
    {
        let text = FIX.container.replacen(&format!("\"{field}\":"), &format!("\"{field}\":{lit},\"_{field}\":"), 1);
        assert!(UnlockedVault::unlock_with_password(&text, MASTER, "d").is_err(), "{field}={lit}");
    }
}

/// Base64 that decodes to the same bytes in a non-canonical way must not be accepted as "the same" container in a
/// way that hides tampering: either rejected or decrypted to the original payload.
#[test]
fn non_canonical_base64_is_rejected_or_harmless() {
    let mut v: Value = serde_json::from_str(&FIX.container).unwrap();
    let nonce = v["payload"]["nonce"].as_str().unwrap().to_string(); // 12 bytes → 16 chars, no padding
    let raw = B64.decode(&nonce).unwrap();
    for alt in [format!("{nonce}="), format!(" {nonce}"), nonce.to_lowercase(), B64.encode(&raw[..11])] {
        v["payload"]["nonce"] = json!(alt);
        let r = UnlockedVault::open_with_data_key(&v.to_string(), &FIX.dek, "d");
        if let Ok(opened) = r {
            assert!(opened.payload() == &FIX.payload);
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Defects found by QA (kept as ignored regression tests; see docs/QA_REPORT.md §5). Run with `-- --ignored`.
// ---------------------------------------------------------------------------------------------------------------

/// QA-DEF-001: `Payload::validate` accepts a `historyFloor` above the record's context. After a normal local
/// password change the new history item (retired by the new dot) is already "below the floor", so the next export
/// fails with `INVALID_FORMAT: passwordHistory`: the edit is applied in memory but can never be saved.
#[test]
fn qa_def_001_history_floor_above_context_blocks_saving_a_password_change() {
    let mut p = FIX.payload.clone();
    // A live record without history (otherwise the floor would cover existing items and the reader rejects it).
    let i = p.records.iter().position(|r| r.is_live() && r.password_history.is_empty()).unwrap();
    let id = p.records[i].id.clone();
    p.records[i].history_floor.insert("dev-a".into(), 1_000_000);
    let text = serde_json::to_vec(&p).unwrap();
    // Fixed: the reader rejects a floor above the context, so the write path can never be bricked.
    let _ = id;
    assert_eq!(
        UnlockedVault::open_with_data_key(&seal_payload(&text), &FIX.dek, "dev-a").unwrap_err(),
        VaultError::InvalidFormat("historyFloor")
    );
}

/// QA-DEF-002: `Payload::validate` accepts `retiredKeys` whose `keyringRevision` is ≥ the container's current
/// keyring revision. A later `rotate_data_key` prepends the current key with the current keyring revision, the list
/// stops being strictly decreasing and every export fails: the rotation (and the new recovery key already shown to
/// the user) can never be saved.
#[test]
fn qa_def_002_retired_key_newer_than_keyring_blocks_rotation() {
    let mut p = FIX.payload.clone();
    p.retired_keys = vec![keyvora_vault::model::RetiredKey { keyring_revision: 50, key: B64.encode([7u8; 32]) }];
    let text = serde_json::to_vec(&p).unwrap();
    let c = seal_payload(&text);
    // Fixed: the reader rejects retired keys newer than the keyring they are stored under.
    assert_eq!(
        UnlockedVault::unlock_with_password(&c, MASTER, "dev-a").unwrap_err(),
        VaultError::InvalidFormat("retiredKeys newer than keyring")
    );
}

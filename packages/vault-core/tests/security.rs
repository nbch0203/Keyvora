//! Mandatory security tests (password-transformer-plan/docs/SECURITY.md §9, docs/THREAT_MODEL.md §5).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use keyvora_vault::{Argon2Params, EntryInput, UnlockedVault, VaultError};
use serde_json::{json, Value};

const FAST: Argon2Params = Argon2Params { memory_kib: 19 * 1024, iterations: 2, parallelism: 1 };
const MASTER: &str = "correct horse battery staple";
/// A second strong master password (the core rejects weak or reused ones).
const NEW_MASTER: &str = "violeta tranvía helecho brújula 47";
const SECRET: &str = "S3cr3t-P@ssw0rd-for-github";

fn inp(title: &str, username: &str, password: &str, urls: &[&str]) -> EntryInput {
    EntryInput {
        title: title.into(),
        username: username.into(),
        password: password.into(),
        urls: urls.iter().map(|u| u.to_string()).collect(),
        notes: String::new(),
    }
}

fn vault_with_entry() -> (UnlockedVault, String, String) {
    let (mut v, rk) = UnlockedVault::create(MASTER, FAST, "dev-1", 0).unwrap();
    v.create_entry(
        EntryInput {
            title: "GitHub".into(),
            username: "alice@example.com".into(),
            password: SECRET.into(),
            urls: vec!["https://github.com".into()],
            notes: "private note".into(),
        },
        1_700_000_000_000,
    )
    .unwrap();
    let c = v.export_container().unwrap();
    (v, c, rk.to_display().to_string())
}

fn mutate(c: &str, f: impl FnOnce(&mut Value)) -> String {
    let mut v: Value = serde_json::from_str(c).unwrap();
    f(&mut v);
    v.to_string()
}

fn flip_b64(s: &Value, idx: usize) -> Value {
    let mut b = B64.decode(s.as_str().unwrap()).unwrap();
    let i = idx % b.len();
    b[i] ^= 0x01;
    json!(B64.encode(b))
}

#[test]
fn wrong_password_rejected() {
    let (_, c, _) = vault_with_entry();
    assert_eq!(
        UnlockedVault::unlock_with_password(&c, "correct horse battery stapl", "d").unwrap_err(),
        VaultError::InvalidCredentials
    );
    assert_eq!(UnlockedVault::unlock_with_password(&c, "", "d").unwrap_err(), VaultError::InvalidCredentials);
    UnlockedVault::unlock_with_password(&c, MASTER, "d").unwrap();
}

#[test]
fn nfc_equivalent_passwords_unlock() {
    // "é" precomposed (U+00E9) vs decomposed (e + U+0301)
    let (mut v, _) = UnlockedVault::create("contrase\u{00e9}a segura", FAST, "d", 0).unwrap();
    let c = v.export_container().unwrap();
    UnlockedVault::unlock_with_password(&c, "contrase\u{0065}\u{0301}a segura", "d").unwrap();
}

#[test]
fn tampered_payload_ciphertext_rejected() {
    let (_, c, _) = vault_with_entry();
    for idx in [0usize, 7, 31, 1000] {
        let t = mutate(&c, |v| v["payload"]["ciphertext"] = flip_b64(&v["payload"]["ciphertext"], idx));
        assert_eq!(
            UnlockedVault::unlock_with_password(&t, MASTER, "d").unwrap_err(),
            VaultError::IntegrityError,
            "byte {idx}"
        );
    }
    let t = mutate(&c, |v| v["payload"]["nonce"] = flip_b64(&v["payload"]["nonce"], 3));
    assert_eq!(UnlockedVault::unlock_with_password(&t, MASTER, "d").unwrap_err(), VaultError::IntegrityError);
}

#[test]
fn tampered_header_fields_rejected() {
    let (_, c, _) = vault_with_entry();
    let cases = [
        mutate(&c, |v| v["revision"] = json!(v["revision"].as_u64().unwrap() + 1)),
        mutate(&c, |v| v["revision"] = json!(0)),
        mutate(&c, |v| v["keyringRevision"] = json!(7)),
        mutate(&c, |v| {
            // drop the recovery slot
            v["keySlots"].as_array_mut().unwrap().truncate(1);
        }),
    ];
    for t in cases {
        assert_eq!(UnlockedVault::unlock_with_password(&t, MASTER, "d").unwrap_err(), VaultError::IntegrityError);
    }
    // altering KDF parameters breaks the slot (AAD) → cannot be opened
    let t = mutate(&c, |v| v["keySlots"][0]["kdf"]["iterations"] = json!(3));
    assert_eq!(UnlockedVault::unlock_with_password(&t, MASTER, "d").unwrap_err(), VaultError::InvalidCredentials);
    let t =
        mutate(&c, |v| v["keySlots"][0]["wrap"]["ciphertext"] = flip_b64(&v["keySlots"][0]["wrap"]["ciphertext"], 5));
    assert_eq!(UnlockedVault::unlock_with_password(&t, MASTER, "d").unwrap_err(), VaultError::InvalidCredentials);
    // swapping in another vault's id
    let t = mutate(&c, |v| v["vaultId"] = json!("00000000-0000-4000-8000-000000000000"));
    assert_eq!(UnlockedVault::unlock_with_password(&t, MASTER, "d").unwrap_err(), VaultError::InvalidCredentials);
}

#[test]
fn slot_from_older_keyring_cannot_be_spliced() {
    let (mut v, c_old, _) = vault_with_entry();
    v.change_master_password(MASTER, NEW_MASTER, FAST, 0).unwrap();
    let c_new = v.export_container().unwrap();
    let old: Value = serde_json::from_str(&c_old).unwrap();
    // attacker puts the old password slot into the new container
    let t = mutate(&c_new, |n| n["keySlots"][0] = old["keySlots"][0].clone());
    assert_eq!(UnlockedVault::unlock_with_password(&t, MASTER, "d").unwrap_err(), VaultError::IntegrityError);
}

#[test]
fn kdf_params_out_of_bounds_rejected_before_derivation() {
    let (_, c, _) = vault_with_entry();
    for (field, val) in [
        ("memoryKiB", json!(1024)),
        ("memoryKiB", json!(u32::MAX)),
        ("iterations", json!(1)),
        ("iterations", json!(1000)),
        ("parallelism", json!(0)),
        ("parallelism", json!(64)),
    ] {
        let t = mutate(&c, |v| v["keySlots"][0]["kdf"][field] = val.clone());
        assert_eq!(
            UnlockedVault::unlock_with_password(&t, MASTER, "d").unwrap_err(),
            VaultError::ParamsOutOfBounds,
            "{field}={val}"
        );
    }
    let t = mutate(&c, |v| v["keySlots"][0]["kdf"]["salt"] = json!(B64.encode([0u8; 8])));
    assert_eq!(UnlockedVault::unlock_with_password(&t, MASTER, "d").unwrap_err(), VaultError::ParamsOutOfBounds);
    assert_eq!(
        UnlockedVault::create(MASTER, Argon2Params { memory_kib: 1024, iterations: 3, parallelism: 1 }, "d", 0)
            .unwrap_err(),
        VaultError::ParamsOutOfBounds
    );
}

#[test]
fn malformed_containers_rejected() {
    let (_, c, _) = vault_with_entry();
    let bad = [
        "".to_string(),
        "{}".to_string(),
        "[1,2,3]".to_string(),
        mutate(&c, |v| v["format"] = json!("other")),
        mutate(&c, |v| v["unexpected"] = json!(true)),
        mutate(&c, |v| v["payload"]["nonce"] = json!("AAAA")),
        mutate(&c, |v| v["payload"]["ciphertext"] = json!("not base64!")),
        mutate(&c, |v| v["keySlots"].as_array_mut().unwrap().reverse()),
        mutate(&c, |v| v["vaultId"] = json!("NOT-A-UUID")),
        mutate(&c, |v| v["keyringRevision"] = json!(0)),
    ];
    for t in bad {
        assert!(
            matches!(UnlockedVault::unlock_with_password(&t, MASTER, "d").unwrap_err(), VaultError::InvalidFormat(_)),
            "{t:.80}"
        );
    }
}

#[test]
fn unknown_versions_rejected() {
    let (_, c, _) = vault_with_entry();
    let t = mutate(&c, |v| {
        v["formatVersion"] = json!(2);
        v["newField"] = json!("future");
    });
    assert_eq!(UnlockedVault::unlock_with_password(&t, MASTER, "d").unwrap_err(), VaultError::UnsupportedVersion);
    let t = mutate(&c, |v| v["payload"]["algorithm"] = json!("XC20P"));
    assert_eq!(UnlockedVault::unlock_with_password(&t, MASTER, "d").unwrap_err(), VaultError::UnsupportedVersion);
}

#[test]
fn container_reveals_no_plaintext() {
    let (_, c, rk) = vault_with_entry();
    for needle in [SECRET, "alice@example.com", "github", "GitHub", "private note", MASTER, &rk] {
        assert!(!c.to_lowercase().contains(&needle.to_lowercase()), "container leaks {needle:?}");
    }
}

#[test]
fn salts_and_nonces_unique() {
    let mut seen = std::collections::HashSet::new();
    let (mut v, _) = UnlockedVault::create(MASTER, FAST, "d", 0).unwrap();
    for i in 0..50 {
        v.create_entry(inp(&format!("t{i}"), "", "", &[]), 1_000 + i).unwrap();
        let c: Value = serde_json::from_str(&v.export_container().unwrap()).unwrap();
        assert!(seen.insert(c["payload"]["nonce"].as_str().unwrap().to_owned()), "payload nonce reused");
        if i == 0 {
            for s in c["keySlots"].as_array().unwrap() {
                assert!(seen.insert(s["kdf"]["salt"].as_str().unwrap().to_owned()));
                assert!(seen.insert(s["wrap"]["nonce"].as_str().unwrap().to_owned()));
            }
        }
    }
    // two vaults from the same password have different salts and DEKs
    let (mut a, _) = UnlockedVault::create(MASTER, FAST, "d", 0).unwrap();
    let (mut b, _) = UnlockedVault::create(MASTER, FAST, "d", 0).unwrap();
    let (ca, cb): (Value, Value) = (
        serde_json::from_str(&a.export_container().unwrap()).unwrap(),
        serde_json::from_str(&b.export_container().unwrap()).unwrap(),
    );
    assert_ne!(ca["keySlots"][0]["kdf"]["salt"], cb["keySlots"][0]["kdf"]["salt"]);
    assert_ne!(*a.export_data_key(), *b.export_data_key());
}

#[test]
fn recovery_unlock_and_reset() {
    let (_, c, rk) = vault_with_entry();
    let mut v = UnlockedVault::unlock_with_recovery_key(&c, &rk, "d").unwrap();
    assert_eq!(v.list_entries().len(), 1);
    let new_rk = v.reset_master_password_with_recovery(&rk, NEW_MASTER, FAST, 0).unwrap().to_display().to_string();
    let c2 = v.export_container().unwrap();
    assert_eq!(UnlockedVault::unlock_with_password(&c2, MASTER, "d").unwrap_err(), VaultError::InvalidCredentials);
    let v2 = UnlockedVault::unlock_with_password(&c2, NEW_MASTER, "d").unwrap();
    assert_eq!(v2.get_entry(&v2.list_entries()[0].id).unwrap().password, SECRET);
    // The reset rotates the recovery key (the one just used may be compromised): only the new one opens the vault.
    assert_ne!(new_rk, rk);
    assert_eq!(UnlockedVault::unlock_with_recovery_key(&c2, &rk, "d").unwrap_err(), VaultError::InvalidCredentials);
    UnlockedVault::unlock_with_recovery_key(&c2, &new_rk, "d").unwrap();
}

#[test]
fn wrong_or_mistyped_recovery_key() {
    let (_, c, rk) = vault_with_entry();
    let (_, _, other) = vault_with_entry();
    assert_eq!(UnlockedVault::unlock_with_recovery_key(&c, &other, "d").unwrap_err(), VaultError::InvalidCredentials);
    let typo = rk.replacen(&rk[0..1], if &rk[0..1] == "A" { "B" } else { "A" }, 1);
    assert_eq!(UnlockedVault::unlock_with_recovery_key(&c, &typo, "d").unwrap_err(), VaultError::InvalidRecoveryKey);
}

#[test]
fn rotate_recovery_invalidates_old() {
    let (mut v, _, old_rk) = vault_with_entry();
    assert_eq!(v.rotate_recovery_key("wrong password!").unwrap_err(), VaultError::InvalidCredentials);
    let new_rk = v.rotate_recovery_key(MASTER).unwrap().to_display().to_string();
    let c = v.export_container().unwrap();
    assert_eq!(UnlockedVault::unlock_with_recovery_key(&c, &old_rk, "d").unwrap_err(), VaultError::InvalidCredentials);
    UnlockedVault::unlock_with_recovery_key(&c, &new_rk, "d").unwrap();
}

#[test]
fn change_password_requires_current() {
    let (mut v, _, _) = vault_with_entry();
    assert_eq!(
        v.change_master_password("not the password", NEW_MASTER, FAST, 0).unwrap_err(),
        VaultError::InvalidCredentials
    );
    assert_eq!(
        v.change_master_password(MASTER, "short", FAST, 0).unwrap_err(),
        VaultError::Validation("masterPassword")
    );
}

#[test]
fn data_key_reopen_and_wrong_key() {
    let (v, c, _) = vault_with_entry();
    let dek = v.export_data_key();
    UnlockedVault::open_with_data_key(&c, &dek, "d").unwrap();
    assert_eq!(UnlockedVault::open_with_data_key(&c, &[7u8; 32], "d").unwrap_err(), VaultError::InvalidCredentials);
    assert_eq!(UnlockedVault::open_with_data_key(&c, &[7u8; 31], "d").unwrap_err(), VaultError::InvalidCredentials);
}

#[test]
fn errors_do_not_leak_secrets() {
    let (mut v, c, _) = vault_with_entry();
    let mut msgs = vec![
        UnlockedVault::unlock_with_password(&c, SECRET, "d").unwrap_err().to_string(),
        v.update_entry("nope", inp(SECRET, "", "", &[]), 1).unwrap_err().to_string(),
        v.create_entry(inp("", "", SECRET, &[]), 1).unwrap_err().to_string(),
        v.create_entry(inp("x", "", "", &[&format!("javascript:{SECRET}")]), 1).unwrap_err().to_string(),
    ];
    msgs.push(format!("{v:?}"));
    for m in msgs {
        assert!(!m.contains(SECRET) && !m.contains(MASTER) && !m.contains("alice"), "leak in {m}");
    }
}

#[test]
fn weak_master_password_rejected() {
    assert_eq!(UnlockedVault::create("short", FAST, "d", 0).unwrap_err(), VaultError::Validation("masterPassword"));
    assert_eq!(
        UnlockedVault::create("correct horse", FAST, "bad device id!", 0).unwrap_err(),
        VaultError::Validation("deviceId")
    );
}

// ---------- security review fixes (docs/SECURITY_REVIEW.md) ----------

#[test]
fn debug_output_never_contains_secrets() {
    let (v, _, _) = vault_with_entry();
    let e = v.get_entry(&v.list_entries()[0].id).unwrap();
    let dumps = [format!("{e:?}"), format!("{:?}", v.payload()), format!("{:?}", inp("t", "alice", SECRET, &[]))];
    for d in dumps {
        assert!(!d.contains(SECRET) && !d.contains("alice") && !d.contains("private note"), "leak in {d}");
    }
}

#[test]
fn deleting_an_entry_drops_its_password_history() {
    let (mut v, _, _) = vault_with_entry();
    let id = v.list_entries()[0].id.clone();
    v.update_entry(&id, inp("GitHub", "alice@example.com", "rotated-password-1", &[]), 2).unwrap();
    v.delete_entry(&id, 3).unwrap();
    let c = v.export_container().unwrap();
    let back = UnlockedVault::unlock_with_password(&c, MASTER, "d").unwrap();
    let rec = &back.payload().records[0];
    assert!(rec.password_history.is_empty() && !rec.is_live());
}

#[test]
fn counters_beyond_two_pow_53_rejected() {
    let (_, c, _) = vault_with_entry();
    let t = mutate(&c, |v| v["revision"] = json!(1u64 << 53));
    assert_eq!(
        UnlockedVault::unlock_with_password(&t, MASTER, "d").unwrap_err(),
        VaultError::InvalidFormat("revision")
    );
    let mut rec = keyvora_vault::Record {
        id: "00000000-0000-4000-8000-000000000000".into(),
        created_at: "2026-01-01T00:00:00.000Z".into(),
        context: [("d".to_string(), keyvora_vault::model::MAX_COUNTER)].into_iter().collect(),
        versions: Vec::new(),
        password_history: Vec::new(),
        history_floor: Default::default(),
    };
    assert_eq!(rec.next_dot("d").unwrap_err(), VaultError::Validation("counter limit reached"));
}

#[test]
fn writer_never_emits_an_unreadable_container() {
    // 257 different devices edit the same entry: the 257th write fails visibly, and every container written before
    // remains readable (the writer enforces the reader's limits instead of bricking the vault).
    let (mut v, mut c, _) = vault_with_entry();
    let id = v.list_entries()[0].id.clone();
    let dek = v.export_data_key();
    let mut failed_at = None;
    for i in 1..=keyvora_vault::model::MAX_CLOCK_DEVICES + 1 {
        let mut dev = UnlockedVault::open_with_data_key(&c, &dek, &format!("device-{i}")).unwrap();
        match dev.update_entry(&id, inp("GitHub", "alice@example.com", &format!("pw-{i}"), &[]), 10 + i as i64) {
            Ok(_) => c = dev.export_container().unwrap(),
            Err(e) => {
                assert_eq!(e, VaultError::Validation("too many devices for this entry"));
                failed_at = Some(i);
                break;
            }
        }
    }
    assert_eq!(failed_at, Some(keyvora_vault::model::MAX_CLOCK_DEVICES));
    UnlockedVault::unlock_with_password(&c, MASTER, "d").unwrap();
    let _ = &mut v;
}

#[test]
fn hostile_kdf_bounds_are_tighter() {
    let (_, c, _) = vault_with_entry();
    for (field, val) in [("memoryKiB", json!(512 * 1024)), ("iterations", json!(11))] {
        let t = mutate(&c, |v| v["keySlots"][0]["kdf"][field] = val.clone());
        assert_eq!(UnlockedVault::unlock_with_password(&t, MASTER, "d").unwrap_err(), VaultError::ParamsOutOfBounds);
    }
}

#[test]
fn huge_unknown_fields_are_rejected_cheaply() {
    let big = format!("{{\"format\":\"keyvora.vault\",\"formatVersion\":1,\"x\":[{}0]}}", "0,".repeat(2_000_000));
    assert!(matches!(
        UnlockedVault::unlock_with_password(&big, MASTER, "d").unwrap_err(),
        VaultError::InvalidFormat(_)
    ));
}

#[test]
fn rotate_data_key_cuts_off_old_secrets() {
    let (mut v, old_container, old_rk) = vault_with_entry();
    let old_dek = v.export_data_key();
    assert_eq!(v.rotate_data_key("wrong master password").unwrap_err(), VaultError::InvalidCredentials);
    let new_rk = v.rotate_data_key(MASTER).unwrap().to_display().to_string();
    let c = v.export_container().unwrap();
    // old DEK, old recovery key and an old password slot no longer open new containers
    assert_eq!(UnlockedVault::open_with_data_key(&c, &old_dek, "d").unwrap_err(), VaultError::InvalidCredentials);
    assert_eq!(UnlockedVault::unlock_with_recovery_key(&c, &old_rk, "d").unwrap_err(), VaultError::InvalidCredentials);
    let old: Value = serde_json::from_str(&old_container).unwrap();
    let spliced = mutate(&c, |n| n["keySlots"][0] = old["keySlots"][0].clone());
    assert_eq!(UnlockedVault::unlock_with_password(&spliced, MASTER, "d").unwrap_err(), VaultError::IntegrityError);
    // the owner keeps access with the same password and the new recovery key; data intact
    let a = UnlockedVault::unlock_with_password(&c, MASTER, "d").unwrap();
    assert_eq!(a.get_entry(&a.list_entries()[0].id).unwrap().password, SECRET);
    UnlockedVault::unlock_with_recovery_key(&c, &new_rk, "d").unwrap();
}

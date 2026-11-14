//! Checks the committed cross-platform vectors (packages/shared-models/test-vectors/vault-v1.json).
//! The same file is consumed by the WASM (TypeScript), Kotlin and Python (independent implementation) tests.

use keyvora_crypto::{derive_recovery_key, derive_wrapping_key, encrypt_with_nonce_for_tests, Argon2Params, SecretKey};
use keyvora_vault::{origin, UnlockedVault};
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn load() -> Option<Value> {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../shared-models/test-vectors/vault-v1.json");
    std::fs::read_to_string(p).ok().map(|s| serde_json::from_str(&s).unwrap())
}

#[test]
fn committed_vectors_hold() {
    let Some(v) = load() else {
        eprintln!("SKIP: vault-v1.json not generated yet (scripts/wsl/test-core.sh generates it)");
        return;
    };
    let a = &v["argon2id"];
    let p = Argon2Params { memory_kib: a["memoryKiB"].as_u64().unwrap() as u32, iterations: a["iterations"].as_u64().unwrap() as u32, parallelism: a["parallelism"].as_u64().unwrap() as u32 };
    let k = derive_wrapping_key(a["passwordUtf8"].as_str().unwrap().as_bytes(), &unhex(a["saltHex"].as_str().unwrap()), &p).unwrap();
    assert_eq!(hex(k.expose()), a["expectedKeyHex"].as_str().unwrap());

    let h = &v["hkdfRecovery"];
    let k = derive_recovery_key(&unhex(h["ikmHex"].as_str().unwrap()), &unhex(h["saltHex"].as_str().unwrap()), h["info"].as_str().unwrap().as_bytes()).unwrap();
    assert_eq!(hex(k.expose()), h["expectedKeyHex"].as_str().unwrap());

    let g = &v["aes256gcm"];
    let key = SecretKey::from_slice(&unhex(g["keyHex"].as_str().unwrap())).unwrap();
    let nonce: [u8; 12] = unhex(g["nonceHex"].as_str().unwrap()).try_into().unwrap();
    let ct = encrypt_with_nonce_for_tests(&key, &nonce, &unhex(g["aadHex"].as_str().unwrap()), &unhex(g["plaintextHex"].as_str().unwrap())).unwrap();
    assert_eq!(hex(&ct), g["expectedCiphertextHex"].as_str().unwrap());

    let vault = &v["vault"];
    let c = vault["container"].as_str().unwrap();
    let expected = vault["expectedEntries"].as_array().unwrap();
    for unlocked in [
        UnlockedVault::unlock_with_password(c, vault["masterPassword"].as_str().unwrap(), "t").unwrap(),
        UnlockedVault::unlock_with_password(c, vault["masterPasswordNfdVariant"].as_str().unwrap(), "t").unwrap(),
        UnlockedVault::unlock_with_recovery_key(c, vault["recoveryKey"].as_str().unwrap(), "t").unwrap(),
    ] {
        let mut got: Vec<Value> = unlocked
            .list_entries()
            .iter()
            .map(|s| {
                let e = unlocked.get_entry(&s.id).unwrap();
                serde_json::json!({"title": e.title, "username": e.username, "password": e.password, "urls": e.urls, "notes": e.notes})
            })
            .collect();
        let mut exp = expected.clone();
        got.sort_by_key(|x| x["title"].to_string());
        exp.sort_by_key(|x| x["title"].to_string());
        assert_eq!(got, exp);
    }

    for m in v["originMatching"].as_array().unwrap() {
        assert_eq!(origin::match_level(m["entryUrl"].as_str().unwrap(), m["pageUrl"].as_str().unwrap()).as_str(), m["expected"].as_str().unwrap(), "{m}");
    }
}

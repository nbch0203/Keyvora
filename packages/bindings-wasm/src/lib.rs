//! WebAssembly API for the browser extension (docs/CONTRACTS.md §2).
//!
//! Errors are thrown as `Error` whose `message` is exactly one stable code (`INVALID_CREDENTIALS`, `LOCKED`, …).
//! Values cross the boundary as plain JSON-compatible objects (camelCase).
#![forbid(unsafe_code)]

use keyvora_passgen::GeneratorOptions;
use keyvora_vault::{Argon2Params, ConflictChoice, EntryInput, UnlockedVault, VaultError};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

fn js_err(e: VaultError) -> JsError {
    JsError::new(e.code())
}

fn to_js<T: Serialize>(v: &T) -> Result<JsValue, JsError> {
    v.serialize(&serde_wasm_bindgen::Serializer::json_compatible()).map_err(|_| JsError::new("INVALID_FORMAT"))
}

fn from_js<T: for<'de> Deserialize<'de>>(v: JsValue) -> Result<T, JsError> {
    serde_wasm_bindgen::from_value(v).map_err(|_| JsError::new("VALIDATION"))
}

/// KDF parameters as seen from JS: `{ memoryKiB, iterations, parallelism }`.
#[derive(Serialize, Deserialize)]
struct KdfParams {
    #[serde(rename = "memoryKiB")]
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl From<KdfParams> for Argon2Params {
    fn from(p: KdfParams) -> Self {
        Argon2Params { memory_kib: p.memory_kib, iterations: p.iterations, parallelism: p.parallelism }
    }
}

/// An unlocked vault handle. After `lock()` every method throws `LOCKED`.
#[wasm_bindgen]
pub struct WasmVault {
    inner: Option<UnlockedVault>,
    recovery_key: Option<zeroize::Zeroizing<String>>,
}

impl WasmVault {
    fn v(&self) -> Result<&UnlockedVault, JsError> {
        self.inner.as_ref().ok_or_else(|| js_err(VaultError::Locked))
    }
    fn vm(&mut self) -> Result<&mut UnlockedVault, JsError> {
        self.inner.as_mut().ok_or_else(|| js_err(VaultError::Locked))
    }
    fn wrap(v: UnlockedVault) -> WasmVault {
        WasmVault { inner: Some(v), recovery_key: None }
    }
}

#[wasm_bindgen]
impl WasmVault {
    /// Creates a new vault. Read the recovery key once with `takeRecoveryKey()`.
    pub fn create(master: &str, params: JsValue, device_id: &str, now_ms: f64) -> Result<WasmVault, JsError> {
        let p: KdfParams = from_js(params)?;
        let (v, rk) = UnlockedVault::create(master, p.into(), device_id, now_ms as i64).map_err(js_err)?;
        Ok(WasmVault { inner: Some(v), recovery_key: Some(rk.to_display()) })
    }

    /// Returns the recovery key created by `create`/`rotateRecoveryKey` exactly once (then `undefined`).
    #[wasm_bindgen(js_name = takeRecoveryKey)]
    pub fn take_recovery_key(&mut self) -> Option<String> {
        self.recovery_key.take().map(|z| z.to_string())
    }

    /// Unlocks with the master password.
    #[wasm_bindgen(js_name = unlockWithPassword)]
    pub fn unlock_with_password(container: &str, master: &str, device_id: &str) -> Result<WasmVault, JsError> {
        UnlockedVault::unlock_with_password(container, master, device_id).map(Self::wrap).map_err(js_err)
    }

    /// Unlocks with the recovery key.
    #[wasm_bindgen(js_name = unlockWithRecoveryKey)]
    pub fn unlock_with_recovery_key(
        container: &str,
        recovery_key: &str,
        device_id: &str,
    ) -> Result<WasmVault, JsError> {
        UnlockedVault::unlock_with_recovery_key(container, recovery_key, device_id).map(Self::wrap).map_err(js_err)
    }

    /// Re-opens with a DEK kept in `chrome.storage.session`.
    #[wasm_bindgen(js_name = openWithDataKey)]
    pub fn open_with_data_key(container: &str, dek: &[u8], device_id: &str) -> Result<WasmVault, JsError> {
        UnlockedVault::open_with_data_key(container, dek, device_id).map(Self::wrap).map_err(js_err)
    }

    /// Encrypted container to persist / upload.
    #[wasm_bindgen(js_name = exportContainer)]
    pub fn export_container(&mut self) -> Result<String, JsError> {
        self.vm()?.export_container().map_err(js_err)
    }

    /// Vault id.
    #[wasm_bindgen(js_name = vaultId)]
    pub fn vault_id(&self) -> Result<String, JsError> {
        Ok(self.v()?.vault_id())
    }

    /// Current revision.
    pub fn revision(&self) -> Result<f64, JsError> {
        Ok(self.v()?.revision() as f64)
    }

    /// Unexported changes pending.
    #[wasm_bindgen(js_name = isDirty)]
    pub fn is_dirty(&self) -> Result<bool, JsError> {
        Ok(self.v()?.is_dirty())
    }

    /// Whether the handle has been locked.
    #[wasm_bindgen(js_name = isLocked)]
    pub fn is_locked(&self) -> bool {
        self.inner.is_none()
    }

    /// `EntrySummary[]` (no passwords).
    #[wasm_bindgen(js_name = listEntries)]
    pub fn list_entries(&self) -> Result<JsValue, JsError> {
        to_js(&self.v()?.list_entries())
    }

    /// UI search.
    pub fn search(&self, query: &str) -> Result<JsValue, JsError> {
        to_js(&self.v()?.search(query))
    }

    /// Full `Entry`.
    #[wasm_bindgen(js_name = getEntry)]
    pub fn get_entry(&self, id: &str) -> Result<JsValue, JsError> {
        to_js(&self.v()?.get_entry(id).map_err(js_err)?)
    }

    /// Creates an entry from `EntryInput`.
    #[wasm_bindgen(js_name = createEntry)]
    pub fn create_entry(&mut self, input: JsValue, now_ms: f64) -> Result<JsValue, JsError> {
        let input: EntryInput = from_js(input)?;
        to_js(&self.vm()?.create_entry(input, now_ms as i64).map_err(js_err)?)
    }

    /// Updates an entry.
    #[wasm_bindgen(js_name = updateEntry)]
    pub fn update_entry(&mut self, id: &str, input: JsValue, now_ms: f64) -> Result<JsValue, JsError> {
        let input: EntryInput = from_js(input)?;
        to_js(&self.vm()?.update_entry(id, input, now_ms as i64).map_err(js_err)?)
    }

    /// Deletes an entry.
    #[wasm_bindgen(js_name = deleteEntry)]
    pub fn delete_entry(&mut self, id: &str, now_ms: f64) -> Result<(), JsError> {
        self.vm()?.delete_entry(id, now_ms as i64).map_err(js_err)
    }

    /// Resolves conflicts: `choice = -1` keeps the current version, `n ≥ 0` takes conflict `n`.
    #[wasm_bindgen(js_name = resolveConflict)]
    pub fn resolve_conflict(&mut self, id: &str, choice: i32, now_ms: f64) -> Result<(), JsError> {
        let c = if choice < 0 { ConflictChoice::KeepCurrent } else { ConflictChoice::TakeConflict(choice as usize) };
        self.vm()?.resolve_conflict(id, c, now_ms as i64).map_err(js_err)
    }

    /// `CredentialMatch[]` for a page URL (best first).
    #[wasm_bindgen(js_name = findMatches)]
    pub fn find_matches(&self, page_url: &str) -> Result<JsValue, JsError> {
        to_js(&self.v()?.find_matches(page_url))
    }

    /// Changes the master password. Also rotates the data key and issues a **new recovery key** (the old one stops
    /// working): read it with `takeRecoveryKey()` and show it once.
    #[wasm_bindgen(js_name = changeMasterPassword)]
    pub fn change_master_password(
        &mut self,
        current: &str,
        next: &str,
        params: JsValue,
        now_ms: f64,
    ) -> Result<(), JsError> {
        let p: KdfParams = from_js(params)?;
        let rk = self.vm()?.change_master_password(current, next, p.into(), now_ms as i64).map_err(js_err)?;
        self.recovery_key = Some(rk.to_display());
        Ok(())
    }

    /// Resets the master password with the recovery key. Rotates the data key and issues a **new recovery key**
    /// (the one just used stops working): read it with `takeRecoveryKey()` and show it once.
    #[wasm_bindgen(js_name = resetMasterPasswordWithRecovery)]
    pub fn reset_master_password_with_recovery(
        &mut self,
        recovery_key: &str,
        next: &str,
        params: JsValue,
        now_ms: f64,
    ) -> Result<(), JsError> {
        let p: KdfParams = from_js(params)?;
        let rk = self
            .vm()?
            .reset_master_password_with_recovery(recovery_key, next, p.into(), now_ms as i64)
            .map_err(js_err)?;
        self.recovery_key = Some(rk.to_display());
        Ok(())
    }

    /// Rotates the recovery key; read the new one with `takeRecoveryKey()`.
    #[wasm_bindgen(js_name = rotateRecoveryKey)]
    pub fn rotate_recovery_key(&mut self, current: &str) -> Result<(), JsError> {
        let rk = self.vm()?.rotate_recovery_key(current).map_err(js_err)?;
        self.recovery_key = Some(rk.to_display());
        Ok(())
    }

    /// Rotates the data-encryption key; a new recovery key is issued (read it with `takeRecoveryKey()`).
    #[wasm_bindgen(js_name = rotateDataKey)]
    pub fn rotate_data_key(&mut self, current: &str) -> Result<(), JsError> {
        let rk = self.vm()?.rotate_data_key(current).map_err(js_err)?;
        self.recovery_key = Some(rk.to_display());
        Ok(())
    }

    /// KDF parameters of the master-password slot `{ memoryKiB, iterations, parallelism }`.
    #[wasm_bindgen(js_name = passwordKdfParams)]
    pub fn password_kdf_params(&self) -> Result<JsValue, JsError> {
        let p = self.v()?.password_kdf_params();
        to_js(&KdfParams { memory_kib: p.memory_kib, iterations: p.iterations, parallelism: p.parallelism })
    }

    /// Re-authenticates with the master password valid for `remoteContainer` (after `KEYRING_CHANGED`) and adopts
    /// its keys, merging local data. Returns a `MergeReport`.
    #[wasm_bindgen(js_name = adoptRemoteKeys)]
    pub fn adopt_remote_keys(&mut self, remote_container: &str, master: &str) -> Result<JsValue, JsError> {
        let report = keyvora_sync::adopt_remote_keys(self.vm()?, remote_container, master).map_err(js_err)?;
        to_js(&report)
    }

    /// Merges a remote container; returns a `MergeReport` (throws `KEYRING_CHANGED` when remote keys are newer).
    #[wasm_bindgen(js_name = mergeRemote)]
    pub fn merge_remote(&mut self, remote_container: &str) -> Result<JsValue, JsError> {
        let report = keyvora_sync::merge_remote(self.vm()?, remote_container).map_err(js_err)?;
        to_js(&report)
    }

    /// Restores entries from an older container of this vault as new entries.
    #[wasm_bindgen(js_name = restoreEntriesFrom)]
    pub fn restore_entries_from(&mut self, container: &str, ids: Vec<String>, now_ms: f64) -> Result<JsValue, JsError> {
        to_js(&self.vm()?.restore_entries_from(container, &ids, now_ms as i64).map_err(js_err)?)
    }

    /// Decrypts another container of this vault and lists its entries (for restore UIs).
    #[wasm_bindgen(js_name = previewContainer)]
    pub fn preview_container(&self, container: &str) -> Result<JsValue, JsError> {
        let f = self.v()?.decrypt_foreign(container).map_err(js_err)?;
        let list: Vec<keyvora_vault::EntrySummary> =
            f.payload.records.iter().filter_map(keyvora_vault::Record::to_summary).collect();
        to_js(&list)
    }

    /// DEK bytes for `chrome.storage.session`. Never persist to disk or sync.
    #[wasm_bindgen(js_name = exportDataKey)]
    pub fn export_data_key(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.v()?.export_data_key().to_vec())
    }

    /// Locks: wipes the DEK and plaintext held in WASM memory.
    pub fn lock(&mut self) {
        self.inner = None;
        self.recovery_key = None;
    }
}

/// Generates a password (`GeneratorOptions`, all fields optional).
#[wasm_bindgen(js_name = generatePassword)]
pub fn generate_password(options: JsValue) -> Result<String, JsError> {
    let o: GeneratorOptions =
        if options.is_undefined() || options.is_null() { GeneratorOptions::default() } else { from_js(options)? };
    keyvora_passgen::generate_password(&o).map_err(|_| JsError::new("VALIDATION"))
}

/// Approximate entropy of the options in bits.
#[wasm_bindgen(js_name = passwordEntropyBits)]
pub fn password_entropy_bits(options: JsValue) -> Result<f64, JsError> {
    let o: GeneratorOptions =
        if options.is_undefined() || options.is_null() { GeneratorOptions::default() } else { from_js(options)? };
    keyvora_passgen::entropy_bits(&o).map_err(|_| JsError::new("VALIDATION"))
}

/// `"exact" | "sameSite" | "none"`.
#[wasm_bindgen(js_name = matchLevel)]
pub fn match_level(entry_url: &str, page_url: &str) -> String {
    keyvora_vault::origin::match_level(entry_url, page_url).as_str().to_owned()
}

/// Normalized `scheme://host[:port]` of a fillable page URL, or `undefined`.
#[wasm_bindgen(js_name = pageOrigin)]
pub fn page_origin(page_url: &str) -> Option<String> {
    keyvora_vault::origin::parse_page_url(page_url).map(|o| o.serialize())
}

/// Default KDF parameters `{ memoryKiB, iterations, parallelism }`.
#[wasm_bindgen(js_name = defaultKdfParams)]
pub fn default_kdf_params() -> Result<JsValue, JsError> {
    let d = Argon2Params::DEFAULT;
    to_js(&KdfParams { memory_kib: d.memory_kib, iterations: d.iterations, parallelism: d.parallelism })
}

/// Runs one Argon2id derivation (for calibration); returns nothing, time it from JS.
#[wasm_bindgen(js_name = benchmarkKdf)]
pub fn benchmark_kdf(params: JsValue) -> Result<(), JsError> {
    let p: KdfParams = from_js(params)?;
    keyvora_crypto::derive_wrapping_key(b"benchmark-password", &[0u8; 32], &p.into())
        .map(|_| ())
        .map_err(|_| JsError::new("PARAMS_OUT_OF_BOUNDS"))
}

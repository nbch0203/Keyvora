//! Outer container (plaintext header + encrypted payload). See docs/VAULT_FORMAT.md §2–3.

use crate::error::{Result, VaultError};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use keyvora_crypto::{sha256, Argon2Params, Sealed, KEY_LEN, NONCE_LEN, TAG_LEN};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Value of the `format` field.
pub const FORMAT_NAME: &str = "keyvora.vault";
/// Supported container format version.
pub const FORMAT_VERSION: u32 = 1;
/// Maximum accepted container size.
pub const MAX_CONTAINER_BYTES: usize = 64 * 1024 * 1024;
/// HKDF info for the recovery slot.
pub const RECOVERY_INFO: &[u8] = b"keyvora.vault.v1.recovery-kek";
const AEAD_NAME: &str = "A256GCM";
const SLOT_AAD_PREFIX: &[u8] = b"keyvora.vault.v1.slot";
const PAYLOAD_AAD_PREFIX: &[u8] = b"keyvora.vault.v1.payload";

// ---------- JSON wire structs ----------

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContainerJson {
    format: String,
    format_version: u32,
    vault_id: String,
    revision: u64,
    keyring_revision: u64,
    key_slots: Vec<SlotJson>,
    payload: SealedJson,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SlotJson {
    slot_id: String,
    kdf: KdfJson,
    wrap: SealedJson,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfJson {
    algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<u32>,
    salt: String,
    #[serde(rename = "memoryKiB", skip_serializing_if = "Option::is_none")]
    memory_kib: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iterations: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parallelism: Option<u32>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedJson {
    algorithm: String,
    nonce: String,
    ciphertext: String,
}

// ---------- parsed model ----------

/// Kind of key slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    /// Unlocked by the master password (Argon2id).
    Password,
    /// Unlocked by the recovery key (HKDF-SHA256).
    Recovery,
}

impl SlotKind {
    fn id(&self) -> &'static str {
        match self {
            SlotKind::Password => "password",
            SlotKind::Recovery => "recovery",
        }
    }
}

/// Key derivation used by a slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfSpec {
    /// Argon2id v1.3.
    Argon2id {
        /// Random salt.
        salt: Vec<u8>,
        /// Cost parameters.
        params: Argon2Params,
    },
    /// HKDF-SHA256 with [`RECOVERY_INFO`].
    HkdfSha256 {
        /// Random salt.
        salt: Vec<u8>,
    },
}

impl KdfSpec {
    /// Canonical ASCII form bound into the AAD.
    pub fn canonical(&self) -> String {
        match self {
            KdfSpec::Argon2id { salt, params } => format!(
                "argon2id$v=19$m={}$t={}$p={}$salt={}",
                params.memory_kib,
                params.iterations,
                params.parallelism,
                B64.encode(salt)
            ),
            KdfSpec::HkdfSha256 { salt } => format!("hkdf-sha256$salt={}", B64.encode(salt)),
        }
    }
}

/// A key slot: a KDF description plus the wrapped DEK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySlot {
    /// Slot kind.
    pub kind: SlotKind,
    /// KDF.
    pub kdf: KdfSpec,
    /// DEK wrapped with the slot's KEK.
    pub wrap: Sealed,
}

/// A parsed, structurally validated container (payload still encrypted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    /// Vault id.
    pub vault_id: Uuid,
    /// Write revision.
    pub revision: u64,
    /// Key-slot revision.
    pub keyring_revision: u64,
    /// Key slots (password first, optional recovery second).
    pub slots: Vec<KeySlot>,
    /// Encrypted payload.
    pub payload: Sealed,
}

fn b64(s: &str, what: &'static str) -> Result<Vec<u8>> {
    B64.decode(s).map_err(|_| VaultError::InvalidFormat(what))
}

fn sealed_from_json(j: &SealedJson, exact_len: Option<usize>) -> Result<Sealed> {
    if j.algorithm != AEAD_NAME {
        return Err(VaultError::UnsupportedVersion);
    }
    let nonce = b64(&j.nonce, "nonce")?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| VaultError::InvalidFormat("nonce length"))?;
    let ciphertext = b64(&j.ciphertext, "ciphertext")?;
    match exact_len {
        Some(n) if ciphertext.len() != n => return Err(VaultError::InvalidFormat("wrapped key length")),
        _ if ciphertext.len() < TAG_LEN => return Err(VaultError::InvalidFormat("ciphertext length")),
        _ => {}
    }
    Ok(Sealed { nonce, ciphertext })
}

fn sealed_to_json(s: &Sealed) -> SealedJson {
    SealedJson { algorithm: AEAD_NAME.into(), nonce: B64.encode(s.nonce), ciphertext: B64.encode(&s.ciphertext) }
}

fn kdf_from_json(j: &KdfJson, kind: SlotKind) -> Result<KdfSpec> {
    let salt = b64(&j.salt, "salt")?;
    if !(keyvora_crypto::MIN_SALT_LEN..=keyvora_crypto::MAX_SALT_LEN).contains(&salt.len()) {
        return Err(VaultError::ParamsOutOfBounds);
    }
    match (kind, j.algorithm.as_str()) {
        (SlotKind::Password, "argon2id") => {
            if j.version != Some(19) {
                return Err(VaultError::UnsupportedVersion);
            }
            let params = Argon2Params {
                memory_kib: j.memory_kib.ok_or(VaultError::InvalidFormat("memoryKiB"))?,
                iterations: j.iterations.ok_or(VaultError::InvalidFormat("iterations"))?,
                parallelism: j.parallelism.ok_or(VaultError::InvalidFormat("parallelism"))?,
            };
            params.validate().map_err(|_| VaultError::ParamsOutOfBounds)?;
            Ok(KdfSpec::Argon2id { salt, params })
        }
        (SlotKind::Recovery, "hkdf-sha256") => {
            if j.version.is_some() || j.memory_kib.is_some() || j.iterations.is_some() || j.parallelism.is_some() {
                return Err(VaultError::InvalidFormat("hkdf fields"));
            }
            Ok(KdfSpec::HkdfSha256 { salt })
        }
        _ => Err(VaultError::UnsupportedVersion),
    }
}

fn kdf_to_json(k: &KdfSpec) -> KdfJson {
    match k {
        KdfSpec::Argon2id { salt, params } => KdfJson {
            algorithm: "argon2id".into(),
            version: Some(19),
            salt: B64.encode(salt),
            memory_kib: Some(params.memory_kib),
            iterations: Some(params.iterations),
            parallelism: Some(params.parallelism),
        },
        KdfSpec::HkdfSha256 { salt } => {
            KdfJson { algorithm: "hkdf-sha256".into(), version: None, salt: B64.encode(salt), memory_kib: None, iterations: None, parallelism: None }
        }
    }
}

impl Container {
    /// Parses and validates a container. Never decrypts.
    pub fn parse(json: &str) -> Result<Container> {
        if json.len() > MAX_CONTAINER_BYTES {
            return Err(VaultError::InvalidFormat("container too large"));
        }
        // Version gate first so that a future version with new fields reports UNSUPPORTED_VERSION.
        let probe: serde_json::Value = serde_json::from_str(json).map_err(|_| VaultError::InvalidFormat("json"))?;
        if probe.get("format").and_then(|v| v.as_str()) != Some(FORMAT_NAME) {
            return Err(VaultError::InvalidFormat("format"));
        }
        match probe.get("formatVersion").and_then(|v| v.as_u64()) {
            Some(v) if v == FORMAT_VERSION as u64 => {}
            Some(_) => return Err(VaultError::UnsupportedVersion),
            None => return Err(VaultError::InvalidFormat("formatVersion")),
        }
        let j: ContainerJson = serde_json::from_value(probe).map_err(|_| VaultError::InvalidFormat("container fields"))?;
        let vault_id = Uuid::parse_str(&j.vault_id).map_err(|_| VaultError::InvalidFormat("vaultId"))?;
        if vault_id.hyphenated().to_string() != j.vault_id {
            return Err(VaultError::InvalidFormat("vaultId"));
        }
        if j.keyring_revision == 0 {
            return Err(VaultError::InvalidFormat("keyringRevision"));
        }
        if j.key_slots.is_empty() || j.key_slots.len() > 2 {
            return Err(VaultError::InvalidFormat("keySlots"));
        }
        let mut slots = Vec::with_capacity(j.key_slots.len());
        for (i, s) in j.key_slots.iter().enumerate() {
            let kind = match (i, s.slot_id.as_str()) {
                (0, "password") => SlotKind::Password,
                (1, "recovery") => SlotKind::Recovery,
                _ => return Err(VaultError::InvalidFormat("keySlots order")),
            };
            slots.push(KeySlot { kind, kdf: kdf_from_json(&s.kdf, kind)?, wrap: sealed_from_json(&s.wrap, Some(KEY_LEN + TAG_LEN))? });
        }
        let payload = sealed_from_json(&j.payload, None)?;
        Ok(Container { vault_id, revision: j.revision, keyring_revision: j.keyring_revision, slots, payload })
    }

    /// Serializes to the canonical JSON wire format.
    pub fn to_json(&self) -> String {
        let j = ContainerJson {
            format: FORMAT_NAME.into(),
            format_version: FORMAT_VERSION,
            vault_id: self.vault_id.hyphenated().to_string(),
            revision: self.revision,
            keyring_revision: self.keyring_revision,
            key_slots: self
                .slots
                .iter()
                .map(|s| SlotJson { slot_id: s.kind.id().into(), kdf: kdf_to_json(&s.kdf), wrap: sealed_to_json(&s.wrap) })
                .collect(),
            payload: sealed_to_json(&self.payload),
        };
        serde_json::to_string(&j).expect("container serialization cannot fail")
    }

    /// The password slot.
    pub fn password_slot(&self) -> &KeySlot {
        &self.slots[0]
    }

    /// The recovery slot, if any.
    pub fn recovery_slot(&self) -> Option<&KeySlot> {
        self.slots.get(1)
    }
}

/// `AAD_slot` (VAULT_FORMAT §3.4).
pub fn slot_aad(vault_id: &Uuid, kind: SlotKind, kdf: &KdfSpec) -> Vec<u8> {
    let mut aad = Vec::with_capacity(128);
    aad.extend_from_slice(SLOT_AAD_PREFIX);
    aad.push(0);
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(kind.id().as_bytes());
    aad.push(0);
    aad.extend_from_slice(kdf.canonical().as_bytes());
    aad
}

/// `AAD_payload` (VAULT_FORMAT §3.5).
pub fn payload_aad(vault_id: &Uuid, revision: u64, keyring_revision: u64, slots: &[KeySlot]) -> Vec<u8> {
    let mut digest_input = Vec::new();
    for s in slots {
        digest_input.extend_from_slice(s.kind.id().as_bytes());
        digest_input.push(0);
        digest_input.extend_from_slice(s.kdf.canonical().as_bytes());
        digest_input.push(0);
        digest_input.extend_from_slice(B64.encode(s.wrap.nonce).as_bytes());
        digest_input.push(0);
        digest_input.extend_from_slice(B64.encode(&s.wrap.ciphertext).as_bytes());
        digest_input.push(0);
    }
    let mut aad = Vec::with_capacity(96);
    aad.extend_from_slice(PAYLOAD_AAD_PREFIX);
    aad.push(0);
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(&revision.to_be_bytes());
    aad.extend_from_slice(&keyring_revision.to_be_bytes());
    aad.extend_from_slice(&sha256(&digest_input));
    aad
}

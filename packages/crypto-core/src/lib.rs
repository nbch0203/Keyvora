//! Keyvora cryptographic primitives.
//!
//! Thin, misuse-resistant wrappers over audited RustCrypto implementations. **No custom cryptography**:
//! - Argon2id (RFC 9106, v1.3) for password-based key derivation (`argon2` crate),
//! - HKDF-SHA256 (RFC 5869) for deriving a wrapping key from a high-entropy recovery secret (`hkdf` crate),
//! - AES-256-GCM (NIST SP 800-38D) with random 96-bit nonces for authenticated encryption (`aes-gcm` crate),
//! - the operating-system CSPRNG for every key, salt and nonce (`getrandom` crate).
//!
//! Secrets are held in [`SecretKey`] which zeroizes its memory on drop and never prints its content.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length in bytes of every symmetric key (AES-256).
pub const KEY_LEN: usize = 32;
/// Length in bytes of an AES-GCM nonce.
pub const NONCE_LEN: usize = 12;
/// Length in bytes of an AES-GCM authentication tag.
pub const TAG_LEN: usize = 16;

/// Errors returned by this crate. They never carry secret material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// A key had the wrong length.
    #[error("invalid key length")]
    InvalidKeyLength,
    /// A parameter (KDF cost, salt, nonce…) is outside the accepted range.
    #[error("invalid parameter: {0}")]
    InvalidParameters(&'static str),
    /// The key derivation function failed.
    #[error("key derivation failed")]
    KdfFailed,
    /// AEAD authentication failed: wrong key, wrong associated data or tampered ciphertext.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// The operating-system random generator is unavailable.
    #[error("randomness unavailable")]
    RandomnessUnavailable,
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, CryptoError>;

/// A 256-bit symmetric key that is wiped from memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(Box<[u8; KEY_LEN]>);

impl SecretKey {
    /// Generates a fresh random key from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut key = Box::new([0u8; KEY_LEN]);
        fill_random(key.as_mut())?;
        Ok(Self(key))
    }

    /// Builds a key from exactly [`KEY_LEN`] bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut key = Box::new([0u8; KEY_LEN]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Exposes the raw key bytes. Callers must not log or persist them in plaintext.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Creates an independent copy (each copy zeroizes itself on drop).
    pub fn duplicate(&self) -> Self {
        Self(Box::new(*self.0))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(**redacted**)")
    }
}

impl PartialEq for SecretKey {
    /// Constant-time comparison.
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(other.0.as_ref()).into()
    }
}
impl Eq for SecretKey {}

/// Output of an AEAD encryption: random nonce plus `ciphertext || tag`.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    /// The 96-bit nonce used for this encryption.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with the 16-byte GCM tag appended.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for Sealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealed").field("nonce_len", &self.nonce.len()).field("ciphertext_len", &self.ciphertext.len()).finish()
    }
}

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    pub parallelism: u32,
}

/// Lower bound for Argon2id memory (OWASP minimum, 19 MiB).
pub const MIN_MEMORY_KIB: u32 = 19 * 1024;
/// Upper bound for Argon2id memory (1 GiB) — protects readers against DoS through hostile headers.
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
/// Lower bound for Argon2id passes.
pub const MIN_ITERATIONS: u32 = 2;
/// Upper bound for Argon2id passes.
pub const MAX_ITERATIONS: u32 = 20;
/// Lower bound for Argon2id lanes.
pub const MIN_PARALLELISM: u32 = 1;
/// Upper bound for Argon2id lanes.
pub const MAX_PARALLELISM: u32 = 8;
/// Minimum salt length accepted by the vault format.
pub const MIN_SALT_LEN: usize = 16;
/// Maximum salt length accepted by the vault format.
pub const MAX_SALT_LEN: usize = 64;

impl Argon2Params {
    /// Provisional default (see docs/DECISIONS.md ADR-005): 64 MiB, 3 passes, 1 lane.
    pub const DEFAULT: Argon2Params = Argon2Params { memory_kib: 64 * 1024, iterations: 3, parallelism: 1 };

    /// Checks the parameters against the accepted bounds.
    pub fn validate(&self) -> Result<()> {
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib) {
            return Err(CryptoError::InvalidParameters("argon2 memory out of bounds"));
        }
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations) {
            return Err(CryptoError::InvalidParameters("argon2 iterations out of bounds"));
        }
        if !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&self.parallelism) {
            return Err(CryptoError::InvalidParameters("argon2 parallelism out of bounds"));
        }
        if self.memory_kib < 8 * self.parallelism {
            return Err(CryptoError::InvalidParameters("argon2 memory too small for parallelism"));
        }
        Ok(())
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::DEFAULT
    }
}

fn check_salt(salt: &[u8]) -> Result<()> {
    if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt.len()) {
        return Err(CryptoError::InvalidParameters("salt length out of bounds"));
    }
    Ok(())
}

/// Derives a key-encryption key from a password with Argon2id v1.3.
///
/// `password` must already be normalized (the vault layer applies Unicode NFC).
pub fn derive_wrapping_key(password: &[u8], salt: &[u8], params: &Argon2Params) -> Result<SecretKey> {
    params.validate()?;
    check_salt(salt)?;
    let p = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(KEY_LEN))
        .map_err(|_| CryptoError::InvalidParameters("argon2 parameters rejected"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Box::new([0u8; KEY_LEN]);
    argon.hash_password_into(password, salt, out.as_mut()).map_err(|_| {
        out.zeroize();
        CryptoError::KdfFailed
    })?;
    Ok(SecretKey(out))
}

/// Derives a 256-bit key with HKDF-SHA256 from high-entropy input keying material.
pub fn derive_recovery_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<SecretKey> {
    if ikm.len() < KEY_LEN {
        return Err(CryptoError::InvalidParameters("recovery input too short"));
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = Box::new([0u8; KEY_LEN]);
    hk.expand(info, out.as_mut()).map_err(|_| CryptoError::KdfFailed)?;
    Ok(SecretKey(out))
}

/// Generates a fresh random data-encryption key (DEK).
pub fn generate_data_key() -> Result<SecretKey> {
    SecretKey::generate()
}

/// Encrypts `plaintext` with AES-256-GCM under a fresh random nonce, authenticating `aad`.
pub fn encrypt(key: &SecretKey, aad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.expose()));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(Sealed { nonce, ciphertext })
}

/// Decrypts and authenticates a [`Sealed`] value. The plaintext is zeroized when dropped.
pub fn decrypt(key: &SecretKey, aad: &[u8], sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.ciphertext.len() < TAG_LEN {
        return Err(CryptoError::AuthenticationFailed);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.expose()));
    cipher
        .decrypt(Nonce::from_slice(&sealed.nonce), Payload { msg: &sealed.ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Encrypts with an explicit nonce. **Only for known-answer tests**; production code uses [`encrypt`].
#[doc(hidden)]
pub fn encrypt_with_nonce_for_tests(key: &SecretKey, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.expose()));
    cipher.encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad }).map_err(|_| CryptoError::AuthenticationFailed)
}

/// Wraps (encrypts) a data key under a key-encryption key, binding `aad`.
pub fn wrap_data_key(dek: &SecretKey, kek: &SecretKey, aad: &[u8]) -> Result<Sealed> {
    encrypt(kek, aad, dek.expose())
}

/// Unwraps a data key. Fails with [`CryptoError::AuthenticationFailed`] on a wrong KEK or tampering.
pub fn unwrap_data_key(sealed: &Sealed, kek: &SecretKey, aad: &[u8]) -> Result<SecretKey> {
    if sealed.ciphertext.len() != KEY_LEN + TAG_LEN {
        return Err(CryptoError::AuthenticationFailed);
    }
    let plain = decrypt(kek, aad, sealed)?;
    SecretKey::from_slice(&plain)
}

/// Fills `buf` from the operating-system CSPRNG.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| CryptoError::RandomnessUnavailable)
}

/// Returns `n` random bytes from the operating-system CSPRNG.
pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; n];
    fill_random(&mut v)?;
    Ok(v)
}

/// SHA-256 digest (used for header binding and recovery-key checksums).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// McGrew & Viega GCM spec, test case 16 (AES-256, 96-bit IV, with AAD).
    #[test]
    fn aes_256_gcm_known_answer() {
        let key = SecretKey::from_slice(&h("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")).unwrap();
        let pt = h("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        let aad = h("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let nonce: [u8; 12] = h("cafebabefacedbaddecaf888").try_into().unwrap();
        let ct = encrypt_with_nonce_for_tests(&key, &nonce, &aad, &pt).unwrap();
        let expected = h("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662\
                          76fc6ece0f4e1768cddf8853bb2d551b");
        assert_eq!(ct, expected);
        let back = decrypt(&key, &aad, &Sealed { nonce, ciphertext: ct }).unwrap();
        assert_eq!(&back[..], &pt[..]);
    }

    /// RFC 5869 test case 1 (first 32 bytes of OKM).
    #[test]
    fn hkdf_sha256_known_answer() {
        let ikm = vec![0x0bu8; 22];
        let salt = h("000102030405060708090a0b0c");
        let info = h("f0f1f2f3f4f5f6f7f8f9");
        let k = derive_recovery_key(&ikm, &salt, &info);
        // ikm shorter than 32 bytes is rejected by our policy...
        assert_eq!(k.unwrap_err(), CryptoError::InvalidParameters("recovery input too short"));
        // ...so check the primitive directly through the hkdf crate to pin the construction.
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(okm.to_vec(), h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"));
    }

    #[test]
    fn argon2id_is_deterministic_and_salt_sensitive() {
        let p = Argon2Params { memory_kib: MIN_MEMORY_KIB, iterations: 2, parallelism: 1 };
        let a = derive_wrapping_key(b"correct horse", &[1u8; 16], &p).unwrap();
        let b = derive_wrapping_key(b"correct horse", &[1u8; 16], &p).unwrap();
        let c = derive_wrapping_key(b"correct horse", &[2u8; 16], &p).unwrap();
        let d = derive_wrapping_key(b"correct horsE", &[1u8; 16], &p).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn argon2_bounds_enforced() {
        let bad = [
            Argon2Params { memory_kib: MIN_MEMORY_KIB - 1, iterations: 3, parallelism: 1 },
            Argon2Params { memory_kib: MAX_MEMORY_KIB + 1, iterations: 3, parallelism: 1 },
            Argon2Params { memory_kib: 65536, iterations: 1, parallelism: 1 },
            Argon2Params { memory_kib: 65536, iterations: 21, parallelism: 1 },
            Argon2Params { memory_kib: 65536, iterations: 3, parallelism: 0 },
            Argon2Params { memory_kib: 65536, iterations: 3, parallelism: 9 },
        ];
        for p in bad {
            assert!(matches!(derive_wrapping_key(b"x", &[0u8; 16], &p), Err(CryptoError::InvalidParameters(_))), "{p:?}");
        }
        assert!(matches!(derive_wrapping_key(b"x", &[0u8; 15], &Argon2Params::DEFAULT), Err(CryptoError::InvalidParameters(_))));
        assert!(matches!(derive_wrapping_key(b"x", &[0u8; 65], &Argon2Params::DEFAULT), Err(CryptoError::InvalidParameters(_))));
    }

    #[test]
    fn wrap_unwrap_roundtrip_and_failures() {
        let dek = generate_data_key().unwrap();
        let kek = SecretKey::generate().unwrap();
        let sealed = wrap_data_key(&dek, &kek, b"aad").unwrap();
        assert_eq!(sealed.ciphertext.len(), KEY_LEN + TAG_LEN);
        assert_eq!(unwrap_data_key(&sealed, &kek, b"aad").unwrap(), dek);
        // wrong AAD, wrong key, flipped bit
        assert_eq!(unwrap_data_key(&sealed, &kek, b"aaD").unwrap_err(), CryptoError::AuthenticationFailed);
        assert_eq!(unwrap_data_key(&sealed, &SecretKey::generate().unwrap(), b"aad").unwrap_err(), CryptoError::AuthenticationFailed);
        let mut t = sealed.clone();
        t.ciphertext[0] ^= 1;
        assert_eq!(unwrap_data_key(&t, &kek, b"aad").unwrap_err(), CryptoError::AuthenticationFailed);
        let mut t = sealed.clone();
        t.nonce[11] ^= 0x80;
        assert_eq!(unwrap_data_key(&t, &kek, b"aad").unwrap_err(), CryptoError::AuthenticationFailed);
        let mut t = sealed;
        t.ciphertext.truncate(10);
        assert_eq!(unwrap_data_key(&t, &kek, b"aad").unwrap_err(), CryptoError::AuthenticationFailed);
    }

    #[test]
    fn nonces_are_unique() {
        let k = SecretKey::generate().unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(encrypt(&k, b"", b"x").unwrap().nonce));
        }
    }

    #[test]
    fn debug_never_prints_key() {
        let k = SecretKey::from_slice(&[0xAB; 32]).unwrap();
        let s = format!("{k:?}");
        assert!(!s.to_lowercase().contains("ab, ab") && !s.contains("171"));
        assert!(s.contains("redacted"));
    }
}

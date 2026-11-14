//! Recovery key: 256 random bits shown once as 56 Base32 characters (key ‖ 3-byte SHA-256 checksum).

use crate::error::{Result, VaultError};
use keyvora_crypto::{sha256, SecretKey, KEY_LEN};
use zeroize::{Zeroize, Zeroizing};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CHECK_LEN: usize = 3;
const ENCODED_LEN: usize = 56; // (32 + 3) * 8 / 5

/// A recovery key. Wiped from memory on drop.
pub struct RecoveryKey(SecretKey);

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey(**redacted**)")
    }
}

impl RecoveryKey {
    /// Generates a new random recovery key.
    pub fn generate() -> Result<Self> {
        Ok(Self(SecretKey::generate()?))
    }

    /// Raw 32 bytes (input keying material for HKDF).
    pub fn secret(&self) -> &SecretKey {
        &self.0
    }

    /// Human-readable form: 14 groups of 4 characters separated by `-`.
    pub fn to_display(&self) -> Zeroizing<String> {
        let mut raw = Zeroizing::new(Vec::with_capacity(KEY_LEN + CHECK_LEN));
        raw.extend_from_slice(self.0.expose());
        raw.extend_from_slice(&sha256(self.0.expose())[..CHECK_LEN]);
        let enc = base32_encode(&raw);
        let mut out = Zeroizing::new(String::with_capacity(ENCODED_LEN + 13));
        for (i, c) in enc.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(c);
        }
        out
    }

    /// Parses user input (case-insensitive; spaces and dashes ignored; 0→O, 1→I, 8→B).
    pub fn parse(input: &str) -> Result<Self> {
        let mut norm = Zeroizing::new(String::with_capacity(ENCODED_LEN));
        for c in input.chars() {
            match c {
                ' ' | '-' | '\t' | '\n' | '\r' => {}
                '0' => norm.push('O'),
                '1' => norm.push('I'),
                '8' => norm.push('B'),
                c => norm.push(c.to_ascii_uppercase()),
            }
        }
        if norm.len() != ENCODED_LEN {
            return Err(VaultError::InvalidRecoveryKey);
        }
        let raw = Zeroizing::new(base32_decode(&norm).ok_or(VaultError::InvalidRecoveryKey)?);
        if raw.len() != KEY_LEN + CHECK_LEN {
            return Err(VaultError::InvalidRecoveryKey);
        }
        let (key, check) = raw.split_at(KEY_LEN);
        if sha256(key)[..CHECK_LEN] != *check {
            return Err(VaultError::InvalidRecoveryKey);
        }
        Ok(Self(SecretKey::from_slice(key)?))
    }
}

/// RFC 4648 Base32 without padding.
fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for &b in data {
        buffer = (buffer << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    buffer.zeroize();
    out
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = ALPHABET.iter().position(|&a| a == c)? as u64;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    buffer.zeroize();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_rfc4648_vectors() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("MZXW6YTBOI").unwrap(), b"foobar");
    }

    #[test]
    fn display_and_parse_roundtrip() {
        let k = RecoveryKey::generate().unwrap();
        let shown = k.to_display();
        assert_eq!(shown.len(), 56 + 13);
        assert_eq!(shown.split('-').count(), 14);
        let back = RecoveryKey::parse(&shown).unwrap();
        assert_eq!(back.secret(), k.secret());
        // lower case, spaces instead of dashes
        let relaxed = shown.to_lowercase().replace('-', " ");
        assert_eq!(RecoveryKey::parse(&relaxed).unwrap().secret(), k.secret());
    }

    #[test]
    fn typo_is_detected() {
        let k = RecoveryKey::generate().unwrap();
        let shown = k.to_display();
        let mut chars: Vec<char> = shown.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert_eq!(RecoveryKey::parse(&typo).unwrap_err(), VaultError::InvalidRecoveryKey);
        assert_eq!(RecoveryKey::parse("ABCD").unwrap_err(), VaultError::InvalidRecoveryKey);
    }
}

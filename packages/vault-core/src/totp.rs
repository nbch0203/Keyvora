//! TOTP (RFC 6238) for the optional two-step verification with an authenticator app (Authy, Google Authenticator…).
//!
//! What it protects: someone who learned the master password and uses the official app on the user's device (new
//! device, export, key changes). What it cannot protect: the encrypted file itself — a code that changes every 30 s
//! cannot be part of the key derivation, so offline attacks on a stolen container still face only the master
//! password. The secret lives inside the encrypted payload.

use crate::error::{Result, VaultError};
use keyvora_crypto as kc;

/// Time step in seconds.
pub const PERIOD: u64 = 30;
/// Digits per code.
pub const DIGITS: u32 = 6;
/// Secret length in bytes (160 bits, the RFC 4226 recommendation).
pub const SECRET_LEN: usize = 20;
/// Accepted clock drift, in steps on each side.
pub const WINDOW: u64 = 1;

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 Base32 without padding.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buf: u64 = 0;
    let mut bits = 0u32;
    for &b in data {
        buf = (buf << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            out.push(B32[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// RFC 4648 Base32 decoding (case-insensitive, spaces and `=` ignored).
pub fn base32_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u64 = 0;
    let mut bits = 0u32;
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let v = B32.iter().position(|&x| x as char == c.to_ascii_uppercase()).ok_or(VaultError::Validation("twoFactorSecret"))?;
        buf = (buf << 5) | v as u64;
        bits += 5;
        if bits >= 8 {
            out.push(((buf >> (bits - 8)) & 0xFF) as u8);
            bits -= 8;
        }
    }
    Ok(out)
}

/// New random secret, Base32.
pub fn generate_secret() -> Result<String> {
    let raw = zeroize::Zeroizing::new(kc::random_bytes(SECRET_LEN)?);
    Ok(base32_encode(&raw))
}

/// Validates a stored secret.
pub fn validate_secret(secret_b32: &str) -> Result<()> {
    let raw = zeroize::Zeroizing::new(base32_decode(secret_b32)?);
    if raw.len() != SECRET_LEN {
        return Err(VaultError::Validation("twoFactorSecret"));
    }
    Ok(())
}

/// HOTP value for a counter (RFC 4226 dynamic truncation).
fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mac = kc::hmac_sha1(secret, &counter.to_be_bytes());
    let off = (mac[19] & 0x0f) as usize;
    let bin = ((mac[off] as u32 & 0x7f) << 24) | ((mac[off + 1] as u32) << 16) | ((mac[off + 2] as u32) << 8) | mac[off + 3] as u32;
    bin % 10u32.pow(DIGITS)
}

/// Code for a Unix time (seconds), zero-padded.
pub fn code_at(secret_b32: &str, unix_secs: u64) -> Result<String> {
    let raw = zeroize::Zeroizing::new(base32_decode(secret_b32)?);
    Ok(format!("{:0width$}", hotp(&raw, unix_secs / PERIOD), width = DIGITS as usize))
}

/// Verifies `code` at `unix_secs` within ±[`WINDOW`] steps. `last_step` is the last step accepted on this device:
/// a code is never accepted twice (replay). Returns the matched step, to be stored as the new `last_step`.
pub fn verify(secret_b32: &str, code: &str, unix_secs: u64, last_step: Option<u64>) -> Result<u64> {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(VaultError::InvalidCredentials);
    }
    let raw = zeroize::Zeroizing::new(base32_decode(secret_b32)?);
    let now = unix_secs / PERIOD;
    let mut matched = None;
    for step in now.saturating_sub(WINDOW)..=now + WINDOW {
        let expected = format!("{:0width$}", hotp(&raw, step), width = DIGITS as usize);
        if kc::ct_eq(expected.as_bytes(), code.as_bytes()) && last_step.is_none_or(|l| step > l) {
            matched = Some(step);
        }
    }
    matched.ok_or(VaultError::InvalidCredentials)
}

/// `otpauth://` URI for the authenticator's QR code. Label and issuer are generic: no personal data.
pub fn otpauth_uri(secret_b32: &str) -> String {
    format!("otpauth://totp/Keyvora?secret={secret_b32}&issuer=Keyvora&algorithm=SHA1&digits={DIGITS}&period={PERIOD}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B, SHA-1 key "12345678901234567890" (8 digits there; we check the last 6).
    #[test]
    fn rfc6238_vectors() {
        let secret = base32_encode(b"12345678901234567890");
        for (t, eight) in [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(code_at(&secret, t).unwrap(), &eight[2..], "t={t}");
        }
    }

    #[test]
    fn base32_round_trip() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(base32_decode(&base32_encode(&data)).unwrap(), data);
        }
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn verify_window_and_replay() {
        let s = generate_secret().unwrap();
        validate_secret(&s).unwrap();
        let t = 1_700_000_000;
        let c = code_at(&s, t).unwrap();
        let step = verify(&s, &c, t, None).unwrap();
        assert!(verify(&s, &c, t + 30, None).is_ok(), "one step of drift is accepted");
        assert!(verify(&s, &c, t + 120, None).is_err(), "old codes expire");
        assert!(verify(&s, &c, t, Some(step)).is_err(), "a code is never accepted twice");
        assert!(verify(&s, "12345", t, None).is_err());
        assert!(verify(&s, "abcdef", t, None).is_err());
    }
}

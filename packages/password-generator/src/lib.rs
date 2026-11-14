//! Random password generator.
//!
//! Every character is drawn uniformly from the selected alphabet using the OS CSPRNG and rejection sampling
//! (no modulo bias). When `require_each_class` is set, candidates missing a class are discarded and regenerated,
//! which keeps the distribution uniform over all valid passwords.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// Symbols chosen to be accepted by most sites: no quotes, backslash or whitespace.
const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
const AMBIGUOUS: &str = "Il1O0o|";

/// Minimum accepted length.
pub const MIN_LENGTH: u32 = 8;
/// Maximum accepted length.
pub const MAX_LENGTH: u32 = 128;
const MAX_ATTEMPTS: usize = 10_000;

/// Generator options (serialized in camelCase for the bindings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GeneratorOptions {
    /// Password length in characters.
    pub length: u32,
    /// Include a–z.
    pub lowercase: bool,
    /// Include A–Z.
    pub uppercase: bool,
    /// Include 0–9.
    pub digits: bool,
    /// Include symbols.
    pub symbols: bool,
    /// Remove look-alike characters (`I l 1 O 0 o |`).
    pub exclude_ambiguous: bool,
    /// Require at least one character of every selected class.
    pub require_each_class: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self { length: 20, lowercase: true, uppercase: true, digits: true, symbols: true, exclude_ambiguous: false, require_each_class: true }
    }
}

/// Generator errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GeneratorError {
    /// Length outside [`MIN_LENGTH`]..=[`MAX_LENGTH`].
    #[error("length out of bounds")]
    InvalidLength,
    /// No character class selected.
    #[error("no character class selected")]
    NoClasses,
    /// More required classes than characters.
    #[error("length too short for the required classes")]
    TooShortForClasses,
    /// CSPRNG failure.
    #[error("randomness unavailable")]
    Randomness,
}

fn classes(opts: &GeneratorOptions) -> Vec<Vec<char>> {
    let mut out = Vec::new();
    for (enabled, set) in [(opts.lowercase, LOWER), (opts.uppercase, UPPER), (opts.digits, DIGITS), (opts.symbols, SYMBOLS)] {
        if enabled {
            let chars: Vec<char> = set.chars().filter(|c| !(opts.exclude_ambiguous && AMBIGUOUS.contains(*c))).collect();
            if !chars.is_empty() {
                out.push(chars);
            }
        }
    }
    out
}

fn validate(opts: &GeneratorOptions) -> Result<Vec<Vec<char>>, GeneratorError> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&opts.length) {
        return Err(GeneratorError::InvalidLength);
    }
    let cls = classes(opts);
    if cls.is_empty() {
        return Err(GeneratorError::NoClasses);
    }
    if opts.require_each_class && (opts.length as usize) < cls.len() {
        return Err(GeneratorError::TooShortForClasses);
    }
    Ok(cls)
}

/// Uniform integer in `0..n` using rejection sampling over 32-bit CSPRNG output.
fn uniform_index(n: usize) -> Result<usize, GeneratorError> {
    debug_assert!(n > 0 && n <= u32::MAX as usize);
    let n = n as u32;
    let zone = u32::MAX - (u32::MAX % n); // values >= zone are rejected
    loop {
        let mut b = [0u8; 4];
        keyvora_crypto::fill_random(&mut b).map_err(|_| GeneratorError::Randomness)?;
        let v = u32::from_le_bytes(b);
        if v < zone {
            return Ok((v % n) as usize);
        }
    }
}

/// Generates a password according to `opts`.
pub fn generate_password(opts: &GeneratorOptions) -> Result<String, GeneratorError> {
    let cls = validate(opts)?;
    let alphabet: Vec<char> = cls.iter().flatten().copied().collect();
    for _ in 0..MAX_ATTEMPTS {
        let mut candidate: Vec<char> = Vec::with_capacity(opts.length as usize);
        for _ in 0..opts.length {
            candidate.push(alphabet[uniform_index(alphabet.len())?]);
        }
        let ok = !opts.require_each_class || cls.iter().all(|set| candidate.iter().any(|c| set.contains(c)));
        if ok {
            let s: String = candidate.iter().collect();
            candidate.zeroize();
            return Ok(s);
        }
        candidate.zeroize();
    }
    Err(GeneratorError::Randomness)
}

/// Approximate entropy in bits: `length × log2(|alphabet|)`.
pub fn entropy_bits(opts: &GeneratorOptions) -> Result<f64, GeneratorError> {
    let cls = validate(opts)?;
    let n: usize = cls.iter().map(Vec::len).sum();
    Ok(opts.length as f64 * (n as f64).log2())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn respects_length_and_classes() {
        let opts = GeneratorOptions { length: 24, ..Default::default() };
        for _ in 0..500 {
            let p = generate_password(&opts).unwrap();
            assert_eq!(p.chars().count(), 24);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn excludes_ambiguous() {
        let opts = GeneratorOptions { length: 128, exclude_ambiguous: true, ..Default::default() };
        for _ in 0..100 {
            assert!(!generate_password(&opts).unwrap().chars().any(|c| AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn digits_only() {
        let opts = GeneratorOptions { length: 12, lowercase: false, uppercase: false, symbols: false, ..Default::default() };
        assert!(generate_password(&opts).unwrap().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn rejects_invalid_options() {
        assert_eq!(generate_password(&GeneratorOptions { length: 7, ..Default::default() }), Err(GeneratorError::InvalidLength));
        assert_eq!(generate_password(&GeneratorOptions { length: 129, ..Default::default() }), Err(GeneratorError::InvalidLength));
        let none = GeneratorOptions { lowercase: false, uppercase: false, digits: false, symbols: false, ..Default::default() };
        assert_eq!(generate_password(&none), Err(GeneratorError::NoClasses));
    }

    #[test]
    fn passwords_are_unique() {
        let opts = GeneratorOptions::default();
        let set: HashSet<String> = (0..2000).map(|_| generate_password(&opts).unwrap()).collect();
        assert_eq!(set.len(), 2000);
    }

    /// Chi-square sanity check of the per-character distribution (not a proof of randomness).
    #[test]
    fn distribution_is_roughly_uniform() {
        let opts = GeneratorOptions { length: 128, require_each_class: false, ..Default::default() };
        let mut counts: HashMap<char, u64> = HashMap::new();
        let rounds = 400;
        for _ in 0..rounds {
            for c in generate_password(&opts).unwrap().chars() {
                *counts.entry(c).or_default() += 1;
            }
        }
        let n_symbols = (LOWER.len() + UPPER.len() + DIGITS.len() + SYMBOLS.len()) as f64;
        assert_eq!(counts.len() as f64, n_symbols);
        let expected = (rounds * 128) as f64 / n_symbols;
        let chi2: f64 = counts.values().map(|&o| (o as f64 - expected).powi(2) / expected).sum();
        // dof = 89; p ≈ 1e-6 threshold ≈ 160
        assert!(chi2 < 160.0, "chi2 = {chi2}");
    }

    #[test]
    fn entropy_estimate() {
        let bits = entropy_bits(&GeneratorOptions::default()).unwrap();
        assert!(bits > 125.0 && bits < 135.0, "{bits}");
    }
}

//! Master-password strength estimator (one implementation for every client, exposed through the bindings).
//!
//! It is deliberately simple and conservative: it never claims a password is strong because of character classes
//! alone. It detects what offline dictionary attacks try first — too short, few distinct characters, only digits,
//! long repeats, alphabet/keyboard sequences and well-known passwords (also with leetspeak) — and estimates the
//! entropy of what is left. A passphrase of four or more distinct words is accepted as such.

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

/// Minimum visible characters (whitespace and invisible characters do not count).
pub const MIN_VISIBLE: usize = 12;
/// Minimum score accepted for a new master password.
pub const MIN_SCORE: u8 = 3;

/// Result of [`master_password_strength`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Strength {
    /// 0 (unusable) … 4 (very strong). New master passwords need at least [`MIN_SCORE`].
    pub score: u8,
    /// Stable codes of what is wrong (the UI translates them): `tooShort`, `fewDistinct`, `onlyDigits`,
    /// `repeated`, `sequence`, `common`.
    pub problems: Vec<String>,
}

impl Strength {
    /// Whether it is good enough for a new master password.
    pub fn acceptable(&self) -> bool {
        self.score >= MIN_SCORE
    }
}

/// Invisible / formatting characters that must not count towards the length (they look like nothing).
fn is_invisible(c: char) -> bool {
    c.is_control()
        || matches!(c as u32, 0x00AD | 0x034F | 0x061C | 0x115F | 0x1160 | 0x17B4 | 0x17B5 | 0x180B..=0x180F
            | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x206F | 0x3164 | 0xFE00..=0xFE0F | 0xFEFF | 0xFFA0)
}

/// Leetspeak folding used only for the common-password check.
fn fold(c: char) -> char {
    match c {
        '0' => 'o',
        '1' | '!' | '|' => 'i',
        '3' => 'e',
        '4' | '@' => 'a',
        '5' | '$' => 's',
        '7' => 't',
        '8' => 'b',
        '9' => 'g',
        _ => c,
    }
}

const KEYBOARD_ROWS: &[&str] = &["qwertyuiop", "asdfghjklñ", "zxcvbnm", "azertyuiop", "qwertzuiop", "1234567890"];

/// Well-known passwords and words that dominate leaked-password lists (English and Spanish). Matched after
/// lower-casing and leet folding, as substrings of at least 4 characters.
const COMMON: &[&str] = &[
    "password", "passw0rd", "contraseña", "contrasena", "qwerty", "azerty", "iloveyou", "teamo", "tequiero", "admin",
    "administrador", "welcome", "bienvenido", "monkey", "dragon", "letmein", "football", "futbol", "baseball",
    "master", "shadow", "sunshine", "princess", "princesa", "superman", "batman", "trustno1",
    "secret", "secreto", "login", "abc123", "starwars", "whatever", "freedom", "michael", "jennifer", "jordan",
    "hunter", "ranger", "buster", "soccer", "hockey", "killer", "george", "charlie", "andrew", "thomas", "jessica",
    "pepper", "ginger", "summer", "winter", "spring", "autumn", "orange", "banana", "cookie", "chocolate", "flower",
    "silver", "golden", "diamond", "matrix", "mustang", "corvette", "ferrari", "porsche", "mercedes", "computer",
    "internet", "samsung", "google", "facebook", "instagram", "twitter", "youtube", "amazon", "microsoft", "apple",
    "windows", "android", "iphone", "pokemon", "naruto", "minecraft", "fortnite", "hello", "hola", "amor", "amorcito",
    "cariño", "corazon", "corazón", "mariposa", "estrella", "angel", "angelito", "familia", "españa", "espana",
    "mexico", "méxico", "argentina", "colombia", "venezuela", "chile", "peru", "perú", "barcelona", "barca",
    "realmadrid", "madrid", "boca", "river", "america", "chivas", "tigres", "dios", "jesus", "jesús", "maria",
    "maría", "jose", "josé", "juan", "carlos", "luis", "miguel", "alejandro", "daniel", "david", "pedro", "antonio",
    "manuel", "francisco", "javier", "sofia", "lucia", "martina", "valentina", "camila", "isabella", "gabriel",
    "sebastian", "nicolas", "samuel", "diego", "mateo", "santiago", "gatito", "perrito", "chuchito", "bebito",
    "bebe", "nene", "nena", "muñeca", "tesoro", "cielo", "mamá", "mama", "papá", "papa", "abuela", "abuelo",
    "qazwsx", "asdasd", "zxczxc", "qweqwe", "aaaaaa", "111111", "123123", "121212", "112233", "654321", "666666",
    "696969", "777777", "888888", "999999", "000000", "123456", "1234567", "12345678", "123456789", "1234567890",
    "987654321", "default", "changeme", "cambiame", "cámbiame", "usuario", "user", "guest", "invitado", "test",
    "demo", "root", "toor", "pass", "clave", "llave", "keyvora", "lovely", "loveme", "love", "sexy",
    "money", "dinero", "lucky", "suerte", "magic", "magia", "snoopy", "garfield", "mickey", "minnie", "donald",
    "spiderman", "ironman", "hulk", "thor", "zelda", "mario", "luigi", "sonic", "metallica", "nirvana", "beatles",
    "liverpool", "chelsea", "arsenal", "united", "juventus", "milan", "inter", "bayern", "dortmund", "psg",
];

/// Estimates the strength of a master password (NFC-normalized first, as the vault does).
pub fn master_password_strength(password: &str) -> Strength {
    let n: String = password.nfc().collect();
    let visible: Vec<char> = n.chars().filter(|c| !c.is_whitespace() && !is_invisible(*c)).collect();
    let mut problems: Vec<&'static str> = Vec::new();
    if visible.len() < MIN_VISIBLE {
        return Strength { score: 0, problems: vec!["tooShort".into()] };
    }

    let lower: Vec<char> = visible.iter().flat_map(|c| c.to_lowercase()).collect();
    let distinct = {
        let mut d: Vec<char> = lower.clone();
        d.sort_unstable();
        d.dedup();
        d.len()
    };
    let mut fatal = false;
    if distinct < 6 {
        problems.push("fewDistinct");
        fatal = true;
    }
    if visible.iter().all(|c| c.is_ascii_digit()) {
        problems.push("onlyDigits");
        fatal = true;
    }

    // Characters "explained" by a pattern (they add almost no entropy).
    let mut penalized = vec![false; lower.len()];

    // Runs of the same character (4+), and the whole string being a repetition of a short unit.
    let mut i = 0;
    let mut repeated = false;
    while i < lower.len() {
        let mut j = i + 1;
        while j < lower.len() && lower[j] == lower[i] {
            j += 1;
        }
        if j - i >= 4 {
            repeated = true;
            penalized[i + 1..j].iter_mut().for_each(|p| *p = true);
        }
        i = j;
    }
    for unit in 1..=lower.len() / 2 {
        if lower.len() % unit == 0 && lower.chunks(unit).all(|c| c == &lower[..unit]) {
            repeated = true;
            penalized[unit..].iter_mut().for_each(|p| *p = true);
            break;
        }
    }
    if repeated {
        problems.push("repeated");
    }

    // Alphabet / digit sequences (ascending or descending, 4+) and keyboard rows (5+).
    let mut sequence = false;
    let mut start = 0;
    while start + 1 < lower.len() {
        let step = lower[start + 1] as i64 - lower[start] as i64;
        if step == 1 || step == -1 {
            let mut end = start + 1;
            while end + 1 < lower.len() && lower[end + 1] as i64 - lower[end] as i64 == step {
                end += 1;
            }
            if end - start + 1 >= 4 && lower[start].is_ascii_alphanumeric() {
                sequence = true;
                penalized[start + 1..=end].iter_mut().for_each(|p| *p = true);
            }
            start = end;
        } else {
            start += 1;
        }
    }
    let joined: String = lower.iter().collect();
    for row in KEYBOARD_ROWS {
        let row: Vec<char> = row.chars().collect();
        for len in (5..=row.len()).rev() {
            for w in row.windows(len) {
                for seq in [w.iter().collect::<String>(), w.iter().rev().collect::<String>()] {
                    if let Some(pos) = joined.find(&seq) {
                        let at = joined[..pos].chars().count();
                        sequence = true;
                        penalized[at + 1..at + len].iter_mut().for_each(|p| *p = true);
                    }
                }
            }
        }
    }
    if sequence {
        problems.push("sequence");
    }

    // Well-known passwords (leet-folded), as substrings of 4+ characters.
    let folded: Vec<char> = lower.iter().map(|c| fold(*c)).collect();
    let folded_s: String = folded.iter().collect();
    let mut common_covered = vec![false; folded.len()];
    for w in COMMON {
        let wf: String = w.chars().flat_map(|c| c.to_lowercase()).map(fold).collect();
        if wf.chars().count() < 4 {
            continue;
        }
        let mut from = 0;
        while let Some(pos) = folded_s[from..].find(&wf) {
            let abs = from + pos;
            let at = folded_s[..abs].chars().count();
            let len = wf.chars().count();
            common_covered[at..at + len].iter_mut().for_each(|p| *p = true);
            from = abs + wf.len();
        }
    }
    let common_count = common_covered.iter().filter(|c| **c).count();

    // Passphrase: 4+ distinct words of 3+ letters separated by spaces or punctuation.
    let words: Vec<String> = n
        .split(|c: char| c.is_whitespace() || matches!(c, '-' | '_' | '.' | ',' | ';' | ':' | '/' | '+'))
        .filter(|w| w.chars().filter(|c| c.is_alphabetic()).count() >= 3)
        .map(|w| w.to_lowercase())
        .collect();
    let distinct_words = {
        let mut d = words.clone();
        d.sort();
        d.dedup();
        d.len()
    };
    let is_passphrase = distinct_words >= 4;

    if common_count > 0 && (common_count * 2 >= folded.len()) && !is_passphrase {
        problems.push("common");
        fatal = true;
    }
    for (p, c) in penalized.iter_mut().zip(&common_covered) {
        if *c {
            *p = true;
        }
    }

    // Entropy of what is left: effective length × log2(pool of character classes used).
    let mut pool = 0f64;
    if visible.iter().any(|c| c.is_ascii_lowercase()) {
        pool += 26.0;
    }
    if visible.iter().any(|c| c.is_ascii_uppercase()) {
        pool += 26.0;
    }
    if visible.iter().any(|c| c.is_ascii_digit()) {
        pool += 10.0;
    }
    if visible.iter().any(|c| c.is_ascii_punctuation()) {
        pool += 33.0;
    }
    if visible.iter().any(|c| !c.is_ascii()) {
        pool += 100.0;
    }
    let effective = penalized.iter().filter(|p| !**p).count() as f64 + 0.25 * penalized.iter().filter(|p| **p).count() as f64;
    let bits = effective * pool.max(2.0).log2();

    let mut score = if bits < 40.0 {
        1
    } else if bits < 60.0 {
        2
    } else if bits < 90.0 {
        3
    } else {
        4
    };
    if is_passphrase && !fatal {
        score = score.max(if distinct_words >= 5 { 4 } else { 3 });
    }
    if fatal {
        score = score.min(1);
    }
    Strength { score, problems: problems.into_iter().map(String::from).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(p: &str) -> u8 {
        master_password_strength(p).score
    }

    #[test]
    fn trivial_passwords_are_rejected() {
        for p in [
            "aaaaaaaaaaaa",
            "123456789012",
            "passwordpass",
            "            ",
            "\u{200b}\u{200b}\u{200b}\u{200b}\u{200b}\u{200b}\u{200b}\u{200b}\u{200b}\u{200b}\u{200b}\u{200b}",
            "qwertyuiopas",
            "abcdefghijkl",
            "P@ssw0rd2024!",
            "Contraseña123",
            "abcabcabcabc",
            "once-chars!",
        ] {
            assert!(s(p) < MIN_SCORE, "{p:?} should be weak, got {}", s(p));
        }
    }

    #[test]
    fn reasonable_passwords_are_accepted() {
        for p in [
            "correct horse battery staple",
            "frase maestra de prueba e2e",
            "Contraseña maestra de prueba \u{1F511}",
            "doce-chars!!",
            "tercera maestra",
            "KeyvoraUiReview2026",
            "gH#7kLp!2qRz@9vXw$Tn",
            "otra maestra 123",
            "cambiada en el dispositivo A",
            "a brand new master password",
            "contraseña maestra de QA",
        ] {
            assert!(s(p) >= MIN_SCORE, "{p:?} should be acceptable, got {:?}", master_password_strength(p));
        }
    }

    #[test]
    fn problems_are_reported() {
        assert_eq!(master_password_strength("short").problems, vec!["tooShort"]);
        assert!(master_password_strength("aaaaaaaaaaaa").problems.contains(&"fewDistinct".to_string()));
        assert!(master_password_strength("123456789012").problems.contains(&"onlyDigits".to_string()));
        assert!(master_password_strength("passwordpass").problems.contains(&"common".to_string()));
    }
}

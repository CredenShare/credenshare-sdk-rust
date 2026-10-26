//! A local generator for passwords, passphrases and PINs (Gitea #404).
//!
//! The app's three modes and the CLI's, with nothing sent anywhere: a generated secret never
//! leaves this process unless the caller sends it. Available without the `client` feature, since
//! it needs nothing but the operating system's random source.

use std::fmt;
use std::sync::OnceLock;

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::errors::{Error, Result};

const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const NUMBERS: &str = "0123456789";

/// The symbols a password may draw from, the app's set.
pub const PASSWORD_SYMBOLS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?`\"~/\\'";

/// The EFF long word list, byte-for-byte as the EFF publishes it (dice numbers, a tab, the
/// word). By the Electronic Frontier Foundation, licensed under CC BY 3.0 US; see NOTICE.
const EFF_LARGE_WORDLIST: &str = include_str!("eff_large_wordlist.txt");

/// A generated secret with its strength.
///
/// The value is behind a method, and withheld from [`Debug`], for the reason a request's seed
/// is: printing one should not put the secret in a log. It is wiped from memory on drop.
pub struct Generated {
    value: Zeroizing<String>,
    /// The entropy of what the options generate, not of this one value.
    pub bits: f64,
    /// [`strength_of`] `bits`: Weak, Fair, Strong or Very Strong.
    pub strength: &'static str,
}

impl Generated {
    fn new(value: String, bits: f64) -> Self {
        Self {
            value: Zeroizing::new(value),
            bits,
            strength: strength_of(bits),
        }
    }

    /// The secret itself.
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for Generated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<Generated {}, {:.0} bits (value withheld)>",
            self.strength, self.bits
        )
    }
}

/// What [`generate_password`] draws from. `PasswordOptions::default()` is the app's default:
/// 20 characters from upper and lower case, numbers and symbols.
#[derive(Debug, Clone)]
pub struct PasswordOptions {
    /// 8 to 128.
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    /// Characters to leave out, such as `0Ol1` for a password read aloud.
    pub exclude: String,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            exclude: String::new(),
        }
    }
}

/// A password drawn uniformly from the chosen characters.
pub fn generate_password(options: &PasswordOptions) -> Result<Generated> {
    if !(8..=128).contains(&options.length) {
        return Err(Error::InvalidArgument(format!(
            "a password is 8 to 128 characters, got {}",
            options.length
        )));
    }
    let pool: Vec<char> = [
        (options.uppercase, UPPERCASE),
        (options.lowercase, LOWERCASE),
        (options.numbers, NUMBERS),
        (options.symbols, PASSWORD_SYMBOLS),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .flat_map(|(_, chars)| chars.chars())
    .filter(|c| !options.exclude.contains(*c))
    .collect();
    if pool.is_empty() {
        return Err(Error::InvalidArgument(
            "those options leave no characters to choose from".to_string(),
        ));
    }
    let value = random_from(&pool, options.length);
    Ok(Generated::new(
        value,
        options.length as f64 * (pool.len() as f64).log2(),
    ))
}

/// How the words of a passphrase are joined, by the names the app and the CLI use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Separator {
    #[default]
    Hyphen,
    Space,
    Period,
    Underscore,
    None,
}

impl Separator {
    /// The characters the separator joins with.
    pub fn as_str(self) -> &'static str {
        match self {
            Separator::Hyphen => "-",
            Separator::Space => " ",
            Separator::Period => ".",
            Separator::Underscore => "_",
            Separator::None => "",
        }
    }
}

/// What [`generate_passphrase`] draws. `PassphraseOptions::default()` is the app's default:
/// five words joined by hyphens.
#[derive(Debug, Clone)]
pub struct PassphraseOptions {
    /// 3 to 12.
    pub words: usize,
    pub separator: Separator,
    /// Upper-case each word's first letter. It changes the look, not the strength: every word
    /// gets one, so it is not random.
    pub capitalize: bool,
    /// Append one random digit to one random word.
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 5,
            separator: Separator::Hyphen,
            capitalize: false,
            include_number: false,
        }
    }
}

/// The EFF long word list, 7,776 words, parsed once on first use.
fn word_list() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        EFF_LARGE_WORDLIST
            .trim()
            .lines()
            .filter_map(|line| line.trim().split_once('\t').map(|(_, word)| word))
            .collect()
    })
}

/// A passphrase drawn uniformly from the EFF long word list (12.9 bits a word).
pub fn generate_passphrase(options: &PassphraseOptions) -> Result<Generated> {
    if !(3..=12).contains(&options.words) {
        return Err(Error::InvalidArgument(format!(
            "a passphrase is 3 to 12 words, got {}",
            options.words
        )));
    }
    let list = word_list();
    let mut picked: Vec<String> = (0..options.words)
        .map(|_| {
            let word = list[random_below(list.len() as u32) as usize];
            if options.capitalize {
                let mut chars = word.chars();
                chars
                    .next()
                    .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
                    .unwrap_or_default()
            } else {
                word.to_string()
            }
        })
        .collect();
    if options.include_number {
        let where_ = random_below(options.words as u32) as usize;
        picked[where_].push_str(&random_below(10).to_string());
    }
    let joined = picked.join(options.separator.as_str());
    // The words are copies of a public list; the joined value is the secret.
    drop(Zeroizing::new(picked));
    Ok(Generated::new(
        joined,
        passphrase_bits(list.len(), options.words, options.include_number),
    ))
}

/// Each word is log2 of the list; the digit adds log2(10) and its position log2(words).
pub(crate) fn passphrase_bits(list_size: usize, words: usize, with_number: bool) -> f64 {
    let mut bits = words as f64 * (list_size as f64).log2();
    if with_number {
        bits += 10f64.log2() + (words as f64).log2();
    }
    bits
}

/// A PIN of `length` digits, 4 to 12. The app's default is 6.
pub fn generate_pin(length: usize) -> Result<Generated> {
    if !(4..=12).contains(&length) {
        return Err(Error::InvalidArgument(format!(
            "a PIN is 4 to 12 digits, got {length}"
        )));
    }
    let digits: Vec<char> = NUMBERS.chars().collect();
    Ok(Generated::new(
        random_from(&digits, length),
        length as f64 * 10f64.log2(),
    ))
}

/// The app generator's label for a number of bits.
pub fn strength_of(bits: f64) -> &'static str {
    if bits < 40.0 {
        "Weak"
    } else if bits < 60.0 {
        "Fair"
    } else if bits < 80.0 {
        "Strong"
    } else {
        "Very Strong"
    }
}

/// A uniform draw from `[0, n)`, by rejection sampling. Reducing a random 32-bit value with
/// `% n` is biased whenever `n` does not divide 2^32, and neither 94 nor 7,776 does: the values
/// at or above the last whole multiple of `n` are drawn again rather than folded back in.
fn random_below(n: u32) -> u32 {
    let limit = (u64::from(u32::MAX) + 1) / u64::from(n) * u64::from(n);
    loop {
        let draw = OsRng.next_u32();
        if u64::from(draw) < limit {
            return draw % n;
        }
    }
}

fn random_from(chars: &[char], n: usize) -> String {
    (0..n)
        .map(|_| chars[random_below(chars.len() as u32) as usize])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_word_list_parses_to_7776_words() {
        let list = word_list();
        assert_eq!(list.len(), 7776);
        assert_eq!(list[0], "abacus");
        assert_eq!(list[7775], "zoom");
    }

    #[test]
    fn strength_matches_the_app_and_the_other_sdks() {
        // The same table is asserted in all four SDKs, and matches the app and the CLI.
        let table: [(&str, f64, &str, &str); 10] = [
            (
                "password 20, all four sets (94)",
                20.0 * 94f64.log2(),
                "131.0918",
                "Very Strong",
            ),
            (
                "password 8, lowercase only (26)",
                8.0 * 26f64.log2(),
                "37.6035",
                "Weak",
            ),
            (
                "password 12, letters and numbers (62)",
                12.0 * 62f64.log2(),
                "71.4504",
                "Strong",
            ),
            (
                "password 10, numbers and symbols (42)",
                10.0 * 42f64.log2(),
                "53.9232",
                "Fair",
            ),
            (
                "passphrase 5 words",
                passphrase_bits(7776, 5, false),
                "64.6241",
                "Strong",
            ),
            (
                "passphrase 3 words",
                passphrase_bits(7776, 3, false),
                "38.7744",
                "Weak",
            ),
            (
                "passphrase 4 words with a digit",
                passphrase_bits(7776, 4, true),
                "57.0212",
                "Fair",
            ),
            (
                "passphrase 7 words",
                passphrase_bits(7776, 7, false),
                "90.4737",
                "Very Strong",
            ),
            ("pin 6", 6.0 * 10f64.log2(), "19.9316", "Weak"),
            ("pin 12", 12.0 * 10f64.log2(), "39.8631", "Weak"),
        ];
        for (name, bits, figure, label) in table {
            assert_eq!(format!("{bits:.4}"), figure, "{name}");
            assert_eq!(strength_of(bits), label, "{name}");
        }
    }

    #[test]
    fn random_below_never_leaves_its_range() {
        for n in [1u32, 2, 10, 94, 7776] {
            for _ in 0..1000 {
                assert!(random_below(n) < n);
            }
        }
    }
}

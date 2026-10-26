//! The local generator through the public API: the app's modes, its character sets, its
//! strength figures, and draws without modulo bias. The strength table itself is asserted next
//! to the code, in `src/generate.rs`, where the private bit counter lives.

use sha2::{Digest, Sha256};

use credenshare::{
    generate_passphrase, generate_password, generate_pin, Error, PassphraseOptions,
    PasswordOptions, Separator, PASSWORD_SYMBOLS,
};

// The EFF publishes this digest's file; the generator must draw from exactly that list.
const EFF_SHA256: &str = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e";
const EFF_LARGE_WORDLIST: &str = include_str!("../src/eff_large_wordlist.txt");

fn invalid(result: credenshare::Result<credenshare::Generated>) -> bool {
    matches!(result, Err(Error::InvalidArgument(_)))
}

#[test]
fn the_word_list_is_the_effs_byte_for_byte() {
    let digest: String = Sha256::digest(EFF_LARGE_WORDLIST.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(digest, EFF_SHA256);
}

#[test]
fn the_default_password_is_the_apps() {
    let g = generate_password(&PasswordOptions::default()).unwrap();
    assert_eq!(g.value().chars().count(), 20);
    assert_eq!(g.strength, "Very Strong");
    assert!((g.bits - 20.0 * 94f64.log2()).abs() < 1e-9);
    let pool =
        format!("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{PASSWORD_SYMBOLS}");
    assert_eq!(pool.len(), 94);
    assert!(g.value().chars().all(|c| pool.contains(c)));
}

#[test]
fn password_options_shape_the_pool() {
    let g = generate_password(&PasswordOptions {
        length: 64,
        uppercase: false,
        symbols: false,
        exclude: "0123abc".into(),
        ..Default::default()
    })
    .unwrap();
    let banned = format!("{PASSWORD_SYMBOLS}0123abc");
    assert!(g
        .value()
        .chars()
        .all(|c| !c.is_ascii_uppercase() && !banned.contains(c)));
    // 26 lower + 10 digits, less the 7 excluded.
    assert!((g.bits - 64.0 * 29f64.log2()).abs() < 1e-9);
}

#[test]
fn password_options_out_of_range_are_refused() {
    for options in [
        PasswordOptions {
            length: 7,
            ..Default::default()
        },
        PasswordOptions {
            length: 129,
            ..Default::default()
        },
        PasswordOptions {
            uppercase: false,
            lowercase: false,
            numbers: false,
            symbols: false,
            ..Default::default()
        },
        PasswordOptions {
            uppercase: false,
            lowercase: false,
            symbols: false,
            exclude: "0123456789".into(),
            ..Default::default()
        },
    ] {
        assert!(invalid(generate_password(&options)), "{options:?}");
    }
}

#[test]
fn the_default_passphrase_is_five_hyphenated_words() {
    let g = generate_passphrase(&PassphraseOptions::default()).unwrap();
    // Four EFF words carry a hyphen of their own (drop-down, felt-tip, t-shirt, yo-yo), so a
    // hyphenated passphrase can split into more than five parts, never fewer.
    assert!(g.value().split('-').count() >= 5, "{}", g.value());
    assert_eq!(g.strength, "Strong");
    let known: std::collections::HashSet<&str> = EFF_LARGE_WORDLIST
        .lines()
        .filter_map(|line| line.split_once('\t').map(|(_, w)| w))
        .collect();
    let spaced = generate_passphrase(&PassphraseOptions {
        words: 12,
        separator: Separator::Space,
        ..Default::default()
    })
    .unwrap();
    assert!(spaced.value().split(' ').all(|w| known.contains(w)));
}

#[test]
fn passphrase_options() {
    let g = generate_passphrase(&PassphraseOptions {
        words: 4,
        separator: Separator::Space,
        capitalize: true,
        include_number: true,
    })
    .unwrap();
    assert!(g
        .value()
        .split(' ')
        .all(|w| w.chars().next().unwrap().is_ascii_uppercase()));
    assert_eq!(g.value().chars().filter(char::is_ascii_digit).count(), 1);
    assert_eq!(g.strength, "Fair");
    for separator in [
        Separator::Hyphen,
        Separator::Space,
        Separator::Period,
        Separator::Underscore,
        Separator::None,
    ] {
        let value = generate_passphrase(&PassphraseOptions {
            words: 3,
            separator,
            ..Default::default()
        })
        .unwrap();
        if !separator.as_str().is_empty() {
            assert!(value.value().split(separator.as_str()).count() >= 3);
        }
    }
    for words in [2, 13] {
        assert!(invalid(generate_passphrase(&PassphraseOptions {
            words,
            ..Default::default()
        })));
    }
}

#[test]
fn pins() {
    let g = generate_pin(6).unwrap();
    assert_eq!(g.value().len(), 6);
    assert!(g.value().chars().all(|c| c.is_ascii_digit()));
    assert_eq!(g.strength, "Weak");
    for length in [3, 13, 0] {
        assert!(invalid(generate_pin(length)), "{length}");
    }
}

#[test]
fn draws_are_uniform() {
    // A % reduction of random values would skew this. 60,000 digits: each should come up about
    // 6,000 times, and 20% either way is far outside what chance produces at this size.
    let mut counts = [0u32; 10];
    for _ in 0..5000 {
        for c in generate_pin(12).unwrap().value().chars() {
            counts[c.to_digit(10).unwrap() as usize] += 1;
        }
    }
    for (digit, n) in counts.iter().enumerate() {
        assert!(
            (4800..7200).contains(n),
            "digit {digit} came up {n} times in 60,000"
        );
    }
}

#[test]
fn a_generated_value_is_withheld_from_debug() {
    let g = generate_password(&PasswordOptions::default()).unwrap();
    let rendered = format!("{g:?} {g:#?}");
    assert!(!rendered.contains(g.value()), "{rendered}");
}

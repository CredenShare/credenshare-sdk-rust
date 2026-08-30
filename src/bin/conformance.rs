//! Verify an installed copy of this crate against the packaged wire-specification vectors.
//!
//! ```bash
//! cargo run --bin credenshare-conformance
//! cargo run --bin credenshare-conformance -- -v
//! ```
//!
//! Exits non-zero on any failure, so it works as a deployment gate. Worth running in the
//! environment that will actually do the encrypting: a client that fails these produces content
//! nothing else can read, and that failure is otherwise invisible until somebody opens a link.

use credenshare::conformance;
use sha2::{Digest, Sha256};

fn main() {
    let verbose = std::env::args().any(|arg| arg == "-v" || arg == "--verbose");

    let digest = Sha256::digest(conformance::VECTORS_JSON.as_bytes());
    println!(
        "CredenShare conformance vectors v{}",
        conformance::SUPPORTED_VERSION
    );
    println!(
        "  sha256:{}\n",
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );

    let (passed, failures) = match conformance::run(verbose, &mut |line| println!("{line}")) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };
    if verbose {
        println!();
    }

    if failures.is_empty() {
        println!("{passed} passed. This installation conforms to the wire specification.");
        return;
    }

    for failure in &failures {
        eprintln!("FAIL {}", failure.name);
        for line in failure.reason.lines() {
            eprintln!("     {line}");
        }
    }
    eprintln!("\n{passed} passed, {} FAILED", failures.len());
    eprintln!(
        "This installation does not implement the wire specification correctly. Content it \
         encrypts may be unreadable by every other client, including the web application."
    );
    std::process::exit(1);
}

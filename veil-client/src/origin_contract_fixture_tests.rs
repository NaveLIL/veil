//! Shared canonical Node-origin grammar consumed by Rust and Go tests.

use crate::auth_contract::CanonicalNodeOriginV1;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const CORPUS_BYTES: &[u8] = include_bytes!("../../test-vectors/transport-auth/origin-v1.json");
const REVIEWED_CORPUS_SHA256: &str =
    "42b8fe154439b3dde57a1c3e9c3f845c7a9df04649e6fd85b28ec577fff0ef5c";
const MAX_CORPUS_BYTES: usize = 64 * 1024;
const MAX_CORPUS_ROWS: usize = 256;
const SYNTHETIC_NOTE: &str =
    "Synthetic cross-runtime canonical Node origin grammar only; contains no credentials or production secrets.";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginCorpusV1 {
    schema_version: u32,
    synthetic_only: bool,
    note: String,
    accepted: Vec<String>,
    rejected: Vec<String>,
}

#[test]
fn shared_origin_v1_corpus_matches_rust_validator() {
    assert!(
        !CORPUS_BYTES.is_empty() && CORPUS_BYTES.len() <= MAX_CORPUS_BYTES,
        "origin corpus must be non-empty and bounded"
    );
    assert!(
        !CORPUS_BYTES.contains(&b'\r')
            && CORPUS_BYTES.ends_with(b"\n")
            && !CORPUS_BYTES.ends_with(b"\n\n"),
        "origin corpus must be LF-only with exactly one final LF"
    );
    assert_eq!(
        hex::encode(Sha256::digest(CORPUS_BYTES)),
        REVIEWED_CORPUS_SHA256,
        "origin corpus SHA-256 changed without review"
    );

    let corpus: OriginCorpusV1 =
        serde_json::from_slice(CORPUS_BYTES).expect("strict typed origin corpus JSON");
    assert_eq!(corpus.schema_version, 1, "unsupported origin corpus schema");
    assert!(
        corpus.synthetic_only,
        "origin corpus must be synthetic-only"
    );
    assert_eq!(corpus.note, SYNTHETIC_NOTE, "origin corpus warning changed");
    assert!(
        !corpus.accepted.is_empty()
            && !corpus.rejected.is_empty()
            && corpus.accepted.len() <= MAX_CORPUS_ROWS
            && corpus.rejected.len() <= MAX_CORPUS_ROWS,
        "origin corpus row count is invalid"
    );

    let mut seen = BTreeSet::new();
    for origin in &corpus.accepted {
        assert!(
            seen.insert(origin.as_str()),
            "duplicate origin corpus row {origin:?}"
        );
        let parsed = CanonicalNodeOriginV1::parse(origin)
            .unwrap_or_else(|error| panic!("accepted origin {origin:?} failed: {error}"));
        assert_eq!(parsed.as_str(), origin, "accepted origin was normalized");
    }
    for origin in &corpus.rejected {
        assert!(
            seen.insert(origin.as_str()),
            "duplicate origin corpus row {origin:?}"
        );
        assert!(
            CanonicalNodeOriginV1::parse(origin).is_err(),
            "rejected origin {origin:?} was accepted"
        );
    }
}

EVIDENCE CHECKPOINT ONLY — Phase 5S remains open.

# Phase 5S Direct-v1 transcript checkpoint

Date: 2026-07-20

This checkpoint freezes one synthetic, executable Direct-v1 transcript across
the shared Rust cryptographic, client-orchestration, and SQLCipher boundaries.
It is a regression and review anchor. It is not an independent audit, a proof
of protocol security, a `libsignal` decision, or a stable/production claim.

## Frozen artifact

- `test-vectors/direct-v1/v1.json` contains only deliberately public synthetic
  identities, keys, identifiers, text, nonce, intermediate values, serialized
  states, headers, associated data, and ciphertext.
- `test-vectors/direct-v1/SHA256SUMS` pins the exact JSON bytes. Git attributes
  pin both artifacts to LF so a checkout cannot silently rewrite the evidence.
- The reviewed `v1.json` SHA-256 is
  `dad0a84e5d7366e5189b24c9fb230c4bdd4cc67245607c148b3e3003d9915c2e`;
  the crypto test hard-codes and verifies the same digest and checksum line.
- The fixture names its schema and Direct protocol version. The executable
  oracle/CI gate rejects a changed hash, schema, encoding, length, intermediate
  value, or state byte.
- Base64 fields use canonical padded RFC 4648 encoding. Integer fields used by
  the wire transcript are unsigned big-endian values of the stated width.

The separately composed executable oracle fixes and checks the currently
implemented byte contract:

1. deterministic mnemonic-derived Alice and Bob identity/signing keys;
2. Bob's signed prekey, one-time prekey, signed-prekey domain separation, and
   signature;
3. the X3DH DH ordering, zero-salt HKDF, `veil-x3dh-v1` info, and X3DH identity
   associated data;
4. initial ratchet derivation, chain/message-key derivation, INITIAL prefix,
   ratchet header, and full Direct header;
5. the client Direct associated data and the ratchet AEAD associated data;
6. text framing, fixed-size padding, fixed XChaCha20-Poly1305 nonce/ciphertext,
   and nonce-prefixed transport bytes;
7. exact initiator and responder session JSON before and after the authenticated
   message, plus the pending INITIAL-header JSON.

The fixed nonce and private-key inputs exist only in the committed synthetic
fixture and crate-private `cfg(test)` helpers. Production X3DH, ratchet, and AEAD
entry points continue to obtain randomness from the operating-system CSPRNG;
there is no deterministic public or FFI runtime API.

## Executable boundaries

### Primitive oracle (`veil-crypto`)

The test reconstructs every cryptographic intermediate recorded in the fixture
from the fixed inputs, compares exact bytes, verifies the fixture SHA-256, and
proves that the fixed packet authenticates and decrypts through the production
responder implementation. Negative probes cover a forged signed-prekey
signature and authenticated transcript mutations without accepting plaintext.

### Production orchestration (`veil-client`)

The client test opens a file-backed SQLCipher database from the fixture
mnemonic, hydrates the exact initiator ratchet and pending INITIAL metadata, and
uses the production preparation/commit paths. The header and ratchet state are
exact; two preparations must use different random transport ciphertext while
remaining decryptable from the frozen responder state. The committed state is
checked at durable ratchet revision `1`.

The responder test hydrates the exact SPK/OPK through production storage. Wrong
conversation, mutated header, and mutated ciphertext must leave runtime session,
durable session, OPK, and stored prekeys byte-identical. The original frozen
tuple must still decrypt afterward; only that authenticated success may install
the session and consume the OPK. Its production post-state intentionally includes
a newly random ratchet key; the exact deterministic responder post-state is
therefore asserted only by the crate-private crypto fixture hook, never by a
runtime feature or FFI API.

### Atomic persistence (`veil-store`)

The store test opens, closes, and reopens a real file-backed SQLCipher database.
It checks the exact initiator pre-state and pending INITIAL header at revision
`0`, commits the exact post-message state with the durable outbox transaction,
rejects a stale revision-`0` CAS, then reopens and checks the exact bytes and
revision `1`. This is storage-boundary evidence, not a simulated in-memory row.

The Rust CI path filter includes `test-vectors/**` and `.gitattributes`, so
changing either the frozen artifact or its LF policy still triggers the Rust
test and lint workflow.

## Findings deliberately left open

The fixture made the following review findings concrete; this checkpoint does
not silently repair or accept them:

1. Public `VeilClient::establish_session(peer_identity_key, bundle)` does not
   itself require `peer_identity_key == bundle.identity_key`. The authenticated
   Direct prekey boundary currently performs that check, but misuse of the
   lower-level public method remains possible.
2. X3DH rejects non-contributory X25519 results, but the later Double Ratchet
   receive-DH transition does not yet apply an equivalent all-zero/contributory
   check to a received ratchet key.
3. `X3DHResult.associated_data` is not passed directly into Direct messaging.
   The client constructs a larger versioned Direct AAD instead. This exact
   behavior is now frozen, but the divergence requires protocol review.
4. Direct AAD binds the conversation ID, ordered identity keys, and wire prefix,
   but not the canonical Node origin, account IDs, or device IDs. Hostile-Node,
   first-contact, and proper multi-device semantics therefore remain open.
5. Non-empty skipped-key session serialization is based on an unordered map,
   and its current deserializer silently drops malformed-length entries. The
   frozen initial transcript has no skipped keys and does not close canonical
   serialization, corruption, exhaustion, or rollback work.

### Follow-up ledger — 2026-07-20

| Finding | Current host-only status |
| --- | --- |
| 1, exact peer/bundle identity | Hardened by the host-tested [Direct-v1 key-validation checkpoint](phase-5s-direct-v1-key-validation-checkpoint.md) |
| 2, contributory received ratchet DH | Hardened by the same key-validation checkpoint using the actual X25519 shared result before state publication |
| 3–5 | Open; AAD review/origin-device binding and skipped-key serialization/exhaustion/rollback remain Phase 5S work |

Owners, residual resolution/acceptance criteria, and external review remain part
of the Phase 5S gate. No ledger entry authorizes plaintext fallback, automatic
session reset, or a weakened origin boundary.

## Evidence and non-claims

Required checkpoint commands are:

```text
cargo fmt --all -- --check
cargo clippy -p veil-crypto -p veil-store -p veil-client --all-targets -- -D warnings
cargo test -p veil-crypto -p veil-store -p veil-client
```

Checkpoint verification on the final fixture SHA produced:

- `veil-crypto`: 93 unit and 8 integration tests passed;
- `veil-store`: 91 tests passed;
- `veil-client`: 171 unit tests passed, 11 explicitly ignored legacy tests, and
  4 integration tests passed;
- combined format and all-target Clippy with `-D warnings` passed;
- the post-fix independent diff review reported no remaining P0/P1/P2.

The resulting Git commit belongs in the handoff/release record. This document
does not claim Android FFI or UI consumption of the fixture,
desktop-to-Android interoperability, physical device evidence, a signed tester
APK, hostile-Node resistance, first-contact key transparency, Sesame-like
session lifecycle, a completed `libsignal` spike, or an independent
cryptographic audit. All remain explicit blocking work in the Phase 5S and
Android Direct Preview gates.

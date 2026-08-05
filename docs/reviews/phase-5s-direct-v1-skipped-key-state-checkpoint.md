EVIDENCE CHECKPOINT ONLY — Phase 5S remains open.

# Phase 5S Direct-v1 skipped-key/state checkpoint

Date: 2026-07-20

This host-only checkpoint hardens the persisted Double Ratchet skipped-message
key path from `veil-crypto` through `veil-client`, SQLCipher, and the standalone
mobile FFI. It is not an independent cryptographic audit, a protocol migration,
a `libsignal` decision, or a production-readiness claim.

## Compatible persisted-state contract

The existing Direct-v1 top-level JSON and `skipped_keys` object shape remain in
place. No wire, AAD, KDF, cipher, header, or frozen transcript byte changed.

- Each member name is canonical padded RFC 4648 Base64 for exactly 32 ratchet
  public-key bytes, one `:`, and the canonical unsigned decimal `u32` message
  number. The value is canonical padded Base64 for exactly 32 message-key bytes.
- Writers sort by raw ratchet public-key bytes and then numeric message number;
  consequently message `2` sorts before message `10`.
- Readers accept every historically valid member order, but reject malformed
  delimiters, decimal aliases, invalid or unpadded Base64, wrong lengths,
  duplicate JSON/logical entries, and more than 5000 entries.
- Readers reject JSON backslash escapes before deserialization. The Veil v1
  writer has never emitted escapes for this Base64-and-numeric schema; rejecting
  equivalent hand-crafted aliases prevents secret text from entering an opaque
  parser scratch allocation that cannot be explicitly wiped.
- A valid old non-empty row is not rewritten during startup. Its member order is
  normalized only when a later authenticated ratchet transition is committed.
- The frozen initial states still contain `"skipped_keys":{}`. The immutable
  `test-vectors/direct-v1/v1.json` SHA-256 remains
  `dad0a84e5d7366e5189b24c9fb230c4bdd4cc67245607c148b3e3003d9915c2e`.

The production decoder is bounded to a 1 MiB ratchet document and now validates
the whole persisted shape: unknown top-level fields, a missing or non-canonical
32-byte sending secret, a secret/public mismatch, any chain combination outside
the responder-initial, initiator-pre-receive, and authenticated-live allowlist,
an authenticated-live state with `Nr = 0`, and a current-chain skipped key at or
ahead of `Nr` all fail closed. The private
persisted wire type is reachable only through the explicit bounded crypto API;
client hydration, state comparison, and `VeilRatchet` FFI all delegate to that
same entry point. A public raw Serde decoder for `RatchetSession` is no longer
exposed.

Secret Base64 intermediates, partially decoded skipped-key maps, rejected
serialized output, and persisted-row wrappers are explicitly zeroized where
owned by these paths.

## Exhaustion and exception semantics

Per-chain gaps remain bounded by `MAX_SKIP = 1000`; the total cache remains
bounded by 5000 keys. Both checks happen before KDF/state mutation, use
overflow-safe counter differences, and return an error. The old arbitrary
`HashMap.keys().next()` eviction is removed, so a restart or another runtime
cannot select a different victim.

Decrypt still mutates a cloned candidate and publishes it only after AEAD
authentication. Capacity errors, counter exhaustion, malformed state, and
authentication failure leave the exact live serialization unchanged. Cached
late packets remain usable after a rejected packet.

This follows the Double Ratchet exception rule and skipped-key cap guidance in
the [Signal Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/),
sections 3.5, 8.4, and 8.7. The legitimate initial responder state with no
receiving chain remains supported.

## SQLCipher publication and rollback boundary

All ratchet reads and writes now share the 32-byte peer-key and 1 MiB per-state
bounds. One native epoch may hydrate at most 4096 rows and 64 MiB of aggregate
serialized ratchet state. Startup checks at most 4097 rows before failing the
row limit, then validates every admitted row, including an orphan not yet
published into an origin-authorized runtime route. A malformed or over-cap row
set aborts and scrubs initialization; it is never silently converted to “no
session” or automatically replaced.

Fresh SQLCipher files create `ratchet_sessions` as `WITHOUT ROWID`, eliminating
the hidden conflict key that could otherwise bypass peer-key guards through raw
`INSERT OR REPLACE`. Existing rowid-backed files are losslessly rebuilt into
that canonical shape inside the same `BEGIN IMMEDIATE` transaction that installs
the capacity guard. The preflight accepts only the three physical legacy shapes
proved by Git history: the original table, that table after its sole appended
`revision` ALTER, and the later fresh-install column order. The oldest shape
receives revision zero only inside the copy transaction; there is no separately
committed preliminary ALTER.

Normalized exact DDL, `STRICT`/`WITHOUT ROWID` markers, primary-key index
topology, main/TEMP triggers and views, foreign keys, and the reserved capacity
objects are checked before mutation. Unknown constraints, case-insensitive name
collisions, future columns, extra autoindexes such as table-level `UNIQUE`, or
external dependencies fail closed rather than being discarded.

The derived additive SQLCipher capacity table plus transactionally maintained
triggers apply the row/aggregate limits to every current ratchet INSERT, UPDATE,
and DELETE path before commit. Metadata is reconstructed from a bounded durable
scan on every open; the exact table and triggers are recreated rather than
trusting an older same-name schema. Existing reserved objects must be either
absent or the complete exact V1 set before replacement. Insert conflict forms
cannot replace an existing peer session, successful grow/shrink/delete
operations update the aggregate only after the real row operation, and a later
transaction failure rolls the aggregate back with the ratchet and private
message rows.

Every existing-session transition uses compare-and-swap over all three values:

1. exact peer identity key;
2. expected SQLCipher revision;
3. exact expected serialized session bytes.

The advanced ratchet is published only if that tuple still matches. Direct
outbox enqueue applies the same exact-state predicate inside its existing
message/outbox transaction. Initial initiator and authenticated responder state
use insert-only publication; neither path may overwrite an existing session.
An ACK does not write or increment ratchet state because the send transition was
already durable.

File-backed tests open multiple SQLCipher handles from the same starting
revision. The first accepts an out-of-order packet and durably caches skipped
keys; stale Direct-history and desktop/general receivers then authenticate old
candidates but lose the exact-state CAS, cannot commit a message or ratchet, and
revoke their runtimes as storage-uncertain. The durable row is rewritten into a
valid historical member order without advancing its revision; a fresh process
hydrates it without eager normalization, then consumes both cached late packets.

## Migration boundary

This hardening does not migrate or reinterpret serialized ratchet JSON. Old
valid JSON member order remains readable, and the existing
`ratchet_sessions.revision` column supplies the live-database CAS counter.

It does perform a physical SQLCipher schema migration for a legacy rowid-backed
`ratchet_sessions` table. After an exact schema/dependency check and bounded
row/byte preflight, one `BEGIN IMMEDIATE` transaction copies the exact peer key,
session bytes, and `updated_at`, preserves an existing revision or synthesizes
the historical default zero, and publishes a `WITHOUT ROWID` table. It verifies
both directions of the copied row set, removes the legacy table, and installs
freshly derived capacity metadata and triggers. The same transaction rolls back
on any mismatch. Reopen is idempotent, while an unknown no-revision future
column, constraint, index, dependency, or reserved-object collision leaves the
legacy schema and rows untouched and aborts the open.

The additive `ratchet_session_capacity_v1` metadata contains no ratchet secret
bytes and is atomically reconstructed from bounded existing rows on every open.

A versioned dual-reader and transactional migration are still required before
changing the `skipped_keys` object shape, persisting insertion age/generation,
changing counter or field meaning, adding origin/account/device/session binding
to state, or changing wire/AAD/KDF/libsignal semantics. The CAS revision is not
a serialization-version discriminator.

## Executable evidence

Focused host tests cover:

- exact canonical bytes across insertion/member order, including numeric
  ordering for `2` and `10`;
- malformed, non-canonical, duplicate, 5001-entry, unknown-field, mismatched-DH,
  impossible-chain, global-cap, per-chain 1000/1001, and `u32::MAX` probes;
- failed skipped-key authentication without consumption;
- bounded standalone FFI deserialize/serialize parity with a non-empty
  out-of-order skipped-key cache and historical member order;
- file-backed corrupt-state restart without replacement;
- exact revision-and-bytes CAS, same-revision equivocation, two-handle stale
  write rejection, insert-only initial publication, unchanged ACK state, and
  SQLCipher row/aggregate capacity rollback;
- fresh `WITHOUT ROWID` storage, lossless migration of all three historical
  legacy shapes with positive and negative rowids, raw-rowid DML rejection, and
  idempotent reopen;
- fail-closed preservation of no-revision future columns, extra `UNIQUE`
  autoindexes, additional `CHECK`/`STRICT` semantics, external main/TEMP
  triggers and views, mixed-case reserved-name collisions, and unknown capacity
  objects or dependencies;
- real skipped-key cache persistence, process reopen, late delivery, and message
  transaction rollback on stale history and desktop/general receivers;
- exact receive-snapshot rollback of Sender-Key distribution-pending state when
  a control frame is rejected on the chat-message path.

Required final commands for this checkpoint are:

```text
cargo fmt --all -- --check
cargo clippy -p veil-crypto -p veil-store -p veil-client -p veil-ffi --all-targets -- -D warnings
cargo test -p veil-crypto -p veil-store -p veil-client -p veil-ffi
```

The final host run passed format and all-target Clippy with `-D warnings`, then:

- `veil-crypto`: 100 unit and 8 integration tests;
- `veil-store`: 108 unit tests;
- `veil-client`: 177 unit tests passed, 11 explicitly ignored superseded tests,
  and 4 integration tests passed;
- `veil-ffi`: 84 unit tests.

Independent internal read-only reviews of the crypto/FFI, store/migration, and
client/contract boundaries found no remaining P0, P1, or P2 after their findings
were fixed and the final host gate was rerun. These reviews are executable
engineering evidence, not the independent external cryptographic audit still
required by Phase 5S. The resulting checkpoint commit is recorded in Git
history.

## Explicit residual risks and non-claims

- Skipped keys still have no deterministic event-age/generation retention
  metadata. They are bounded but can remain until consumed or an explicit
  future versioned policy removes them.
- Exact-state CAS prevents concurrent/stale-writer rollback in one live
  SQLCipher history. It cannot detect rollback of the complete database file,
  where state and revision are restored together; that needs an external
  non-rollbackable anchor and threat-model decision.
- Direct AAD still lacks canonical Node origin, account IDs, and device IDs.
- Sender-Key hydration still combines durable load/migration failures and
  missing-generation rejection behind an older string-returning helper. The
  Direct pairwise paths covered here are typed; a broader all-inbound typed
  contract remains future work.
- The legacy public `process_initial_message` helper now refuses existing
  runtime/durable sessions and revokes on typed storage uncertainty, but it is
  context-free and does not authenticate an AEAD packet. Only the authenticated
  receive path is evidence for responder publication; the legacy helper is not
  a production protocol claim.
- `DirectMessageOutboxEnqueueV1` gained an exact expected-state field and the
  old blind save API was removed while these crates remain unpublished preview
  `0.x` workspace APIs. If an external downstream has treated that Rust source
  surface as stable, it requires a versioned V2/compatibility bridge.
- Hostile-Node, first-contact key transparency, Sesame-like lifecycle,
  multi-device, cross-runtime desktop/Android vectors, and the isolated
  `libsignal` spike remain open Phase 5S work.
- No Android device, ADB, APK, Pass, recovery, or server operation was performed
  for this checkpoint. Physical testing remains intentionally deferred by the
  user.
- This checkpoint does not make Preview, unaudited cryptography, or any demo UI
  production-ready.

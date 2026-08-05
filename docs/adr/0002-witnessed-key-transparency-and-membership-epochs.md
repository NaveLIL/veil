# ADR 0002: witnessed key transparency and authorized membership epochs

- Status: accepted for staged implementation; no security claim until the exit
  gates below pass
- Date: 2026-08-04
- Scope: first-contact account/device identity and Circle/Space membership
  authorization under a malicious or compromised Node

## Decision

Veil will use two separate, composable protocols:

1. A per-origin append-only Merkle log records immutable account registrations,
   account-authorized device-binding versions, and forward-only recovery/key
   transition events. A Node signs each tree head, clients pin and verify
   consistency from their last accepted head, and independently operated
   witnesses or client gossip countersign/compare the exact same head.
2. Each encrypted Circle/Space has a predecessor-linked, monotonically numbered
   membership epoch. The epoch commits to the complete account/device roster,
   authorization policy, crypto profile/era, and predecessor. A transition is
   accepted only with the signatures required by the previous epoch's policy.
   Sender-Key or MLS key material may target only the exact accepted epoch.

The protocols solve different problems. Transparency establishes which
account/device chain an origin has published consistently. Membership epochs
establish which of those accounts were authorized to receive a particular
group key. Neither protocol is replaced by TLS, account signatures, Sender
Keys, MLS, or a signature made only by the potentially malicious Node.

## Threat model and limits

The design must detect or fail closed on:

- first-contact account-key substitution and split views;
- removal, reordering, rollback, or equivocation of account/device events;
- two different roots for one `(origin, log_id, tree_size)`;
- a valid but inconsistent newer tree head;
- reuse of a stale inclusion proof under another head or origin;
- group-roster rollback, same-epoch equivocation, skipped predecessors, and an
  unauthorized membership transition;
- Sender-Key/MLS delivery to a roster that differs from the accepted epoch.

The design does not hide IP addresses, timing, message sizes, Node membership,
or availability. A Node and every configured witness may collude. A first-ever
client with no pinned or witnessed checkpoint still needs an out-of-band
fingerprint/QR comparison for immediate authentication.

## Transparency v1

### Hash grammar

All integers are unsigned big-endian. All origins are already validated exact
canonical origins; the cryptographic layer rejects non-ASCII, empty, or
overlong values and never normalizes them.

```text
empty_root = SHA-256("veil-transparency-empty-v1\0")
leaf_hash  = SHA-256("veil-transparency-leaf-v1\0" || u32(len(event)) || event)
node_hash  = SHA-256("veil-transparency-node-v1\0" || left[32] || right[32])
```

The tree shape is the history-tree shape from RFC 6962: for a non-power-of-two
size, split at the largest power of two smaller than the size. Veil uses its own
domains and canonical events, so a proof from a generic CT log cannot be
replayed into Veil.

The Node tree-head signature covers:

```text
"veil-transparency-sth-v1\0"
u16(origin_len) || canonical_origin
log_id[32]
tree_size_u64
root_hash[32]
issued_at_ms_u64
```

`log_id` is permanently bound to the origin and Node transparency public key.
Changing that key is a visible, versioned log transition; deleting/recreating a
log is not recovery. Tree size and timestamp cannot use JSON numbers at a
JavaScript boundary and are encoded as canonical decimal strings on HTTP.

### Canonical events

V1 event kinds are account registration, device-binding version, witness-key
change, and explicit account-recovery transition. Every event commits to the
canonical origin and fixed-size identifiers/keys. Account registration is
unique for `(origin, account_uuid)`; device events include account UUID, device
ID, binding version, status, capabilities, both device keys, account signature,
and the preceding binding commitment.

The PostgreSQL transaction that creates an account or appends a device binding
also appends exactly one transparency leaf and advances the compact Merkle
frontier. A response exposing the new identity is unavailable until the same
transaction commits. Direct SQL mutation that bypasses the event append is
blocked by constraints/triggers and startup auditing.

### Client acceptance

A directory result is usable only when all of the following hold:

- its canonical event has an exact inclusion proof under the supplied head;
- the head has a valid Node signature for the configured origin/log key;
- the head is identical to, or has a valid append-only consistency proof from,
  the highest head pinned in SQLCipher/OS-protected state;
- every configured mandatory witness signature is valid, fresh enough, and
  covers the exact head; and
- gossip has not observed a different root at the same log size.

Until the witness policy and gossip path are active, this state is named
`Transparency checked (unwitnessed)`, never `Verified`. Local account-v2
fingerprint/QR verification remains authoritative for explicit human
comparison and survives only for the exact identity tuple already implemented.

## Membership epoch v1

An epoch commits to:

```text
canonical origin
conversation UUID and conversation kind
epoch number and predecessor epoch hash
complete sorted account/device roster commitment
authorization-policy commitment
crypto profile and era
effective mutation nonce
```

Epoch 1 is signed by the transparently resolved conversation owner. Epoch
`N+1` is accepted only if it names the exact hash of epoch `N`, increments by
one, and satisfies epoch `N`'s signature policy. The initial policy is a
threshold over designated administrator accounts; self-removal and recovery
use explicit rules and cannot silently weaken the threshold. Signers are
account keys resolved through Transparency v1, and signatures are domain
separated from ordinary account/device authentication.

The Node atomically stores the authorized product mutation and its epoch. A
server ACL snapshot without the required client signatures cannot advance the
cryptographic membership epoch. Clients pin epoch number/hash, reject rollback
or same-number equivocation, and gossip epoch heads. Sender-Key v5 distribution
and messages add the exact membership epoch number/hash; MLS uses the same
application authorization check around proposal/commit processing. A roster
change blocks encryption until the new epoch and exact per-device key
distribution are durable.

## Migration and compatibility

- Existing Direct v2 and Sender-Key v5 history remains readable under its
  explicit historical profile. No record is relabeled as transparent or
  membership-authorized retroactively.
- Transparency is introduced read-only first: shared proof primitives and
  fixtures, database append/audit, proof endpoint, client pinning, then witness
  enforcement. Production activation is one-way per origin and has no fallback
  to an unproved directory result.
- Membership epochs are introduced as a new crypto era. Existing channels stay
  on the current fail-closed Sender-Key v5 path until all active devices advertise
  the capability and an authorized epoch-1 ceremony completes.
- Offline clients retain proof/epoch history needed for delayed ciphertext.
  Bounds fail closed with explicit remediation; they do not silently evict an
  unacknowledged security era.

## Rejected alternatives

- **Node signature only:** permits the Node to sign two split views.
- **Hash chain only:** gives linear-size first-contact/inclusion verification
  and is not operationally scalable.
- **Server ACL plus monotonic roster version:** detects local rollback after
  observation but lets a malicious Node authorize and reveal keys to its own
  account.
- **MLS alone:** authenticates MLS state transitions but does not define Veil's
  product-level administrator or membership authorization policy.
- **Global third-party-only service:** breaks self-hosting and creates one new
  universal trust/availability dependency. Multiple optional/mandatory
  witnesses plus client gossip preserve deployment choice.

## Exit gates

No stable security claim is permitted until:

1. Rust and Go share exact vectors for event encoding, tree roots, inclusion,
   consistency, tree-head signatures, and mutation rejection.
2. Account/device writes and log append are one PostgreSQL transaction; startup
   audit detects any legacy/bypassed row and proof endpoints are bounded.
3. SQLCipher and OS-backed pinning reject head rollback after database restore;
   two clients detect a simulated Node split view through witness/gossip.
4. Every active desktop/Android directory and Direct first-contact path requires
   the activated proof policy without downgrade.
5. Membership mutations require predecessor-policy signatures and every
   Sender-Key/MLS path binds the exact epoch; hostile roster equivocation,
   rollback, concurrent mutation, removal, and offline recovery matrices pass.
6. At least two independent implementations verify the fixture corpus, fuzzing
   covers proof parsers/state machines, and an external cryptographic audit has
   no unresolved mandatory finding.

# ADR-0004: Clean Slate v0.3 and open-source protocol preference

- Status: Accepted
- Date: 2026-08-30
- Target release: v0.3.0 Preview

## Context

Veil is still pre-release and has no compatibility obligation to deployed
message history. The v0.2.0 security cutover deliberately retained read-only
support for historical Direct v1 and Sender-Key v5 data, an Android identity
vault migration adapter, 4-5 digit desktop PIN unlock, and a retired `/ws`
tombstone. Those paths were useful while the integrated beta line was being
promoted, but keeping them indefinitely increases review surface and creates
more states that must remain fail-closed.

Veil also contains a substantial amount of protocol orchestration designed in
this repository. The primitives are supplied by established libraries, but
group membership, key distribution, persistence, recovery, and version
negotiation remain application-owned security decisions. Continuing to add new
custom protocol generations would slow development and increase assurance
cost.

## Decision

Veil v0.3 is a controlled clean-slate release.

1. New runtime paths do not preserve old message ciphertext, ratchet state, or
   Sender-Key state merely for compatibility.
2. Account identity, device identity, Node configuration, and explicit trust
   decisions are preserved when their current representation satisfies the new
   invariants. Message history being disposable does not authorize a silent
   identity reset.
3. A version mismatch fails closed and offers an explicit local messaging-state
   reset. It never silently selects an older protocol.
4. Circle and Space/Room group encryption move to MLS through OpenMLS after the
   persistence, identity binding, offline, concurrency, and platform gates in
   this ADR pass.
5. Direct v2 remains the active one-to-one protocol until a two-party MLS
   implementation proves equal or better reliability and usability. There is
   no permanent dual-protocol fallback.
6. After the MLS group cutover, Sender Keys and their compatibility storage are
   deleted in the same release line. After a future Direct cutover, the replaced
   X3DH/Double-Ratchet orchestration is deleted by the same rule.

## Open-source selection policy

For security-sensitive functionality, prefer a maintained open standard and a
maintained open-source implementation over a new Veil-specific protocol when
all of the following hold:

- its threat model and security properties match Veil's requirement;
- its license is compatible with AGPL-3.0-or-later distribution;
- releases, advisories, and dependency provenance can be pinned and monitored;
- Veil owns and tests every application boundary that the library intentionally
  leaves to the caller, including authentication, persistence, delivery,
  rollback protection, limits, and user-visible recovery;
- desktop and Android behavior is verified, rather than inferred from a library
  build succeeding;
- replacing the component does not require a silent downgrade or weaken the
  existing fail-closed behavior.

An open-source dependency is not accepted only because it is popular or newer.
The repository records the selected version, known advisories, local patches,
and the reason for every security-critical fork or vendored copy.

## Clean-slate inventory

### Remove before the v0.3 runtime cutover

- desktop unlock support and UI copy for 4-5 digit legacy PINs;
- Android SharedPreferences identity-vault migration code once clean reset
  behavior is covered by tests;
- the retired `/ws` handler and its compatibility response;
- Direct v1 and Sender-Key v5 history-only parsing/storage after the new
  messaging-state epoch is enforced;
- pre-activation Sender-Key v5 creation after new groups start with an
  authenticated membership epoch;
- originless caches, legacy pre-key publication receipts, and other migration
  branches that are proven unreachable from the v0.3 runtime;
- documentation and tests that advertise a removed runtime mode. Adversarial
  downgrade tests and frozen security vectors remain when they still protect a
  current invariant.

### Do not remove by name alone

- `/v1/...` resource paths: they are an API namespace and currently use REST
  authentication v2;
- Direct v1-named primitive/vector code that still defines or tests the active
  Direct v2 ratchet until Direct itself is replaced;
- migration files until the fresh baseline and VPS recreation procedure are
  independently tested;
- fail-closed parsers, hostile-Node tests, transparency proofs, rollback
  barriers, and audit evidence.

## Implementation checkpoint: persisted messaging epoch

Implemented on 2026-08-31. SQLCipher `client_state` stores the current epoch as
an exact eight-byte big-endian value. Opening an older or unversioned vault
performs one `BEGIN IMMEDIATE` transaction that removes messages, attachments,
ratchets, pending headers/outboxes, Sender-Key material and inactive MLS
prototype state, then publishes the v0.3 marker. The transaction retains
account/device identity, explicit trust, transparency state, membership epoch
history, Node configuration/cache and conversation metadata.

The derived plaintext search index is cleared before it can be attached to the
new client epoch. A durable one-time notice is acknowledged only after unlock;
the desktop surfaces it without requiring security choices during ordinary
messaging. An unknown newer epoch or malformed marker aborts without deleting
any row.

## MLS integration gates

OpenMLS runtime activation requires all of the following:

- an reviewed upgrade from the current pinned dependency graph with no ignored
  applicable security advisory;
- MLS credentials bound to the exact Veil account identity, device identity,
  binding version, canonical Node origin, and transparency state;
- an atomic SQLCipher-backed storage provider whose state commit happens before
  ciphertext release and whose obsolete secrets are durably deleted;
- a rollback-detection anchor outside the replaceable SQLCipher database;
- bounded KeyPackage publication/consumption and authenticated Delivery Service
  operations;
- deterministic handling of concurrent commits, reordering, replay, removal,
  offline catch-up, rejoin, process death, and exhausted KeyPackages;
- hostile-Node, parser/fuzz, restart, power-loss, desktop/Android interop, and
  physical-device evidence;
- no manual security ceremony during ordinary send, receive, reconnect, or
  group membership changes.

## Data cutover

The v0.3 cutover may delete message rows, attachments, ratchet sessions,
Sender-Key material, MLS prototype state, outbox entries, and derived search
indexes. Before any VPS database recreation, operators take a recoverable
encrypted backup and verify the exact target database. Account/device identity,
Node access policy, and transparency continuity are migrated or explicitly
re-established; they are not treated as disposable message history.

The v0.2.0 tag remains the historical source and schema reference. The live
v0.3 repository does not retain a downgrade mode to read that state.

## Delivery sequence

1. Land this ADR, roadmap status, and a mechanically checked legacy inventory.
2. Remove low-risk compatibility surfaces and add explicit version barriers.
3. Upgrade and harden the isolated OpenMLS foundation without activating it.
4. Integrate MLS group delivery and persistence behind tests.
5. Perform one atomic group cutover and delete Sender Keys.
6. Evaluate two-party MLS separately before changing Direct.
7. Run the complete CI and physical release matrices, update operator docs,
   publish v0.3.0 Preview artifacts, and only then consider a new tag.

## Consequences

Users of development builds can lose local message history and may need one
explicit messaging-state reset. Normal post-reset messaging remains automatic;
MLS internals are not exposed as routine UI choices. The codebase becomes
smaller only after replacement paths satisfy their security and UX gates, so
freshness does not create a temporary protection gap.

# ADR-0005: Immutable authenticated events, sync and retention

- Status: **Proposed — not accepted and not a production protocol change**
- Date: 2026-10-04
- Scope: roadmap R07 and the design portion of R10; prerequisites for R08/R09/R12
- Existing protocol authority: [ADR-0004](0004-clean-slate-v0.3-and-open-source-crypto.md)

## Context and verified defect

`messages` currently combines delivery history and a mutable display projection.
`UpdateMessageCiphertext` replaces ciphertext; `SoftDeleteMessage` clears ciphertext/header.
The original encrypted steps cannot subsequently be reconstructed from that row.
`GetConversationHistoryPage` provides one authorized Repeatable Read snapshot per
page, including attachments/reactions, but uses `created_at` or `(created_at,id)`
as its incremental cursor. Migration `001_initial.sql` defaults `created_at` to
`now()`. PostgreSQL fixes that value at transaction start, rather than commit:
[date/time semantics](https://www.postgresql.org/docs/16/functions-datetime.html).

The [integration characterization](../../veil-server/internal/db/event_order_experiment_integration_test.go)
uses actual `StoreMessage`, `StoreMessageTx` and `GetConversationHistoryPage`:
transaction A starts; B commits; a reader checkpoints B; A commits with its older
timestamp. A is visible in full history but missed by both current incremental
cursors. A separate `BIGSERIAL` experiment reproduces the same inversion.
These tests characterize a live defect; a passing test does not repair it.

The isolated conversation-counter experiment verifies a candidate remedy:
the next writer actually waits on a PostgreSQL row lock, the reader sees only
the committed head, an unrelated conversation continues, and rollback does not
publish an event or consume a committed coordinate. Locks are retained to the
transaction boundary under [PostgreSQL row-lock semantics](https://www.postgresql.org/docs/16/explicit-locking.html).
Production roster/device/ACL lock interactions have not been proved by this
experiment. [Watermill SQL](https://watermill.io/pubsubs/sql/) also documents the
commit-order cursor problem; importing its offset API is not this proposal.

## Proposed event contract

Keep `messages` as a derived projection. Introduce a retained, immutable event
stream and a separately mutable retention policy. The names below describe the
contract, not an approved migration or wire format.

| Record | Required scope and meaning |
| --- | --- |
| Conversation head | `(node/origin, conversation, history_era)` plus committed `last_seq` and `replay_floor`; no reuse across eras |
| Event identity | Canonical `event_id`, author account/device, client mutation identity, logical message identity, event kind and profile/format version |
| Delivery coordinate | `(conversation, history_era, seq)`; assigned by Node at commit, never an E2E authenticity claim |
| Authenticated envelope | Exact immutable bytes, recipient/session binding and authenticated application operation; optionally several explicitly targeted device envelopes |
| Projection | Logical message, `creation_seq`, latest validated `revision_seq`, visibility and attachment references; never a replacement for the event stream |
| Native checkpoint | Origin/account/device/conversation/history era/profile scope, verified event digests, delivery scan position and durable cryptographic state |

An authenticated application operation must bind its kind, logical target,
author/device context and client mutation identity. The Node assigns `seq` after
encryption; it cannot be included in a pre-existing author's AEAD as if the
author had authenticated it. Current Direct v2 associated data binds session,
sender/recipient devices and wire prefix; its session transcript carries
additional conversation/origin context. **This does not establish that today's
wire bytes authenticate the new event kind or logical mutation target.** A
reviewed canonical encoding and fixtures must establish those bindings before
R08 enables this contract. This ADR does not choose a new signature scheme,
invent a Direct generation or bypass ADR-0004's protocol gates.

The Rust core remains responsible for origin/account/device/session binding,
trust/transparency, membership epoch, profile and content validation. A Node
delivery coordinate provides an honest-Node ordering property. It does not
prove that a malicious Node delivered all events or could not suppress them;
stronger omission detection would need a separately reviewed witness protocol.

| Operation | Cryptographic and projection behavior |
| --- | --- |
| Create | New authenticated encrypted application event; advances the applicable receive state once; creates projection |
| Edit | New encrypted application step authenticating its logical target; retains original and intervening steps for replay; updates projection only after validation |
| Author delete | Authenticated application control with defined author/scope rules; if encoded as a ratchet application message, it advances that ratchet once; immediately hides the validated target |
| Reaction or other author control | Must explicitly specify whether it is a ratchet application message or a reviewed independently authenticated control before being admitted to the feed |
| Node expiry, purge, ACL change | Delivery/storage policy metadata; cannot impersonate author delete, advance an E2E ratchet or restore revoked access |

The receiver processes required original create/edit/delete steps even when
the final display is hidden. It does not display a deleted original while
replaying it. Unknown kind/profile/version fails closed for the affected
conversation; it does not become a plain-text fallback or an ignored crypto
step. Server-side permission checks supplement author authentication, including
explicit moderator scope if moderator deletion is later specified.

## Commit order and mutation boundary

All mutations in a conversation acquire the same head row and retain its lock
through commit. Increment the counter in that transaction, append the immutable
event, update its projection, persist the idempotency outcome, and enqueue only
a delivery reference using the evaluated River `InsertTx` adapter. Rollback
removes all five effects. No provider/network operation runs under these locks.
An allocated coordinate is not published before commit; reusing one which was
rolled back and never published is permitted. Independent conversations do not
share a global writer lock.

Before implementation, enumerate send/edit/delete/reaction, roster changes,
device binding/revoke, channel purge and attachment admission in one lock graph.
Preserve Serializable security checks and bounded retry of the complete
transaction on `40001`/`40P01`. The counter experiment alone does not authorize
changing isolation. Exact idempotent replay looks up a retained outcome before
requiring a still-existing conversation: deletion/TTL must not turn an already
accepted send into a new attempt. A timeout or lost ACK after commit remains an
uncertain outcome to resolve using the exact original identity/bytes.

Commit ordering is not a replacement for sender ratchet ordering. Existing
prepared-envelope ownership must serialize local mutations appropriately;
bounded out-of-order receive support still applies. Missing required sender
steps cannot be fabricated from a consecutive Node sequence.

## Bootstrap, incremental pages and live overlap

Use an opaque cursor scoped to origin, account, device, conversation, history
era and feed format. At bootstrap capture `H = committed last_seq`, eligibility
and `replay_floor` in one authorized snapshot. Fetch a closed window `(C,H]`
in bounded pages. Each HTTP request opens a new short authorized snapshot and
checks current ACL/device binding; no SQL transaction spans requests. A revoke
can invalidate the next page. The existing Repeatable Read page boundary is a
useful implementation starting point, with [snapshot semantics](https://www.postgresql.org/docs/16/transaction-iso.html).

Retain an explicit `scan_through` bound separate from encrypted-event progress.
A global conversation stream can contain envelopes for other devices. Those
gaps do not authorize decrypting their ciphertext or pretending to take their
ratchet steps. A response must account for its scanned range without disclosing
foreign envelopes; the exact eligibility/skip representation is an acceptance
gate. A client advances its scan checkpoint only after its complete page has
been validated and durably stored. It must not infer progress from the largest
WS sequence it happens to see. Server scan metadata has the honest-Node limit
stated above; it is not an author-authenticated completeness proof.

REST and WS carry one canonical event representation into one Rust processor.
WS hints do not grant authority. During bootstrap, use the existing bounded
native live buffer; fetch through fixed H, deduplicate overlapping live events,
then catch up beyond H before entering steady live mode. Overflow, reconnect or
a gap starts a bounded REST catch-up; it does not discard events and advance C.
Directory reconciliation has its own scoped watermark, including removal
markers, so lost WS cannot hide newly accessible or deleted conversations.
The separation of snapshot, incremental token and live delivery is informed by
[Matrix sync](https://spec.matrix.org/latest/client-server-api/#syncing), not a
claim that Matrix tokens provide Veil's crypto guarantees.

In one SQLCipher transaction, native receive commits verified digest, crypto
transition, projection and checkpoint. The same event ID and authenticated
bytes/context are a duplicate and take no second crypto step. The same ID with
different bytes/context is a conflict: isolate the conversation, keep its
checkpoint and expose an explicit error. Validation failures cannot advance
the checkpoint. Storage uncertainty revokes authority for the entire runtime,
using the existing storage safety boundary, rather than allowing other
conversations to continue with an unreliable store. Tauri and UniFFI consume
the same outcomes; mobile `UnsupportedMessage` gates stay until those outcomes
and operations are implemented.

## Proposed retention and recovery policy

These are concrete **proposed** operational values for review, not deployed
defaults or promises about the existing service:

| Data | Candidate policy |
| --- | --- |
| Replay ciphertext/envelopes | 30-day replay horizon; retain every required crypto step within the advertised replayable window |
| Validated author delete | Hide immediately; allow up to 24 hours of replay grace, then purge original payloads; an immediate-purge mode must explicitly forfeit affected offline replay |
| Expired messages | Hide at expiry; payload purge follows the declared policy and advances the affected replay floor if a required step becomes unavailable |
| Delivery reference jobs | No plaintext, keys or duplicated ciphertext; cancel/finish expired or inaccessible references with bounded cleanup |
| Attachments | Revoke projection access immediately; purge blob and metadata after no retained event/reference requires them, with the same documented deletion deadline |
| Backups | Proposed maximum 14 days; restoration must enforce current deletion/floor/era metadata before serving or replaying anything |
| Replay floor and era tombstones | Retain for the history era lifetime; prevent a stale cursor from reopening a purged range |
| Send idempotency outcome | Minimal digest/ACK metadata survives payload and conversation purge; account lifetime until a separately specified era-closure barrier can prove no old prepared outcome remains unresolved |

The floor F is the highest coordinate at/below which required replay is no
longer guaranteed. Purging a required step at k raises F to at least k, even if
some earlier payload remains locally displayable. A checkpoint C < F receives
`resync_required`, never a partial success silently omitting k. A device at or
above F may continue only if its scoped native crypto state is valid. A missing
target-device step or a crypto skip-window failure can require resync even if
the global cursor passes the floor. New devices cannot inherit another device's
checkpoint and keys.

Resync uses an explicit, authenticated re-establishment/rejoin path permitted
by ADR-0004, preserving identity, trust and transparency. It does not enlarge
`MAX_SKIP`, replay a latest projection as missing history or implicitly advance
the ratchet. This necessarily trades old offline recovery for deletion. The UI
must state what history is unavailable before an explicit messaging reset.

Deletion also applies to local search/cache/projection and attachment storage.
Retained minimal tombstones and current era metadata suppress resurrection from
an old backup; a restored Node must reconcile them before readiness. Media
backend deletion and backup expiry require verified jobs outside SQL locks.
These deadlines do not claim secure physical erasure of arbitrary SSD blocks.
Operational values and the backup tombstone authority remain review gates.

## Cutover and rollback plan

1. Accept a reviewed event authentication/encoding contract, eligibility format,
   numerical retention policy and recovery protocol. Publish version/era
   capability requirements explicitly. Build fixtures before enabling writes.
2. Implement the shared lock graph, migrations, processor and dual-write
   characterization behind a disabled capability. Existing message/ACK
   semantics remain authoritative until an announced cutoff. Compare outputs;
   do not label mutable legacy rows a complete cryptographic event history.
3. Inventory every immutable prepared outbox envelope. Resolve it with its old
   exact client identity/digest and retained server ledger. Accepted outcomes
   retain their ACK; proven unaccepted outcomes follow an explicit reviewed
   cancellation/retry rule. An unknown outcome blocks migration of that send
   context; do not create a new intent and re-encrypt it automatically.
4. At the controlled boundary stop admission and drain bounded commands. Under
   the common coordination and per-conversation locks, establish era/head/floor
   metadata, then publish the new capability. A deterministic backfill may
   provide a display baseline; replaced legacy edit ciphertext cannot be
   recovered. Such histories require an explicitly labelled limited baseline
   or the controlled messaging-state reset already allowed by ADR-0004.
5. Native storage migration atomically records the era/version, settles or
   preserves blocking prepared states, and installs new messaging authority.
   Preserve account/device identity, Node configuration, trust and transparency.
   Reuse existing SQLCipher messaging-version and rollback-anchor boundaries;
   malformed/newer versions fail closed. Clear obsolete search/cache state.
6. Enable the shared processor on desktop and FFI only after identical fixtures
   pass. Old runtimes reject the new format/cutoff explicitly; no downgrade.
   Direct v2 remains active unless its separate replacement gate passes. Group
   MLS cutover keeps its own validated membership and persistence gates.
7. Remove obsolete compatibility paths only after release verification and
   documented recovery. Once crypto authority/anchor or deletion floor has
   advanced, rollback to an old backup is not a safe runtime rollback. Recovery
   restores identities and policy metadata, then explicitly re-establishes
   messaging; it never silently reinstalls old secrets or deleted history.

Migration crashes before/after each SQL commit, local commit, anchor update,
capability publication and old-path removal need fixtures. Startup/readiness
must refuse partially applied or schema-drift states. No cutover or acceptance
is performed by this document.

## Required examples and acceptance evidence

| Scenario | Required outcome |
| --- | --- |
| Live create → edit → delete | Three validated application transitions exactly once; hidden final projection; replay payload follows declared grace |
| Offline through the same operations | Consume original/intermediate steps without displaying deleted content, then the same final state |
| Lost WS event, later event arrives | Do not checkpoint the later hint; REST fills the closed gap and duplicate overlap is harmless |
| Same event replay after restart | Digest/context match; no second ratchet transition, projection mutation or delivery side effect |
| Same ID, different authenticated bytes | Conflict; no checkpoint movement; conversation isolated |
| Unknown profile/era/format | Explicit unsupported/resync outcome; no fallback and no state advancement |
| Device excluded or revoked mid-page series | Current authorized page boundary is honored; next page denies access; foreign envelopes stay undisclosed |
| Purge while device offline | Replay floor is durable; old cursor gets explicit resync; no fake missing step |
| Restore a pre-delete/pre-cutover backup | Current tombstone/era authority prevents resurrection; stale crypto authority fails closed |
| Retry after channel/message purge | Retained ledger resolves exact old outcome without requiring the conversation row |
| Concurrent send/edit/delete/revoke | One tested lock graph; unique committed sequences and no mixed security snapshot or unbounded retry |
| Crash after external notification | Idempotent worker may run again; provider delivery is not claimed exactly once |

Before acceptance resolve: canonical author-authenticated operation encoding;
device eligibility/scan representation and its privacy bounds; delete/moderator
authorization; target-device replay floor semantics; retention numbers and
backup deletion authority; safe Direct re-establishment and group rejoin;
prepared-outcome closure barrier; deployment locking and contention budgets.
Security/protocol review must accept these choices, and integration/native
fixtures must verify them. The present SQL experiment satisfies only the
commit-order characterization and isolated counter part of that evidence.

## Implementation status

R07 and the design portion of R10 have a reviewable proposal. They are not
accepted. R08 production schema/feed, R09 shared native processor and R10
retention/cutover remain unimplemented. R11's evaluated River adapter is not
wired into production R12 and does not settle this ADR's event/device contract.

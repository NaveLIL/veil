# ADR-0001: Authenticated Sender Keys v5 for server channels

- Status: Accepted and implemented Phase 4C baseline; residual risks are listed below
- Date: 2026-07-11
- Scope: text channels and group conversations
- Owners: Veil client, desktop, crypto, and server maintainers

## Context

Veil has two related but different structures:

- a **server** contains membership, roles, permission overwrites, and channels;
- every text **channel** owns a unique backing conversation UUID.

The server persists and routes opaque message ciphertext. It also decides which
authenticated users currently have channel access. It must not possess a channel
message key. Treating a whole server as one cryptographic group would make every
channel share key lifecycle, history, and blast radius even when its permissions
differ.

The current group/channel implementation uses one outgoing Sender Key state per
sender device and conversation. A raw symmetric v4 message proves possession of
the chain key, but every recipient knows that key and could therefore impersonate
the sender. Veil wraps the v4 ciphertext in a v5 envelope signed by the sender's
pinned device Ed25519 identity, whose versioned binding is account-authorized.
Sender Key Distribution Messages (SKDMs) use the signed, sealed v3 format.

The database also contains an older, unused `channel_epochs` design. No runtime
code reads or writes `channel_epochs`, `channel_key_envelopes`, or
`messages.channel_epoch`. That design conflicts with the active per-sender model
and must not become an accidental second channel crypto protocol.

The Phase 4C roster is cryptographically per-device. Each installation has
independent X25519 and Ed25519 keys authorized by an account signature. The
gateway resolves an exact, versioned conversation roster and retains a distinct
sealed SKDM for each target device. Sender, target, binding versions, roster
version/commitment, and the immutable envelope commitment travel as one route
tuple.

This ADR defines the implemented Sender Keys v5 baseline and the remaining
trust, migration, and resource-policy boundaries. Acceptance does **not** claim
identity transparency or activate future crypto profiles such as MLS.

## Threat and trust boundary

The baseline protects message contents from the transport/server and prevents a
normal group member from forging another member's v5 messages. It assumes local
device secrets and pinned sender bindings are not compromised.

The service remains authoritative for account authentication, current
membership, roles, channel permissions, routing, and availability. Consequently,
E2EE does not hide metadata and does not by itself prevent a malicious service
from omitting members, presenting inconsistent rosters, withholding ciphertext,
or causing denial of service. Continuity pinning detects unexpected account or
device-key replacement, binding rollback, same-version equivocation, and
revoked-device resurrection after a binding has been observed. A first
historical observation for a former sender is still service-mediated TOFU: the
account-signed chain is pinned atomically, but without transparency or
out-of-band verification the service can misattribute a previously unseen
identity. The UI MUST NOT label that state as verified.

A recipient that already learned plaintext or a generation key cannot be made to
forget it. Rotation limits future access; it is not retroactive erasure.

## Decision

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

### 1. A server is a container; a channel is a security domain

1. A server MUST remain an authorization and routing container. It MUST NOT have
   a server-wide message encryption key.
2. Every text channel's backing `conversation_id` MUST be an independent
   cryptographic security domain.
3. Sender Key state, generation counters, roster version, retained SKDMs,
   capability profile, and history policy MUST be scoped to that conversation
   UUID. Display names and mutable channel positions are not cryptographic IDs.
4. Keys MUST NOT be reused across channels, even inside the same server and even
   when their member sets currently match.
5. Voice and category rows are not implicitly text security domains. They need a
   separate ADR before carrying encrypted media or messages.
6. Direct messages remain Double Ratchet conversations. A DM MUST reject Sender
   Key distributions and Sender Key message frames.

The server may evaluate server roles and channel overwrites to produce the
authorized roster, but the resulting key distribution is still channel-local.

### 2. The baseline wire profile is authenticated Sender Keys v5

For a live group/channel message:

- the authenticated conversation type MUST select Sender Key mode before the
  untrusted frame is parsed;
- the outer message MUST be exact v5;
- the embedded ciphertext MUST be the context-bound v4 form;
- the signature MUST verify with the sender's independently pinned Ed25519 key;
- the signed data MUST bind the exact conversation UUID, claimed X25519 sender
  identity, and complete inner v4 bytes;
- the v4 AEAD context MUST bind the conversation UUID, sender identity,
  generation, iteration, and header;
- malformed lengths, trailing bytes, unknown versions, unknown identities, and
  identity/signing-key mismatches MUST fail closed without advancing ratchets.

Raw v4 is a low-level primitive only. It MUST NOT be emitted or accepted as a
network group/channel message. The gateway cannot enforce this rule for opaque
chat ciphertext; every receiving client MUST enforce it.

For current Sender Key distribution:

- the wire envelope MUST be signed and sealed SKDM v3;
- public v3 metadata is an untrusted routing hint only;
- live traffic MUST resolve the sender and target against the exact current,
  pinned device roster before verifying the signature and AEAD;
- retained traffic MAY carry the exact historical account-authorized sender
  binding that authenticated the route when it was committed. A first
  historical observation MUST be pinned atomically as unverified
  service-mediated TOFU; any conflict with an existing account/device pin MUST
  fail closed;
- after route proof is resolved, the recipient MUST cross-check conversation,
  sender account/device identities and binding version, signing identity,
  recipient account/device identities and binding version, roster version and
  commitment, generation, and immutable envelope commitment before installation;
- a generation older than installed state MUST be rejected; the same generation
  MAY be accepted idempotently only when it represents the same authenticated
  state;
- legacy unauthenticated sealed formats MUST fail closed.

The separately typed, Double-Ratchet-protected legacy SKDM control payload is not
permission to retry an invalid v3 envelope. No receive path may fall back to it
after v3 parsing or authentication fails. New channel distribution MUST use v3.

### 3. No silent downgrade

Crypto mode is authenticated conversation state, not a guess derived from a
wire header or a failed decryption attempt.

1. An unsupported or unknown conversation crypto profile MUST block send and
   receive with an explicit error.
2. A channel frame whose E2EE header conflicts with the pinned conversation type
   MUST be rejected. It MUST NOT be retried as a DM, plaintext, raw v4, another
   SKDM version, or an older mode.
3. Failure to verify v5 or v3 MUST NOT trigger compatibility fallback.
4. A database default such as `crypto_mode = 'sender_key'` is only a legacy-data
   default. It MUST NOT override a newer authenticated profile advertised for an
   existing conversation.
5. Historical frames MAY be decoded by the profile recorded for their migration
   era. That does not permit old-profile frames as new live traffic after cutover.

### 4. The roster is an authorization input and a cryptographic snapshot

#### Current state

The server derives a user roster from conversation membership plus current
server membership, role permissions, and channel overwrites, then expands it to
active account-authorized device bindings. The client verifies and pins the
canonical roster commitment, monotonic roster version, account keys, independent
device keys, capability bits, binding status/version, and account signature. A
sender seals once per exact non-self target device. The gateway commits that
immutable route before its transport ACK and retained replay preserves the
original account-authorized sender proof even after later roster churn.

#### Per-device target

The cryptographic roster is a versioned expansion of each authorized user into
active devices. Every entry MUST contain at least:

- `user_id` and stable `device_id`;
- an independent device encryption identity;
- an independent device signing identity;
- a monotonic device-binding version and applicable capability bits;
- supported crypto profiles and versions;
- active, revoked, or excluded status;
- an account-authorized binding that clients can verify against the pinned user
  identity.

The roster snapshot MUST bind the conversation UUID and a monotonically
increasing `roster_version`. Clients MUST reject rollback and unexpected key
replacement. An SKDM MUST be sealed separately for each target device key; one
user-sealed blob MUST NOT be copied across devices.

Authorization remains user/role based. Cryptographic delivery is device based.
Adding, removing, revoking, replacing, or changing the capabilities of a device
changes the cryptographic roster even when server membership does not change.

### 5. Sending gate and acknowledgements

A new outgoing generation MUST NOT encrypt application content until its SKDMs
have been durably accepted for the exact current roster snapshot.

The distribution transaction is identified by:

`(conversation_id, sender_device_id, generation, roster_version)`.

Every target device has an independent envelope and durable-storage result. A
roster change while distribution is in flight invalidates the transaction: the
sender MUST rotate again, distribute to the new snapshot, and keep sending
blocked. An ACK for an older generation or roster version MUST NOT unblock it.

Waiting for every device to come online would make offline members block a
channel indefinitely. Therefore:

- a server ACK MAY unblock sending only after all per-device envelopes for that
  exact snapshot are committed durably and monotonically;
- such an ACK means **stored by the transport**, not installed or read by the
  recipient;
- device receipt/install ACKs permit exact retained-row garbage collection and
  diagnostics, but are not the online sending gate;
- the UI MUST NOT call a transport ACK "delivered to device" or "read".

The client associates each request sequence with an immutable
`(conversation, generation, roster, target-device, envelope-commitment)` tuple
and accepts an ACK only when its explicit metadata matches. The gateway ACKs an
outbound SKDM only after the exact per-device row is durable. A recipient queues
its install receipt only after SQLCipher commits the generation, historical
route proof, account signing pin, and device-binding anchor; the gateway prunes
only the matching retained row.

An installation receipt attests only that this exact SKDM is durably installed.
It does not attest that every later REST history row exists or decrypts, and it
MUST NOT be delayed on that unrelated condition: doing so would turn a missing
history row into a retained-key storage denial of service.

### 6. Rotation

Each sender device owns an independent monotonically increasing generation in
each security domain. Generations MUST NOT wrap or be reused.

Rotation is mandatory:

- before first send when no valid outgoing state exists;
- after any authorized user is added or removed;
- after permissions change so that channel-read authorization changes;
- after any target device is added, revoked, replaced, excluded, or changes an
  applicable capability;
- after sender-device compromise/revocation or local key replacement;
- before exceeding the chain iteration limit;
- at an explicit crypto-profile migration cutover;
- whenever authoritative roster continuity cannot be established.

All rotations use the sending gate above. Rotation protects future traffic. Old
messages are not re-encrypted, and removal cannot revoke keys or plaintext that a
former member already possessed.

The baseline does not require wall-clock-only rotation: the chain advances per
message and membership/device changes are stronger lifecycle boundaries. A
deployment MAY add a time limit, but it must use the same monotonic generation
and complete-distribution gate.

A locally prepared roster-triggered generation is a pending current-head
transition, not permission to send. If later history sync quarantines that
conversation, the client invalidates its live roster proof and suppresses
fan-out, but retains the immutable pending generation. Reconnect MUST reuse that
exact generation and retry tuple rather than create another rotation.

### 7. History and offline devices

The default channel history policy is **future-only key admission**:

- a newly authorized user or device receives current and future generations, not
  old generation keys;
- it may be authorized to download old ciphertext while still being unable to
  decrypt pre-join content;
- sharing old keys requires a separate, explicit, auditable history-sharing
  feature and MUST NOT occur as a side effect of joining;
- a removed user may retain content and keys learned before removal, but MUST
  receive neither later SKDMs nor later ciphertext through authorized endpoints.

For a device that was already authorized but offline, the transport MUST retain
every unacknowledged generation needed to decrypt ciphertext sent during its
authorized interval. On reconnect it MUST re-evaluate current authorization and
deliver retained control state in generation order before dependent ciphertext.

Retained storage MUST therefore distinguish generations. It MUST NOT overwrite
generation N merely because N+1 arrived before the device acknowledged N. A
device receipt ACK may permit collection of older retained envelopes. A bounded
retention policy is allowed, but expiry MUST be explicit and surface history as
unavailable; it MUST NOT silently present ciphertext as corrupt.

The implemented Phase 4C bound is 128 unacknowledged generations per exact
server stream and 128 retained generations per client
`(conversation, sender-device)`. The 129th admission fails before mutating
durable or in-memory key state and before queuing a receipt; it is not resolved
by silently evicting an older generation. Retained restore is all-or-nothing
within one conversation and isolated between conversations, so a malformed,
expired, oversized, or conflicting backlog cannot partially install that
conversation or prevent healthy conversations from restoring.

Removed or no-longer-authorized devices MUST NOT receive queued SKDMs. Deleting a
queued envelope does not erase a key already installed on that device.

### 8. Capability negotiation and crypto-mode migration

`sender_key_v5 + sealed_skdm_v3` is the only active server-channel baseline.
The MLS schema and library work are experimental foundation, not an active
desktop channel mode.

Future profiles require explicit, versioned capabilities per active device. A
profile can be selected only if every device in the intended roster supports it,
unless an explicit administrative policy first excludes or revokes unsupported
devices and visibly changes the roster.

A migration uses two phases:

1. **Prepare**: publish the target profile, monotonically increasing migration
   epoch, exact roster version, required suites, and device acknowledgements;
   continue sending only in the old profile.
2. **Cut over**: after all required acknowledgements, atomically pin the new
   profile and migration epoch, install/distribute its key state, emit a visible
   system event, and reject new live frames in the old profile.

Rollback is permitted only before cutover. After cutover, rollback is another
explicit forward migration with a new epoch. Historical messages retain their
recorded profile/epoch so they can be decoded without enabling an old live mode.
Mixed-mode opportunistic sending and decrypt-failure-based fallback are forbidden.

### 9. Deprecate the unused channel-epoch path

The following schema is deprecated and reserved only for compatibility analysis:

- `channel_epochs`;
- `channel_key_envelopes`;
- `messages.channel_epoch`.

Production code MUST NOT begin using these objects. They do not define the
Sender Keys v5 baseline and MUST NOT be treated as a fallback.

They are not dropped by this ADR because migrations may already exist in user
databases. A future cleanup migration may remove them only after:

1. confirming no released runtime consumed them;
2. checking deployed databases for unexpected data;
3. defining backup/rollback behavior;
4. verifying no historical decoder depends on `messages.channel_epoch`.

Unexpected data MUST stop automatic cleanup and require an explicit migration
decision.

## Current implementation evidence

| Invariant | Current enforcement |
| --- | --- |
| Text channel has a unique backing conversation | [`servers.go`](../../veil-server/internal/db/servers.go) creates `conv_type = 2`, copies members, and assigns `channels.conversation_id`; [`001_initial.sql`](../../veil-server/migrations/001_initial.sql) makes it unique. |
| Channel access is dynamic, not membership-row-only | [`conversation_acl.go`](../../veil-server/internal/db/conversation_acl.go) combines conversation membership with current server membership, roles, and channel permissions. |
| Channel overwrite resolution is deterministic and fail-closed | [`channel_overwrites.go`](../../veil-server/internal/db/channel_overwrites.go) applies `@everyone`, aggregate role, then member tiers; [`016_channel_permission_invariants.sql`](../../veil-server/migrations/016_channel_permission_invariants.sql), [`channel_overwrites_test.go`](../../veil-server/internal/db/channel_overwrites_test.go), and [`channel_acl_parity_integration_test.go`](../../veil-server/internal/integration/channel_acl_parity_integration_test.go) lock database/runtime parity and concurrent mutation behavior. |
| Server stores/routes opaque ciphertext | [`chat.go`](../../veil-server/internal/chat/chat.go) authorizes and fans out messages without decrypting them. |
| v5 sender authentication and context binding | [`sender_key.rs`](../../veil-crypto/src/sender_key.rs) signs the exact group, sender identity, and inner v4 bytes, and verifies before transactional ratchet advancement. |
| Signed/sealed SKDM v3 | [`sender_key.rs`](../../veil-crypto/src/sender_key.rs) binds sender, signing key, recipient, group, generation, ephemeral key, signature, and AEAD context. |
| Conversation type is selected before wire parsing | [`api.rs`](../../veil-client/src/api.rs) checks that the E2E header agrees with the pinned conversation mode and rejects unknown headers/plaintext. |
| Account-authorized per-device identities and immutable history | [`013_device_bindings.sql`](../../veil-server/migrations/013_device_bindings.sql) introduces signed, versioned device bindings; [`device_bindings.go`](../../veil-server/internal/db/device_bindings.go) and [`device_identity.rs`](../../veil-client/src/device_identity.rs) build and verify them. [`019_cryptographic_identity_history.sql`](../../veil-server/migrations/019_cryptographic_identity_history.sql) makes account keys, device route keys, device crypto keys, and historical binding versions immutable. |
| Monotonic, canonical per-conversation device roster | [`017_conversation_roster_linearization.sql`](../../veil-server/migrations/017_conversation_roster_linearization.sql), [`device_roster.go`](../../veil-server/internal/db/device_roster.go), and [`runtime_roster.go`](../../veil-server/internal/gateway/runtime_roster.go) linearize revisions and commitments; [`api.rs`](../../veil-client/src/api.rs) verifies canonical entries, account signatures, rollback, same-version equivocation, and current authorization. |
| Exact per-device route and historical proof | [`chat.proto`](../../veil-proto/veil/v1/chat.proto) fields 4–18 bind the target device, both binding versions, roster version/commitment, immutable envelope commitment, and historical sender proof. [`sender_key_device_routing.go`](../../veil-server/internal/gateway/sender_key_device_routing.go), [`connection.rs`](../../veil-client/src/connection.rs), and [`api.rs`](../../veil-client/src/api.rs) enforce the tuple on the server, wire barrier, and client. |
| Membership or device-roster changes rotate and block | [`api.rs`](../../veil-client/src/api.rs) rotates on authoritative roster replacement, including an empty target set, and keeps sending blocked until the exact durable ACK set completes. The `changed_roster_rotates_even_when_old_generation_is_still_prepared_and_zero_targets_complete` regression covers stale prepared state and the zero-target transition. |
| Rotation persistence is atomic | [`db.rs`](../../veil-store/src/db.rs) commits the new outgoing state and invalidates old retry envelopes in one SQLCipher transaction. The client prepares state on a clone and publishes it in memory only after commit; injected-failure tests prove rollback preserves both the old live generation and immutable cache. `cold_restore_conservatively_rotates_once_when_roster_continuity_is_unknown` and `cold_restore_early_hydration_cannot_cause_a_second_rotation` prove pending `N+1` is reused rather than replaced by `N+2`. Generation exhaustion fails without wrap/reuse. |
| Iteration-limit rotation uses the same send gate | [`api.rs`](../../veil-client/src/api.rs) rotates into pending state and returns without ciphertext; the boundary regression test proves retries reuse that generation until distribution completes. |
| Immutable multi-generation retained distribution | [`014_sender_key_device_routing.sql`](../../veil-server/migrations/014_sender_key_device_routing.sql) and [`015_sender_key_retention_policy.sql`](../../veil-server/migrations/015_sender_key_retention_policy.sql) preserve an exact row per generation and make expiry fail closed rather than destructive. [`queries.go`](../../veil-server/internal/db/queries.go) serializes admission, rejects stale/equivocating retries, and never replaces an accepted commitment. [`sender_key_integration_test.go`](../../veil-server/internal/gateway/sender_key_integration_test.go) covers two-generation restore, retry immutability, expiry, receipts, and the bound. |
| Exact transport ACK and installation receipt | [`sender_key_device_routing.go`](../../veil-server/internal/gateway/sender_key_device_routing.go) emits an ACK only after the exact row commits; [`sender_key_receipt.go`](../../veil-server/internal/gateway/sender_key_receipt.go) collects only the receipt's exact route. [`api.rs`](../../veil-client/src/api.rs) matches ACK metadata to its immutable request cache and queues a receipt only after SQLCipher commits the key, route, proof, and pins. |
| Retained restore is conversation-atomic and conversation-isolated | [`queries.go`](../../veil-server/internal/db/queries.go) reports bounded backlog metadata per conversation and [`sender_key_integration_test.go`](../../veil-server/internal/gateway/sender_key_integration_test.go) proves one unavailable conversation does not suppress a healthy one. Client savepoints and runtime snapshots in [`api.rs`](../../veil-client/src/api.rs) are covered by `retained_conversation_batch_rolls_back_an_earlier_success_before_diagnosing` and `retained_failure_is_isolated_to_its_conversation`. |
| Multi-generation state survives restart and decrypts both eras | [`db.rs`](../../veil-store/src/db.rs) persists incoming keys by conversation, sender device, and generation; [`sender_key.rs`](../../veil-crypto/src/sender_key.rs) selects the authenticated generation. The client regression `exact_device_skdm_restores_and_decrypts_two_generations_after_restart` exercises a file-backed SQLCipher restart. |
| Bounded history fails closed without cross-conversation mutation | The server enforces 128 generations per exact stream plus target-wide row/byte bounds in [`queries.go`](../../veil-server/internal/db/queries.go); `TestSenderKeyRetentionDeadlineAndBound`, `TestSenderKeyTargetWideBacklogBound`, and its concurrent-admission variant exercise them. Client tests `live_sender_key_generation_cap_blocks_only_the_affected_conversation` and `hydration_rejects_oversized_generation_history_without_partial_heap_state` in [`api.rs`](../../veil-client/src/api.rs), crypto test `retained_generation_cap_rejects_129th_without_mutating_other_conversations` in [`sender_key.rs`](../../veil-crypto/src/sender_key.rs), and store test `incoming_sender_key_generation_retention_cap_is_fail_closed_and_scoped` in [`db.rs`](../../veil-store/src/db.rs) prove rejection happens before partial durable/heap state or a receipt and another conversation remains usable. |
| Retained TOFU is explicit and transactional | [`api.rs`](../../veil-client/src/api.rs) labels first-seen historical identity as unverified service-mediated TOFU and atomically stores the account/device pins with the key and route. `retained_first_seen_tofu_conflict_rolls_back_key_route_and_receipt` proves a conflicting pin leaves none of those artifacts behind. |
| AuthResult is a hard live/retained barrier | [`connection.rs`](../../veil-client/src/connection.rs) sends only pre-AuthResult retained rows through historical processing; post-barrier events stay in live FIFO and require the exact current roster. `first_post_barrier_skdm_stays_live_fifo_and_requires_exact_current_roster` locks in the race boundary. |
| Message rows preserve their security era | [`018_message_security_context.sql`](../../veil-server/migrations/018_message_security_context.sql) adds fail-closed profile, era, roster, and sender-device context. [`migration_upgrade_integration_test.go`](../../veil-server/internal/integration/migration_upgrade_integration_test.go) verifies upgrades and structural constraints; [`security_integration_test.go`](../../veil-server/internal/integration/security_integration_test.go) exercises authorization and message-context boundaries. |
| DM rejects Sender Keys | [`sender_key_integration_test.go`](../../veil-server/internal/gateway/sender_key_integration_test.go) covers DM rejection alongside exact device routing, replay, malformed metadata, retained restore, and receipts. |
| MLS is not the active runtime baseline | [`008_mls.sql`](../../veil-server/migrations/008_mls.sql) and the experimental MLS crates provide groundwork; the current support boundary is also documented in [`veil-server/README.md`](../../veil-server/README.md). |
| Channel epochs are unused | [`005_servers.sql`](../../veil-server/migrations/005_servers.sql) is the only current source reference for those objects. |

## Residual risks and future work

The obsolete per-device fan-out, multi-generation retention, immutable retry,
exact receipt, and duplicate-rotation gaps are closed by the Phase 4C baseline.
The following boundaries remain deliberately open:

1. **Service-mediated TOFU has no transparency proof.** Account signatures,
   immutable binding history, monotonic roster versions, and continuity pins
   detect rollback or replacement after observation, but a malicious service can
   still misattribute a previously unseen account/device chain. Phase 4D needs
   out-of-band verification and, separately, an auditable transparency or
   consistency design. Until then, first-seen historical identities remain
   explicitly unverified.
2. **Future crypto-profile migration is not implemented.** The active baseline
   is only `sender_key_v5 + sealed_skdm_v3`. MLS or any successor still requires
   the two-phase, authenticated migration epoch described above, complete device
   capability agreement, historical-era decoding, and no decrypt-failure
   fallback.
3. **Resource policy is bounded but not operationally complete.** Phase 4C caps
   each exact stream/client sender history at 128 generations and the server also
   caps each target device's aggregate retained rows and bytes. It does not yet
   define deployment-wide/account-wide storage budgets, quota observability, or
   a complete user/operator remediation flow when expiry or a bound makes history
   unavailable. Remediation MUST be explicit and MUST NOT silently evict keys or
   acknowledge an SKDM that was not durably installed.
4. **Device and account-key recovery needs a versioned ceremony and UI.** The
   baseline intentionally makes current account keys, device route keys, and
   historical bindings immutable. Lost-device replacement, account-key rotation,
   durable local binding-head repair, revocation/exclusion diagnostics, and
   history-unavailable UX need an explicit forward-only protocol; in-place key
   rewriting remains forbidden.
5. **Deprecated channel-epoch objects still require an operator-safe cleanup.**
   They remain unused by production Sender Keys, but may be removed only after
   the audit and reversible migration preconditions in section 9 are satisfied.

## Completed Phase 4C sequence and next migrations

1. **Completed:** freeze the deprecated channel-epoch path and add conformance
   coverage for v5/v3 parsing, ACL, rotation, migration, and offline ordering.
2. **Completed:** route iteration-limit and roster-change rotations through one
   pending generation and the exact distribution gate before ciphertext.
3. **Completed:** retain immutable generations independently, add exact durable
   route commitments and authenticated installation receipts, and enforce the
   fail-closed 128-generation bound without silent eviction.
4. **Completed:** introduce account-authorized independent device identities,
   capability/status bindings, append-only binding history, and a monotonic,
   canonical per-conversation device roster.
5. **Completed:** make exact per-device v5/v3 routing the only live channel path;
   retained restore carries its historical proof and neither live nor retained
   failure falls back to account-routed, raw v4, DM, or plaintext handling.
6. **Completed:** bind immutable retry, transport ACK, install receipt, rotation,
   and restored state to the exact device/generation/roster/commitment tuple;
   prove conversation-atomic restore and multi-generation restart recovery.
7. **Next profile work:** implement the two-phase crypto-profile migration state
   machine before enabling MLS or any successor in desktop channels.
8. **Next identity work (Phase 4D):** design out-of-band verification and a
   transparency/consistency model without overstating TOFU as verification.
9. **Next operations work:** specify aggregate storage budgets and explicit
   device/history remediation for expired, over-bound, lost, or revoked state.
10. **Later cleanup:** audit deployed databases, then remove deprecated
    channel-epoch objects in a dedicated reversible migration only when no
    required data exists.

## Consequences

### Positive

- Private channels inside one server have independent compromise and lifecycle
  boundaries.
- Recipients authenticate the claimed sender instead of trusting symmetric-key
  possession.
- Membership/device churn has an explicit future-secrecy boundary and send gate.
- Offline delivery remains possible without waiting for devices to reconnect.
- Future MLS work has a fail-closed migration contract instead of an implicit
  fallback path.

### Costs

- Per-device envelopes and retained generations increase storage and fan-out.
- Permission and device changes can temporarily block sending while a new roster
  snapshot is committed.
- Clients must persist profile, roster, generation, ACK, and history-era metadata
  transactionally.
- Device registration/revocation becomes part of the cryptographic protocol, not
  only account administration.

## Rejected alternatives

- **One server-wide key:** rejected because channel permissions and histories are
  different security domains.
- **One shared unsigned channel key:** rejected because any member can forge any
  sender and compromise has server-wide/channel-wide impact.
- **Raw Sender Key v4 on the network:** rejected because it does not authenticate
  the claimed sender against other key holders.
- **Wait for every device to be online before sending:** rejected because an
  offline device could indefinitely deny service; durable per-device commit is
  the availability boundary.
- **Give old keys automatically to new members/devices:** rejected because it
  silently changes history access and defeats future-only admission.
- **Select a mode by trying decryptors:** rejected because it creates downgrade
  and parser-confusion paths.
- **Revive `channel_epochs` for compatibility:** rejected because it creates a
  second, unaudited lifecycle beside the accepted per-sender v5 model.

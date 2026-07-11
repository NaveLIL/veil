# ADR-0001: Authenticated Sender Keys v5 for server channels

- Status: Accepted baseline; implementation gaps are listed below
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
sender and conversation. A raw symmetric v4 message proves possession of the
chain key, but every recipient knows that key and could therefore impersonate the
sender. Veil wraps the v4 ciphertext in a v5 envelope signed by the sender's
pinned Ed25519 identity. Sender Key Distribution Messages (SKDMs) use the signed,
sealed v3 format.

The database also contains an older, unused `channel_epochs` design. No runtime
code reads or writes `channel_epochs`, `channel_key_envelopes`, or
`messages.channel_epoch`. That design conflicts with the active per-sender model
and must not become an accidental second channel crypto protocol.

The current roster is user-oriented. The gateway expands a target user identity
to all registered device rows and stores the same user-sealed SKDM for each row.
That is useful durable fan-out, but it is not cryptographic per-device delivery:
devices do not yet have independently bound E2EE identities and capabilities.

This ADR defines the accepted baseline, names current conformance gaps, and sets
the migration target. Acceptance of the ADR does **not** mean every target item
is already implemented.

## Threat and trust boundary

The baseline protects message contents from the transport/server and prevents a
normal group member from forging another member's v5 messages. It assumes local
device secrets and pinned sender bindings are not compromised.

The service remains authoritative for account authentication, current
membership, roles, channel permissions, routing, and availability. Consequently,
E2EE does not hide metadata and does not by itself prevent a malicious service
from omitting members, presenting inconsistent rosters, withholding ciphertext,
or causing denial of service. Continuity pinning detects unexpected identity
replacement after a binding has been observed; a future per-device design must
add account-signed device bindings and rollback-resistant roster versions.

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
- the recipient MUST locate an already authenticated/pinned sender binding, then
  verify the signature and AEAD and cross-check conversation, sender identity,
  signing identity, recipient identity, and generation before installation;
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
server membership, role permissions, and channel overwrites. The client validates
and pins each user's X25519/Ed25519 binding. A sender distributes once per
non-self user identity; the gateway atomically stores that envelope for every
currently registered target device row before acknowledging it.

This is the accepted transitional behavior, not the final multi-device model.

#### Per-device target

The cryptographic roster MUST become a versioned expansion of each authorized
user into active devices. Every entry MUST contain at least:

- `user_id` and stable `device_id`;
- an independent device encryption identity;
- an independent device signing identity;
- the device's current pre-key/session binding;
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
- device receipt/install ACKs SHOULD be added for queue garbage collection,
  diagnostics, and honest delivery status, but are not the online sending gate;
- the UI MUST NOT call a transport ACK "delivered to device" or "read".

Today the client tracks transport ACKs by request sequence and the gateway ACKs
after atomic fan-out to current device rows. This approximates the durable gate
at user granularity. The target protocol must bind ACKs explicitly to generation,
roster version, sender device, and target devices rather than relying only on a
connection-local sequence number.

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
| Server stores/routes opaque ciphertext | [`chat.go`](../../veil-server/internal/chat/chat.go) authorizes and fans out messages without decrypting them. |
| v5 sender authentication and context binding | [`sender_key.rs`](../../veil-crypto/src/sender_key.rs) signs the exact group, sender identity, and inner v4 bytes, and verifies before transactional ratchet advancement. |
| Signed/sealed SKDM v3 | [`sender_key.rs`](../../veil-crypto/src/sender_key.rs) binds sender, signing key, recipient, group, generation, ephemeral key, signature, and AEAD context. |
| Conversation type is selected before wire parsing | [`api.rs`](../../veil-client/src/api.rs) checks that the E2E header agrees with the pinned conversation mode and rejects unknown headers/plaintext. |
| Membership changes rotate and block | [`api.rs`](../../veil-client/src/api.rs) rotates on authoritative live-session roster replacement, conservatively rotates a restored outgoing generation when cold-start roster continuity is unavailable, and tracks pending distribution; [`lib.rs`](../../veil-desktop/src-tauri/src/lib.rs) refreshes/invalidates rosters on server events. The desktop offline-sync path may currently add a second forced rotation, so exact-once restore rotation is not claimed. |
| Iteration-limit rotation uses the same send gate | [`api.rs`](../../veil-client/src/api.rs) rotates into pending state and returns without ciphertext; the boundary regression test proves retries reuse that generation until distribution completes. |
| Durable gateway fan-out | [`hub.go`](../../veil-server/internal/gateway/hub.go) validates routing metadata and current ACL, resolves target devices, stores before ACK, and then performs best-effort live fan-out. |
| Monotonic retained distribution | [`queries.go`](../../veil-server/internal/db/queries.go) atomically upserts distributions and rejects stale generations; [`009_security_constraints.sql`](../../veil-server/migrations/009_security_constraints.sql) constrains the generation range and foreign keys. |
| Retained SKDM precedes offline ciphertext sync | [`lib.rs`](../../veil-desktop/src-tauri/src/lib.rs) installs retained control state after authenticated directories are pinned and before backlog decryption. |
| DM rejects Sender Keys | [`sender_key_integration_test.go`](../../veil-server/internal/gateway/sender_key_integration_test.go) covers DM rejection, durable device fan-out, replay, malformed metadata, and stale generation behavior. |
| MLS is not the active runtime baseline | [`008_mls.sql`](../../veil-server/migrations/008_mls.sql) and the experimental MLS crates provide groundwork; the current support boundary is also documented in [`veil-server/README.md`](../../veil-server/README.md). |
| Channel epochs are unused | [`005_servers.sql`](../../veil-server/migrations/005_servers.sql) is the only current source reference for those objects. |

## Known conformance gaps found during this audit

These are implementation work, not alternative decisions. Item 1 was resolved
while adopting this ADR; the remaining items are still open:

1. **Iteration-limit rotation gate — resolved 2026-07-11.**
   `VeilClient::encrypt_outgoing` now rotates through the same pending-state
   transition as membership changes and returns without ciphertext. A regression
   test advances exactly 2,000 messages, proves that generation N+1 is created
   only once, and keeps sending blocked until distribution completes.
2. **Fan-out is not cryptographically per-device.** Device rows receive copies of
   an envelope sealed to the shared user identity. Independent device identities,
   account-authorized bindings, capabilities, and per-device SKDMs are missing.
3. **Retained storage keeps only the latest generation per
   `(conversation, owner_device, target_device)`.** A device offline across
   multiple rotations can lose an intermediate SKDM before reconnect and then be
   unable to decrypt messages from that interval. Retention must include
   generation until receipt/expiry.
4. **Equal-generation retries are not provably immutable.** The server currently
   permits an equal generation to replace its sealed envelope, while an already
   initialized client treats that generation as idempotent without comparing the
   chain key. A buggy or malicious sender can therefore create different state
   for devices under one generation. Retention must make the first accepted
   generation immutable or bind a signed key commitment that every retry and
   recipient verifies; correction requires a higher generation.
5. **There is no device receipt ACK.** Current rows remain available for
   idempotent replay and a server ACK proves durable transport only. The target
   needs authenticated device installation ACKs and explicit garbage collection.
6. **Crypto-profile capability/cutover is not wired end to end.** The database
   has `crypto_mode` and MLS scaffolding, but the desktop Sender Key path does not
   yet consume a versioned, authenticated profile with migration epochs.
7. **Directory consistency is service-dependent.** Current pinning detects later
   key replacement, but account-signed device bindings, monotonic roster proofs,
   and equivocation/transparency defenses remain target work. The current
   user-roster snapshot/version is not persisted locally; until it is, cold
   restore rotates the recovered outgoing generation and blocks on
   redistribution. The desktop offline-sync orchestration can then call a
   second forced rotation, so an end-to-end regression must prove and reduce
   this to one intended transition. The current behavior closes the offline
   removal confidentiality gap conservatively, but can impose two rotations
   after a native restart and is not a substitute for rollback-resistant roster
   continuity.

Until retained multi-generation offline delivery (gap 3) is fixed and tested,
offline behavior must not be described as fully conformant to this ADR.

## Migration sequence

1. Freeze the deprecated channel-epoch path and add conformance tests around
   existing v5/v3 parsing, ACL, rotation, and offline ordering.
2. **Completed:** fix iteration-limit rotation so generation creation always
   enters the exact roster distribution gate before any application ciphertext
   is produced.
3. Change retained SKDM storage to preserve every required unacknowledged,
   immutable generation; bind retries to the same state (or retain first-write),
   then add authenticated device receipt ACK and bounded, observable GC.
4. Introduce account-authorized device identities, prekeys, capabilities, and a
   rollback-resistant per-conversation device roster version.
5. Dual-read transitional user/device records, but create new SKDMs only in the
   explicit profile selected for that conversation. Never infer compatibility
   from decryption failure.
6. Move distribution and ACK tracking to per-device tuples. Rotate once when the
   migrated roster becomes authoritative and block until its durable ACK set is
   complete.
7. Add the two-phase profile migration state machine before enabling MLS or any
   successor profile in desktop channels.
8. Audit deployed databases, then remove deprecated channel-epoch objects in a
   dedicated reversible migration if and only if they contain no required data.

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

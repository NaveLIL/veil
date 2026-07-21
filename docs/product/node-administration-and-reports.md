# Node administration, moderation and reports

> Status: planned product/security contract. The current Preview does not have
> a Veil Node admin console or an in-app report queue. This document must not be
> read as evidence that those features are implemented.

Veil has two different administration domains. They must never be merged into
one implicit "admin" role:

- a **Space owner or moderator** manages membership, roles, Rooms and
  invitations inside one Space;
- a **Node operator** manages one self-hosted instance, its admission policy,
  quotas, account availability and abuse cases.

Operator privileges do not provide a decryption API, private keys or a new E2EE
bypass. A report about encrypted content can contain plaintext only when the
reporter explicitly selects and discloses that evidence. Existing residual risks
still apply: the service is authoritative for discovery/routing, service-mediated
TOFU can misattribute a previously unseen identity until key transparency or
out-of-band verification exists, and endpoint compromise remains out of scope.

## Current foundation and gaps

The current backend and desktop client already implement Space roles, Room ACL,
kick, authoritative Space ban/unban and bounded Veil Links. Space settings expose
Rooms, roles, members, links and a ban list. This is useful per-Space moderation,
not Node administration.

Known gaps in the current Preview:

- `veil-admin` only creates Node Access Passes; it cannot list or suspend
  accounts, revoke devices, manage quotas or inspect cases;
- there is no `/admin` API, private operator console or separate Node-operator
  credential;
- there is no report schema, `Report` action, case inbox, appeal flow or account
  suspension state;
- delegated kick/ban permissions exist on the server, but the desktop moderation
  controls are still effectively owner-only;
- `Manage Messages` is presented by the role editor, while deletion of another
  member's message is not implemented server-side;
- the generic `server_audit` table is not an operational audit trail. A bounded
  Veil Link lifecycle journal exists, but it has no read API or operator UI;
- until an in-product flow ships, product complaints use `abuse@erez.pro`.

The implementation evidence lives in
[`veil-server/internal/servers`](../../veil-server/internal/servers),
[`veil-server/internal/db/servers.go`](../../veil-server/internal/db/servers.go),
[`ServerSettingsScreen.tsx`](../../veil-desktop/src/components/server/ServerSettingsScreen.tsx)
and [`veil-admin`](../../veil-server/cmd/veil-admin/main.go).

## Authority and access boundary

Node operations use a credential and authorization namespace separate from
ordinary Veil accounts and Space roles. A compromised moderator account must not
become a Node operator, and the operator surface must not introduce a user
impersonation/signing function. This does not erase the existing malicious-service
and service-mediated TOFU limits described above.

The first supported surface is CLI-first and local:

1. `veil-admin` talks through a root-owned local socket or runs inside the
   trusted deployment boundary.
2. Remote operation uses SSH or a private management network such as Tailscale;
   no public `/admin` listener is enabled.
3. Destructive operations require an explicit reason, target, expected current
   revision and re-authentication or a short-lived operator authorization.
4. A later console is native or served on a separate private listener with
   strong operator authentication, short sessions, CSRF protection and no
   bearer credential in browser storage.

Initial operator roles are deliberately narrow: `owner`, `moderator`, `support`
and read-only `auditor`. Permission checks happen in the service layer and are
covered by deny-by-default tests; hiding a button is never authorization.

## Operator capabilities

The first release of Node administration should support:

- list and inspect bounded account/device state without private keys or message
  content;
- create, list, name, expire and revoke Node Access Passes without revealing an
  existing raw pass again;
- suspend and restore an account or place a Node-level denial on an account or
  device. This denial is a separate operator-owned overlay and authorization
  revision; it never forges or overwrites an account-signed device binding;
- treat HTTP as stateless signed requests and WebSocket connections as live
  sessions. Committing a sanction and its audit row is the linearization point;
  authorization revisions invalidate cached HTTP/WS authorization, while
  process-local or distributed connections close idempotently within a bounded
  deadline rather than pretending DB commit and network teardown are atomic;
- configure storage, bandwidth and Secure Share quotas within deployment-wide
  hard ceilings;
- revoke a Secure Share, quarantine server-visible presentation metadata and act
  on a report. Normal Veil Link revocation remains a Space permission; an
  exceptional Node-policy override requires a case, bounded reason,
  re-authentication and its own audit action;
- display health, migration/release identity, backup freshness and bounded abuse
  metrics without exposing raw identifiers in ordinary logs.

Node suspension and Space ban remain separate actions. A self-hosted Node owns
its policy; there is no implicit global ban across every Veil instance.

## Report and evidence contract

Registered users can report an account/profile, Space/Room metadata, a Veil
Link, a Secure Share reference, a file or a specific message. Guest Secure Share
recipients can submit a narrowly scoped report for that share without receiving
an account session. The guest proves scope with a domain-separated report
capability derived from the fragment secret; the root secret is never submitted,
reporting does not consume a claim, public responses are uniform, and both
per-capability and per-IP limits apply.

Every report contains a bounded category, optional bounded comment, target
reference, reporter-visible Node origin and a random receipt identifier. Its
schema has no fields for recovery, account/device, ratchet or attachment key
material, and the official evidence builder never reads those protected stores.
Conversation history, contact lists, IP addresses and unrelated messages are not
attached automatically. Reporter-supplied text/files remain untrusted arbitrary
content and may contain a secret pasted by mistake or intent, so the confirmation
warns the reporter and operators never treat the package as trusted proof.

For E2EE content the UI shows an explicit evidence ceremony:

1. The reporter selects the exact message/file and the minimum useful context.
2. The client explains that this selection will be disclosed to the Node's
   moderation team and is no longer protected from those operators.
3. Only after confirmation does the client create a versioned, size-bounded
   evidence package encrypted to the Node moderation evidence key. Node storage
   receives ciphertext; only an authorized moderation role may decrypt it.
4. The package records what can and cannot be independently verified. It must
   not claim that reporter-supplied plaintext is automatically a cryptographic
   proof of authorship.

Selective-disclosure evidence needs its own cryptographic review. No design may
export an entire ratchet state or weaken forward secrecy merely to make a report
easier to verify.

The moderation evidence key is not a single unmanaged server secret. Its ADR
must define envelope encryption, private-key custody, which operator roles may
decrypt, audited authorization, rotation, moderator offboarding, compromise
recovery, backups and deletion. `support` and `auditor` receive no evidence
decryption right by default.

## Case lifecycle and audit

A report moves through an explicit state machine such as `new -> triaged ->
actioned | dismissed -> appealed? -> closed`. Assignment, status transitions and
sanctions are revision-checked and idempotent under retries and concurrent
operators. The reporter receives a receipt and a privacy-safe status, not
internal notes or another user's data.

Operator actions append a typed, hash-linked integrity journal entry containing
a scoped immutable actor reference, action, target reference, case ID, reason
code, timestamp and previous-entry commitment. Calling this journal
tamper-evident against a root/DB operator additionally requires independently
protected signed checkpoints whose signing custody is outside the live Node/DB,
export to an independent append-only sink, ordering/partition rules,
rollback/fork detection and a documented verifier procedure. Usernames, public keys, IP addresses,
tokens, raw content and arbitrary JSON do not belong in ordinary logs or journal
rows. Access to disclosed evidence is itself audited.

Report bodies, evidence and audit metadata have separate documented retention
and purge schedules. Backups follow the same maximum retention contract and a
restore drill proves that expired evidence is not resurrected into the live
queue.

## Delivery stages

1. **4F.1 — boundary and CLI:** operator identity, local transport, read-only
   inspection, Access Pass lifecycle, typed audit and authorization-revision
   suspension with bounded connection invalidation.
2. **4F.2 — Space moderation parity:** expose delegated moderator permissions in
   desktop, add warning/timeout flows, and either implement `Manage Messages`
   correctly or remove the misleading permission until it exists.
3. **4F.3 — reports:** submission, explicit evidence, rate limits, deduplication,
   case states, retention, receipts and appeal intake.
4. **4F.4 — private console:** read-only dashboard first, then narrowly scoped
   mutations with re-authentication and complete audit coverage.

## Completion gate

Phase 4F is not complete until automated and physical evidence proves that:

- operator authentication and authorization fail closed and are isolated from
  account/Space credentials;
- a Space moderator cannot gain Node privileges; the report schema has no key-
  material fields and official clients cannot read or automatically export
  recovery, account/device, ratchet or attachment key stores; Node storage
  receives only an encrypted evidence package, and only an authorized moderation
  role can decrypt its explicitly selected, untrusted reporter content;
- DB sanction plus audit is the linearization point; its monotonic authorization
  revision prevents stale HTTP/WS authorization after commit and active
  connections terminate idempotently within the specified deadline, while
  restore is separately authorized and audited;
- report cost and queue growth are bounded per account/capability/IP, responses
  are uniform and non-enumerating, no attacker-selected content is reflected to
  third parties, evidence must already exist on the reporter's device and only
  explicitly selected context enters the package; receipt/status reveals no
  target, operator-note or case data;
- concurrent case and sanction operations are idempotent and preserve a valid
  journal chain and independently verified checkpoint;
- secrets, plaintext, usernames, public keys, IP addresses and tokens do not
  enter ordinary logs, metrics or audit rows; protected audit rows use only the
  scoped immutable references required for accountability and appeals;
- retention, purge, backup/restore, accessibility and privacy documentation have
  passing integration, security and native UI tests.

Until that gate closes, Veil must describe the current feature honestly as
Space administration plus a manual abuse contact, not as a Node admin system.

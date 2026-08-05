# Secure Share for guests

> Status: planned product/security contract. The existing `shares` table,
> `veil-crypto::share` module and `veil-share-viewer` are an incomplete
> prototype. The production gateway does not expose a working Secure Share
> service.

Secure Share lets a registered Veil user create an encrypted, configurable link
for a recipient who does not need a Veil account. A share can contain text and,
in the large-file phase, one or more files. It is a narrow capability-oriented
web flow, not a browser messenger and not an anonymous account session.

The strongest honest promise is:

- the Node stores ciphertext and bounded lifecycle metadata, not plaintext or
  the content key;
- expiry or revocation closes subsequent server requests; reaching the claim
  limit closes new claims. Hosted ciphertext is scheduled for deletion after
  every previously issued lease reaches a terminal state;
- Veil cannot erase plaintext that a recipient already copied, saved,
  photographed or backed up.

## Existing reusable foundation

The repository already contains useful pieces:

- a legacy `shares` table with TTL/view fields;
- small-payload XChaCha20-Poly1305 encryption and optional Argon2id wrapping;
- an experimental Rust/WASM viewer;
- production-oriented chunked AEAD, bounded-memory tus upload/download and
  resumable attachment primitives for files up to the configured 2 GiB ceiling;
- a reviewed Veil Link selector/secret pattern with fragment transport, stored
  hashes, generic errors and atomic consume.

These pieces are not a compatible end-to-end product today. The gateway has no
share routes, the viewer's expected API and generated JS bundle are absent, the
SQL/protobuf/password fields disagree, and the viewer loads a complete base64
ciphertext/plaintext into browser memory. It must not be published as a working
large-file service.

Relevant sources are [`veil-crypto/src/share.rs`](../../veil-crypto/src/share.rs),
[`veil-share-viewer`](../../veil-share-viewer),
[`veil-uploads`](../../veil-uploads),
[`veil-crypto/src/chunked_aead.rs`](../../veil-crypto/src/chunked_aead.rs) and
the [Veil Link security review](../reviews/phase-4e-veil-link-schema-security-review.md).

## Threat model and browser boundary

The creator is authenticated to a Veil Node. This gives the Node enforceable
quota and abuse controls. The recipient may be completely unregistered and
receives only a share-scoped capability.

The browser viewer protects content from storage/database disclosure and an
honest-but-curious Node that serves the reviewed viewer. It cannot protect
against an actively malicious Node that replaces the viewer JavaScript at open
time: a browser does not enforce the native application's release signature.
The UI and documentation must state this boundary. Opening the share in a
signed native Veil client can provide a stronger code-integrity path.

The Node necessarily observes the creator account, ciphertext size, timestamps,
share state, claim count and recipient network metadata at the transport edge.
Filename, MIME, text, manifest and content keys remain encrypted. Normal access
logs use bounded pseudonymous references and never record raw capability
material.

## Versioned capability

The canonical v1 form is:

```text
https://node.example/s/v1/<public-selector>#k=<root-secret>
```

`public-selector` is independently random and only locates the record. The
256-bit `root-secret` is carried in the URL fragment, which is not part of the
HTTP request or ordinary referrer/access log. A domain-separated KDF derives
independent values:

- a manifest/content root used only by the creator/viewer;
- a redemption key used to authorize an atomic claim;
- a report capability that proves scope without revealing the root secret.

The Node stores domain-separated hashes of redemption, report and issued lease
credentials, never the root secret or content keys. The viewer sends only the
redemption key over validated TLS when claiming; knowledge of it does not derive
the content key. A successful claim returns a fresh random lease credential; the
redemption key is never reused as a download bearer. The versioned ADR and test
vectors fix canonical origin, protocol version and selector in every KDF context,
canonical base64url encoding, distinct manifest and per-file keys (or random
per-file keys wrapped by the manifest), and AEAD AAD covering version, origin,
selector, immutable item ID/ordinal and descriptor.

Every claim/download request is pinned to the exact versioned canonical API
origin with browser `redirect: "error"` and equivalent native no-redirect policy.
Downgrade, userinfo, alternate-port and origin-changing redirects are rejected.
Lease credentials travel only in the `Authorization` header, never path/query;
when viewer and API origins differ, CORS uses an exact allowlist rather than `*`.

Initial metadata fetch is generic and does not consume a view. Link scanners,
unfurl bots and browser prefetch must not burn a share. Consumption begins only
after an explicit user action and successful capability claim.

## Claim, resume and destruction semantics

Each share has bounded TTL, `max_claims`, optional manual revoke and a creator
quota. A successful atomic claim increments `consumed_claims` and creates its own
short, single-share lease row. The lease can resume the same transfer for a
bounded window but cannot open another share or increase the number of claims.
An abandoned lease stays consumed; completion acknowledgement is telemetry, not
authority to refund or consume a claim.

The share state machine distinguishes:

- `active`: new claims are allowed while `consumed_claims < max_claims`;
- `burned`: the configured successful-claim count has been reached, so no new
  claims are allowed while existing leases finish or expire;
- `expired` or `revoked`: new claims and all subsequent lease/range/resume
  requests are denied;
- `purging`: ciphertext/blob deletion is queued and retried idempotently.

Each issued lease has its own `issued -> expired | revoked` lifecycle. Concurrent
claims lock or compare-and-swap the share counter, so `max_claims > 1` permits
only that many independent leases. For a strict one-time link, successful
capability/password verification and lease issuance consume the only claim in one
transaction. This intentionally favors a precise security promise over refunding
claims after an unverifiable client failure. The browser supports reconnect and
resume only for the current page lifetime without persistent secrets; native
clients may support crash/resume using reviewed OS-protected lease storage. UI
wording says "one server retrieval" rather than "impossible to copy".

The revoke/expiry commit immediately closes subsequent authorization and marks
issued leases revoked. Active responses are cancelled best-effort within a
bounded deadline, but bytes already sent or buffered cannot be recalled. Burned
shares retain ciphertext only until every previously issued lease is terminal;
then physical blob purge is asynchronous and observable to the operator.
Encrypted backups may retain a blob only for their documented maximum retention;
restore must not reactivate an expired or burned capability.

## Content and large files

Every share contains an authenticated, encrypted manifest. It carries the
version, text, file descriptors, original filenames, MIME hints, plaintext
sizes, chunk geometry and end-to-end commitments. The Node receives only
bounded ciphertext objects and `application/octet-stream`.

Delivery is split deliberately:

1. **4G.1 — text/small payload:** a hard-bounded envelope, native create/list/
   revoke UI, atomic claim and a minimal audited viewer.
2. **4G.2 — files up to the configured ceiling:** reuse chunked AEAD and tus for
   authenticated creator uploads only after adding `purpose=secure_share` and an
   immutable `draft_share_id` to upload authorization. Binding into one immutable
   share blob set is one-time, dual attachment to a message and share is
   forbidden, share expiry clamps object retention, and transactional/outbox
   purge cannot delete an object still referenced elsewhere. Add a separate guest
   read lease scoped to exactly one share and its blob set; never widen the
   ordinary account upload bearer.

The large-file viewer decrypts and authenticates complete chunks with bounded
memory. It must not build a multi-gigabyte base64 JSON response, `Vec`, JS array
or browser `Blob`. Browser private/OPFS temporary storage contains either the
original ciphertext or temporary plaintext re-encrypted with a random
page-lifetime key that is never persisted. It exports only after full commitment
verification and safely scavenges orphan ciphertext on startup. Plaintext
temporary files are allowed
only where deletion on success/error/cancel and startup cleanup have physical
evidence plus documented residual risk. A browser without equivalent atomic
temporary-file semantics falls back to the signed native client; the supported
browser, version and filesystem API matrix is explicit. Resume aligns to
authenticated chunk boundaries; a partial or unverified plaintext file is never
presented as complete. Unsupported content is download-only rather than rendered
inline.

## Options and password mode

The planned creator options are:

- text and one or more files within Node hard limits;
- TTL selected from a bounded policy;
- one or a bounded number of claims;
- burn after the final consumed claim, manual revoke and optional coarse
  open/completion notification without recipient identity;
- an optional separately communicated password gate;
- optional size padding within a strict quota budget.

A downloadable wrapped key permits offline password guessing, so server-side
rate limiting cannot protect the legacy password design. V1 must not claim both
"the server never sees the password" and "the server prevents brute force".

A candidate requiring ADR and security review is a password as a server-verified
second gate on top of the random fragment secret. The creator submits a
versioned salt/verifier; the Node, not the requester, selects bounded Argon2id
parameters. Capability checks precede expensive password work, public failures
are uniform, global/per-IP Argon2 concurrency is bounded, a failed password never
consumes a claim, and successful verification plus lease creation is one
transaction. The Node sees the submitted password inside TLS but still lacks the
fragment-derived content key. Database theft permits offline guessing of the
verifier, so this is not described as zero-knowledge; that property requires a
separate OPAQUE/PAKE design and review.

## Viewer and web hardening

The viewer uses a dedicated cookieless origin; if deployment constraints require
the public Node origin, every viewer/API request uses `credentials: "omit"`,
share endpoints ignore cookies, and the operator console is served from a
separate management origin. It has no analytics, third-party scripts, remote
fonts, generic Veil IPC or service worker. Viewer HTML, metadata, claim and
ciphertext responses use `Cache-Control: no-store`; content-hashed JS/WASM/CSS
without capability material may use long-lived immutable caching. Required
policy also includes `Referrer-Policy: no-referrer`,
`X-Content-Type-Options: nosniff`, no indexing, `frame-ancestors 'none'`, a
strict hash/nonce-based CSP, limited `connect-src`, COOP/CORP and a restrictive
`Permissions-Policy`.

The application removes secrets from the visible URL immediately after parsing
and never places them in query/path, DOM attributes, application logs,
exceptions, telemetry, clipboard by default or persistent browser storage. URL
fragments are excluded from HTTP/referrer traffic, but Veil cannot guarantee
that a browser/history-sync implementation did not briefly retain the original
URL before `replaceState`; this residual browser boundary is documented. Generic
public errors make unknown, expired, revoked, exhausted and malformed shares
indistinguishable.

## Abuse and reports

Only authenticated creators can upload in the first release. Per-account and
per-IP creation/claim limits, concurrent-transfer ceilings, storage windows,
orphan cleanup and instance-wide emergency disable protect a self-hosted Node.
Anonymous guest uploads are a separate future `Guest Drop` capability with a
larger abuse surface and are not smuggled into Secure Share v1.

A guest can report a share reference and bounded category without receiving an
account session. A domain-separated report capability proves scope without
submitting the root secret or consuming a claim; uniform responses and
per-capability/IP limits prevent enumeration and amplification. Only explicitly
selected, untrusted plaintext is attached through a separate disclosure ceremony
described by the [reporting contract](node-administration-and-reports.md).
Operators can revoke or quarantine a share and sanction its authenticated
creator, but do not gain a hidden E2EE scanner.

## Completion gate

Secure Share remains labelled prototype/planned until evidence proves:

- selector-only access reveals no protected metadata; fragment secrets never
  enter path, query, referrer, application logs, application caches or telemetry,
  and browser history/sync residual risk is documented;
- claim/lease/expiry/revoke/max-claim races are atomic and cross-share
  substitution fails closed;
- wrong key/password, tamper, truncation, reordering and resume corruption never
  publish unauthenticated plaintext;
- viewer CSP/XSS/origin tests and physical supported-browser tests pass;
- crash/reload/cancel leaves no readable plaintext residue in browser temporary
  storage and orphan ciphertext is safely scavenged;
- Windows/Linux native creation and text/small/large-file retrieval pass,
  including a real configured-maximum transfer and OS-protected crash/resume;
  browser physical tests cover only the declared browser/API matrix, use verified
  temporary publication and prove current-page reconnect/resume;
- quota exhaustion, abandoned uploads, purge retries, backup retention and abuse
  revocation have integration and operations evidence;
- a versioned ADR, threat model, privacy text and separate security review
  are published before the feature is described as ready.

The old design sketch remains useful history, but this contract and its future
ADR supersede it for implementation and product claims.

# ADR-0002: Origin-bound one-time Node Access Passes

- Status: Accepted for the managed Preview Node
- Date: 2026-07-15
- Scope: first account registration on a Veil Node
- Owners: Veil desktop, client, protocol, server, and operations maintainers

## Context

The managed Preview Node is intentionally not open for public registration.
Testers still need a safe way to create their own account identity without the
operator generating or learning their recovery phrase. Temporarily opening
registration is raceable and difficult to communicate. Pre-generating complete
accounts would permanently disclose their account secrets to the operator.

A Space **Veil Link** is not suitable for this job. It authorizes membership for
an already registered identity and has different revocation, preview, and trust
semantics. Account admission and Space membership must remain separate
capabilities.

## Decision

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

1. A **Node Access Pass** authorizes exactly one successful creation of a new
   account identity on one canonical HTTPS Veil Node origin. It is not a login
   session, identity proof, recovery credential, or Space invitation.
2. A pass MUST contain 256 bits from a cryptographically secure random source.
   The server MUST store only its SHA-256 digest, expiry, and usage metadata.
   The plaintext bearer MUST be emitted only once by the operator command.
3. The HTTPS enrollment URL MUST place the bearer in the fragment so it is not
   sent in HTTP requests, referrers, or reverse-proxy access logs. The portal
   MUST remove that fragment from browser history immediately after reading it.
4. The custom `veil://` URL MAY carry the bearer in its query because it is an
   OS activation URI rather than an HTTP request. The native parser MUST reject
   duplicate or ambiguous query/fragment bearers and MUST bind the pass to the
   exact canonical HTTPS origin supplied by the portal.
5. Desktop deep links MUST be parsed natively. The raw bearer MUST NOT be
   returned to the renderer, logged, written to configuration, SQLCipher, OS
   keychain, analytics, or crash metadata. A manual clipboard fallback MAY read
   the complete HTTPS link natively after an explicit user action. Native
   pending state expires after ten minutes and is zeroized when replaced,
   cancelled, locked, or successfully used.
6. The gateway MUST verify X25519/Ed25519 account proof before revealing whether
   registration is closed or a pass is invalid. Signature, device-binding,
   database, and other failures remain the generic authentication failure.
7. Account creation and pass consumption MUST commit in one database
   transaction. Invalid, unknown, expired, reused, and concurrently consumed
   passes MUST have one indistinguishable client-visible result. A failed
   account insert MUST roll back consumption.
8. An existing registered identity MUST authenticate without a pass. If it
   presents an unused pass, the server MUST ignore and MUST NOT consume it.
   Reconnection and account recovery therefore never require a new pass.
9. Production MUST keep `VEIL_ALLOW_REGISTRATION=false`. Operators create
   bounded, expiring batches through `veil-admin`, redirect output to a
   mode-0600 file, deliver each line privately, and delete the batch after
   distribution.

## Consequences

- The operator can admit testers without holding their recovery phrases.
- A database disclosure does not reveal unused pass bearers.
- A stolen unused URL can still be redeemed by whoever presents it first. This
  is inherent to a bearer capability; private delivery and short expiry remain
  required.
- OS protocol activation and clipboard history can retain a URL outside Veil's
  process. The UI must warn about the clipboard fallback, and release testing
  must cover installed Windows and Linux handlers.
- Custom URI schemes are not domain-verified and can be hijacked by another
  local application. A compromised local desktop is outside the trust boundary;
  the HTTPS-link fallback remains available when Veil is not the registered
  handler.
- Initial operations provide create-only batches. Listing, naming, and explicit
  revocation are follow-up operator features; until then, a suspected leak is
  replaced and allowed to expire.

## Rejected alternatives

- **Temporarily open public registration:** susceptible to races, automation,
  and accidental admission outside the tester cohort.
- **Pre-created recovery phrases:** the operator can always impersonate or
  recover those identities, which is incompatible with the account trust model.
- **Reuse Space Veil Links:** conflates account admission with membership and
  creates ambiguous authorization and revocation semantics.
- **Store plaintext pass tokens:** turns a database read into immediate account
  admission and provides no operational benefit.

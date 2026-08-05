# Identity transparency witness rollout

This runbook describes the Veil Node side of an independently operated
Transparency v1 witness. Veil contains the strict client and wire contract, but
does not currently ship a production witness server. Do not claim independent
witnessing by running the witness in the same trust, host, database, or operator
boundary as the Node.

## Node configuration

Enable the Node log first and keep its dedicated Ed25519 seed in a deployment
secret manager:

```text
VEIL_IDENTITY_TRANSPARENCY_ENABLED=true
VEIL_IDENTITY_TRANSPARENCY_SIGNING_SEED=<canonical-unpadded-base64url-32-byte-seed>
VEIL_IDENTITY_TRANSPARENCY_WITNESSES=https://w1.example:443/v1/checkpoint|<32-byte-lowercase-hex-key>,https://w2.example:443/v1/checkpoint|<32-byte-lowercase-hex-key>
VEIL_IDENTITY_TRANSPARENCY_WITNESS_QUORUM=2
```

URLs and public keys must be unique. Non-loopback witnesses require canonical
HTTPS URLs with explicit ports. Witness configuration and quorum must be set
together; partial or malformed configuration fails Node startup.

Desktop clients pin public witness keys with
`VEIL_IDENTITY_TRANSPARENCY_WITNESS_KEYS` and the same quorum variable. Android
trust is compiled into the native library. A client policy is sticky after it
has accepted a witnessed head; policy removal cannot silently restore the
unwitnessed path.

## Witness contract

The Node sends a bounded `POST application/json` request containing version 1,
canonical origin, Node signing key, log ID, tree size/root/timestamp, Node
signature, and an optional historical consistency proof. Integers are canonical
decimal strings and keys, roots, proofs, and signatures are canonical lowercase
hex.

A witness must durably remember its highest accepted `(origin, log_id,
node_signing_key, tree_size, root_hash)` state, verify the Node signature and
log identity, and accept only an identical or append-only-consistent head. It
returns either:

```json
{"version":1,"witness_signing_key":"<64 lowercase hex>","signature":"<128 lowercase hex>"}
```

or HTTP 409 with its retained state:

```json
{"version":1,"tree_size":"42","root_hash":"<64 lowercase hex>"}
```

After 409, the Node may retry once with the exact consistency proof from that
retained head. Redirects are disabled, the complete request is bounded by the
Node proof limits, each response is limited to 4 KiB, and the concurrent quorum
operation has a four-second HTTP timeout. The Node locally re-verifies every
witness signature and fails the trust advance if quorum is not reached.

The exact signed checkpoint grammar and verification code live in
`veil-server/internal/transparency/log_v1.go` and `witness_v1.go`; the frozen
cross-language fixture is under `test-vectors/transparency/`.

## Deployment gate

Before enabling a mandatory quorum:

1. Back up the Node transparency seed and each witness signing/state store by
   separate recovery procedures.
2. Confirm every witness starts from the same audited Node head and persists an
   fsync-safe monotonic state before signing.
3. Exercise normal advance, lag/409 consistency retry, timeout, malformed
   response, wrong key, same-size fork, rollback, and quorum-loss cases.
4. Roll the public witness policy into clients before relying on its security
   property. Never rotate a witness key as an ordinary environment edit.
5. Monitor quorum latency/failure without logging checkpoint request bodies,
   account data, secrets, or private keys.

Quorum loss is an availability event, not permission to disable the pinned
policy. A planned witness-key transition needs a separately reviewed,
cryptographically authorized protocol; it is not implemented by this runbook.

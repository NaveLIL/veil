EVIDENCE CHECKPOINT ONLY — NON-ACTIVATED — the hostile-Node P1 and Phase 5S remain open.

# Phase 5S WebSocket auth v3 verifier and admission checkpoint

Date: 2026-07-20

Status: checkpoint 5S.3B-4 is implemented and host-tested. Runtime activation
is prohibited by the open gates below.

## Scope

This checkpoint adds the transport-neutral server verifier and durable
PostgreSQL admission boundary for the previously frozen WebSocket auth v3 byte
contract. It does not connect either component to `/ws`.

The verifier accepts only an already canonically decoded `WSAuthV3ResponseInput`.
It consumes one v3 challenge, requires the challenge's exact configured public
origin, and verifies, in order:

1. fixed widths, canonical metadata, explicit registration intent, and the
   intent-coherent presence or absence of a raw Node Access Pass;
2. the active account-signed device binding with all required secure-channel
   capabilities, deriving the binding commitment only from that verified
   signing message;
3. a contributory account X25519 result and the account Ed25519 proof;
4. a contributory device X25519 result and the device Ed25519 proof chained to
   the exact accepted account signature; and
5. one durable admission result matching every verified account, device, and
   binding field.

No registration-policy or Pass lookup occurs before both possession proofs
pass. The decoded transport Pass is cleared on every return path, including a
missing challenge or invalid context. The verifier copies all proof and binding
fields into fixed owned values before verification or admission, clears its
Pass and proof-signature copies, clears temporary DH-derived messages, and does
not retain the bearer in its success result.

## Atomic durable admission

`AdmitWSAuthV3` runs account, device, immutable device keys, binding
version/head, and Pass state in one PostgreSQL transaction. An identity-derived
transaction advisory lock closes concurrent lookup/create races.

After that lock, the exact existing identity and its pinned account signing key
are resolved before the Pass table is inspected. Therefore:

- an exact existing identity authenticates without consuming a supplied Pass;
- a retry after an uncertain successful commit can present the same now-used
  Pass and resolve idempotently to the committed account/device;
- only an absent identity enters the signed intent branch;
- `EXISTING` rejects an absent identity, `OPEN` requires explicit open policy,
  and `PASS` locks and consumes the matching live capability; and
- a device conflict, binding gap, cancellation, failed commit, or other error
  cannot leave a partial account/device/binding graph or consumed Pass.

One Pass raced by two different identities has one winner. Concurrent retries
for the same identity converge on one durable principal. Public-safe
`REGISTRATION_CLOSED` and `NODE_ACCESS_PASS_INVALID` classifications are
possible only for their already authenticated signed intents; storage and
incoherent internal errors remain operational failures rather than auth
oracles.

## Verified success product

The verifier no longer returns the legacy principal alone. It returns an
opaque `WSAuthV3VerifiedResult` whose private state carries:

- a copied durable principal;
- protocol version 3;
- the exact origin taken from the consumed challenge; and
- the registration intent taken from the verified proof.

Callers receive copies through read-only getters and cannot replace those
values with separately reconstructed request data. The result carries no Pass,
signature, DH secret, or binding preimage. An `EXISTING` proof can never produce
an incoherent `IsNew=true` success, and every UUID, account key, device owner,
device key, binding field, status, capability, signature, and commitment is
revalidated against the committed store result before a principal is
published.

## Executable evidence

The ordinary and race suites cover every intent, every signed security-field
mutation, other-origin and legacy-proof substitution, challenge one-shot and
protocol mismatch behavior, typed-nil dependencies, nil context/config,
caller-owned alias mutation, Pass clearing, simultaneous challenge consumers,
failure classification, copied success state, and the complete inconsistent
store-result matrix.

Tagged disposable-PostgreSQL tests cover:

- new PASS admission and the complete committed graph;
- used-Pass uncertain-commit retry and existing-identity-before-Pass behavior;
- unused Pass preservation for an existing identity;
- device conflicts and initial binding gaps with rollback;
- deterministic cancellation while a Pass row is locked, release of the
  transaction with zero graph effects, and a successful retry;
- one Pass raced by two identities; and
- concurrent same-identity convergence.

A repository-wide AST gate rejects production calls or method-value/method-
expression aliases of `CreateChallengeV3`, `VerifyResponseV3`, and
`AdmitWSAuthV3`. Its sole allowlisted production edge is the transport-neutral
verifier calling the atomic admission store. The scanner has a self-test for
alias detection.

The settled WS slice passed:

```text
# veil-server/
go test ./...
go test -race ./...
go vet ./...
go test -tags=integration -run 'TestWSAuthV3Admission' -count=1 -v ./internal/db
go test -race -tags=integration -run '^TestWSAuthV3Admission' -count=1 ./internal/db

# repository root
git diff --check
```

The tagged commands used a disposable synthetic PostgreSQL container. They did
not contact or alter a Veil Node.

## Deliberately not activated

The live gateway still emits and verifies only WS auth v2. There is no
canonical raw protobuf adapter, no strict v3 subprotocol negotiation, no
gateway `AuthResponseV3` dispatch, no live result serializer, and no client
transport consumption. In particular, normal protobuf decoding is not evidence
that duplicate, unknown, or non-canonical security fields are rejected at the
raw wire boundary.

The next activation gates are:

- canonical raw protobuf validation before decoded Pass bytes can reach the
  verifier;
- explicit `v3-only` and finite reviewed Preview compatibility negotiation
  with no fallback;
- gateway result mapping from the opaque verified attempt;
- a real two-Node A↔B relay matrix with valid local identities and Pass state on
  both Nodes; and
- desktop/Android request preparation, exact selected-origin comparison,
  reconnect/process-death behavior, and reviewed public error/action mapping.

This checkpoint does not close the cross-Node credential-relay P1, hostile-Node
analysis, key transparency, Phase 5S, Android Direct Preview, or an external
cryptographic audit. It is not production readiness.

No phone, ADB, APK, signing key, recovery ceremony, Pass issuance/application,
live configuration, Compose Node, or deployment was accessed. Physical Android
testing remains deferred until it is explicitly resumed and a newly displayed
recovery phrase is confirmed recorded.

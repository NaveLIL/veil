# PublicFailureCodeV1

`public-failure-code-v1.json` is the machine-readable, append-only registry of
public support codes for the closed Android Direct Preview. Version 1 starts
with the 16 codes approved in `INTEGRATION_ROADMAP.md`.

This is a presentation and recovery contract, not a wire-protocol field. It
does not replace internal `E_VEIL_*` errors, HTTP status, server `publicerr`
values, tus `ERR_*` values, or protobuf fields. In particular, the existing
`Error.reason = 5` Direct-send field is unrelated. A future wire code requires
a separately reviewed protobuf field number.

## Entry contract

Every entry contains exactly these fields, in this order:

- `code`: stable, copyable ASCII identifier matching
  `VEIL-[A-Z][A-Z0-9]*-[0-9]{3}`. It is not localized and is never an event ID.
- `semantic_key`: stable local-catalog semantic identity.
- `exposure_gate`: the reviewed typed condition that permits presentation.
- `recovery_action_key`: stable local-catalog next-action identity. It never
  grants retry, reconnect, Pass replay, or weaker trust by itself.
- `state`: `active`, `retired`, or `reserved`.

All values are ASCII. Keys other than `code` use lower snake case. UI title,
description, and action copy must come from a reviewed local catalog keyed by
the registry; untrusted native/server text, URLs, response bodies, and
`String(error)` are never rendered.

`VEIL-SETUP-002` deliberately covers an interrupted result, an ambiguous or
busy start that may still own a native ceremony/lease, and an unconfirmed local
identity publication. A vault `absent` read alone never authorizes restart while
native setup may still be active. Any newly shown create phrase is preserved
until native reports the ceremony settled; only settled setup plus authoritative
vault absence permits destroying that phrase and starting again.

`reserved` entries permanently occupy a code that was never public. They use a
`reserved_...` semantic key, `never` as the exposure gate, and `none` as the
recovery action. An active entry may become `retired`; a retired or reserved
entry never becomes active again. Retired identities remain in the registry.

## Append-only changes

Never edit or delete
`history/public-failure-code-v1.initial.json`. Existing entries keep their
position and immutable `code`, `semantic_key`, `exposure_gate`, and
`recovery_action_key`. New entries are appended only. State may remain
unchanged or transition once from `active` to `retired`.

Run the dependency-free gate from the repository root:

```sh
node scripts/validate-public-failure-code-v1.mjs
node --test scripts/tests/validate-public-failure-code-v1.test.mjs
```

CI additionally compares the registry and immutable initial history snapshot
with the target branch Git revision. This catches deletion, reordering,
identity mutation, state resurrection, and edits to the baseline snapshot.
The same dependency-free gate statically parses both restricted mobile
consumers: the TypeScript `PUBLIC_FAILURE_CODES_V1` literal array and Android's
Kotlin `PublicFailureCodeV1` literal enum. It neither imports nor executes
consumer code. Both value sequences must exactly equal the active registry
entries; retired and reserved codes are not consumer-visible.

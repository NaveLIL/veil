# Cryptographic identity rotation

Veil currently treats the canonical account X25519 identity key, account
Ed25519 signing key, device protocol identifier, device X25519/Ed25519 keys,
and every signed device-binding version as immutable protocol history.
Migration 019 enforces that rule in PostgreSQL, including for direct SQL
writers. A no-op update is accepted; changing key material fails closed.

Do **not** rotate an account by updating `users.identity_key` or
`users.signing_key`. Retained Sender-Key distributions carry the historical
device-binding version and its account signature. Replacing the account key in
place would make that proof unverifiable and could silently reinterpret an old
identity as a new one.

A future account-key rotation protocol must be a versioned migration, not an
`UPDATE users` operation. At minimum it needs:

- an append-only account identity/version table and an explicit current head;
- a signed old-key to new-key transition (plus a recovery rule when the old
  signing key is unavailable);
- retained old public keys and proof lookup for the full ciphertext/SKDM
  retention interval;
- device-binding signatures scoped to the exact account identity version;
- roster commitments and message security context bound to that version;
- client verification, downgrade rejection, recovery UX, audit events, and a
  tested rollback/cutover procedure.

Device binding rotation already follows the required append-only shape: insert
the next `device_binding_versions` row, then advance `device_binding_heads`.
Never rewrite an existing version. Changing the device's protocol identifier or
device public keys requires registering a new device.

## Hard deletion

Hard account deletion is an explicit destructive cleanup path, not rotation.
`users -> devices -> sender_keys/device_binding_versions` cascades remove
retained envelopes, stream heads, and their exact binding history atomically.
Migration 019 adds deferred composite foreign keys from every retained row to
both historical binding versions; the transaction cannot commit with an
orphaned proof. Back up any required audit material before deleting an account,
because offline Sender-Key delivery for that account/device is intentionally
lost.

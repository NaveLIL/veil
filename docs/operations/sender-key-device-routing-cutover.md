# Sender-Key device-routing cutover

Migration `015_sender_key_retention_policy.sql` intentionally stops when
`sender_keys` contains a legacy or partial device-route tuple. Those rows were
sealed to an account identity before per-device routing existed. The current
runtime cannot authenticate, deliver, or acknowledge them, so automatic
deletion would silently make offline history unavailable and retaining them
would leave data with no collection path.

The migration does **not** delete `sender_key_heads`. Those heads are permanent
rollback barriers and must survive the cutover.

## Operator procedure

1. Stop all Veil gateway/server writers and take a database backup. At minimum,
   export the affected rows and their heads; a full database backup is safer.

   ```sql
   SELECT sk.*
   FROM sender_keys AS sk
   WHERE sk.roster_version IS NULL
      OR sk.roster_commitment IS NULL
      OR sk.owner_binding_version IS NULL
      OR sk.target_binding_version IS NULL;

   SELECT head.*
   FROM sender_key_heads AS head
   WHERE EXISTS (
       SELECT 1
       FROM sender_keys AS sk
       WHERE sk.conversation_id = head.conversation_id
         AND sk.owner_device_id = head.owner_device_id
         AND sk.target_device_id = head.target_device_id
         AND (
             sk.roster_version IS NULL
             OR sk.roster_commitment IS NULL
             OR sk.owner_binding_version IS NULL
             OR sk.target_binding_version IS NULL
         )
   );
   ```

2. Audit the export and explicitly accept that deleting these unsupported
   account-routed envelopes sacrifices pending legacy offline delivery. If that
   is not acceptable, keep migration 015 blocked and build a separately audited
   export/recovery tool; do not enable a compatibility fallback in the live
   per-device protocol.

3. In a transaction, count and delete only rows with an incomplete route tuple.
   Do not delete or rewrite `sender_key_heads`.

   ```sql
   BEGIN;

   SELECT COUNT(*) AS legacy_sender_key_rows
   FROM sender_keys
   WHERE roster_version IS NULL
      OR roster_commitment IS NULL
      OR owner_binding_version IS NULL
      OR target_binding_version IS NULL;

   DELETE FROM sender_keys
   WHERE roster_version IS NULL
      OR roster_commitment IS NULL
      OR owner_binding_version IS NULL
      OR target_binding_version IS NULL;

   COMMIT;
   ```

4. Rerun migrations. A transactional migration failure normally rolls back the
   helper function along with the rest of migration 015. Only when the function
   is verifiably present (for example, after an earlier successful migration)
   may the same preflight be run directly:

   ```sql
   SELECT veil_assert_sender_key_device_routing_cutover();
   ```

5. Start the server only after migration 015 succeeds. The migration makes all
   four device-route columns `NOT NULL`, so the cutover cannot regress through
   a future legacy writer. Verify that `sender_keys` contains complete route
   tuples and that every retained row has `created_at` and `expires_at`
   populated.

   ```sql
   SELECT COUNT(*) AS invalid_retained_rows
   FROM sender_keys
   WHERE roster_version IS NULL
      OR roster_commitment IS NULL
      OR owner_binding_version IS NULL
      OR target_binding_version IS NULL
      OR created_at IS NULL
      OR expires_at IS NULL
      OR expires_at <= created_at;
   ```

The final count must be zero. Preserve the backup according to the deployment's
data-retention policy and record who approved the loss of pending legacy
delivery.

## Retained-envelope runtime limits

The live runtime retains at most 128 unacknowledged generations per
`(conversation, owner device, target device)` stream and, across every stream
addressed to one target device, at most 2,048 rows or 4 MiB of encrypted SKDM
payload. Admission is atomic with those target-wide bounds. Pre-auth restore
first reads bounded per-conversation aggregate metadata, checks current roster
readiness, and only then materializes an all-or-nothing conversation suffix.
Both encrypted payload and encoded wire output remain under the same global
row/byte ceilings, so an unavailable or manually overfilled group is never
loaded merely to decide that it must be isolated.

An envelope whose receipt deadline has expired is not collected silently. Its
presence closes new SKDM admission for that stream and isolates the **entire
conversation** from pre-auth Sender-Key delivery. No prefix or suffix from that
conversation is sent, ACKed, or pruned. Other ready conversations and ordinary
Double-Ratchet DMs still authenticate and sync; when ciphertext for the
isolated conversation is encountered, the client marks that conversation's
encrypted history unavailable. A currently not-ready roster (for example, a
legacy/unbound member device) is isolated by the same all-or-nothing rule.
This avoids turning one damaged group into a global account lockout while still
failing closed for its ciphertext.

Normal recovery is an authenticated receipt for the exact conversation,
owner-device, target-device, generation, roster version, and envelope
commitment before the deadline. After expiry, or when the target-wide bound is
already exceeded, an operator must preserve and audit the affected rows before
an administrator explicitly excludes/revokes the target device or approves a
separate recovery/removal procedure. Do not delete rows merely to make login or
admission succeed, and never delete the corresponding `sender_key_heads`
rollback barriers.

A committed loss of the **target account's** channel-read authorization is a
separate automatic collection path: deferred ACL triggers delete that target's
pending `sender_keys` rows so a rapid remove/re-add cannot resurrect old
history. The stream heads remain as rollback barriers, and re-admission requires
a newer generation for the newer roster. Losing only the sender/owner role or
membership does **not** collect rows for targets that stayed authorized; those
targets must still be able to restore ciphertext from their authorized
interval. Role/overwrite changes that leave a target continuously authorized
also preserve its pending rows.

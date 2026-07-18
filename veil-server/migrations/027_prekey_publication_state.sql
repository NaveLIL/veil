-- Bounded X3DH prekey publication state.
--
-- Once a device has an idempotency receipt, a claimed OPK no longer needs a
-- server-side row after its public bundle is returned: the initial message
-- carries its protocol id and the recipient retains the matching private key.
-- Remembering only monotonically retired protocol ids prevents an old upload
-- from ever resurrecting that OPK.
-- The SHA-256 digest of the exact already-validated HTTP request bytes is a
-- bounded, durable idempotency receipt so a client that lost the HTTP
-- acknowledgement can retry forever without republishing compacted keys.
CREATE TABLE IF NOT EXISTS prekey_publication_state (
    device_id                       UUID PRIMARY KEY
                                    REFERENCES devices(id) ON DELETE CASCADE,
    signed_prekey_high_watermark    BIGINT NOT NULL DEFAULT 0,
    one_time_prekey_high_watermark  BIGINT NOT NULL DEFAULT 0,
    latest_upload_digest            BYTEA,
    latest_upload_stored            INTEGER,
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT prekey_state_signed_watermark_range
        CHECK (signed_prekey_high_watermark BETWEEN 0 AND 4294967295),
    CONSTRAINT prekey_state_one_time_watermark_range
        CHECK (one_time_prekey_high_watermark BETWEEN 0 AND 4294967295),
    CONSTRAINT prekey_state_receipt_complete
        CHECK ((latest_upload_digest IS NULL) = (latest_upload_stored IS NULL)),
    CONSTRAINT prekey_state_receipt_digest_length
        CHECK (latest_upload_digest IS NULL OR octet_length(latest_upload_digest) = 32),
    CONSTRAINT prekey_state_receipt_stored_range
        CHECK (latest_upload_stored IS NULL OR latest_upload_stored BETWEEN 1 AND 1001)
);

-- Upgrade state is deliberately receipt-less: the old schema did not retain
-- the exact upload boundary. The application may establish the first receipt
-- only from a fully verifiable legacy retry whose every row is still present,
-- or from a strictly monotonic new publication.
INSERT INTO prekey_publication_state (
    device_id,
    signed_prekey_high_watermark,
    one_time_prekey_high_watermark
)
SELECT
    device_id,
    COALESCE(MAX(protocol_key_id) FILTER (WHERE key_type = 0), 0),
    COALESCE(MAX(protocol_key_id) FILTER (WHERE key_type = 1), 0)
FROM prekeys
GROUP BY device_id
ON CONFLICT (device_id) DO UPDATE SET
    signed_prekey_high_watermark = GREATEST(
        prekey_publication_state.signed_prekey_high_watermark,
        EXCLUDED.signed_prekey_high_watermark
    ),
    one_time_prekey_high_watermark = GREATEST(
        prekey_publication_state.one_time_prekey_high_watermark,
        EXCLUDED.one_time_prekey_high_watermark
    );

-- Only the newest SPK is served. Older public SPKs are not required to finish
-- an in-flight X3DH message because the recipient owns the corresponding
-- private key and the message carries signed_prekey_id.
DELETE FROM prekeys older
WHERE older.key_type = 0
  AND EXISTS (
      SELECT 1
      FROM prekeys newer
      WHERE newer.device_id = older.device_id
        AND newer.key_type = 0
        AND newer.id > older.id
  );

-- Legacy claimed rows stay until the first fully verifiable receipt is
-- established. This permits an old lost-ACK retry to be checked byte-for-byte
-- instead of trusting material for an already missing id. Claims cannot grow
-- this set; they only move one of the bounded live rows into it.

-- Retain only bounded live inventory for each device during the upgrade.
DELETE FROM prekeys doomed
USING (
    SELECT id
    FROM (
        SELECT id,
               row_number() OVER (
                   PARTITION BY device_id
                   ORDER BY protocol_key_id DESC, id DESC
               ) AS position
        FROM prekeys
        WHERE key_type = 1 AND used = false
    ) ranked
    WHERE ranked.position > 100
) excess
WHERE doomed.id = excess.id;

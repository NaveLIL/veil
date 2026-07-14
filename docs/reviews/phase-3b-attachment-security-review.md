# Phase 3B attachment schema, privacy, and security review

Status: approved for implementation (desktop foundation)

Date: 2026-07-14

## Scope

This review covers encrypted file attachments in DMs, Circles, and Space rooms.
It does not introduce a profile API, remote avatars, plaintext fallback, or a
new trust/roster mechanism. Double Ratchet and authenticated Sender Keys remain
the only authorities that decide who can read a message.

## Security properties

- A file is encrypted once with a random 256-bit content key using the existing
  chunked-AEAD v2 stream. Upload and download use bounded memory and support
  files up to the existing 2 GiB protocol ceiling.
- The server receives only the ciphertext blob, its ciphertext byte length, a
  random media identifier, and `application/octet-stream`. Filename, detected
  MIME type, plaintext length, chunk metadata, and content key stay inside the
  E2EE message payload and SQLCipher.
- The content key is wrapped with XChaCha20-Poly1305. Its random wrapping key is
  carried inside the existing E2EE message, so a Circle or Room does not perform
  per-recipient file encryption. Membership is still enforced by the exact
  Sender-Key roster used for the message.
- The wrapped-key AEAD additional data binds the conversation, attachment
  ordinal, media id, ciphertext geometry, filename, MIME type, and chunked-AEAD
  metadata. The E2EE payload also commits to the complete public attachment
  descriptor. A server-side descriptor substitution therefore fails closed.
- Attachment metadata and keys are committed in the same SQLCipher savepoint as
  the decrypted message and ratchet/Sender-Key receive state. A malformed
  attachment rolls the whole receive operation back.
- Receivers re-detect the MIME type from decrypted bytes before opening or
  previewing a file. The sender-provided type is presentation metadata, not an
  execution or trust decision.
- Image sanitisation happens before encryption. Supported raster images are
  decoded and re-encoded, dropping EXIF and unrelated container metadata.
  Unsupported image formats are sent as generic files, never silently passed
  through an "image-safe" path.

## Versioning and downgrade behaviour

Text-only messages keep their current UTF-8 payload. An attachment message uses
the explicit `veil-attachment-message/v1` envelope inside the same authenticated
E2EE layer. This is a content-format distinction, not weaker encryption.

If a message carries any public attachment descriptor, its decrypted payload
must be a valid attachment envelope and must match every descriptor exactly.
Invalid JSON, unknown fields, duplicate media ids, unsupported versions,
descriptor mismatch, unwrap failure, or inconsistent chunk geometry rejects
the message. There is no path that drops the descriptors and displays only the
text.

Conversely, a text-only payload is rejected if it claims attachment metadata
without public descriptors. Edits of attachment messages remain disabled until
an exact attachment-edit protocol is reviewed.

## Storage and lifecycle

`message_attachments_v1` is keyed by `(message_id, ordinal)` and has unique
`(message_id, media_id)`. It is deleted with its message and follows the local
message UUID when the authoritative ACK replaces it. Keys never leave native
memory or SQLCipher and are never serialized to the renderer.

Incomplete uploads are not messages and are swept by the existing server upload
expiry. A client cancellation stops at a bounded chunk boundary. Resuming must
reuse the exact encrypted upload plan; a changed source file or key is rejected.

## Explicitly excluded

- No arbitrary remote URL, server thumbnailing, or plaintext MIME disclosure.
- No display name, avatar, role, or filename input to crypto trust, ACLs, or
  Sender-Key rotation.
- No browser file renderer. Native saves use an explicit user-selected path;
  media playback will use the separately constrained `veilfile://` protocol.
- No MLS dependency. A future MLS migration may replace only the wrapping-key
  transport after a separate protocol review.


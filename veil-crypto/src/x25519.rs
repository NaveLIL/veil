use x25519_dalek::SharedSecret as X25519SharedSecret;

/// Reject an X25519 input whenever the actual DH result is the identity.
///
/// Checking only the received 32 bytes for zero is insufficient because
/// X25519 accepts several equivalent and low-order public encodings. Call this
/// immediately after every security-authoritative DH operation and before any
/// derived key or protocol state is published.
pub(crate) fn require_contributory(
    shared_secret: &X25519SharedSecret,
    peer_key_kind: &str,
) -> Result<(), String> {
    if shared_secret.was_contributory() {
        Ok(())
    } else {
        Err(format!(
            "non-contributory X25519 {peer_key_kind} was rejected"
        ))
    }
}

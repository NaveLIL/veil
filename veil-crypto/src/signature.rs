use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

use crate::keys::IdentityKeyPair;

/// Sign a message with Ed25519.
pub fn sign(identity: &IdentityKeyPair, message: &[u8]) -> [u8; 64] {
    let sig = identity.ed25519_signing_key().sign(message);
    sig.to_bytes()
}

/// Verify an Ed25519 signature.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    verifying_key.verify(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKeyPair;

    #[test]
    fn test_sign_verify() {
        let identity = IdentityKeyPair::generate();
        let message = b"authenticate me";

        let sig = sign(&identity, message);
        let valid = verify(&identity.ed25519_public_bytes(), message, &sig);

        assert!(valid, "Signature must verify");
    }

    #[test]
    fn test_wrong_key_fails() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let message = b"alice's message";

        let sig = sign(&alice, message);
        let valid = verify(&bob.ed25519_public_bytes(), message, &sig);

        assert!(!valid, "Wrong key must not verify");
    }

    #[test]
    fn test_tampered_message_fails() {
        let identity = IdentityKeyPair::generate();
        let message = b"original";

        let sig = sign(&identity, message);
        let valid = verify(&identity.ed25519_public_bytes(), b"tampered", &sig);

        assert!(!valid, "Tampered message must not verify");
    }

    #[test]
    fn test_tampered_signature_fails() {
        let identity = IdentityKeyPair::generate();
        let message = b"test";

        let mut sig = sign(&identity, message);
        sig[0] ^= 0xff;
        let valid = verify(&identity.ed25519_public_bytes(), message, &sig);

        assert!(!valid, "Tampered signature must not verify");
    }

    #[test]
    fn test_sign_deterministic() {
        let identity = IdentityKeyPair::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ).unwrap();
        let message = b"deterministic test";

        let sig1 = sign(&identity, message);
        let sig2 = sign(&identity, message);

        assert_eq!(sig1, sig2, "Ed25519 signatures must be deterministic");
    }
}

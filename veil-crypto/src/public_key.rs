use curve25519_dalek::edwards::CompressedEdwardsY;

/// Accept an Ed25519 public key only when it is a canonical encoding of a
/// non-identity point in the prime-order subgroup.
///
/// Length-only checks and ordinary signature verification are not sufficient
/// admission rules for an authoritative identity key: pure or mixed torsion
/// points do not represent possession of a prime-order Ed25519 secret. This
/// predicate mirrors the Go server boundary and is intentionally stricter than
/// parsers kept permissive for ecosystem compatibility.
pub fn valid_ed25519_public_key(public_key: &[u8; 32]) -> bool {
    let Some(point) = CompressedEdwardsY(*public_key).decompress() else {
        return false;
    };
    point.compress().to_bytes() == *public_key && !point.is_small_order() && point.is_torsion_free()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    use ed25519_dalek::SigningKey;

    #[test]
    fn accepts_generated_prime_order_key() {
        let signing = SigningKey::from_bytes(&[0x51; 32]);
        assert!(valid_ed25519_public_key(
            &signing.verifying_key().to_bytes()
        ));
    }

    #[test]
    fn rejects_every_small_order_and_mixed_torsion_point() {
        for point in EIGHT_TORSION {
            assert!(!valid_ed25519_public_key(&point.compress().to_bytes()));
        }
        let mixed = ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
        assert!(!valid_ed25519_public_key(&mixed.compress().to_bytes()));
    }

    #[test]
    fn rejects_noncanonical_negative_zero_and_invalid_encodings() {
        // y = p + 1 is a non-canonical encoding equivalent to identity.
        let mut noncanonical_identity = [0xff; 32];
        noncanonical_identity[0] = 0xee;
        noncanonical_identity[31] = 0x7f;
        assert!(!valid_ed25519_public_key(&noncanonical_identity));

        let mut negative_zero = [0u8; 32];
        negative_zero[0] = 1;
        negative_zero[31] = 0x80;
        assert!(!valid_ed25519_public_key(&negative_zero));

        assert!(!valid_ed25519_public_key(&[0xff; 32]));
    }
}

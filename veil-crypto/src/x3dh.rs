use ed25519_dalek::Signer;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::kdf;
use crate::keys::IdentityKeyPair;

/// A prekey bundle published to the server for X3DH session establishment.
#[derive(Clone)]
pub struct PreKeyBundle {
    /// Identity key (IK) — X25519 public
    pub identity_key: [u8; 32],
    /// Ed25519 signing (verifying) key — for SPK signature verification
    pub signing_key: [u8; 32],
    /// Signed prekey (SPK) — X25519 public
    pub signed_prekey: [u8; 32],
    /// Ed25519 signature over SPK
    pub signed_prekey_signature: [u8; 64],
    /// SPK ID (for server-side tracking)
    pub signed_prekey_id: u32,
    /// One-time prekey (OPK) — optional, consumed on first use
    pub one_time_prekey: Option<[u8; 32]>,
    /// OPK ID
    pub one_time_prekey_id: Option<u32>,
}

/// Result of X3DH key agreement — the shared secret used to initialize Double Ratchet.
#[derive(ZeroizeOnDrop)]
pub struct X3DHResult {
    /// Shared secret (32 bytes) — input to Double Ratchet
    pub shared_secret: [u8; 32],
    /// Ephemeral public key to send to the peer
    pub ephemeral_public: [u8; 32],
    /// Associated data: IK_initiator || IK_responder
    pub associated_data: [u8; 64],
}

/// Server-side prekey pair (secret + public).
pub struct SignedPreKey {
    pub secret: X25519StaticSecret,
    pub public: X25519PublicKey,
    pub id: u32,
    pub signature: [u8; 64],
}

impl Drop for SignedPreKey {
    fn drop(&mut self) {
        // X25519StaticSecret doesn't implement Zeroize, so we overwrite via to_bytes()
        let mut bytes = self.secret.to_bytes();
        bytes.zeroize();
        self.signature.zeroize();
    }
}

/// One-time prekey pair.
pub struct OneTimePreKey {
    pub secret: X25519StaticSecret,
    pub public: X25519PublicKey,
    pub id: u32,
}

impl Drop for OneTimePreKey {
    fn drop(&mut self) {
        let mut bytes = self.secret.to_bytes();
        bytes.zeroize();
    }
}

impl SignedPreKey {
    /// Generate a new signed prekey, signed with the identity's Ed25519 key.
    pub fn generate(identity: &IdentityKeyPair, id: u32) -> Self {
        let secret = X25519StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);

        let signature = identity.ed25519_signing_key().sign(public.as_bytes());

        Self {
            secret,
            public,
            id,
            signature: signature.to_bytes(),
        }
    }
}

impl OneTimePreKey {
    /// Generate a new one-time prekey.
    pub fn generate(id: u32) -> Self {
        let secret = X25519StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public, id }
    }

    /// Generate a batch of one-time prekeys.
    pub fn generate_batch(start_id: u32, count: u32) -> Vec<Self> {
        (start_id..start_id + count).map(|id| Self::generate(id)).collect()
    }
}

/// X3DH initiator side: compute shared secret when starting a new session.
///
/// Alice (initiator) fetches Bob's prekey bundle and computes:
/// - DH1 = DH(IK_A, SPK_B)
/// - DH2 = DH(EK_A, IK_B)
/// - DH3 = DH(EK_A, SPK_B)
/// - DH4 = DH(EK_A, OPK_B)  (if available)
/// - SK = HKDF(DH1 || DH2 || DH3 [|| DH4])
pub fn initiate(
    identity: &IdentityKeyPair,
    peer_bundle: &PreKeyBundle,
) -> Result<X3DHResult, String> {
    // Verify SPK signature with peer's Ed25519 signing key
    if !crate::signature::verify(
        &peer_bundle.signing_key,
        &peer_bundle.signed_prekey,
        &peer_bundle.signed_prekey_signature,
    ) {
        return Err("invalid SPK signature: peer's signed prekey failed verification".to_string());
    }

    // Generate ephemeral keypair
    let ek_secret = X25519StaticSecret::random_from_rng(OsRng);
    let ek_public = X25519PublicKey::from(&ek_secret);

    let spk_public = X25519PublicKey::from(peer_bundle.signed_prekey);

    // DH computations
    let dh1 = identity.x25519_secret().diffie_hellman(&spk_public);
    let ik_public = X25519PublicKey::from(peer_bundle.identity_key);
    let dh2 = ek_secret.diffie_hellman(&ik_public);
    let dh3 = ek_secret.diffie_hellman(&spk_public);

    // Concatenate DH outputs
    let mut dh_concat = Vec::with_capacity(128);
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    if let Some(opk_bytes) = peer_bundle.one_time_prekey {
        let opk_public = X25519PublicKey::from(opk_bytes);
        let dh4 = ek_secret.diffie_hellman(&opk_public);
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    // Derive shared secret: HKDF-SHA256
    let mut sk_vec = kdf::hkdf_sha256(
        &[0u8; 32], // salt (all zeros per Signal spec)
        &dh_concat,
        b"veil-x3dh-v1",
        32,
    );

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&sk_vec);

    // Associated data: IK_A || IK_B
    let mut ad = [0u8; 64];
    ad[..32].copy_from_slice(&identity.x25519_public_bytes());
    ad[32..].copy_from_slice(&peer_bundle.identity_key);

    // Zeroize intermediate material
    dh_concat.zeroize();
    sk_vec.zeroize();

    Ok(X3DHResult {
        shared_secret,
        ephemeral_public: *ek_public.as_bytes(),
        associated_data: ad,
    })
}

/// X3DH responder side: compute shared secret from initial message.
///
/// Bob receives Alice's initial message containing her IK and EK,
/// and computes the same shared secret.
pub fn respond(
    identity: &IdentityKeyPair,
    spk: &SignedPreKey,
    opk: Option<&OneTimePreKey>,
    peer_identity_key: &[u8; 32],
    peer_ephemeral_key: &[u8; 32],
) -> Result<X3DHResult, String> {
    let ik_public = X25519PublicKey::from(*peer_identity_key);
    let ek_public = X25519PublicKey::from(*peer_ephemeral_key);

    // DH computations (mirror of initiator)
    let dh1 = spk.secret.diffie_hellman(&ik_public);
    let dh2 = identity.x25519_secret().diffie_hellman(&ek_public);
    let dh3 = spk.secret.diffie_hellman(&ek_public);

    let mut dh_concat = Vec::with_capacity(128);
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    if let Some(opk) = opk {
        let dh4 = opk.secret.diffie_hellman(&ek_public);
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    // Derive shared secret (same HKDF as initiator)
    let mut sk_vec = kdf::hkdf_sha256(&[0u8; 32], &dh_concat, b"veil-x3dh-v1", 32);

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&sk_vec);

    // Associated data: IK_A (peer) || IK_B (self)
    let mut ad = [0u8; 64];
    ad[..32].copy_from_slice(peer_identity_key);
    ad[32..].copy_from_slice(&identity.x25519_public_bytes());

    dh_concat.zeroize();
    sk_vec.zeroize();

    Ok(X3DHResult {
        shared_secret,
        ephemeral_public: *peer_ephemeral_key, // Not used by responder, but kept for API symmetry
        associated_data: ad,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKeyPair;

    #[test]
    fn test_x3dh_with_opk() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        // Bob publishes prekeys
        let bob_spk = SignedPreKey::generate(&bob, 1);
        let bob_opk = OneTimePreKey::generate(1);

        let bob_bundle = PreKeyBundle {
            identity_key: bob.x25519_public_bytes(),
            signing_key: bob.ed25519_public_bytes(),
            signed_prekey: *bob_spk.public.as_bytes(),
            signed_prekey_signature: bob_spk.signature,
            signed_prekey_id: bob_spk.id,
            one_time_prekey: Some(*bob_opk.public.as_bytes()),
            one_time_prekey_id: Some(bob_opk.id),
        };

        // Alice initiates
        let alice_result = initiate(&alice, &bob_bundle).unwrap();

        // Bob responds
        let bob_result = respond(
            &bob,
            &bob_spk,
            Some(&bob_opk),
            &alice.x25519_public_bytes(),
            &alice_result.ephemeral_public,
        ).unwrap();

        assert_eq!(
            alice_result.shared_secret, bob_result.shared_secret,
            "X3DH shared secrets must match"
        );
        assert_eq!(
            alice_result.associated_data, bob_result.associated_data,
            "Associated data must match"
        );
    }

    #[test]
    fn test_x3dh_without_opk() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let bob_spk = SignedPreKey::generate(&bob, 1);

        let bob_bundle = PreKeyBundle {
            identity_key: bob.x25519_public_bytes(),
            signing_key: bob.ed25519_public_bytes(),
            signed_prekey: *bob_spk.public.as_bytes(),
            signed_prekey_signature: bob_spk.signature,
            signed_prekey_id: bob_spk.id,
            one_time_prekey: None,
            one_time_prekey_id: None,
        };

        let alice_result = initiate(&alice, &bob_bundle).unwrap();
        let bob_result = respond(
            &bob,
            &bob_spk,
            None,
            &alice.x25519_public_bytes(),
            &alice_result.ephemeral_public,
        ).unwrap();

        assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
    }

    #[test]
    fn test_x3dh_different_sessions() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let bob_spk = SignedPreKey::generate(&bob, 1);
        let bob_opk1 = OneTimePreKey::generate(1);
        let bob_opk2 = OneTimePreKey::generate(2);

        let bundle1 = PreKeyBundle {
            identity_key: bob.x25519_public_bytes(),
            signing_key: bob.ed25519_public_bytes(),
            signed_prekey: *bob_spk.public.as_bytes(),
            signed_prekey_signature: bob_spk.signature,
            signed_prekey_id: bob_spk.id,
            one_time_prekey: Some(*bob_opk1.public.as_bytes()),
            one_time_prekey_id: Some(1),
        };

        let bundle2 = PreKeyBundle {
            identity_key: bob.x25519_public_bytes(),
            signing_key: bob.ed25519_public_bytes(),
            signed_prekey: *bob_spk.public.as_bytes(),
            signed_prekey_signature: bob_spk.signature,
            signed_prekey_id: bob_spk.id,
            one_time_prekey: Some(*bob_opk2.public.as_bytes()),
            one_time_prekey_id: Some(2),
        };

        let result1 = initiate(&alice, &bundle1).unwrap();
        let result2 = initiate(&alice, &bundle2).unwrap();

        assert_ne!(
            result1.shared_secret, result2.shared_secret,
            "Different OPKs must produce different shared secrets"
        );
    }
}

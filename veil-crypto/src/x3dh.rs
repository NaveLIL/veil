use ed25519_dalek::Signer;
use rand::rngs::OsRng;
use x25519_dalek::{
    PublicKey as X25519PublicKey, SharedSecret as X25519SharedSecret,
    StaticSecret as X25519StaticSecret,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::kdf;
use crate::keys::IdentityKeyPair;

/// Domain separator for Ed25519 signatures over X3DH signed prekeys.
pub const SIGNED_PREKEY_SIGNATURE_DOMAIN: &[u8] = b"veil-x3dh-spk-v1\0";

/// Reject X25519 inputs that collapse a DH term to the identity element.
///
/// RFC 7748 requires protocols to check the all-zero shared-secret result.
/// X25519 accepts several equivalent/low-order public encodings, so checking
/// the received bytes for `[0; 32]` is insufficient. Keeping the check here,
/// immediately after every DH operation, protects all callers before X3DH can
/// derive a root key or publish a Double Ratchet session.
fn require_contributory(
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

/// Build the canonical message covered by an X3DH signed-prekey signature.
///
/// Raw 32-byte SPK signatures from the legacy format are intentionally not
/// accepted: callers must sign this domain-separated message exactly.
pub fn signed_prekey_signature_message(signed_prekey: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNED_PREKEY_SIGNATURE_DOMAIN.len() + 32);
    message.extend_from_slice(SIGNED_PREKEY_SIGNATURE_DOMAIN);
    message.extend_from_slice(signed_prekey);
    message
}

/// A prekey bundle published to the server for X3DH session establishment.
#[derive(Clone)]
pub struct PreKeyBundle {
    /// Identity key (IK) — X25519 public
    pub identity_key: [u8; 32],
    /// Ed25519 signing (verifying) key — for SPK signature verification
    pub signing_key: [u8; 32],
    /// Signed prekey (SPK) — X25519 public
    pub signed_prekey: [u8; 32],
    /// Ed25519 signature over `veil-x3dh-spk-v1\0 || SPK`
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

        let signature_message = signed_prekey_signature_message(public.as_bytes());
        let signature = identity.ed25519_signing_key().sign(&signature_message);

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
        (start_id..start_id + count).map(Self::generate).collect()
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
    verify_peer_bundle_signature(peer_bundle)?;

    let ek_secret = X25519StaticSecret::random_from_rng(OsRng);
    initiate_with_ephemeral_secret(identity, peer_bundle, ek_secret)
}

/// Test-only deterministic entry point for immutable interoperability vectors.
///
/// The fixed secret is accepted only after the same signed-prekey verification
/// used by [`initiate`]. Keeping this helper crate-private and behind
/// `cfg(test)` prevents deterministic key generation from becoming a runtime
/// capability or crossing the public/UniFFI API boundary.
#[cfg(test)]
pub(crate) fn initiate_with_ephemeral_secret_for_test(
    identity: &IdentityKeyPair,
    peer_bundle: &PreKeyBundle,
    ephemeral_secret: &[u8; 32],
) -> Result<X3DHResult, String> {
    verify_peer_bundle_signature(peer_bundle)?;
    initiate_with_ephemeral_secret(
        identity,
        peer_bundle,
        X25519StaticSecret::from(*ephemeral_secret),
    )
}

fn verify_peer_bundle_signature(peer_bundle: &PreKeyBundle) -> Result<(), String> {
    let signature_message = signed_prekey_signature_message(&peer_bundle.signed_prekey);
    if !crate::signature::verify(
        &peer_bundle.signing_key,
        &signature_message,
        &peer_bundle.signed_prekey_signature,
    ) {
        return Err("invalid SPK signature: peer's signed prekey failed verification".to_string());
    }
    Ok(())
}

fn initiate_with_ephemeral_secret(
    identity: &IdentityKeyPair,
    peer_bundle: &PreKeyBundle,
    ek_secret: X25519StaticSecret,
) -> Result<X3DHResult, String> {
    let ek_public = X25519PublicKey::from(&ek_secret);

    let spk_public = X25519PublicKey::from(peer_bundle.signed_prekey);

    // DH computations
    let dh1 = identity.x25519_secret().diffie_hellman(&spk_public);
    let ik_public = X25519PublicKey::from(peer_bundle.identity_key);
    let dh2 = ek_secret.diffie_hellman(&ik_public);
    let dh3 = ek_secret.diffie_hellman(&spk_public);
    let dh4 = peer_bundle.one_time_prekey.map(|opk_bytes| {
        let opk_public = X25519PublicKey::from(opk_bytes);
        ek_secret.diffie_hellman(&opk_public)
    });

    require_contributory(&dh1, "signed prekey")?;
    require_contributory(&dh2, "identity key")?;
    require_contributory(&dh3, "signed prekey")?;
    if let Some(shared) = dh4.as_ref() {
        require_contributory(shared, "one-time prekey")?;
    }

    // Concatenate DH outputs
    let mut dh_concat = Vec::with_capacity(128);
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    if let Some(shared) = dh4.as_ref() {
        dh_concat.extend_from_slice(shared.as_bytes());
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
    let dh4 = opk.map(|one_time_prekey| one_time_prekey.secret.diffie_hellman(&ek_public));

    require_contributory(&dh1, "identity key")?;
    require_contributory(&dh2, "ephemeral key")?;
    require_contributory(&dh3, "ephemeral key")?;
    if let Some(shared) = dh4.as_ref() {
        require_contributory(shared, "ephemeral key")?;
    }

    let mut dh_concat = Vec::with_capacity(128);
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    if let Some(shared) = dh4.as_ref() {
        dh_concat.extend_from_slice(shared.as_bytes());
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

    fn non_zero_low_order_public_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = 1;
        key
    }

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
        )
        .unwrap();

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
        )
        .unwrap();

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

    #[test]
    fn initiator_rejects_non_contributory_identity_spk_and_opk() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(&bob, 1);
        let bob_opk = OneTimePreKey::generate(1);
        let bundle = PreKeyBundle {
            identity_key: bob.x25519_public_bytes(),
            signing_key: bob.ed25519_public_bytes(),
            signed_prekey: *bob_spk.public.as_bytes(),
            signed_prekey_signature: bob_spk.signature,
            signed_prekey_id: bob_spk.id,
            one_time_prekey: Some(*bob_opk.public.as_bytes()),
            one_time_prekey_id: Some(bob_opk.id),
        };
        let low_order = non_zero_low_order_public_key();

        let mut low_identity = bundle.clone();
        low_identity.identity_key = low_order;
        assert!(initiate(&alice, &low_identity)
            .err()
            .expect("low-order identity key must fail")
            .contains("non-contributory X25519 identity key"));

        let mut low_spk = bundle.clone();
        low_spk.signed_prekey = low_order;
        low_spk.signed_prekey_signature = bob
            .ed25519_signing_key()
            .sign(&signed_prekey_signature_message(&low_order))
            .to_bytes();
        assert!(initiate(&alice, &low_spk)
            .err()
            .expect("low-order signed prekey must fail")
            .contains("non-contributory X25519 signed prekey"));

        let mut low_opk = bundle;
        low_opk.one_time_prekey = Some(low_order);
        assert!(initiate(&alice, &low_opk)
            .err()
            .expect("low-order one-time prekey must fail")
            .contains("non-contributory X25519 one-time prekey"));
    }

    #[test]
    fn responder_rejects_non_contributory_identity_and_ephemeral_keys() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(&bob, 1);
        let bob_opk = OneTimePreKey::generate(1);
        let low_order = non_zero_low_order_public_key();

        assert!(respond(
            &bob,
            &bob_spk,
            Some(&bob_opk),
            &low_order,
            &alice.x25519_public_bytes(),
        )
        .err()
        .expect("low-order identity key must fail")
        .contains("non-contributory X25519 identity key"));

        assert!(respond(
            &bob,
            &bob_spk,
            Some(&bob_opk),
            &alice.x25519_public_bytes(),
            &low_order,
        )
        .err()
        .expect("low-order ephemeral key must fail")
        .contains("non-contributory X25519 ephemeral key"));
    }

    #[test]
    fn test_signed_prekey_signature_is_domain_separated() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(&identity, 1);
        let public = *spk.public.as_bytes();
        let message = signed_prekey_signature_message(&public);

        assert!(crate::signature::verify(
            &identity.ed25519_public_bytes(),
            &message,
            &spk.signature
        ));
        assert!(
            !crate::signature::verify(&identity.ed25519_public_bytes(), &public, &spk.signature),
            "legacy raw-SPK signatures must be rejected"
        );

        let mut other_public = public;
        other_public[0] ^= 1;
        assert!(!crate::signature::verify(
            &identity.ed25519_public_bytes(),
            &signed_prekey_signature_message(&other_public),
            &spk.signature
        ));
    }
}

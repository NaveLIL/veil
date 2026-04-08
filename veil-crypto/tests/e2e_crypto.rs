//! Integration tests: full E2E cryptographic flow.
//!
//! These tests exercise the complete path a real client would follow:
//! identity generation → X3DH → Double Ratchet → session persistence.
//!
//! Run with: cargo test -p veil-crypto --test e2e_crypto

use veil_crypto::keys::{generate_mnemonic, IdentityKeyPair};
use veil_crypto::ratchet::RatchetSession;
use veil_crypto::x3dh::{self, OneTimePreKey, SignedPreKey};
use veil_crypto::{aead, fingerprint, kdf, share, signature};

/// Full lifecycle: mnemonic → identity → X3DH → ratchet → 100 messages → serialize → restore → more messages
#[test]
fn test_full_messaging_lifecycle() {
    // === Phase 1: Identity Creation ===
    let alice_mnemonic = generate_mnemonic();
    let bob_mnemonic = generate_mnemonic();

    let alice = IdentityKeyPair::from_mnemonic(&alice_mnemonic.to_string()).unwrap();
    let bob = IdentityKeyPair::from_mnemonic(&bob_mnemonic.to_string()).unwrap();

    // Verify deterministic derivation
    let alice2 = IdentityKeyPair::from_mnemonic(&alice_mnemonic.to_string()).unwrap();
    assert_eq!(alice.x25519_public_bytes(), alice2.x25519_public_bytes());
    assert_eq!(alice.ed25519_public_bytes(), alice2.ed25519_public_bytes());

    // === Phase 2: Fingerprint Verification ===
    let (emoji_ab, hex_ab) = fingerprint::generate(
        &alice.x25519_public_bytes(),
        &bob.x25519_public_bytes(),
    );
    let (emoji_ba, hex_ba) = fingerprint::generate(
        &bob.x25519_public_bytes(),
        &alice.x25519_public_bytes(),
    );
    assert_eq!(emoji_ab, emoji_ba, "Fingerprint must be symmetric");
    assert_eq!(hex_ab, hex_ba);

    // === Phase 3: X3DH Session Establishment ===
    let bob_spk = SignedPreKey::generate(&bob, 1);
    let bob_opk = OneTimePreKey::generate(1);

    let bob_bundle = x3dh::PreKeyBundle {
        identity_key: bob.x25519_public_bytes(),
        signing_key: bob.ed25519_public_bytes(),
        signed_prekey: *bob_spk.public.as_bytes(),
        signed_prekey_signature: bob_spk.signature,
        signed_prekey_id: 1,
        one_time_prekey: Some(*bob_opk.public.as_bytes()),
        one_time_prekey_id: Some(1),
    };

    let alice_x3dh = x3dh::initiate(&alice, &bob_bundle).unwrap();
    let bob_x3dh = x3dh::respond(
        &bob,
        &bob_spk,
        Some(&bob_opk),
        &alice.x25519_public_bytes(),
        &alice_x3dh.ephemeral_public,
    )
    .unwrap();

    assert_eq!(alice_x3dh.shared_secret, bob_x3dh.shared_secret);

    // === Phase 4: Double Ratchet ===
    let mut alice_session = RatchetSession::init_initiator(
        &alice_x3dh.shared_secret,
        &bob_bundle.signed_prekey,
    );
    let mut bob_session = RatchetSession::init_responder(
        &bob_x3dh.shared_secret,
        &bob_spk.secret.to_bytes(),
        bob_spk.public.as_bytes(),
    );

    // 100 alternating messages
    for i in 0u32..100 {
        if i % 2 == 0 {
            let msg = format!("Alice→Bob #{i}: {}", "x".repeat((i as usize) % 500));
            let (header, ct) = alice_session.encrypt(msg.as_bytes()).unwrap();
            let pt = bob_session.decrypt(&header, &ct).unwrap();
            assert_eq!(pt, msg.as_bytes(), "Message {i} mismatch");
        } else {
            let msg = format!("Bob→Alice #{i}");
            let (header, ct) = bob_session.encrypt(msg.as_bytes()).unwrap();
            let pt = alice_session.decrypt(&header, &ct).unwrap();
            assert_eq!(pt, msg.as_bytes(), "Message {i} mismatch");
        }
    }

    // === Phase 5: Session Persistence ===
    let alice_data = alice_session.serialize().unwrap();
    let bob_data = bob_session.serialize().unwrap();

    let mut alice_restored = RatchetSession::deserialize(&alice_data).unwrap();
    let mut bob_restored = RatchetSession::deserialize(&bob_data).unwrap();

    // Continue messaging after restore
    for i in 100u32..120 {
        let msg = format!("Post-restore message #{i}");
        let (header, ct) = alice_restored.encrypt(msg.as_bytes()).unwrap();
        let pt = bob_restored.decrypt(&header, &ct).unwrap();
        assert_eq!(pt, msg.as_bytes());
    }

    // Bob replies after restore
    let (header, ct) = bob_restored.encrypt(b"Bob is back!").unwrap();
    let pt = alice_restored.decrypt(&header, &ct).unwrap();
    assert_eq!(pt, b"Bob is back!");
}

/// Out-of-order delivery with large gaps — simulates unreliable network
#[test]
fn test_out_of_order_stress() {
    let alice_id = IdentityKeyPair::generate();
    let bob_id = IdentityKeyPair::generate();

    let bob_spk = SignedPreKey::generate(&bob_id, 1);
    let bob_opk = OneTimePreKey::generate(1);

    let bundle = x3dh::PreKeyBundle {
        identity_key: bob_id.x25519_public_bytes(),
        signing_key: bob_id.ed25519_public_bytes(),
        signed_prekey: *bob_spk.public.as_bytes(),
        signed_prekey_signature: bob_spk.signature,
        signed_prekey_id: 1,
        one_time_prekey: Some(*bob_opk.public.as_bytes()),
        one_time_prekey_id: Some(1),
    };

    let alice_x3dh = x3dh::initiate(&alice_id, &bundle).unwrap();
    let bob_x3dh = x3dh::respond(
        &bob_id,
        &bob_spk,
        Some(&bob_opk),
        &alice_id.x25519_public_bytes(),
        &alice_x3dh.ephemeral_public,
    )
    .unwrap();

    let mut alice = RatchetSession::init_initiator(&alice_x3dh.shared_secret, &bundle.signed_prekey);
    let mut bob = RatchetSession::init_responder(
        &bob_x3dh.shared_secret,
        &bob_spk.secret.to_bytes(),
        bob_spk.public.as_bytes(),
    );

    // Alice sends 50 messages, Bob receives them in reverse order
    let mut messages = Vec::new();
    for i in 0..50u32 {
        let msg = format!("msg-{i}");
        let (header, ct) = alice.encrypt(msg.as_bytes()).unwrap();
        messages.push((header, ct, msg));
    }

    // Reverse order
    for (header, ct, expected) in messages.into_iter().rev() {
        let pt = bob.decrypt(&header, &ct).unwrap();
        assert_eq!(String::from_utf8(pt).unwrap(), expected);
    }
}

/// Tampered ciphertext must fail — verifies authentication
#[test]
fn test_tamper_detection() {
    let alice_id = IdentityKeyPair::generate();
    let bob_id = IdentityKeyPair::generate();

    let bob_spk = SignedPreKey::generate(&bob_id, 1);

    let bundle = x3dh::PreKeyBundle {
        identity_key: bob_id.x25519_public_bytes(),
        signing_key: bob_id.ed25519_public_bytes(),
        signed_prekey: *bob_spk.public.as_bytes(),
        signed_prekey_signature: bob_spk.signature,
        signed_prekey_id: 1,
        one_time_prekey: None,
        one_time_prekey_id: None,
    };

    let alice_x3dh = x3dh::initiate(&alice_id, &bundle).unwrap();
    let bob_x3dh = x3dh::respond(
        &bob_id,
        &bob_spk,
        None,
        &alice_id.x25519_public_bytes(),
        &alice_x3dh.ephemeral_public,
    )
    .unwrap();

    let mut alice = RatchetSession::init_initiator(&alice_x3dh.shared_secret, &bundle.signed_prekey);
    let mut bob = RatchetSession::init_responder(
        &bob_x3dh.shared_secret,
        &bob_spk.secret.to_bytes(),
        bob_spk.public.as_bytes(),
    );

    let (header, mut ct) = alice.encrypt(b"authentic message").unwrap();

    // Flip a byte in ciphertext
    let mid = ct.len() / 2;
    ct[mid] ^= 0xff;

    let result = bob.decrypt(&header, &ct);
    assert!(result.is_err(), "Tampered ciphertext must be rejected");
}

/// X3DH with forged SPK signature must fail
#[test]
fn test_x3dh_forged_spk_rejected() {
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    let mallory = IdentityKeyPair::generate();

    let bob_spk = SignedPreKey::generate(&bob, 1);

    // Mallory substitutes her own SPK but keeps Bob's signature
    let mallory_spk = SignedPreKey::generate(&mallory, 1);

    let forged_bundle = x3dh::PreKeyBundle {
        identity_key: bob.x25519_public_bytes(),
        signing_key: bob.ed25519_public_bytes(),
        // Mallory's SPK with Bob's signature → MISMATCH
        signed_prekey: *mallory_spk.public.as_bytes(),
        signed_prekey_signature: bob_spk.signature,
        signed_prekey_id: 1,
        one_time_prekey: None,
        one_time_prekey_id: None,
    };

    let result = x3dh::initiate(&alice, &forged_bundle);
    assert!(result.is_err(), "Forged SPK must be rejected");
    let err = result.err().unwrap();
    assert!(
        err.contains("invalid SPK signature"),
        "Error must mention SPK signature, got: {err}"
    );
}

/// Standalone AEAD: encrypt → tamper → fail
#[test]
fn test_aead_integrity() {
    let key = [0x42u8; 32];

    // Various payload sizes
    for size in [0, 1, 255, 256, 257, 1024, 10_000] {
        let plaintext = vec![0xAB; size];
        let (ct, nonce) = aead::encrypt(&key, &plaintext).unwrap();
        let pt = aead::decrypt(&key, &ct, &nonce).unwrap();
        assert_eq!(pt, plaintext, "Roundtrip failed for size {size}");
    }

    // Wrong key
    let (ct, nonce) = aead::encrypt(&key, b"secret").unwrap();
    assert!(aead::decrypt(&[0u8; 32], &ct, &nonce).is_err());

    // Wrong nonce
    let mut bad_nonce = nonce;
    bad_nonce[0] ^= 1;
    assert!(aead::decrypt(&key, &ct, &bad_nonce).is_err());
}

/// Secure share: full lifecycle with and without password
#[test]
fn test_share_lifecycle() {
    let payload = b"This is a confidential document that self-destructs.";

    // Without password
    let bundle = share::encrypt_share(payload, None).unwrap();
    let decrypted = share::decrypt_share(
        &bundle.ciphertext,
        Some(&bundle.content_key),
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(decrypted, payload);

    // With password
    let bundle_pw = share::encrypt_share(payload, Some("$ecureP@ss!")).unwrap();
    assert!(bundle_pw.wrapped_key.is_some());
    assert!(bundle_pw.salt.is_some());

    let decrypted_pw = share::decrypt_share(
        &bundle_pw.ciphertext,
        None,
        Some("$ecureP@ss!"),
        bundle_pw.wrapped_key.as_deref(),
        bundle_pw.salt.as_ref(),
    )
    .unwrap();
    assert_eq!(decrypted_pw, payload);

    // Wrong password
    let result = share::decrypt_share(
        &bundle_pw.ciphertext,
        None,
        Some("wrong"),
        bundle_pw.wrapped_key.as_deref(),
        bundle_pw.salt.as_ref(),
    );
    assert!(result.is_err());
}

/// Ed25519 signature: sign → verify → tamper check
#[test]
fn test_signature_flow() {
    let identity = IdentityKeyPair::generate();
    let message = b"I authorize this transaction";

    let sig = signature::sign(&identity, message);
    assert!(signature::verify(
        &identity.ed25519_public_bytes(),
        message,
        &sig
    ));

    // Different message
    assert!(!signature::verify(
        &identity.ed25519_public_bytes(),
        b"I authorize a DIFFERENT transaction",
        &sig
    ));

    // Different key
    let other = IdentityKeyPair::generate();
    assert!(!signature::verify(
        &other.ed25519_public_bytes(),
        message,
        &sig
    ));
}

/// KDF determinism: same inputs → same outputs
#[test]
fn test_kdf_determinism() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let seed1 = kdf::derive_seed_from_mnemonic(mnemonic).unwrap();
    let seed2 = kdf::derive_seed_from_mnemonic(mnemonic).unwrap();
    assert_eq!(seed1, seed2);

    let salt = [1u8; 32];
    let pin_key1 = kdf::derive_key_from_pin("1234", &salt).unwrap();
    let pin_key2 = kdf::derive_key_from_pin("1234", &salt).unwrap();
    assert_eq!(pin_key1, pin_key2);

    // Different PIN → different key
    let pin_key3 = kdf::derive_key_from_pin("5678", &salt).unwrap();
    assert_ne!(pin_key1, pin_key3);
}

//! Integration tests: client API + store layer.
//!
//! Tests the full client workflow: mnemonic → init → DB operations.
//! Run with: cargo test -p veil-client --test e2e_client

use veil_crypto::keys::IdentityKeyPair;

/// Test that VeilClient initializes and produces consistent keys
#[test]
fn test_client_init_deterministic() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let id1 = IdentityKeyPair::from_mnemonic(mnemonic).unwrap();
    let id2 = IdentityKeyPair::from_mnemonic(mnemonic).unwrap();

    assert_eq!(id1.x25519_public_bytes(), id2.x25519_public_bytes());
    assert_eq!(id1.ed25519_public_bytes(), id2.ed25519_public_bytes());
}

/// Test DB key derivation produces different keys for different mnemonics
#[test]
fn test_db_key_isolation() {
    use veil_crypto::kdf;

    let key1 = kdf::hkdf_sha256(
        b"veil-db-key-v1",
        b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        b"database-encryption",
        32,
    );
    let key2 = kdf::hkdf_sha256(
        b"veil-db-key-v1",
        b"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        b"database-encryption",
        32,
    );

    assert_ne!(
        key1, key2,
        "Different mnemonics must produce different DB keys"
    );
    assert_eq!(key1.len(), 32);
}

/// Test SQLCipher DB round-trip with store layer
#[test]
fn test_store_conversation_roundtrip() {
    use veil_store::db::VeilDb;

    let key = [0x42u8; 32];
    let db = VeilDb::open_memory(&key).unwrap();

    // Insert conversation
    db.conn()
        .execute(
            "INSERT INTO conversations (id, conv_type, name) VALUES (?1, ?2, ?3)",
            rusqlite::params!["conv-test-1", 1, "Integration Test Group"],
        )
        .unwrap();

    // Insert message
    db.conn()
        .execute(
            "INSERT INTO messages (id, conversation_id, sender_key, plaintext, is_outgoing)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "msg-1",
                "conv-test-1",
                vec![1u8; 32],
                "Hello from integration test",
                1
            ],
        )
        .unwrap();

    // Query back
    let (name, count): (String, i64) = db
        .conn()
        .query_row(
            "SELECT c.name, COUNT(m.id)
             FROM conversations c
             LEFT JOIN messages m ON m.conversation_id = c.id
             WHERE c.id = ?1
             GROUP BY c.id",
            rusqlite::params!["conv-test-1"],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();

    assert_eq!(name, "Integration Test Group");
    assert_eq!(count, 1);
}

/// Test ratchet session persistence through veil-store
#[test]
fn test_ratchet_session_store_roundtrip() {
    use veil_crypto::ratchet::RatchetSession;
    use veil_crypto::x3dh::{self, OneTimePreKey, SignedPreKey};
    use veil_store::db::VeilDb;

    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();

    let bob_spk = SignedPreKey::generate(&bob, 1);
    let bob_opk = OneTimePreKey::generate(1);

    let bundle = x3dh::PreKeyBundle {
        identity_key: bob.x25519_public_bytes(),
        signing_key: bob.ed25519_public_bytes(),
        signed_prekey: *bob_spk.public.as_bytes(),
        signed_prekey_signature: bob_spk.signature,
        signed_prekey_id: 1,
        one_time_prekey: Some(*bob_opk.public.as_bytes()),
        one_time_prekey_id: Some(1),
    };

    let alice_x3dh = x3dh::initiate(&alice, &bundle).unwrap();
    let bob_x3dh = x3dh::respond(
        &bob,
        &bob_spk,
        Some(&bob_opk),
        &alice.x25519_public_bytes(),
        &alice_x3dh.ephemeral_public,
    )
    .unwrap();

    let mut alice_session =
        RatchetSession::init_initiator(&alice_x3dh.shared_secret, &bundle.signed_prekey);
    let mut bob_session = RatchetSession::init_responder(
        &bob_x3dh.shared_secret,
        &bob_spk.secret.to_bytes(),
        bob_spk.public.as_bytes(),
    );

    // Exchange a few messages
    let (h, ct) = alice_session.encrypt(b"before store").unwrap();
    bob_session.decrypt(&h, &ct).unwrap();

    let (h, ct) = bob_session.encrypt(b"reply before store").unwrap();
    alice_session.decrypt(&h, &ct).unwrap();

    // Serialize and store in SQLCipher
    let key = [0x99u8; 32];
    let db = VeilDb::open_memory(&key).unwrap();

    let alice_data = alice_session.serialize().unwrap();
    let bob_data = bob_session.serialize().unwrap();

    db.conn()
        .execute(
            "INSERT INTO ratchet_sessions (peer_identity_key, session_data) VALUES (?1, ?2)",
            rusqlite::params![bob.x25519_public_bytes().to_vec(), alice_data],
        )
        .unwrap();

    db.conn()
        .execute(
            "INSERT INTO ratchet_sessions (peer_identity_key, session_data) VALUES (?1, ?2)",
            rusqlite::params![alice.x25519_public_bytes().to_vec(), bob_data],
        )
        .unwrap();

    // Restore from DB
    let restored_alice_data: Vec<u8> = db
        .conn()
        .query_row(
            "SELECT session_data FROM ratchet_sessions WHERE peer_identity_key = ?1",
            rusqlite::params![bob.x25519_public_bytes().to_vec()],
            |row| row.get(0),
        )
        .unwrap();

    let restored_bob_data: Vec<u8> = db
        .conn()
        .query_row(
            "SELECT session_data FROM ratchet_sessions WHERE peer_identity_key = ?1",
            rusqlite::params![alice.x25519_public_bytes().to_vec()],
            |row| row.get(0),
        )
        .unwrap();

    let mut alice_restored = RatchetSession::deserialize(&restored_alice_data).unwrap();
    let mut bob_restored = RatchetSession::deserialize(&restored_bob_data).unwrap();

    // Continue messaging
    let (h, ct) = alice_restored.encrypt(b"after DB restore").unwrap();
    let pt = bob_restored.decrypt(&h, &ct).unwrap();
    assert_eq!(pt, b"after DB restore");

    let (h, ct) = bob_restored.encrypt(b"bob after restore too").unwrap();
    let pt = alice_restored.decrypt(&h, &ct).unwrap();
    assert_eq!(pt, b"bob after restore too");
}

use super::*;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

const FIXTURE_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../test-vectors/direct-v1/v1.json"
));
const FIXTURE_ORIGIN: &str = "https://phase5s-fixture.test:443";
const ALICE_USER_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BOB_USER_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const CREATED_AT: &str = "2026-07-20T00:00:00Z";

#[derive(Deserialize)]
struct DirectV1Fixture {
    inputs: DirectV1Inputs,
    expected: DirectV1Expected,
}

#[derive(Deserialize)]
struct DirectV1Inputs {
    alice_mnemonic: String,
    bob_mnemonic: String,
    conversation_id: String,
    text: String,
    bob_signed_prekey_secret_b64: String,
    bob_one_time_prekey_secret_b64: String,
    xchacha_nonce_b64: String,
    signed_prekey_id: u32,
    one_time_prekey_id: u32,
}

#[derive(Deserialize)]
struct DirectV1Expected {
    identities: DirectV1Identities,
    prekeys: DirectV1PreKeys,
    headers: DirectV1Headers,
    payload: DirectV1Payload,
    sessions: DirectV1Sessions,
}

#[derive(Deserialize)]
struct DirectV1Identities {
    alice: DirectV1Identity,
    bob: DirectV1Identity,
}

#[derive(Deserialize)]
struct DirectV1Identity {
    x25519_public_b64: String,
    ed25519_public_b64: String,
}

#[derive(Deserialize)]
struct DirectV1PreKeys {
    signed_public_b64: String,
    signed_signature_b64: String,
    one_time_public_b64: String,
}

#[derive(Deserialize)]
struct DirectV1Headers {
    pending_initial_json_b64: String,
    initial_prefix_b64: String,
    ratchet_b64: String,
    full_b64: String,
}

#[derive(Deserialize)]
struct DirectV1Payload {
    inner_plaintext_b64: String,
    client_associated_data_b64: String,
    ciphertext_b64: String,
    transport_b64: String,
}

#[derive(Deserialize)]
struct DirectV1Sessions {
    initiator_before_message_json_b64: String,
    initiator_after_message_json_b64: String,
    responder_before_message_json_b64: String,
    responder_after_message_json_b64: String,
}

#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
struct ReceiverPersistenceSnapshot {
    runtime_session_json: Option<Vec<u8>>,
    runtime_one_time_prekey: Option<[u8; 32]>,
    durable_session: Option<(Vec<u8>, u64)>,
    durable_prekeys: Vec<DurablePreKeySnapshot>,
}

#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
struct DurablePreKeySnapshot {
    key_type: u8,
    protocol_key_id: u32,
    secret_key: [u8; 32],
    public_key: [u8; 32],
    signature: Option<[u8; 64]>,
}

fn fixture() -> DirectV1Fixture {
    serde_json::from_str(FIXTURE_JSON).expect("Direct-v1 fixture must remain valid JSON")
}

fn decode_b64(label: &str, encoded: &str) -> Vec<u8> {
    let decoded = BASE64_STANDARD
        .decode(encoded)
        .unwrap_or_else(|error| panic!("decode {label}: {error}"));
    assert_eq!(
        BASE64_STANDARD.encode(&decoded),
        encoded,
        "{label} must use canonical padded RFC 4648 Base64"
    );
    decoded
}

fn decode_b64_array<const N: usize>(label: &str, encoded: &str) -> [u8; N] {
    decode_b64(label, encoded)
        .try_into()
        .unwrap_or_else(|value: Vec<u8>| {
            panic!("{label} must contain {N} bytes, got {}", value.len())
        })
}

fn fixture_database_path(role: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "veil-phase5s-direct-v1-{role}-{}.db",
        uuid::Uuid::new_v4()
    ))
}

fn remove_fixture_database(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
    let _ = std::fs::remove_file(path.with_extension("db-journal"));
}

fn install_direct_route(
    client: &VeilClient,
    conversation_id: &str,
    peer_user_id: &str,
    peer_identity_key: &[u8; 32],
) {
    client
        .db()
        .expect("fixture client has SQLCipher")
        .upsert_directory_conversation(
            conversation_id,
            ConversationType::DM as u8,
            FIXTURE_ORIGIN,
            Some("Phase 5S fixture peer"),
            Some(peer_user_id),
            Some(peer_identity_key),
            None,
            CREATED_AT,
        )
        .expect("install exact fixture Direct route");
}

fn serialize_runtime_session(client: &VeilClient, peer: &[u8; 32]) -> Option<Vec<u8>> {
    client
        .ratchet_sessions
        .get(peer)
        .map(|session| serde_json::to_vec(session).expect("serialize runtime ratchet"))
}

fn receiver_persistence_snapshot(
    client: &VeilClient,
    sender_identity_key: &[u8; 32],
    one_time_prekey_id: u32,
) -> ReceiverPersistenceSnapshot {
    let db = client.db().expect("fixture receiver has SQLCipher");
    let durable_session = db
        .load_ratchet_session_with_revision_v1(sender_identity_key)
        .expect("load durable fixture ratchet")
        .map(|stored| (stored.session_data.clone(), stored.revision));
    let durable_prekeys = db
        .load_local_prekeys()
        .expect("load durable fixture prekeys")
        .into_iter()
        .map(|prekey| DurablePreKeySnapshot {
            key_type: prekey.key_type,
            protocol_key_id: prekey.protocol_key_id,
            secret_key: prekey.secret_key,
            public_key: prekey.public_key,
            signature: prekey.signature,
        })
        .collect();
    ReceiverPersistenceSnapshot {
        runtime_session_json: serialize_runtime_session(client, sender_identity_key),
        runtime_one_time_prekey: client.otk_secrets.get(&one_time_prekey_id).copied(),
        durable_session,
        durable_prekeys,
    }
}

fn assert_text_payload(payload: DecryptedPayload, expected: &str) {
    match payload {
        DecryptedPayload::Text(plaintext) => assert_eq!(plaintext, expected.as_bytes()),
        DecryptedPayload::Control => panic!("Direct-v1 text fixture decoded as a control frame"),
    }
}

#[test]
fn direct_v1_fixture_hydrates_exact_sender_state_and_keeps_nonce_random() {
    let fixture = fixture();
    let alice_identity_key = decode_b64_array::<32>(
        "Alice X25519 identity",
        &fixture.expected.identities.alice.x25519_public_b64,
    );
    let alice_signing_key = decode_b64_array::<32>(
        "Alice Ed25519 identity",
        &fixture.expected.identities.alice.ed25519_public_b64,
    );
    let bob_identity_key = decode_b64_array::<32>(
        "Bob X25519 identity",
        &fixture.expected.identities.bob.x25519_public_b64,
    );
    let bob_signing_key = decode_b64_array::<32>(
        "Bob Ed25519 identity",
        &fixture.expected.identities.bob.ed25519_public_b64,
    );
    let pending_header = decode_b64(
        "pending initial header JSON",
        &fixture.expected.headers.pending_initial_json_b64,
    );
    let initiator_before = decode_b64(
        "initiator pre-message session JSON",
        &fixture.expected.sessions.initiator_before_message_json_b64,
    );
    let initiator_after = decode_b64(
        "initiator post-message session JSON",
        &fixture.expected.sessions.initiator_after_message_json_b64,
    );
    let expected_prefix = decode_b64(
        "initial wire prefix",
        &fixture.expected.headers.initial_prefix_b64,
    );
    let expected_ratchet_header =
        decode_b64("ratchet header", &fixture.expected.headers.ratchet_b64);
    let expected_full_header = decode_b64("full Direct header", &fixture.expected.headers.full_b64);
    let expected_inner = decode_b64(
        "inner Direct plaintext",
        &fixture.expected.payload.inner_plaintext_b64,
    );
    let fixed_transport = decode_b64(
        "fixed-nonce transport ciphertext",
        &fixture.expected.payload.transport_b64,
    );
    let fixed_ciphertext = decode_b64(
        "fixed-nonce AEAD ciphertext",
        &fixture.expected.payload.ciphertext_b64,
    );
    let fixed_nonce = decode_b64_array::<{ veil_crypto::aead::NONCE_SIZE }>(
        "fixed XChaCha20 nonce",
        &fixture.inputs.xchacha_nonce_b64,
    );
    let expected_client_associated_data = decode_b64(
        "client Direct associated data",
        &fixture.expected.payload.client_associated_data_b64,
    );

    assert_eq!(
        expected_full_header,
        [
            expected_prefix.as_slice(),
            expected_ratchet_header.as_slice()
        ]
        .concat()
    );
    assert_eq!(
        &fixed_transport[..veil_crypto::aead::NONCE_SIZE],
        fixed_nonce
    );
    assert_eq!(
        &fixed_transport[veil_crypto::aead::NONCE_SIZE..],
        fixed_ciphertext
    );
    assert_eq!(
        ratchet_associated_data(
            &fixture.inputs.conversation_id,
            &alice_identity_key,
            &bob_identity_key,
            &expected_prefix,
        )
        .unwrap(),
        expected_client_associated_data,
        "conversation, identities, and INITIAL metadata must retain their exact Direct-v1 binding"
    );
    assert_eq!(
        expected_inner,
        VeilClient::wrap_text_inner(&fixture.inputs.text),
        "client text framing must remain part of the frozen Direct-v1 transcript"
    );

    let path = fixture_database_path("alice");
    remove_fixture_database(&path);
    {
        let mut seed = VeilClient::new();
        seed.init_with_mnemonic(&fixture.inputs.alice_mnemonic, &path)
            .expect("initialize Alice fixture database");
        assert_eq!(seed.identity_key().unwrap(), alice_identity_key);
        assert_eq!(seed.signing_key().unwrap(), alice_signing_key);
        install_direct_route(
            &seed,
            &fixture.inputs.conversation_id,
            BOB_USER_ID,
            &bob_identity_key,
        );
        seed.pin_peer_signing_key(bob_identity_key, bob_signing_key)
            .expect("pin Bob fixture signing key");
        seed.db()
            .unwrap()
            .save_initiator_session(&bob_identity_key, &initiator_before, &pending_header)
            .expect("persist exact initiator fixture state");
    }

    let mut alice = VeilClient::new();
    alice
        .init_with_mnemonic(&fixture.inputs.alice_mnemonic, &path)
        .expect("hydrate Alice fixture state through production open");
    assert_eq!(alice.identity_key().unwrap(), alice_identity_key);
    assert_eq!(alice.signing_key().unwrap(), alice_signing_key);
    assert_eq!(
        serialize_runtime_session(&alice, &bob_identity_key).as_deref(),
        Some(initiator_before.as_slice()),
        "production open must hydrate the exact frozen initiator pre-state"
    );
    assert_eq!(
        alice
            .pending_initial_headers
            .get(&bob_identity_key)
            .map(|header| serde_json::to_vec(header).unwrap())
            .as_deref(),
        Some(pending_header.as_slice()),
        "production open must hydrate the exact pending INITIAL metadata"
    );
    let hydrated_persisted = alice
        .db()
        .unwrap()
        .load_ratchet_session_with_revision_v1(&bob_identity_key)
        .unwrap()
        .expect("hydrated initiator session must remain durable");
    assert_eq!(hydrated_persisted.session_data, initiator_before);
    assert_eq!(hydrated_persisted.revision, 0);
    alice
        .bind_dm_conversation(&fixture.inputs.conversation_id, bob_identity_key)
        .expect("publish exact authenticated fixture route");
    assert_eq!(
        alice.dm_conversations.get(&fixture.inputs.conversation_id),
        Some(&bob_identity_key)
    );

    let prepared_one = alice
        .prepare_direct_ciphertext_v1(
            &bob_identity_key,
            &fixture.inputs.conversation_id,
            &expected_inner,
        )
        .expect("prepare first production Direct packet");
    let prepared_two = alice
        .prepare_direct_ciphertext_v1(
            &bob_identity_key,
            &fixture.inputs.conversation_id,
            &expected_inner,
        )
        .expect("prepare second production Direct packet");

    for prepared in [&prepared_one, &prepared_two] {
        assert_eq!(prepared.peer_identity_key, bob_identity_key);
        assert_eq!(prepared.header, expected_full_header);
        assert_eq!(
            serde_json::to_vec(&prepared.candidate).unwrap(),
            initiator_after,
            "nonce selection must not change the ratchet candidate"
        );
        assert_eq!(prepared.ciphertext.len(), fixed_transport.len());

        let mut responder = RatchetSession::deserialize(&decode_b64(
            "responder pre-message session JSON",
            &fixture.expected.sessions.responder_before_message_json_b64,
        ))
        .expect("deserialize frozen responder pre-state");
        let header = MessageHeader::from_bytes(&prepared.header[expected_prefix.len()..])
            .expect("parse production ratchet header");
        let associated_data = ratchet_associated_data(
            &fixture.inputs.conversation_id,
            &alice_identity_key,
            &bob_identity_key,
            &prepared.header[..expected_prefix.len()],
        )
        .expect("construct production Direct associated data");
        assert_eq!(
            responder
                .decrypt_with_ad(&header, &prepared.ciphertext, &associated_data)
                .expect("decrypt random-nonce production packet from frozen pre-state"),
            expected_inner
        );
    }
    assert_ne!(
        prepared_one.ciphertext, prepared_two.ciphertext,
        "the production client must not expose deterministic Direct ciphertext"
    );
    assert_eq!(
        serialize_runtime_session(&alice, &bob_identity_key).as_deref(),
        Some(initiator_before.as_slice()),
        "preparation must leave the live ratchet at the exact pre-state until commit"
    );
    let still_uncommitted = alice
        .db()
        .unwrap()
        .load_ratchet_session_with_revision_v1(&bob_identity_key)
        .unwrap()
        .expect("prepared initiator session must remain durable");
    assert_eq!(still_uncommitted.session_data, initiator_before);
    assert_eq!(still_uncommitted.revision, 0);

    let (committed_ciphertext, committed_header) = alice
        .encrypt_outgoing(&fixture.inputs.conversation_id, &fixture.inputs.text)
        .expect("commit one production Direct encryption");
    assert_eq!(committed_header, expected_full_header);
    assert_eq!(committed_ciphertext.len(), fixed_transport.len());
    assert_eq!(
        serialize_runtime_session(&alice, &bob_identity_key).as_deref(),
        Some(initiator_after.as_slice())
    );
    let persisted = alice
        .db()
        .unwrap()
        .load_ratchet_session_with_revision_v1(&bob_identity_key)
        .unwrap()
        .expect("committed production candidate must be durable");
    assert_eq!(persisted.session_data, initiator_after);
    assert_eq!(persisted.revision, 1);
    assert_eq!(
        alice.db().unwrap().load_pending_initial_headers().unwrap(),
        vec![(bob_identity_key, pending_header)],
        "encryption alone must not retire the exact INITIAL header before peer possession"
    );

    drop(alice);
    remove_fixture_database(&path);
}

#[test]
fn direct_v1_fixed_packet_failures_do_not_consume_responder_state() {
    let fixture = fixture();
    let alice_identity_key = decode_b64_array::<32>(
        "Alice X25519 identity",
        &fixture.expected.identities.alice.x25519_public_b64,
    );
    let alice_signing_key = decode_b64_array::<32>(
        "Alice Ed25519 identity",
        &fixture.expected.identities.alice.ed25519_public_b64,
    );
    let bob_identity_key = decode_b64_array::<32>(
        "Bob X25519 identity",
        &fixture.expected.identities.bob.x25519_public_b64,
    );
    let bob_signing_key = decode_b64_array::<32>(
        "Bob Ed25519 identity",
        &fixture.expected.identities.bob.ed25519_public_b64,
    );
    let signed_prekey_secret = decode_b64_array::<32>(
        "Bob signed prekey secret",
        &fixture.inputs.bob_signed_prekey_secret_b64,
    );
    let signed_prekey_public = decode_b64_array::<32>(
        "Bob signed prekey public",
        &fixture.expected.prekeys.signed_public_b64,
    );
    let signed_prekey_signature = decode_b64_array::<64>(
        "Bob signed prekey signature",
        &fixture.expected.prekeys.signed_signature_b64,
    );
    let one_time_prekey_secret = decode_b64_array::<32>(
        "Bob one-time prekey secret",
        &fixture.inputs.bob_one_time_prekey_secret_b64,
    );
    let one_time_prekey_public = decode_b64_array::<32>(
        "Bob one-time prekey public",
        &fixture.expected.prekeys.one_time_public_b64,
    );
    let full_header = decode_b64("full Direct header", &fixture.expected.headers.full_b64);
    let transport = decode_b64(
        "fixed-nonce transport ciphertext",
        &fixture.expected.payload.transport_b64,
    );
    let responder_before = decode_b64(
        "responder pre-message session JSON",
        &fixture.expected.sessions.responder_before_message_json_b64,
    );
    let deterministic_responder_after = decode_b64(
        "deterministic responder post-message session JSON",
        &fixture.expected.sessions.responder_after_message_json_b64,
    );

    let path = fixture_database_path("bob");
    remove_fixture_database(&path);
    {
        let mut seed = VeilClient::new();
        seed.init_with_mnemonic(&fixture.inputs.bob_mnemonic, &path)
            .expect("initialize Bob fixture database");
        assert_eq!(seed.identity_key().unwrap(), bob_identity_key);
        assert_eq!(seed.signing_key().unwrap(), bob_signing_key);
        install_direct_route(
            &seed,
            &fixture.inputs.conversation_id,
            ALICE_USER_ID,
            &alice_identity_key,
        );
        seed.pin_peer_signing_key(alice_identity_key, alice_signing_key)
            .expect("pin Alice fixture signing key");
        seed.db()
            .unwrap()
            .save_local_prekeys(&[
                LocalPreKey {
                    key_type: 0,
                    protocol_key_id: fixture.inputs.signed_prekey_id,
                    secret_key: signed_prekey_secret,
                    public_key: signed_prekey_public,
                    signature: Some(signed_prekey_signature),
                },
                LocalPreKey {
                    key_type: 1,
                    protocol_key_id: fixture.inputs.one_time_prekey_id,
                    secret_key: one_time_prekey_secret,
                    public_key: one_time_prekey_public,
                    signature: None,
                },
            ])
            .expect("persist exact responder prekeys");
    }

    let mut bob = VeilClient::new();
    bob.init_with_mnemonic(&fixture.inputs.bob_mnemonic, &path)
        .expect("hydrate Bob fixture prekeys through production open");
    bob.bind_dm_conversation(&fixture.inputs.conversation_id, alice_identity_key)
        .expect("publish exact authenticated fixture route");
    assert_eq!(
        bob.dm_conversations.get(&fixture.inputs.conversation_id),
        Some(&alice_identity_key)
    );
    assert_eq!(
        serde_json::to_vec(
            &bob.build_responder_session(
                &alice_identity_key,
                &full_header[1..33].try_into().unwrap(),
                fixture.inputs.signed_prekey_id,
                Some(fixture.inputs.one_time_prekey_id),
            )
            .expect("derive exact responder pre-state from hydrated SQLCipher keys")
        )
        .unwrap(),
        responder_before
    );

    let untouched =
        receiver_persistence_snapshot(&bob, &alice_identity_key, fixture.inputs.one_time_prekey_id);
    assert!(untouched.runtime_session_json.is_none());
    assert_eq!(
        untouched.runtime_one_time_prekey,
        Some(one_time_prekey_secret)
    );

    let wrong_conversation = "11111111-2222-4333-8444-555555555556";
    assert!(bob
        .decrypt_from(
            &alice_identity_key,
            wrong_conversation,
            &full_header,
            &transport,
        )
        .is_err());
    assert_eq!(
        receiver_persistence_snapshot(&bob, &alice_identity_key, fixture.inputs.one_time_prekey_id,),
        untouched,
        "cross-conversation authentication failure must not consume an OPK or install a session"
    );

    let mut changed_header = full_header.clone();
    changed_header[1] ^= 1;
    assert!(bob
        .decrypt_from(
            &alice_identity_key,
            &fixture.inputs.conversation_id,
            &changed_header,
            &transport,
        )
        .is_err());
    assert_eq!(
        receiver_persistence_snapshot(&bob, &alice_identity_key, fixture.inputs.one_time_prekey_id,),
        untouched,
        "authenticated header failure must leave responder state byte-identical"
    );

    let mut changed_transport = transport.clone();
    *changed_transport.last_mut().unwrap() ^= 1;
    assert!(bob
        .decrypt_from(
            &alice_identity_key,
            &fixture.inputs.conversation_id,
            &full_header,
            &changed_transport,
        )
        .is_err());
    assert_eq!(
        receiver_persistence_snapshot(&bob, &alice_identity_key, fixture.inputs.one_time_prekey_id,),
        untouched,
        "ciphertext authentication failure must leave responder state byte-identical"
    );

    let decrypted = bob
        .decrypt_from(
            &alice_identity_key,
            &fixture.inputs.conversation_id,
            &full_header,
            &transport,
        )
        .expect("the exact frozen Direct-v1 tuple must decrypt after failed probes");
    assert_text_payload(decrypted, &fixture.inputs.text);
    assert!(bob.has_session(&alice_identity_key));
    assert!(!bob
        .otk_secrets
        .contains_key(&fixture.inputs.one_time_prekey_id));
    let committed = bob
        .db()
        .unwrap()
        .load_ratchet_session_with_revision_v1(&alice_identity_key)
        .unwrap()
        .expect("successful authentication must commit the responder session");
    assert_eq!(committed.revision, 0);
    assert_ne!(committed.session_data, responder_before);
    assert_ne!(
        committed.session_data, deterministic_responder_after,
        "production responder state must not reuse the fixture's deterministic next ratchet key"
    );
    assert_eq!(
        serialize_runtime_session(&bob, &alice_identity_key).as_deref(),
        Some(committed.session_data.as_slice()),
        "the randomized production responder post-state must commit identically to memory and SQLCipher"
    );
    let remaining_prekeys = bob.db().unwrap().load_local_prekeys().unwrap();
    assert_eq!(remaining_prekeys.len(), 1);
    assert_eq!(remaining_prekeys[0].key_type, 0);
    assert_eq!(
        remaining_prekeys[0].protocol_key_id,
        fixture.inputs.signed_prekey_id
    );
    assert_eq!(remaining_prekeys[0].secret_key, signed_prekey_secret);
    assert_eq!(remaining_prekeys[0].public_key, signed_prekey_public);
    assert_eq!(
        remaining_prekeys[0].signature,
        Some(signed_prekey_signature)
    );

    drop(bob);
    remove_fixture_database(&path);
}
